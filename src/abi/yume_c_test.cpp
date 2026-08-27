/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "yume/yume.h"

#include "service_open_wait.hpp"
#include "service_status.hpp"
#include "client/transport/runtime_lifetime.hpp"

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#if !defined(_WIN32)
#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

static_assert(YUME_BUILD_INFO_MIN_SIZE ==
              offsetof(yume_build_info, yume_version));
static_assert(yume::abi::detail::service_read_status(
                  yume::runtime::ServiceStream::ReadResult::Data, 0) ==
              YUME_STATUS_OK);
static_assert(yume::abi::detail::service_read_status(
                  yume::runtime::ServiceStream::ReadResult::Eof, 0) ==
              YUME_STATUS_OK);
static_assert(yume::abi::detail::service_read_status(
                  yume::runtime::ServiceStream::ReadResult::Timeout, 0) ==
              YUME_STATUS_WOULD_BLOCK);
static_assert(yume::abi::detail::service_read_status(
                  yume::runtime::ServiceStream::ReadResult::Timeout, 1) ==
              YUME_STATUS_TIMEOUT);
static_assert(yume::abi::detail::service_read_status(
                  yume::runtime::ServiceStream::ReadResult::Closed, 0) ==
              YUME_STATUS_NOT_RUNNING);

int test_service_open_wait_lifetime_and_cancellation() {
    using Wait = yume::abi::detail::ServiceOpenWait;

    auto timed_out = std::make_shared<Wait>();
    std::weak_ptr<Wait> weak_timed_out = timed_out;
    std::function<void()> late_callback = [timed_out] {
        timed_out->complete(true, "late acceptance");
    };

    const auto timeout_result = timed_out->wait_for(std::chrono::milliseconds{0});
    if (timeout_result.outcome != Wait::Outcome::timed_out) return 42;
    timed_out.reset();
    if (weak_timed_out.expired()) return 43;

    late_callback();
    auto retained = weak_timed_out.lock();
    if (!retained) return 44;
    const auto late_result = retained->wait_for(std::chrono::milliseconds{0});
    if (late_result.outcome != Wait::Outcome::timed_out) return 45;
    retained.reset();
    late_callback = {};
    if (!weak_timed_out.expired()) return 46;

    auto cancelled = std::make_shared<Wait>();
    cancelled->cancel("tunnel disconnected");
    cancelled->complete(true, "late acceptance");
    const auto cancel_result = cancelled->wait_for(std::chrono::milliseconds{0});
    if (cancel_result.outcome != Wait::Outcome::cancelled) return 47;
    if (cancel_result.reason != "tunnel disconnected") return 48;

    auto wakeable = std::make_shared<Wait>();
    Wait::Result wake_result;
    std::thread waiter([wakeable, &wake_result] {
        wake_result = wakeable->wait_for(std::chrono::seconds{2});
    });
    std::this_thread::sleep_for(std::chrono::milliseconds{10});
    const auto cancel_started = std::chrono::steady_clock::now();
    wakeable->cancel("client stop");
    waiter.join();
    const auto cancel_elapsed = std::chrono::steady_clock::now() - cancel_started;
    if (wake_result.outcome != Wait::Outcome::cancelled) return 49;
    if (cancel_elapsed >= std::chrono::seconds{1}) return 50;

    return 0;
}

int test_runtime_lifetime_gate_revocation_barrier() {
    using Gate = yume::client::RuntimeLifetimeGate;
    auto gate = std::make_shared<Gate>();
    if (!gate->activate() || !gate->active()) return 51;

    auto lease = gate->try_acquire();
    if (!lease) return 52;
    gate->revoke();
    if (gate->active() || gate->try_acquire()) return 53;

    std::atomic<bool> entered{false};
    std::atomic<bool> quiesced{false};
    std::thread waiter([gate, &entered, &quiesced] {
        entered.store(true, std::memory_order_release);
        gate->wait_for_quiescence();
        quiesced.store(true, std::memory_order_release);
    });
    while (!entered.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{5});
    if (quiesced.load(std::memory_order_acquire)) {
        lease.release();
        waiter.join();
        return 54;
    }
    lease.release();
    waiter.join();
    return quiesced.load(std::memory_order_acquire) ? 0 : 55;
}

#if !defined(_WIN32)
int test_inproc_ignores_desktop_config_path() {
    char work_dir_template[] = "/tmp/yume-abi-config-path-XXXXXX";
    char* const work_dir = ::mkdtemp(work_dir_template);
    if (!work_dir) return 25;

    std::error_code ec;
    const auto original_dir = std::filesystem::current_path(ec);
    if (ec) return 26;
    const auto blocked_dir = std::filesystem::path(work_dir) / "config";
    if (!std::filesystem::create_directory(blocked_dir, ec) || ec) return 27;
    if (::chmod(blocked_dir.c_str(), 0000) != 0) return 28;
    std::filesystem::current_path(work_dir, ec);
    if (ec) return 29;

    yume_client* client = yume_client_create();
    if (!client) return 30;
    const int status = yume_client_start_json(
        client,
        R"({"server":"127.0.0.1","port":1,"tunnels":1,"inner_crypto":true})",
        work_dir,
        1);
    const std::string error = yume_handle_last_error(client)
        ? yume_handle_last_error(client)
        : "";
    yume_client_destroy(client);

    std::filesystem::current_path(original_dir, ec);
    const bool restored = !ec;
    (void)::chmod(blocked_dir.c_str(), 0700);
    std::filesystem::remove_all(work_dir, ec);

    // No server is listening, so startup must fail. The important contract is
    // that an in-process config never probes the CLI's relative desktop path.
    if (status == YUME_STATUS_OK) return 31;
    if (error.find("config/yume.json") != std::string::npos ||
        error.find("filesystem error") != std::string::npos) {
        return 32;
    }
    return restored ? 0 : 33;
}

int test_pq_public_path_failure_removes_private_key() {
    char work_dir_template[] = "/tmp/yume-abi-pq-keypair-XXXXXX";
    char* const work_dir = ::mkdtemp(work_dir_template);
    if (!work_dir) return 37;

    const auto base = std::filesystem::path(work_dir);
    const auto private_path = base / "private.bin";
    const auto public_path = base / "public.bin";
    {
        std::ofstream existing(public_path, std::ios::binary);
        existing << "do-not-replace";
    }

    const int status = yume_generate_pq_keypair(
        private_path.c_str(), public_path.c_str());
    const std::string detail = yume_last_error() ? yume_last_error() : "";
    const bool private_removed = !std::filesystem::exists(private_path);
    std::ifstream persisted(public_path, std::ios::binary);
    const std::string public_contents(
        (std::istreambuf_iterator<char>(persisted)),
        std::istreambuf_iterator<char>());
    persisted.close();

    std::error_code cleanup_error;
    std::filesystem::remove_all(base, cleanup_error);

    if (status != YUME_STATUS_INTERNAL_ERROR) return 38;
    if (detail.empty()) return 39;
    if (!private_removed) return 40;
    if (public_contents != "do-not-replace") return 41;
    return 0;
}

int test_client_config_file_statuses() {
    char work_dir_template[] = "/tmp/yume-abi-client-config-XXXXXX";
    char* const work_dir = ::mkdtemp(work_dir_template);
    if (!work_dir) return 61;

    const auto base = std::filesystem::path(work_dir);
    const auto invalid_path = base / "invalid.json";
    {
        std::ofstream output(invalid_path);
        output << R"({"server":"localhost","port":"443"})";
        if (!output) return 62;
    }

    yume_client* client = yume_client_create();
    if (!client) return 63;
    const int invalid_status = yume_client_start_file(
        client, invalid_path.c_str(), 1);
    const int missing_status = yume_client_start_file(
        client, (base / "missing.json").c_str(), 1);
    yume_client_destroy(client);

    std::error_code cleanup_error;
    std::filesystem::remove_all(base, cleanup_error);
    if (invalid_status != YUME_STATUS_PARSE_ERROR) return 64;
    if (missing_status != YUME_STATUS_NOT_FOUND) return 65;
    return 0;
}

int test_stop_cancels_start_during_config_io() {
    char work_dir_template[] = "/tmp/yume-abi-start-handoff-XXXXXX";
    char* const work_dir = ::mkdtemp(work_dir_template);
    if (!work_dir) return 67;

    const auto base = std::filesystem::path(work_dir);
    const auto config_fifo = base / "client.json.fifo";
    if (::mkfifo(config_fifo.c_str(), S_IRUSR | S_IWUSR) != 0) {
        std::error_code ignored;
        std::filesystem::remove_all(base, ignored);
        return 68;
    }

    yume_client* client = yume_client_create();
    if (!client) {
        std::error_code ignored;
        std::filesystem::remove_all(base, ignored);
        return 69;
    }
    std::atomic<int> start_status{YUME_STATUS_INTERNAL_ERROR};
    std::thread starter([&] {
        start_status.store(
            yume_client_start_file(client, config_fifo.c_str(), 5'000),
            std::memory_order_release);
    });

    int writer = -1;
    const auto writer_deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds{2};
    while (std::chrono::steady_clock::now() < writer_deadline) {
        writer = ::open(config_fifo.c_str(), O_WRONLY | O_NONBLOCK | O_CLOEXEC);
        if (writer >= 0) break;
        if (errno != ENXIO && errno != EINTR) break;
        std::this_thread::sleep_for(std::chrono::milliseconds{1});
    }
    if (writer < 0) {
        // Opening both ends releases a start thread that failed to reach the
        // intended blocking read, so the test can still clean up safely.
        const int wake = ::open(
            config_fifo.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC);
        if (wake >= 0) (void)::close(wake);
        (void)yume_client_stop(client);
        starter.join();
        yume_client_destroy(client);
        std::error_code ignored;
        std::filesystem::remove_all(base, ignored);
        return 70;
    }

    // The FIFO writer cannot open until load_client() has opened its read end.
    // Start admission and its cancellation token are therefore definitely
    // published while the caller remains blocked in configuration I/O.
    const int stop_status = yume_client_stop(client);
    static constexpr char kConfig[] =
        R"({"server":"127.0.0.1","port":1,"tunnels":1,"inner_crypto":true})";
    std::size_t written = 0;
    while (written < sizeof(kConfig) - 1) {
        const ssize_t count = ::write(
            writer, kConfig + written, sizeof(kConfig) - 1 - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        written += static_cast<std::size_t>(count);
    }
    (void)::close(writer);
    starter.join();
    const int observed_start_status =
        start_status.load(std::memory_order_acquire);
    yume_client_destroy(client);
    std::error_code ignored;
    std::filesystem::remove_all(base, ignored);

    if (written != sizeof(kConfig) - 1) return 71;
    if (stop_status != YUME_STATUS_OK) return 72;
    if (observed_start_status != YUME_STATUS_NOT_RUNNING) return 73;
    return 0;
}
#endif

}  // namespace

int main() {
    if (const int rc = test_service_open_wait_lifetime_and_cancellation();
        rc != 0) {
        return rc;
    }
    if (const int rc = test_runtime_lifetime_gate_revocation_barrier();
        rc != 0) {
        return rc;
    }
    if (yume_abi_version() != YUME_ABI_VERSION) {
        return 1;
    }
    if (!yume_version() || !yume_basefwx_version()) {
        return 2;
    }
    if ((yume_feature_flags() & YUME_FEATURE_PBKDF2_HKDF) == 0) {
        return 3;
    }
    if ((yume_feature_flags() & YUME_FEATURE_PACKET_BULK) == 0 ||
        (yume_feature_flags() & YUME_FEATURE_PQ_MLKEM1024) == 0) {
        return 21;
    }
    if (yume_get_build_info(nullptr, sizeof(yume_build_info)) != YUME_STATUS_INVALID_ARGUMENT) {
        return 4;
    }

    yume_build_info info{};
    if (yume_get_build_info(&info, YUME_BUILD_INFO_MIN_SIZE - 1) !=
        YUME_STATUS_BUFFER_TOO_SMALL) {
        return 5;
    }
    static constexpr char kUnwritten[] = "unwritten";
    info.yume_version = kUnwritten;
    info.basefwx_version = kUnwritten;
    info.pq_backend = kUnwritten;
    info.argon2_backend = kUnwritten;
    if (yume_get_build_info(&info, YUME_BUILD_INFO_MIN_SIZE) !=
        YUME_STATUS_OK) {
        return 56;
    }
    if (info.struct_size != sizeof(info) ||
        info.abi_version != YUME_ABI_VERSION ||
        info.yume_version != kUnwritten ||
        info.basefwx_version != kUnwritten ||
        info.pq_backend != kUnwritten ||
        info.argon2_backend != kUnwritten) {
        return 57;
    }
    if (yume_get_build_info(&info, sizeof(info) - 1) != YUME_STATUS_OK ||
        info.argon2_backend != kUnwritten) {
        return 58;
    }
    if (yume_get_build_info(&info, sizeof(info)) != YUME_STATUS_OK) {
        return 6;
    }
    if (info.struct_size != sizeof(info) || info.abi_version != YUME_ABI_VERSION) {
        return 7;
    }
    if (!info.yume_version || !info.basefwx_version || !info.pq_backend || !info.argon2_backend) {
        return 8;
    }
    if (std::strcmp(yume_strerror(YUME_STATUS_TIMEOUT), "timeout") != 0) {
        return 9;
    }
    if (std::strcmp(yume_strerror(YUME_STATUS_RESOURCE_EXHAUSTED),
                    "resource exhausted") != 0) {
        return 66;
    }

    yume_client* client = yume_client_create();
    if (!client) {
        return 10;
    }
    if (yume_client_set_socket_protector(client, nullptr, nullptr) !=
        YUME_STATUS_OK) {
        yume_client_destroy(client);
        return 23;
    }
    if (yume_client_start_json(
            client, R"({"server":"localhost","port":"443"})",
            nullptr, 1) != YUME_STATUS_PARSE_ERROR) {
        yume_client_destroy(client);
        return 60;
    }
    if (yume_client_start_json(
            client, R"({"server":"localhost","port":443,"tunnels":0})",
            nullptr, 1) != YUME_STATUS_INVALID_ARGUMENT) {
        yume_client_destroy(client);
        return 24;
    }
    if (yume_client_start_json(client, "{", nullptr, 1) != YUME_STATUS_PARSE_ERROR) {
        yume_client_destroy(client);
        return 11;
    }
    if (!yume_handle_last_error(client) || yume_handle_last_error(client)[0] == '\0') {
        yume_client_destroy(client);
        return 12;
    }
    yume_stream* client_stream = nullptr;
    if (yume_client_open_stream(client, "example-service-v1", 0,
                                &client_stream) != YUME_STATUS_WOULD_BLOCK ||
        client_stream != nullptr) {
        yume_client_destroy(client);
        return 59;
    }
    yume_packet* packet = nullptr;
    if (yume_client_open_packet(client, 0, &packet) != YUME_STATUS_WOULD_BLOCK || packet) {
        yume_client_destroy(client);
        return 22;
    }
    char small[2];
    size_t needed = 0;
    if (yume_client_status_json(client, small, sizeof(small), &needed) != YUME_STATUS_BUFFER_TOO_SMALL ||
        needed <= sizeof(small)) {
        yume_client_destroy(client);
        return 13;
    }
    if (yume_client_request_json(client, "runtime.status", "[]",
                                 small, sizeof(small), &needed, 1) !=
        YUME_STATUS_INVALID_ARGUMENT) {
        yume_client_destroy(client);
        return 74;
    }
    if (yume_client_request_json(client, "runtime.status",
                                 "{\"limit\":1e10000}",
                                 small, sizeof(small), &needed, 1) !=
        YUME_STATUS_PARSE_ERROR) {
        yume_client_destroy(client);
        return 76;
    }
    constexpr std::size_t kMaxRequestOperationBytes = 128U;
    constexpr std::size_t kMaxRequestArgsJsonBytes = 1024U * 1024U;
    const std::string maximum_operation(kMaxRequestOperationBytes, 'x');
    if (yume_client_request_json(
            client, maximum_operation.c_str(), nullptr,
            small, sizeof(small), &needed, 1) != YUME_STATUS_NOT_RUNNING) {
        yume_client_destroy(client);
        return 80;
    }
    const std::string oversized_operation(
        kMaxRequestOperationBytes + 1U, 'x');
    if (yume_client_request_json(
            client, oversized_operation.c_str(), nullptr,
            small, sizeof(small), &needed, 1) !=
        YUME_STATUS_RESOURCE_EXHAUSTED) {
        yume_client_destroy(client);
        return 78;
    }
    std::string maximum_args(kMaxRequestArgsJsonBytes, ' ');
    maximum_args[0] = '{';
    maximum_args[1] = '}';
    if (yume_client_request_json(
            client, "runtime.status", maximum_args.c_str(),
            small, sizeof(small), &needed, 1) != YUME_STATUS_NOT_RUNNING) {
        yume_client_destroy(client);
        return 81;
    }
    const std::string oversized_args(kMaxRequestArgsJsonBytes + 1U, ' ');
    if (yume_client_request_json(
            client, "runtime.status", oversized_args.c_str(),
            small, sizeof(small), &needed, 1) !=
        YUME_STATUS_RESOURCE_EXHAUSTED) {
        yume_client_destroy(client);
        return 79;
    }
    yume_client_destroy(client);

#if !defined(_WIN32)
    if (const int rc = test_inproc_ignores_desktop_config_path(); rc != 0) {
        return rc;
    }
    if (const int rc = test_pq_public_path_failure_removes_private_key();
        rc != 0) {
        return rc;
    }
    if (const int rc = test_client_config_file_statuses(); rc != 0) {
        return rc;
    }
    if (const int rc = test_stop_cancels_start_during_config_io(); rc != 0) {
        return rc;
    }
#endif

    yume_server* server = yume_server_create();
    if (!server) {
        return 14;
    }
    if (yume_server_register_service(server, "example-service-v1") != YUME_STATUS_NOT_RUNNING) {
        yume_server_destroy(server);
        return 15;
    }
    if (yume_server_reload_auth(server) != YUME_STATUS_NOT_RUNNING) {
        yume_server_destroy(server);
        return 20;
    }
    yume_stream* stream = nullptr;
    if (yume_server_accept_stream(server, "example-service-v1", 0, &stream) != YUME_STATUS_NOT_RUNNING ||
        stream != nullptr) {
        yume_server_destroy(server);
        return 16;
    }

    // yume_server_request_json argument and lifecycle contract. Invalid
    // handles and missing/empty operation names are rejected consistently in
    // full and client-only builds before any runtime dispatch.
    if (yume_server_request_json(nullptr, "runtime.status", nullptr,
                                 small, sizeof(small), &needed) !=
        YUME_STATUS_INVALID_ARGUMENT) {
        yume_server_destroy(server);
        return 40;
    }
    if (yume_server_request_json(server, nullptr, nullptr,
                                 small, sizeof(small), &needed) !=
        YUME_STATUS_INVALID_ARGUMENT) {
        yume_server_destroy(server);
        return 41;
    }
    if (yume_server_request_json(server, "", nullptr,
                                 small, sizeof(small), &needed) !=
        YUME_STATUS_INVALID_ARGUMENT) {
        yume_server_destroy(server);
        return 42;
    }
    // A stopped server reports NOT_RUNNING rather than an operation error, so
    // an embedder can tell "not started yet" from "that op does not exist".
    if (yume_server_request_json(server, "federation.status", nullptr,
                                 small, sizeof(small), &needed) !=
        YUME_STATUS_NOT_RUNNING) {
        yume_server_destroy(server);
        return 43;
    }
    // JSON syntax and the object-shaped argument schema are validated before
    // lifecycle dispatch in both full and client-only builds.
    const int server_request_parse_status = yume_server_request_json(
        server, "federation.status", "{", small, sizeof(small), &needed);
    if (server_request_parse_status != YUME_STATUS_PARSE_ERROR) {
        yume_server_destroy(server);
        return 44;
    }
    if (yume_server_request_json(server, "federation.status", "[]",
                                 small, sizeof(small), &needed) !=
        YUME_STATUS_INVALID_ARGUMENT) {
        yume_server_destroy(server);
        return 75;
    }
    if (yume_server_request_json(server, "federation.status",
                                 "{\"limit\":1e10000}",
                                 small, sizeof(small), &needed) !=
        YUME_STATUS_PARSE_ERROR) {
        yume_server_destroy(server);
        return 77;
    }
    if (yume_server_request_json(
            server, oversized_operation.c_str(), nullptr,
            small, sizeof(small), &needed) !=
        YUME_STATUS_RESOURCE_EXHAUSTED) {
        yume_server_destroy(server);
        return 82;
    }
    if (yume_server_request_json(
            server, "federation.status", oversized_args.c_str(),
            small, sizeof(small), &needed) !=
        YUME_STATUS_RESOURCE_EXHAUSTED) {
        yume_server_destroy(server);
        return 83;
    }
    const int server_start_status = yume_server_start_json(server, "{", nullptr);
#if defined(YUME_ABI_CLIENT_ONLY) && YUME_ABI_CLIENT_ONLY
    if (server_start_status != YUME_STATUS_PERMISSION_DENIED) {
#else
    if (server_start_status != YUME_STATUS_PARSE_ERROR) {
#endif
        yume_server_destroy(server);
        return 17;
    }
    yume_server_destroy(server);

    if (yume_stream_read(nullptr, small, sizeof(small), &needed, 0) != YUME_STATUS_INVALID_ARGUMENT) {
        return 18;
    }
    if (yume_stream_peer_json(nullptr, small, sizeof(small), &needed) != YUME_STATUS_INVALID_ARGUMENT) {
        return 19;
    }

    // NULL is the only invalid handle value the ABI promises to recognize.
    const char* null_error = yume_handle_last_error(nullptr);
    if (!null_error || std::strcmp(null_error, "invalid handle") != 0) {
        return 34;
    }

    if (yume_generate_pq_keypair(nullptr, nullptr) !=
        YUME_STATUS_INVALID_ARGUMENT) {
        return 35;
    }
    const char* abi_error = yume_last_error();
    if (!abi_error || std::strstr(abi_error, "private_path") == nullptr) {
        return 36;
    }

    return 0;
}
