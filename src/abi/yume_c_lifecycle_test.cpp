/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Install a paused backend without adding a test hook to the public ABI.
// This executable compiles the ABI shell here and does not link libyume.
#if defined(__GNUC__) && !defined(__clang__)
// GCC warns about private member types when these opaque definitions appear
// in an included file. They still occur in exactly one translation unit here.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsubobject-linkage"
#endif
#include "abi/yume_c.cpp"
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <thread>

namespace {

using namespace yume::embed;

void require(bool condition, const char* message) {
    if (condition) return;
    std::cerr << message << '\n';
    std::abort();
}

struct PublicationProbe {
    mutable std::mutex mutex;
    mutable std::condition_variable changed;
    mutable bool entered{false};
    bool released{false};
    std::atomic<unsigned> published{0U};
    std::atomic<unsigned> destroyed{0U};

    void pause() const {
        std::unique_lock lock(mutex);
        entered = true;
        changed.notify_all();
        require(changed.wait_for(lock, std::chrono::seconds(5),
                                 [this] { return released; }),
                "publication barrier timed out");
    }

    void wait_until_entered() const {
        std::unique_lock lock(mutex);
        require(changed.wait_for(lock, std::chrono::seconds(5),
                                 [this] { return entered; }),
                "channel did not reach publication barrier");
    }

    void release() {
        std::lock_guard lock(mutex);
        released = true;
        changed.notify_all();
    }
};

class TestChannel final : public BackendStream, public BackendPacket {
public:
    explicit TestChannel(PublicationProbe& probe) : probe_(probe) {}
    ~TestChannel() override { ++probe_.destroyed; }
    BackendIo read(void*, std::size_t, std::uint32_t, std::size_t&,
                   std::string&) override {
        return BackendIo::Closed;
    }
    BackendIo write(const void*, std::size_t, std::uint32_t,
                    std::string&) override {
        return BackendIo::Closed;
    }
    BackendIo shutdown_write(std::uint32_t, std::string&) override {
        return BackendIo::Closed;
    }
    BackendIo read(void*, std::size_t, std::span<BackendPacketSlot>,
                   std::uint32_t, std::size_t&, std::size_t&,
                   std::string&) override {
        return BackendIo::Closed;
    }
    BackendIo write(std::span<const BackendPacketView>, std::uint32_t,
                    std::string&) override {
        return BackendIo::Closed;
    }
    void publish() noexcept override { ++probe_.published; }
    void close() noexcept override {}
    BackendPeerIdentity peer_identity() const override {
        probe_.pause();
        return {};
    }

private:
    PublicationProbe& probe_;
};

class TestBackend final : public EndpointBackend {
public:
    explicit TestBackend(PublicationProbe& probe) : probe_(probe) {}
    BackendIo start(std::uint32_t, const std::shared_ptr<StartCancellation>&,
                    std::string&) override {
        running_ = true;
        return BackendIo::Ok;
    }
    void stop() noexcept override { running_ = false; }
    bool running() const noexcept override { return running_; }
    BackendStatus status() const override { return {}; }
    BackendMessage message_after(std::uint64_t) const override { return {}; }
    BackendIo retry_now() noexcept override { return BackendIo::Invalid; }
    BackendIo open_stream(const std::string&,
                          const std::optional<BackendDestination>&,
                          std::uint32_t, std::unique_ptr<BackendStream>& out,
                          std::string&) override {
        out = std::make_unique<TestChannel>(probe_);
        return BackendIo::Ok;
    }
    BackendIo accept_stream(const std::string& service, std::uint32_t timeout,
                            std::unique_ptr<BackendStream>& out,
                            std::string& error) override {
        return open_stream(service, {}, timeout, out, error);
    }
    BackendIo open_packet(const std::string&,
                          const std::optional<BackendDestination>&,
                          std::uint32_t, std::unique_ptr<BackendPacket>& out,
                          std::string&) override {
        out = std::make_unique<TestChannel>(probe_);
        return BackendIo::Ok;
    }
    BackendIo accept_packet(const std::string& service, std::uint32_t timeout,
                            std::unique_ptr<BackendPacket>& out,
                            std::string& error) override {
        return open_packet(service, {}, timeout, out, error);
    }

private:
    PublicationProbe& probe_;
    std::atomic<bool> running_{false};
};

enum class Lifecycle { Unchanged, Stop, Restart };

void test_empty_write_reaches_backend() {
    PublicationProbe probe;
    probe.released = true;
    yume_stream stream(std::make_unique<TestChannel>(probe));
    std::size_t written = 99U;
    require(yume_stream_write(&stream, nullptr, 0U, &written, 0U) ==
                    YUME_STATUS_CLOSED &&
                written == 0U,
            "empty write bypassed the backend's terminal state");
}

void test_identity_preserves_diagnostic() {
    PublicationProbe probe;
    probe.released = true;
    yume_stream stream(std::make_unique<TestChannel>(probe));
    yume_packet packet(std::make_unique<TestChannel>(probe));
    const char byte = 'x';
    const yume_packet_view view{&byte, 1U};
    std::size_t written = 0U;
    require(yume_stream_write(&stream, &byte, 1U, &written, 0U) ==
                    YUME_STATUS_CLOSED &&
                yume_packet_write_batch(&packet, &view, 1U, &written, 0U) ==
                    YUME_STATUS_CLOSED,
            "test writes did not store a failure diagnostic");
    const auto check = [](const auto* handle, auto query) {
        const auto diagnostic = [handle] {
            yume_diagnostic out{};
            out.struct_size = sizeof(out);
            out.abi_version = YUME_ABI_VERSION;
            require(yume_handle_get_diagnostic(handle, &out, sizeof(out)) ==
                        YUME_STATUS_OK,
                    "diagnostic query failed");
            return out;
        };
        const auto before = diagnostic();
        require(before.status == YUME_STATUS_CLOSED && before.message[0],
                "test did not establish a prior I/O failure");
        const auto unchanged = [&] {
            const auto after = diagnostic();
            require(
                after.status == before.status && after.flags == before.flags &&
                    std::strcmp(after.message, before.message) == 0 &&
                    std::strcmp(after.json_pointer, before.json_pointer) == 0,
                "identity query changed an earlier I/O diagnostic");
        };
        yume_peer_identity identity{};
        identity.struct_size = sizeof(identity);
        identity.abi_version = YUME_ABI_VERSION;
        require(query(handle, &identity, sizeof(identity)) == YUME_STATUS_OK,
                "valid identity query failed");
        unchanged();
        identity.struct_size = YUME_PEER_IDENTITY_MIN_SIZE;
        require(query(handle, &identity, sizeof(identity)) ==
                    YUME_STATUS_BUFFER_TOO_SMALL,
                "identity query did not report its valid truncated output");
        unchanged();
        require(query(handle, &identity, 0U) == YUME_STATUS_INVALID_ARGUMENT,
                "identity query accepted a zero-sized output");
        unchanged();
        require(query(handle, nullptr, sizeof(identity)) ==
                    YUME_STATUS_INVALID_ARGUMENT,
                "identity query accepted a null output");
        unchanged();
        {
            CallbackScope callback;
            require(query(handle, &identity, sizeof(identity)) ==
                        YUME_STATUS_INVALID_STATE,
                    "identity query was allowed in a callback");
        }
        unchanged();
    };
    check(&stream, yume_stream_get_peer_identity);
    check(&packet, yume_packet_get_peer_identity);
}

void test_publication(std::string_view config_text, bool packet, bool accept,
                      Lifecycle lifecycle) {
    PublicationProbe probe;
    auto backend = std::make_shared<TestBackend>(probe);
    yume_runtime_options runtime_options{};
    runtime_options.struct_size = sizeof(runtime_options);
    runtime_options.abi_version = YUME_ABI_VERSION;
    yume_runtime* runtime = nullptr;
    require(yume_runtime_create(&runtime_options, &runtime) == YUME_STATUS_OK,
            "runtime creation failed");
    yume_config* config = nullptr;
    require(
        yume_config_parse_json(runtime, config_text.data(), config_text.size(),
                               &config) == YUME_STATUS_OK,
        "config parsing failed");
    yume_endpoint* endpoint = nullptr;
    require(yume_endpoint_create(runtime, config, &endpoint) == YUME_STATUS_OK,
            "endpoint creation failed");
    yume_config_destroy(config);
    endpoint->control->backend = backend;
    require(yume_endpoint_start(endpoint, 0U) == YUME_STATUS_OK,
            "endpoint start failed");

    yume_open_options open{};
    open.struct_size = sizeof(open);
    open.abi_version = YUME_ABI_VERSION;
    open.kind = packet ? YUME_SERVICE_PACKET : YUME_SERVICE_BYTE_STREAM;
    open.service = {"test", 4U};
    open.destination.struct_size = sizeof(open.destination);
    open.destination.abi_version = YUME_ABI_VERSION;
    yume_accept_options accepting{};
    accepting.struct_size = sizeof(accepting);
    accepting.abi_version = YUME_ABI_VERSION;
    accepting.kind = open.kind;
    accepting.service = open.service;
    yume_stream* stream = nullptr;
    yume_packet* channel = nullptr;
    const auto invoke = [&] {
        if (packet) {
            return accept ? yume_endpoint_accept_packet(endpoint, &accepting,
                                                        0U, &channel)
                          : yume_endpoint_open_packet(endpoint, &open, 0U,
                                                      &channel);
        }
        return accept ? yume_endpoint_accept_stream(endpoint, &accepting, 0U,
                                                    &stream)
                      : yume_endpoint_open_stream(endpoint, &open, 0U, &stream);
    };
    yume_status result = YUME_STATUS_INTERNAL_ERROR;
    std::jthread caller([&] { result = invoke(); });
    probe.wait_until_entered();
    if (lifecycle != Lifecycle::Unchanged) {
        require(yume_endpoint_stop(endpoint, 0U) == YUME_STATUS_OK,
                "endpoint stop failed");
    }
    if (lifecycle == Lifecycle::Restart) {
        require(yume_endpoint_start(endpoint, 0U) == YUME_STATUS_OK,
                "endpoint restart failed");
        require(endpoint->control->backend == backend,
                "test did not reuse the backend");
    }
    probe.release();
    caller.join();

    if (lifecycle == Lifecycle::Unchanged) {
        require(result == YUME_STATUS_OK && probe.published == 1U &&
                    (packet ? channel != nullptr : stream != nullptr),
                "unchanged endpoint failed to publish its channel");
    } else {
        require(result == YUME_STATUS_CANCELLED && !channel && !stream &&
                    probe.published == 0U && probe.destroyed == 1U,
                "stopped operation escaped as a handle or missed rollback");
        if (lifecycle == Lifecycle::Restart) {
            require(invoke() == YUME_STATUS_OK && probe.published == 1U &&
                        (packet ? channel != nullptr : stream != nullptr),
                    "new start could not publish its own channel");
        }
    }
    yume_stream_destroy(stream);
    yume_packet_destroy(channel);
    yume_endpoint_destroy(endpoint);
    yume_runtime_destroy(runtime);
}

std::string load_config(const char* path) {
    std::ifstream input(path);
    require(input.good(), "cannot read config fixture");
    return {std::istreambuf_iterator<char>(input), {}};
}

}  // namespace

int main(int argc, char** argv) {
    require(argc == 3, "usage: lifecycle_test CLIENT_CONFIG SERVER_CONFIG");
    test_empty_write_reaches_backend();
    test_identity_preserves_diagnostic();
    const auto client = load_config(argv[1]);
    const auto server = load_config(argv[2]);
    for (const bool packet : {false, true}) {
        for (const bool accept : {false, true}) {
            for (const auto lifecycle :
                 {Lifecycle::Unchanged, Lifecycle::Stop, Lifecycle::Restart}) {
                test_publication(accept ? server : client, packet, accept,
                                 lifecycle);
            }
        }
    }
    return 0;
}
