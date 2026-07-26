/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "yume/yume.h"

#include <cstring>
#include <string>

#if !defined(_WIN32)
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

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
#endif

}  // namespace

int main() {
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
    if (yume_get_build_info(&info, sizeof(info) - 1) != YUME_STATUS_BUFFER_TOO_SMALL) {
        return 5;
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
    yume_client_destroy(client);

#if !defined(_WIN32)
    if (const int rc = test_inproc_ignores_desktop_config_path(); rc != 0) {
        return rc;
    }
    if (const int rc = test_pq_public_path_failure_removes_private_key();
        rc != 0) {
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
