/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "yume/yume.h"

#include <cstring>

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
    if (yume_client_start_json(client, "{", nullptr, 1) != YUME_STATUS_PARSE_ERROR) {
        yume_client_destroy(client);
        return 11;
    }
    if (!yume_handle_last_error(client) || yume_handle_last_error(client)[0] == '\0') {
        yume_client_destroy(client);
        return 12;
    }
    char small[2];
    size_t needed = 0;
    if (yume_client_status_json(client, small, sizeof(small), &needed) != YUME_STATUS_BUFFER_TOO_SMALL ||
        needed <= sizeof(small)) {
        yume_client_destroy(client);
        return 13;
    }
    yume_client_destroy(client);

    yume_server* server = yume_server_create();
    if (!server) {
        return 14;
    }
    if (yume_server_register_service(server, "example-control-v1") != YUME_STATUS_NOT_RUNNING) {
        yume_server_destroy(server);
        return 15;
    }
    yume_stream* stream = nullptr;
    if (yume_server_accept_stream(server, "example-control-v1", 0, &stream) != YUME_STATUS_NOT_RUNNING ||
        stream != nullptr) {
        yume_server_destroy(server);
        return 16;
    }
    if (yume_server_start_json(server, "{", nullptr) != YUME_STATUS_PARSE_ERROR) {
        yume_server_destroy(server);
        return 17;
    }
    yume_server_destroy(server);

    if (yume_stream_read(nullptr, small, sizeof(small), &needed, 0) != YUME_STATUS_INVALID_ARGUMENT) {
        return 18;
    }
    return 0;
}
