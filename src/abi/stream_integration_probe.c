/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "yume/yume.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char kService[] = "abi-stream-v1";

static void report_failure(const char* operation,
                           int status,
                           const void* handle) {
    const char* detail = handle ? yume_handle_last_error(handle)
                                : yume_last_error();
    fprintf(stderr, "%s failed: %s (%d)%s%s\n",
            operation,
            yume_strerror(status),
            status,
            detail && detail[0] ? ": " : "",
            detail && detail[0] ? detail : "");
}

static int expect_status(const char* operation,
                         int actual,
                         int expected,
                         const void* handle) {
    if (actual == expected) {
        return 1;
    }
    fprintf(stderr, "%s returned %s (%d), expected %s (%d)\n",
            operation,
            yume_strerror(actual),
            actual,
            yume_strerror(expected),
            expected);
    if (handle) {
        const char* detail = yume_handle_last_error(handle);
        if (detail && detail[0]) {
            fprintf(stderr, "%s detail: %s\n", operation, detail);
        }
    }
    return 0;
}

static int write_exact(yume_stream* stream,
                       const void* data,
                       size_t size) {
    size_t written = 0;
    const int status = yume_stream_write(
        stream, data, size, &written, 5000);
    if (status != YUME_STATUS_OK || written != size) {
        report_failure("yume_stream_write", status, stream);
        fprintf(stderr, "write count: %zu of %zu\n", written, size);
        return 0;
    }
    return 1;
}

static int read_exact(yume_stream* stream,
                      const void* expected,
                      size_t expected_size) {
    unsigned char buffer[256];
    size_t offset = 0;
    while (offset < expected_size) {
        size_t received = 0;
        const int status = yume_stream_read(
            stream,
            buffer + offset,
            sizeof(buffer) - offset,
            &received,
            5000);
        if (status != YUME_STATUS_OK || received == 0) {
            report_failure("yume_stream_read", status, stream);
            return 0;
        }
        offset += received;
    }
    if (offset != expected_size ||
        memcmp(buffer, expected, expected_size) != 0) {
        fprintf(stderr, "stream payload mismatch\n");
        return 0;
    }
    return 1;
}

int main(int argc, char** argv) {
    yume_server* server = NULL;
    yume_client* client = NULL;
    yume_stream* client_stream = NULL;
    yume_stream* server_stream = NULL;
    yume_stream* aborted_client_stream = NULL;
    yume_stream* aborted_server_stream = NULL;
    int result = 1;

    if (argc != 3) {
        fprintf(stderr, "usage: %s <server.json> <client.json>\n", argv[0]);
        return 2;
    }

    server = yume_server_create();
    client = yume_client_create();
    if (!server || !client) {
        fprintf(stderr, "failed to allocate ABI runtime handles\n");
        goto cleanup;
    }

    {
        int status = yume_server_start_file(server, argv[1]);
        if (status != YUME_STATUS_OK) {
            report_failure("yume_server_start_file", status, server);
            goto cleanup;
        }
        status = yume_server_start_file(server, argv[1]);
        if (!expect_status("repeated yume_server_start_file", status,
                           YUME_STATUS_ALREADY_RUNNING, server)) {
            goto cleanup;
        }
        status = yume_server_register_service(server, kService);
        if (status != YUME_STATUS_OK) {
            report_failure("yume_server_register_service", status, server);
            goto cleanup;
        }
        status = yume_server_accept_stream(
            server, kService, 0, &server_stream);
        if (!expect_status("zero-time accept", status,
                           YUME_STATUS_WOULD_BLOCK, server) ||
            server_stream != NULL) {
            goto cleanup;
        }
        status = yume_client_start_file(client, argv[2], 15000);
        if (status != YUME_STATUS_OK) {
            report_failure("yume_client_start_file", status, client);
            goto cleanup;
        }
    }

    {
        int status = yume_client_open_stream(
            client, kService, 5000, &client_stream);
        if (status != YUME_STATUS_OK || !client_stream) {
            report_failure("yume_client_open_stream", status, client);
            goto cleanup;
        }
        status = yume_server_accept_stream(
            server, kService, 5000, &server_stream);
        if (status != YUME_STATUS_OK || !server_stream) {
            report_failure("yume_server_accept_stream", status, server);
            goto cleanup;
        }

        {
            unsigned char byte = 0;
            size_t received = 123;
            status = yume_stream_read(
                server_stream, &byte, sizeof(byte), &received, 0);
            if (!expect_status("zero-time stream read", status,
                               YUME_STATUS_WOULD_BLOCK, server_stream) ||
                received != 0) {
                goto cleanup;
            }
        }

        {
            size_t needed = 0;
            char* peer_json = NULL;
            status = yume_stream_peer_json(
                server_stream, NULL, 0, &needed);
            if (status != YUME_STATUS_BUFFER_TOO_SMALL || needed < 2) {
                report_failure("yume_stream_peer_json sizing", status,
                               server_stream);
                goto cleanup;
            }
            peer_json = (char*)malloc(needed);
            if (!peer_json) {
                fprintf(stderr, "failed to allocate peer JSON buffer\n");
                goto cleanup;
            }
            status = yume_stream_peer_json(
                server_stream, peer_json, needed, &needed);
            if (status != YUME_STATUS_OK ||
                strstr(peer_json, "auth_fingerprint_sha256") == NULL) {
                report_failure("yume_stream_peer_json", status,
                               server_stream);
                free(peer_json);
                goto cleanup;
            }
            free(peer_json);
        }

        {
            static const char client_payload[] = "client-to-server";
            static const char server_payload[] = "server-to-client";
            if (!write_exact(client_stream,
                             client_payload,
                             sizeof(client_payload) - 1) ||
                !read_exact(server_stream,
                            client_payload,
                            sizeof(client_payload) - 1) ||
                !write_exact(server_stream,
                             server_payload,
                             sizeof(server_payload) - 1) ||
                !read_exact(client_stream,
                            server_payload,
                            sizeof(server_payload) - 1)) {
                goto cleanup;
            }
        }

        status = yume_stream_shutdown_write(client_stream);
        if (status != YUME_STATUS_OK) {
            report_failure("client yume_stream_shutdown_write", status,
                           client_stream);
            goto cleanup;
        }
        {
            unsigned char byte = 0;
            size_t received = 123;
            status = yume_stream_read(
                server_stream, &byte, sizeof(byte), &received, 5000);
            if (status != YUME_STATUS_OK || received != 0) {
                report_failure("server clean EOF", status, server_stream);
                goto cleanup;
            }
        }
        status = yume_stream_shutdown_write(server_stream);
        if (status != YUME_STATUS_OK) {
            report_failure("server yume_stream_shutdown_write", status,
                           server_stream);
            goto cleanup;
        }
        {
            unsigned char byte = 0;
            size_t received = 123;
            status = yume_stream_read(
                client_stream, &byte, sizeof(byte), &received, 5000);
            if (status != YUME_STATUS_OK || received != 0) {
                report_failure("client clean EOF", status, client_stream);
                goto cleanup;
            }
        }
    }

    yume_stream_destroy(server_stream);
    server_stream = NULL;
    yume_stream_destroy(client_stream);
    client_stream = NULL;

    {
        int status = yume_client_open_stream(
            client, kService, 5000, &aborted_client_stream);
        if (status != YUME_STATUS_OK || !aborted_client_stream) {
            report_failure("second yume_client_open_stream", status, client);
            goto cleanup;
        }
        status = yume_server_accept_stream(
            server, kService, 5000, &aborted_server_stream);
        if (status != YUME_STATUS_OK || !aborted_server_stream) {
            report_failure("second yume_server_accept_stream", status, server);
            goto cleanup;
        }
        status = yume_stream_close(aborted_server_stream);
        if (status != YUME_STATUS_OK) {
            report_failure("server yume_stream_close", status,
                           aborted_server_stream);
            goto cleanup;
        }
        {
            unsigned char byte = 0;
            size_t received = 123;
            status = yume_stream_read(
                aborted_client_stream, &byte, sizeof(byte), &received, 5000);
            if (!expect_status("aborted stream read", status,
                               YUME_STATUS_NOT_RUNNING,
                               aborted_client_stream) ||
                received != 0) {
                goto cleanup;
            }
        }
    }

    result = 0;

cleanup:
    yume_stream_destroy(aborted_server_stream);
    yume_stream_destroy(aborted_client_stream);
    yume_stream_destroy(server_stream);
    yume_stream_destroy(client_stream);
    if (client) {
        (void)yume_client_stop(client);
    }
    if (server) {
        (void)yume_server_stop(server);
    }
    yume_client_destroy(client);
    yume_server_destroy(server);
    return result;
}
