#define _POSIX_C_SOURCE 200809L

/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Drives a schema-1 client and server through the public C ABI v1 in one
 * process with real setup credentials. It checks the YTP/1 backend as an
 * embedder sees it: registration and lifecycle rules, authenticated peer
 * identity, refused opens, deadlines, half-close, an end of stream that a lost
 * session cannot imitate, stop, restart, and stream handles that outlive
 * their endpoint.
 */

#include <yume/yume.h>

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const char kEcho[] = "echo";
static const char kUnregistered[] = "unregistered";
static const char kDenied[] = "denied";
static const char kUndeclared[] = "undeclared";
static const char kClientPayload[] = "schema-1 client payload";
static const char kServerPayload[] = "schema-1 server reply";
static const char kLatePayload[] = "bytes sent after a read deadline expired";
static const char kAbortPayload[] = "bytes followed by an abort";
static const char kRetainedPayload[] = "retained stream payload";
static const char kRestartPayload[] = "payload after restart";

static _Atomic unsigned int protected_sockets = 0u;
static _Atomic unsigned int rejected_sockets = 0u;

static int protect_socket(uintptr_t socket_handle, void* user_data) {
    (void)socket_handle;
    (void)user_data;
    atomic_fetch_add_explicit(&protected_sockets, 1u, memory_order_relaxed);
    return 1;
}

static int reject_socket(uintptr_t socket_handle, void* user_data) {
    (void)socket_handle;
    (void)user_data;
    atomic_fetch_add_explicit(&rejected_sockets, 1u, memory_order_relaxed);
    return 0;
}

static void report(const char* operation, yume_status status,
                   const void* handle) {
    yume_diagnostic diagnostic;
    memset(&diagnostic, 0, sizeof(diagnostic));
    diagnostic.struct_size = sizeof(diagnostic);
    diagnostic.abi_version = YUME_ABI_VERSION;
    if (handle != NULL) {
        (void)yume_handle_get_diagnostic(handle, &diagnostic,
                                         sizeof(diagnostic));
    }
    fprintf(stderr, "%s: status=%d%s%s\n", operation, (int)status,
            diagnostic.message[0] != '\0' ? ": " : "", diagnostic.message);
}

static int expect_status(yume_status actual, yume_status expected,
                         const char* operation, const void* handle) {
    if (actual == expected) return 1;
    fprintf(stderr, "%s: expected status %d\n", operation, (int)expected);
    report(operation, actual, handle);
    return 0;
}

static struct timespec monotonic_now(void) {
    struct timespec value;
    (void)clock_gettime(CLOCK_MONOTONIC, &value);
    return value;
}

static long elapsed_milliseconds(struct timespec start, struct timespec end) {
    return (long)(end.tv_sec - start.tv_sec) * 1000L +
           (end.tv_nsec - start.tv_nsec) / 1000000L;
}

static void pause_milliseconds(long milliseconds) {
    struct timespec delay;
    delay.tv_sec = milliseconds / 1000L;
    delay.tv_nsec = (milliseconds % 1000L) * 1000000L;
    (void)nanosleep(&delay, NULL);
}

static char* read_file(const char* path, size_t* out_size) {
    FILE* file = fopen(path, "rb");
    char* buffer = NULL;
    long size = 0;
    if (file == NULL) return NULL;
    if (fseek(file, 0, SEEK_END) != 0) goto fail;
    size = ftell(file);
    if (size < 0 || fseek(file, 0, SEEK_SET) != 0) goto fail;
    buffer = (char*)malloc((size_t)size + 1u);
    if (buffer == NULL) goto fail;
    if (fread(buffer, 1u, (size_t)size, file) != (size_t)size) goto fail;
    buffer[size] = '\0';
    *out_size = (size_t)size;
    fclose(file);
    return buffer;

fail:
    free(buffer);
    fclose(file);
    return NULL;
}

static yume_runtime* make_runtime(const char* base_dir) {
    yume_runtime_options options;
    yume_runtime* runtime = NULL;
    yume_status status;
    memset(&options, 0, sizeof(options));
    options.struct_size = sizeof(options);
    options.abi_version = YUME_ABI_VERSION;
    /* Kit credential references are relative to each role's directory. */
    options.config_base_dir = base_dir;
    status = yume_runtime_create(&options, &runtime);
    if (status != YUME_STATUS_OK) {
        report("yume_runtime_create", status, NULL);
        return NULL;
    }
    return runtime;
}

static yume_endpoint* make_endpoint(yume_runtime* runtime, const char* path,
                                    uint32_t expected_role) {
    size_t size = 0u;
    char* text = read_file(path, &size);
    yume_config* config = NULL;
    yume_endpoint* endpoint = NULL;
    yume_status status;
    if (text == NULL) {
        fprintf(stderr, "cannot read configuration %s\n", path);
        return NULL;
    }
    status = yume_config_parse_json(runtime, text, size, &config);
    free(text);
    if (status != YUME_STATUS_OK) {
        report("yume_config_parse_json", status, runtime);
        return NULL;
    }
    if (yume_config_role(config) != expected_role) {
        fprintf(stderr, "configuration %s has an unexpected role\n", path);
        yume_config_destroy(config);
        return NULL;
    }
    status = yume_endpoint_create(runtime, config, &endpoint);
    yume_config_destroy(config);
    if (status != YUME_STATUS_OK) {
        report("yume_endpoint_create", status, runtime);
        return NULL;
    }
    return endpoint;
}

static yume_status register_stream(yume_endpoint* endpoint, const char* name) {
    yume_service_descriptor descriptor;
    memset(&descriptor, 0, sizeof(descriptor));
    descriptor.struct_size = sizeof(descriptor);
    descriptor.abi_version = YUME_ABI_VERSION;
    descriptor.name.data = name;
    descriptor.name.size = strlen(name);
    descriptor.kind = YUME_SERVICE_BYTE_STREAM;
    return yume_endpoint_register_service(endpoint, &descriptor);
}

static yume_status open_named(yume_endpoint* endpoint, const char* name,
                              uint32_t timeout_ms, yume_stream** out) {
    yume_open_options options;
    memset(&options, 0, sizeof(options));
    /* The shorter prefix declares that no destination follows. */
    options.struct_size = YUME_OPEN_OPTIONS_MIN_SIZE;
    options.abi_version = YUME_ABI_VERSION;
    options.service.data = name;
    options.service.size = strlen(name);
    options.kind = YUME_SERVICE_BYTE_STREAM;
    return yume_endpoint_open_stream(endpoint, &options, timeout_ms, out);
}

static yume_status accept_named(yume_endpoint* endpoint, const char* name,
                                uint32_t timeout_ms, yume_stream** out) {
    yume_accept_options options;
    memset(&options, 0, sizeof(options));
    options.struct_size = sizeof(options);
    options.abi_version = YUME_ABI_VERSION;
    options.service.data = name;
    options.service.size = strlen(name);
    options.kind = YUME_SERVICE_BYTE_STREAM;
    return yume_endpoint_accept_stream(endpoint, &options, timeout_ms, out);
}

static int hex_digit(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    return -1;
}

static int fingerprint_matches(const uint8_t* fingerprint, const char* hex) {
    size_t index;
    if (strlen(hex) != 64u) return 0;
    for (index = 0u; index < 32u; ++index) {
        const int high = hex_digit(hex[index * 2u]);
        const int low = hex_digit(hex[index * 2u + 1u]);
        if (high < 0 || low < 0 ||
            fingerprint[index] != (uint8_t)((high << 4) | low)) {
            return 0;
        }
    }
    return 1;
}

static int check_peer(yume_stream* stream, uint32_t role, const char* service,
                      const char* fingerprint) {
    yume_peer_identity identity;
    yume_status status;
    memset(&identity, 0, sizeof(identity));
    identity.struct_size = sizeof(identity);
    identity.abi_version = YUME_ABI_VERSION;
    status = yume_stream_get_peer_identity(stream, &identity, sizeof(identity));
    if (status != YUME_STATUS_OK) {
        report("yume_stream_get_peer_identity", status, stream);
        return 0;
    }
    if (identity.authenticated == 0u || identity.role != role ||
        strcmp(identity.service, service) != 0 ||
        identity.peer_label[0] == '\0' ||
        !fingerprint_matches(identity.composite_fingerprint_sha256,
                             fingerprint)) {
        fprintf(stderr,
                "unexpected peer identity: authenticated=%u role=%u "
                "service=%s label=%s\n",
                identity.authenticated, identity.role, identity.service,
                identity.peer_label);
        return 0;
    }
    return 1;
}

static int write_text(yume_stream* stream, const char* text) {
    size_t written = 0u;
    const size_t length = strlen(text);
    const yume_status status =
        yume_stream_write(stream, text, length, &written, 20000u);
    if (status != YUME_STATUS_OK || written != length) {
        report("yume_stream_write", status, stream);
        return 0;
    }
    return 1;
}

/* Reads exactly the expected bytes. Records may split one payload. */
static int read_text(yume_stream* stream, const char* expected) {
    char buffer[256];
    size_t total = 0u;
    const size_t length = strlen(expected);
    if (length > sizeof(buffer)) return 0;
    while (total < length) {
        size_t received = 0u;
        const yume_status status = yume_stream_read(
            stream, buffer + total, length - total, &received, 20000u);
        if (status != YUME_STATUS_OK) {
            report("yume_stream_read", status, stream);
            return 0;
        }
        total += received;
    }
    if (memcmp(buffer, expected, length) != 0) {
        fprintf(stderr, "stream payload mismatch\n");
        return 0;
    }
    return 1;
}

static int expect_read(yume_stream* stream, uint32_t timeout_ms,
                       yume_status expected, const char* operation) {
    char byte = 0;
    size_t received = 0u;
    const yume_status status =
        yume_stream_read(stream, &byte, 1u, &received, timeout_ms);
    if (status != expected || received != 0u) {
        fprintf(stderr, "%s: expected read status %d\n", operation,
                (int)expected);
        report(operation, status, stream);
        return 0;
    }
    return 1;
}

static void discard_stream(yume_stream** stream) {
    if (*stream == NULL) return;
    (void)yume_stream_close(*stream, 0u);
    yume_stream_destroy(*stream);
    *stream = NULL;
}

struct echo_context {
    yume_endpoint* endpoint;
    const char* client_fingerprint;
    int ok;
};

/* Accepts one stream, reads the payload and the client's FIN, then replies
 * and shuts down its own write side. */
static void* echo_worker(void* opaque) {
    struct echo_context* context = (struct echo_context*)opaque;
    yume_stream* stream = NULL;
    const yume_status status =
        accept_named(context->endpoint, kEcho, 20000u, &stream);
    if (status != YUME_STATUS_OK || stream == NULL) {
        report("echo accept", status, context->endpoint);
        return NULL;
    }
    if (!check_peer(stream, YUME_ROLE_CLIENT, kEcho,
                    context->client_fingerprint) ||
        !read_text(stream, kClientPayload) ||
        !expect_read(stream, 20000u, YUME_STATUS_EOF, "server end of stream") ||
        !write_text(stream, kServerPayload) ||
        !expect_status(yume_stream_shutdown_write(stream, 20000u),
                       YUME_STATUS_OK, "server shutdown_write", stream)) {
        discard_stream(&stream);
        return NULL;
    }
    context->ok = 1;
    discard_stream(&stream);
    return NULL;
}

struct deadline_context {
    yume_endpoint* endpoint;
    _Atomic int release;
    int ok;
};

/* Writes only after the client's short read has expired. The client's later
 * abort must be reported as closure, never as a clean end of stream. */
static void* deadline_worker(void* opaque) {
    struct deadline_context* context = (struct deadline_context*)opaque;
    yume_stream* stream = NULL;
    char buffer[256];
    int waited = 0;
    yume_status status =
        accept_named(context->endpoint, kEcho, 20000u, &stream);
    if (status != YUME_STATUS_OK || stream == NULL) {
        report("deadline accept", status, context->endpoint);
        return NULL;
    }
    while (atomic_load_explicit(&context->release, memory_order_acquire) == 0) {
        if (++waited > 2000) {
            fprintf(stderr, "deadline worker was never released\n");
            discard_stream(&stream);
            return NULL;
        }
        pause_milliseconds(10L);
    }
    if (!write_text(stream, kLatePayload)) {
        discard_stream(&stream);
        return NULL;
    }
    for (;;) {
        size_t received = 0u;
        status = yume_stream_read(stream, buffer, sizeof(buffer), &received,
                                  20000u);
        if (status == YUME_STATUS_OK) continue;
        if (status == YUME_STATUS_CLOSED) {
            context->ok = 1;
        } else {
            report("server read after the client abort", status, stream);
        }
        break;
    }
    discard_stream(&stream);
    return NULL;
}

struct accept_context {
    yume_endpoint* endpoint;
    uint32_t timeout_ms;
    _Atomic int entered;
    yume_status status;
    yume_stream* stream;
};

static void* accept_worker(void* opaque) {
    struct accept_context* context = (struct accept_context*)opaque;
    atomic_store_explicit(&context->entered, 1, memory_order_release);
    context->status = accept_named(context->endpoint, kEcho,
                                   context->timeout_ms, &context->stream);
    return NULL;
}

static int test_listener_conflict(yume_runtime* runtime, const char* path,
                                  yume_endpoint* server) {
    yume_endpoint* duplicate = make_endpoint(runtime, path, YUME_ROLE_SERVER);
    int passed = 0;
    if (duplicate == NULL) return 0;
    if (!expect_status(register_stream(duplicate, kEcho), YUME_STATUS_OK,
                       "duplicate listener registration", duplicate) ||
        !expect_status(yume_endpoint_start(duplicate, 0u),
                       YUME_STATUS_INVALID_STATE, "occupied listener address", duplicate)) {
        goto done;
    }
    if (yume_endpoint_state(duplicate) != YUME_ENDPOINT_FAILED ||
        yume_endpoint_state(server) != YUME_ENDPOINT_RUNNING) {
        fprintf(stderr, "bind conflict published incorrect endpoint states\n");
        goto done;
    }
    /* Clearing the external cause does not settle the FAILED lifecycle state.
     * Stop the failed endpoint before retrying, retaining its registrations. */
    if (!expect_status(yume_endpoint_stop(server, 0u), YUME_STATUS_OK,
                       "release occupied address", server) ||
        !expect_status(yume_endpoint_start(duplicate, 0u),
                       YUME_STATUS_INVALID_STATE, "retry before failed stop", duplicate)) {
        goto done;
    }
    if (yume_endpoint_state(duplicate) != YUME_ENDPOINT_FAILED) {
        fprintf(stderr, "rejected retry changed FAILED state\n");
        goto done;
    }
    if (!expect_status(yume_endpoint_stop(duplicate, 0u), YUME_STATUS_OK,
                       "settle failed listener", duplicate)) {
        goto done;
    }
    if (yume_endpoint_state(duplicate) != YUME_ENDPOINT_STOPPED) {
        fprintf(stderr, "failed listener stop did not settle STOPPED\n");
        goto done;
    }
    if (!expect_status(yume_endpoint_start(duplicate, 0u), YUME_STATUS_OK,
                       "retry failed listener", duplicate) ||
        !expect_status(yume_endpoint_stop(duplicate, 0u), YUME_STATUS_OK,
                       "stop retried listener", duplicate) ||
        !expect_status(yume_endpoint_start(server, 0u), YUME_STATUS_OK,
                       "restart original listener", server)) {
        goto done;
    }
    passed = 1;
done:
    (void)yume_endpoint_stop(duplicate, 0u);
    yume_endpoint_destroy(duplicate);
    return passed;
}

int main(int argc, char** argv) {
    char server_path[4096];
    char client_path[4096];
    const char* client_fingerprint = NULL;
    const char* server_fingerprint = NULL;
    yume_runtime* server_runtime = NULL;
    yume_runtime* client_runtime = NULL;
    yume_endpoint* server = NULL;
    yume_endpoint* client = NULL;
    yume_stream* stream = NULL;
    yume_stream* retained_client = NULL;
    yume_stream* retained_server = NULL;
    yume_stream* restarted_client = NULL;
    struct echo_context echo;
    struct deadline_context deadline;
    struct accept_context pairing;
    struct accept_context blocked;
    pthread_t echo_thread;
    pthread_t deadline_thread;
    pthread_t pairing_thread;
    pthread_t blocked_thread;
    int echo_started = 0;
    int deadline_started = 0;
    int pairing_started = 0;
    int blocked_started = 0;
    yume_status status;
    int result = 1;

    memset(&echo, 0, sizeof(echo));
    memset(&deadline, 0, sizeof(deadline));
    memset(&pairing, 0, sizeof(pairing));
    memset(&blocked, 0, sizeof(blocked));
    atomic_init(&deadline.release, 0);
    atomic_init(&pairing.entered, 0);
    atomic_init(&blocked.entered, 0);

    if (argc != 5) {
        fprintf(stderr,
                "usage: %s SERVER_DIR CLIENT_DIR CLIENT_FINGERPRINT "
                "SERVER_FINGERPRINT\n",
                argv[0]);
        return 2;
    }
    if (snprintf(server_path, sizeof(server_path), "%s/yumed.json", argv[1]) >=
            (int)sizeof(server_path) ||
        snprintf(client_path, sizeof(client_path), "%s/yume.json", argv[2]) >=
            (int)sizeof(client_path)) {
        fprintf(stderr, "kit path is too long\n");
        return 2;
    }
    client_fingerprint = argv[3];
    server_fingerprint = argv[4];

    server_runtime = make_runtime(argv[1]);
    client_runtime = make_runtime(argv[2]);
    if (server_runtime == NULL || client_runtime == NULL) goto cleanup;
    server = make_endpoint(server_runtime, server_path, YUME_ROLE_SERVER);
    client = make_endpoint(client_runtime, client_path, YUME_ROLE_CLIENT);
    if (server == NULL || client == NULL) goto cleanup;

    /* Schema-1 registration happens on a stopped server and must name a
     * service its immutable configuration declares. */
    if (!expect_status(register_stream(server, kUndeclared),
                       YUME_STATUS_PERMISSION_DENIED,
                       "undeclared service registration", server) ||
        !expect_status(register_stream(server, kEcho), YUME_STATUS_OK,
                       "echo registration", server) ||
        !expect_status(register_stream(server, kDenied), YUME_STATUS_OK,
                       "denied registration", server) ||
        !expect_status(register_stream(server, kEcho),
                       YUME_STATUS_INVALID_ARGUMENT,
                       "duplicate registration", server) ||
        !expect_status(register_stream(client, kEcho),
                       YUME_STATUS_INVALID_ARGUMENT,
                       "client registration", client)) {
        goto cleanup;
    }

    if (!expect_status(
            yume_endpoint_set_socket_protector(server, protect_socket, NULL),
            YUME_STATUS_UNSUPPORTED, "server socket protector", server) ||
        !expect_status(yume_endpoint_start(server, 1u),
                       YUME_STATUS_UNSUPPORTED, "bounded server start",
                       server) ||
        !expect_status(yume_endpoint_start(server, 0u), YUME_STATUS_OK,
                       "server start", server)) {
        goto cleanup;
    }
    if (yume_endpoint_state(server) != YUME_ENDPOINT_RUNNING) {
        fprintf(stderr, "started server is not RUNNING\n");
        goto cleanup;
    }
    if (!test_listener_conflict(server_runtime, server_path, server)) goto cleanup;
    if (!expect_status(register_stream(server, kUnregistered),
                       YUME_STATUS_INVALID_STATE,
                       "registration while running", server) ||
        !expect_status(accept_named(server, kEcho, 0u, &stream),
                       YUME_STATUS_WOULD_BLOCK, "zero-timeout accept",
                       server) ||
        !expect_status(accept_named(server, kUnregistered, 0u, &stream),
                       YUME_STATUS_NOT_FOUND,
                       "accept of an unregistered service", server) ||
        !expect_status(open_named(server, kEcho, 1000u, &stream),
                       YUME_STATUS_INVALID_ARGUMENT, "server-initiated OPEN",
                       server)) {
        goto cleanup;
    }

    /* A refusing socket protector fails closed before connecting. A
     * replacement installed while FAILED is used by the next start. */
    if (!expect_status(
            yume_endpoint_set_socket_protector(client, reject_socket, NULL),
            YUME_STATUS_OK, "install rejecting protector", client)) {
        goto cleanup;
    }
    status = yume_endpoint_start(client, 30000u);
    if (status != YUME_STATUS_IO_ERROR ||
        atomic_load_explicit(&rejected_sockets, memory_order_relaxed) == 0u) {
        report("fail-closed socket protector", status, client);
        goto cleanup;
    }
    if (!expect_status(
            yume_endpoint_set_socket_protector(client, protect_socket, NULL),
            YUME_STATUS_OK, "replace failed socket protector", client) ||
        !expect_status(yume_endpoint_stop(client, 0u), YUME_STATUS_OK,
                       "stop after rejected socket", client) ||
        !expect_status(yume_endpoint_start(client, 30000u), YUME_STATUS_OK,
                       "client start", client)) {
        goto cleanup;
    }
    if (atomic_load_explicit(&protected_sockets, memory_order_relaxed) == 0u) {
        fprintf(stderr, "client socket protector was never invoked\n");
        goto cleanup;
    }

    /* Direction, declaration and authorization refusals keep the session. */
    {
        yume_open_options routed;
        memset(&routed, 0, sizeof(routed));
        routed.struct_size = sizeof(routed);
        routed.abi_version = YUME_ABI_VERSION;
        routed.service.data = kEcho;
        routed.service.size = sizeof(kEcho) - 1u;
        routed.kind = YUME_SERVICE_BYTE_STREAM;
        routed.destination.struct_size = sizeof(routed.destination);
        routed.destination.abi_version = YUME_ABI_VERSION;
        routed.destination.kind = YUME_DESTINATION_HOSTNAME;
        routed.destination.host.data = "example.com";
        routed.destination.host.size = sizeof("example.com") - 1u;
        routed.destination.port = 443u;
        if (!expect_status(accept_named(client, kEcho, 0u, &stream),
                           YUME_STATUS_INVALID_ARGUMENT, "client accept",
                           client) ||
            !expect_status(open_named(client, kEcho, 0u, &stream),
                           YUME_STATUS_WOULD_BLOCK, "zero-timeout OPEN",
                           client) ||
            !expect_status(
                yume_endpoint_open_stream(client, &routed, 20000u, &stream),
                YUME_STATUS_UNSUPPORTED, "destination-routed OPEN", client) ||
            !expect_status(open_named(client, kUndeclared, 20000u, &stream),
                           YUME_STATUS_NOT_FOUND, "undeclared service OPEN",
                           client) ||
            !expect_status(open_named(client, kUnregistered, 20000u, &stream),
                           YUME_STATUS_PERMISSION_DENIED,
                           "unregistered service OPEN", client) ||
            !expect_status(open_named(client, kDenied, 20000u, &stream),
                           YUME_STATUS_PERMISSION_DENIED,
                           "unauthorized service OPEN", client)) {
            goto cleanup;
        }
    }

    /* Named bytes both ways, peer identity and half-close. */
    echo.endpoint = server;
    echo.client_fingerprint = client_fingerprint;
    if (pthread_create(&echo_thread, NULL, echo_worker, &echo) != 0) {
        fprintf(stderr, "cannot start the echo worker\n");
        goto cleanup;
    }
    echo_started = 1;
    if (!expect_status(open_named(client, kEcho, 20000u, &stream),
                       YUME_STATUS_OK, "echo OPEN", client) ||
        !check_peer(stream, YUME_ROLE_SERVER, kEcho, server_fingerprint) ||
        !expect_read(stream, 0u, YUME_STATUS_WOULD_BLOCK,
                     "zero-timeout read") ||
        !write_text(stream, kClientPayload) ||
        !expect_status(yume_stream_shutdown_write(stream, 20000u),
                       YUME_STATUS_OK, "client shutdown_write", stream)) {
        goto cleanup;
    }
    {
        size_t written = 0u;
        if (!expect_status(yume_stream_write(stream, "x", 1u, &written, 1000u),
                           YUME_STATUS_CLOSED, "write after shutdown",
                           stream)) {
            goto cleanup;
        }
    }
    if (!read_text(stream, kServerPayload) ||
        !expect_read(stream, 20000u, YUME_STATUS_EOF, "client end of stream") ||
        !expect_read(stream, 0u, YUME_STATUS_EOF, "repeated end of stream")) {
        goto cleanup;
    }
    if (pthread_join(echo_thread, NULL) != 0) {
        fprintf(stderr, "cannot join the echo worker\n");
        goto cleanup;
    }
    echo_started = 0;
    if (echo.ok == 0) {
        fprintf(stderr, "the server side of the echo exchange failed\n");
        goto cleanup;
    }
    if (!expect_status(yume_stream_close(stream, 1u),
                       YUME_STATUS_INVALID_ARGUMENT, "nonzero stream close",
                       stream) ||
        !expect_status(yume_stream_close(stream, 0u), YUME_STATUS_OK,
                       "stream close", stream)) {
        goto cleanup;
    }
    yume_stream_destroy(stream);
    stream = NULL;

    /* An expired read keeps no caller storage and loses no later data. An
     * abort after data is closure for the peer, not end of stream. */
    deadline.endpoint = server;
    if (pthread_create(&deadline_thread, NULL, deadline_worker, &deadline) !=
        0) {
        fprintf(stderr, "cannot start the deadline worker\n");
        goto cleanup;
    }
    deadline_started = 1;
    if (!expect_status(open_named(client, kEcho, 20000u, &stream),
                       YUME_STATUS_OK, "deadline OPEN", client)) {
        goto cleanup;
    }
    {
        const struct timespec started = monotonic_now();
        if (!expect_read(stream, 50u, YUME_STATUS_TIMEOUT,
                         "expired read deadline")) {
            goto cleanup;
        }
        if (elapsed_milliseconds(started, monotonic_now()) < 40L) {
            fprintf(stderr, "read deadline expired early\n");
            goto cleanup;
        }
    }
    atomic_store_explicit(&deadline.release, 1, memory_order_release);
    if (!read_text(stream, kLatePayload) || !write_text(stream, kAbortPayload) ||
        !expect_status(yume_stream_close(stream, 0u), YUME_STATUS_OK,
                       "abort stream", stream) ||
        !expect_read(stream, 0u, YUME_STATUS_CLOSED,
                     "read after local close")) {
        goto cleanup;
    }
    yume_stream_destroy(stream);
    stream = NULL;
    if (pthread_join(deadline_thread, NULL) != 0) {
        fprintf(stderr, "cannot join the deadline worker\n");
        goto cleanup;
    }
    deadline_started = 0;
    if (deadline.ok == 0) {
        fprintf(stderr, "the server did not observe the abort as closure\n");
        goto cleanup;
    }

    /* A stream pair kept open across the server stop below. */
    pairing.endpoint = server;
    pairing.timeout_ms = 20000u;
    if (pthread_create(&pairing_thread, NULL, accept_worker, &pairing) != 0) {
        fprintf(stderr, "cannot start the pairing worker\n");
        goto cleanup;
    }
    pairing_started = 1;
    if (!expect_status(open_named(client, kEcho, 20000u, &retained_client),
                       YUME_STATUS_OK, "retained OPEN", client)) {
        goto cleanup;
    }
    if (pthread_join(pairing_thread, NULL) != 0) {
        fprintf(stderr, "cannot join the pairing worker\n");
        goto cleanup;
    }
    pairing_started = 0;
    retained_server = pairing.stream;
    pairing.stream = NULL;
    if (pairing.status != YUME_STATUS_OK || retained_server == NULL) {
        report("retained accept", pairing.status, server);
        goto cleanup;
    }
    if (!check_peer(retained_server, YUME_ROLE_CLIENT, kEcho,
                    client_fingerprint) ||
        !write_text(retained_client, kRetainedPayload) ||
        !read_text(retained_server, kRetainedPayload)) {
        goto cleanup;
    }

    /* Stop settles a blocked accept promptly. */
    blocked.endpoint = server;
    blocked.timeout_ms = 60000u;
    if (pthread_create(&blocked_thread, NULL, accept_worker, &blocked) != 0) {
        fprintf(stderr, "cannot start the blocked accept worker\n");
        goto cleanup;
    }
    blocked_started = 1;
    while (atomic_load_explicit(&blocked.entered, memory_order_acquire) == 0) {
        sched_yield();
    }
    pause_milliseconds(50L);
    {
        const struct timespec started = monotonic_now();
        if (!expect_status(yume_endpoint_stop(server, 0u), YUME_STATUS_OK,
                           "stop with a blocked accept", server)) {
            goto cleanup;
        }
        if (elapsed_milliseconds(started, monotonic_now()) > 5000L) {
            fprintf(stderr, "server stop with a blocked accept was slow\n");
            goto cleanup;
        }
    }
    if (pthread_join(blocked_thread, NULL) != 0) {
        fprintf(stderr, "cannot join the blocked accept worker\n");
        goto cleanup;
    }
    blocked_started = 0;
    if (blocked.status == YUME_STATUS_OK || blocked.stream != NULL) {
        fprintf(stderr, "blocked accept succeeded while the server stopped\n");
        goto cleanup;
    }

    /* The stopped server's handle fails typed. The client loses its session,
     * which must never read as a clean end of stream. */
    {
        size_t written = 0u;
        if (!expect_read(retained_server, 0u, YUME_STATUS_CLOSED,
                         "read on a stopped server's stream") ||
            !expect_status(
                yume_stream_write(retained_server, "x", 1u, &written, 0u),
                YUME_STATUS_CLOSED, "write on a stopped server's stream",
                retained_server) ||
            !expect_read(retained_client, 20000u, YUME_STATUS_CLOSED,
                         "client read after the server stopped") ||
            !expect_status(open_named(client, kEcho, 5000u, &stream),
                           YUME_STATUS_INVALID_STATE,
                           "OPEN without a live session", client)) {
            goto cleanup;
        }
    }
    if (!expect_status(yume_stream_close(retained_server, 0u), YUME_STATUS_OK,
                       "close after server stop", retained_server)) {
        goto cleanup;
    }
    yume_stream_destroy(retained_server);
    retained_server = NULL;

    /* Registrations survive restart. The restarted pair carries traffic. */
    if (!expect_status(yume_endpoint_start(server, 0u), YUME_STATUS_OK,
                       "server restart", server) ||
        !expect_status(accept_named(server, kEcho, 0u, &stream),
                       YUME_STATUS_WOULD_BLOCK,
                       "registration retained across restart", server) ||
        !expect_status(accept_named(server, kUnregistered, 0u, &stream),
                       YUME_STATUS_NOT_FOUND,
                       "unregistered service after restart", server) ||
        !expect_status(yume_endpoint_stop(client, 0u), YUME_STATUS_OK,
                       "client stop", client) ||
        !expect_status(yume_endpoint_start(client, 30000u), YUME_STATUS_OK,
                       "client restart", client)) {
        goto cleanup;
    }
    pairing.status = YUME_STATUS_OK;
    pairing.stream = NULL;
    atomic_store_explicit(&pairing.entered, 0, memory_order_release);
    if (pthread_create(&pairing_thread, NULL, accept_worker, &pairing) != 0) {
        fprintf(stderr, "cannot restart the pairing worker\n");
        goto cleanup;
    }
    pairing_started = 1;
    if (!expect_status(open_named(client, kEcho, 20000u, &restarted_client),
                       YUME_STATUS_OK, "OPEN after restart", client)) {
        goto cleanup;
    }
    if (pthread_join(pairing_thread, NULL) != 0) {
        fprintf(stderr, "cannot join the restarted pairing worker\n");
        goto cleanup;
    }
    pairing_started = 0;
    if (pairing.status != YUME_STATUS_OK || pairing.stream == NULL) {
        report("accept after restart", pairing.status, server);
        goto cleanup;
    }
    if (!write_text(restarted_client, kRestartPayload) ||
        !read_text(pairing.stream, kRestartPayload) ||
        !write_text(pairing.stream, kRestartPayload) ||
        !read_text(restarted_client, kRestartPayload)) {
        goto cleanup;
    }
    discard_stream(&pairing.stream);

    /* Client handles from both runs outlive client stop and endpoint
     * destruction. They report closure and release cleanly afterwards. */
    if (!expect_status(yume_endpoint_stop(client, 0u), YUME_STATUS_OK,
                       "client stop with retained streams", client) ||
        !expect_read(restarted_client, 0u, YUME_STATUS_CLOSED,
                     "read after client stop") ||
        !expect_read(retained_client, 0u, YUME_STATUS_CLOSED,
                     "read on an earlier run's stream")) {
        goto cleanup;
    }
    yume_endpoint_destroy(client);
    client = NULL;
    if (!expect_status(yume_stream_close(restarted_client, 0u), YUME_STATUS_OK,
                       "close after endpoint destruction", restarted_client)) {
        goto cleanup;
    }
    yume_stream_destroy(restarted_client);
    restarted_client = NULL;
    discard_stream(&retained_client);
    if (!expect_status(yume_endpoint_stop(server, 0u), YUME_STATUS_OK,
                       "final server stop", server)) {
        goto cleanup;
    }

    result = 0;
    printf("C ABI v1 schema-1 stream integration passed\n");

cleanup:
    discard_stream(&stream);
    /* Stopping an endpoint settles any worker blocked in accept or read. */
    if (echo_started || deadline_started || pairing_started ||
        blocked_started) {
        if (server != NULL) (void)yume_endpoint_stop(server, 0u);
        if (client != NULL) (void)yume_endpoint_stop(client, 0u);
    }
    if (echo_started) (void)pthread_join(echo_thread, NULL);
    if (deadline_started) (void)pthread_join(deadline_thread, NULL);
    if (pairing_started) (void)pthread_join(pairing_thread, NULL);
    if (blocked_started) (void)pthread_join(blocked_thread, NULL);
    discard_stream(&pairing.stream);
    discard_stream(&blocked.stream);
    discard_stream(&retained_server);
    discard_stream(&retained_client);
    discard_stream(&restarted_client);
    if (client != NULL) {
        (void)yume_endpoint_stop(client, 0u);
        yume_endpoint_destroy(client);
    }
    if (server != NULL) {
        (void)yume_endpoint_stop(server, 0u);
        yume_endpoint_destroy(server);
    }
    yume_runtime_destroy(client_runtime);
    yume_runtime_destroy(server_runtime);
    return result;
}
