/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Drives a real client and server through the public C ABI v1 in one process
 * and moves bytes both directions over a named service stream. This is the
 * only check that the ABI is a transport rather than a lifecycle shell.
 */

#include <yume/yume.h>

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char kService[] = "abi-stream-v1";
static const char kClientPayload[] = "yume abi client payload";
static const char kServerPayload[] = "yume abi server reply";

static void report(const char* operation, yume_status status, const void* handle) {
    yume_diagnostic diagnostic;
    memset(&diagnostic, 0, sizeof(diagnostic));
    diagnostic.struct_size = sizeof(diagnostic);
    diagnostic.abi_version = YUME_ABI_VERSION;
    if (handle != NULL) {
        (void)yume_handle_get_diagnostic(handle, &diagnostic, sizeof(diagnostic));
    }
    fprintf(stderr, "%s failed: status=%d %s%s\n", operation, (int)status,
            diagnostic.message[0] != '\0' ? ": " : "", diagnostic.message);
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

struct accept_context {
    yume_endpoint* endpoint;
    int ok;
};

/* Accepts one stream, echoes the client payload back, then half-closes. */
static void* accept_worker(void* opaque) {
    struct accept_context* context = (struct accept_context*)opaque;
    yume_accept_options options;
    yume_stream* stream = NULL;
    yume_peer_identity identity;
    char received[128];
    size_t received_bytes = 0;
    size_t written = 0;
    yume_status status;

    memset(&options, 0, sizeof(options));
    options.struct_size = sizeof(options);
    options.abi_version = YUME_ABI_VERSION;
    options.service.data = kService;
    options.service.size = sizeof(kService) - 1u;
    options.kind = YUME_SERVICE_BYTE_STREAM;

    status = yume_endpoint_accept_stream(context->endpoint, &options, 20000u,
                                         &stream);
    if (status != YUME_STATUS_OK || stream == NULL) {
        report("yume_endpoint_accept_stream", status, context->endpoint);
        return NULL;
    }

    memset(&identity, 0, sizeof(identity));
    identity.struct_size = sizeof(identity);
    identity.abi_version = YUME_ABI_VERSION;
    status = yume_stream_get_peer_identity(stream, &identity, sizeof(identity));
    if (status != YUME_STATUS_OK) {
        report("yume_stream_get_peer_identity", status, stream);
        goto done;
    }
    if (identity.authenticated == 0u) {
        fprintf(stderr, "accepted stream reported an unauthenticated peer\n");
        goto done;
    }
    if (strcmp(identity.service, kService) != 0) {
        fprintf(stderr, "accepted stream reported service '%s'\n",
                identity.service);
        goto done;
    }

    memset(received, 0, sizeof(received));
    status = yume_stream_read(stream, received, sizeof(received) - 1u,
                              &received_bytes, 20000u);
    if (status != YUME_STATUS_OK) {
        report("server yume_stream_read", status, stream);
        goto done;
    }
    if (received_bytes != sizeof(kClientPayload) - 1u ||
        memcmp(received, kClientPayload, received_bytes) != 0) {
        fprintf(stderr, "server received unexpected payload '%s'\n", received);
        goto done;
    }

    status = yume_stream_write(stream, kServerPayload,
                               sizeof(kServerPayload) - 1u, &written, 20000u);
    if (status != YUME_STATUS_OK || written != sizeof(kServerPayload) - 1u) {
        report("server yume_stream_write", status, stream);
        goto done;
    }
    status = yume_stream_shutdown_write(stream, 20000u);
    if (status != YUME_STATUS_OK) {
        report("server yume_stream_shutdown_write", status, stream);
        goto done;
    }
    context->ok = 1;

done:
    (void)yume_stream_close(stream, 5000u);
    yume_stream_destroy(stream);
    return NULL;
}

static yume_status start_endpoint(yume_runtime* runtime,
                                  const char* path,
                                  yume_endpoint** out_endpoint) {
    size_t size = 0;
    char* text = read_file(path, &size);
    yume_config* config = NULL;
    yume_status status;

    *out_endpoint = NULL;
    if (text == NULL) {
        fprintf(stderr, "cannot read configuration %s\n", path);
        return YUME_STATUS_IO_ERROR;
    }
    status = yume_config_parse_json(runtime, text, size, &config);
    free(text);
    if (status != YUME_STATUS_OK) {
        report("yume_config_parse_json", status, runtime);
        return status;
    }
    status = yume_endpoint_create(runtime, config, out_endpoint);
    yume_config_destroy(config);
    if (status != YUME_STATUS_OK) {
        report("yume_endpoint_create", status, runtime);
        return status;
    }
    status = yume_endpoint_start(*out_endpoint, 30000u);
    if (status != YUME_STATUS_OK) {
        report("yume_endpoint_start", status, *out_endpoint);
        return status;
    }
    if (yume_endpoint_state(*out_endpoint) != YUME_ENDPOINT_RUNNING) {
        fprintf(stderr, "started endpoint %s is not RUNNING\n", path);
        return YUME_STATUS_INVALID_STATE;
    }
    return YUME_STATUS_OK;
}

int main(int argc, char** argv) {
    yume_runtime_options options;
    yume_runtime* runtime = NULL;
    yume_endpoint* server = NULL;
    yume_endpoint* client = NULL;
    yume_service_descriptor descriptor;
    yume_open_options open_options;
    yume_stream* stream = NULL;
    struct accept_context context;
    pthread_t worker;
    int worker_started = 0;
    char reply[128];
    size_t reply_bytes = 0;
    size_t written = 0;
    size_t trailing = 0;
    yume_status status;
    int result = 1;

    if (argc != 3) {
        fprintf(stderr, "usage: %s SERVER_CONFIG CLIENT_CONFIG\n", argv[0]);
        return 2;
    }

    memset(&options, 0, sizeof(options));
    options.struct_size = sizeof(options);
    options.abi_version = YUME_ABI_VERSION;
    options.config_base_dir = ".";
    status = yume_runtime_create(&options, &runtime);
    if (status != YUME_STATUS_OK) {
        report("yume_runtime_create", status, NULL);
        return 1;
    }

    if (start_endpoint(runtime, argv[1], &server) != YUME_STATUS_OK) goto cleanup;

    memset(&descriptor, 0, sizeof(descriptor));
    descriptor.struct_size = sizeof(descriptor);
    descriptor.abi_version = YUME_ABI_VERSION;
    descriptor.name.data = kService;
    descriptor.name.size = sizeof(kService) - 1u;
    descriptor.kind = YUME_SERVICE_BYTE_STREAM;
    descriptor.max_concurrent = 4u;
    descriptor.max_pending_accepts = 4u;
    descriptor.max_queued_bytes = 262144u;
    status = yume_endpoint_register_service(server, &descriptor);
    if (status != YUME_STATUS_OK) {
        report("yume_endpoint_register_service", status, server);
        goto cleanup;
    }

    context.endpoint = server;
    context.ok = 0;
    if (pthread_create(&worker, NULL, accept_worker, &context) != 0) {
        fprintf(stderr, "cannot start the accept worker\n");
        goto cleanup;
    }
    worker_started = 1;

    if (start_endpoint(runtime, argv[2], &client) != YUME_STATUS_OK) goto cleanup;

    memset(&open_options, 0, sizeof(open_options));
    /* A named service stream carries no destination. Declaring the shorter
     * prefix size is how the sized-struct contract says "this field is not
     * present"; zeroing the nested descriptor instead would be a truncated
     * destination, not an absent one. */
    open_options.struct_size = YUME_OPEN_OPTIONS_MIN_SIZE;
    open_options.abi_version = YUME_ABI_VERSION;
    open_options.service.data = kService;
    open_options.service.size = sizeof(kService) - 1u;
    open_options.kind = YUME_SERVICE_BYTE_STREAM;
    status = yume_endpoint_open_stream(client, &open_options, 20000u, &stream);
    if (status != YUME_STATUS_OK || stream == NULL) {
        report("yume_endpoint_open_stream", status, client);
        goto cleanup;
    }

    status = yume_stream_write(stream, kClientPayload,
                               sizeof(kClientPayload) - 1u, &written, 20000u);
    if (status != YUME_STATUS_OK || written != sizeof(kClientPayload) - 1u) {
        report("client yume_stream_write", status, stream);
        goto cleanup;
    }

    memset(reply, 0, sizeof(reply));
    status = yume_stream_read(stream, reply, sizeof(reply) - 1u, &reply_bytes,
                              20000u);
    if (status != YUME_STATUS_OK) {
        report("client yume_stream_read", status, stream);
        goto cleanup;
    }
    if (reply_bytes != sizeof(kServerPayload) - 1u ||
        memcmp(reply, kServerPayload, reply_bytes) != 0) {
        fprintf(stderr, "client received unexpected reply '%s'\n", reply);
        goto cleanup;
    }

    /* The server half-closed after replying, so the next read must report EOF
     * rather than blocking until the deadline. */
    status = yume_stream_read(stream, reply, sizeof(reply) - 1u, &trailing,
                              20000u);
    if (status != YUME_STATUS_EOF || trailing != 0u) {
        report("client EOF after peer shutdown", status, stream);
        goto cleanup;
    }

    if (pthread_join(worker, NULL) != 0) {
        fprintf(stderr, "cannot join the accept worker\n");
        goto cleanup;
    }
    worker_started = 0;
    if (context.ok == 0) {
        fprintf(stderr, "the server side of the exchange failed\n");
        goto cleanup;
    }

    result = 0;
    printf("C ABI v1 stream integration passed\n");

cleanup:
    if (stream != NULL) {
        (void)yume_stream_close(stream, 5000u);
        yume_stream_destroy(stream);
    }
    if (worker_started != 0) {
        /* Stopping the server settles a blocked accept so the join returns. */
        if (server != NULL) (void)yume_endpoint_stop(server, 10000u);
        (void)pthread_join(worker, NULL);
    }
    if (client != NULL) {
        (void)yume_endpoint_stop(client, 10000u);
        yume_endpoint_destroy(client);
    }
    if (server != NULL) {
        (void)yume_endpoint_stop(server, 10000u);
        yume_endpoint_destroy(server);
    }
    yume_runtime_destroy(runtime);
    return result;
}
