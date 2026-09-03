/*
 * YUME - embeddable stealth universal transport
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#ifndef YUME_YUME_H
#define YUME_YUME_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#  if defined(YUME_ABI_BUILD)
#    define YUME_API __declspec(dllexport)
#  else
#    define YUME_API __declspec(dllimport)
#  endif
#elif defined(__GNUC__) || defined(__clang__)
#  define YUME_API __attribute__((visibility("default")))
#else
#  define YUME_API
#endif

#ifdef __cplusplus
#  define YUME_NOEXCEPT noexcept
extern "C" {
#else
#  define YUME_NOEXCEPT
#endif

#define YUME_ABI_VERSION 1u
#define YUME_TIMEOUT_INFINITE UINT32_MAX

#define YUME_MAX_VERSION_TEXT 32u
#define YUME_MAX_PROVIDER_NAME 32u
#define YUME_MAX_SUITE_NAME 48u
#define YUME_MAX_PROFILE_NAME 64u
#define YUME_MAX_SERVICE_NAME 128u
#define YUME_MAX_IDENTITY_TEXT 96u
#define YUME_MAX_DIAGNOSTIC_TEXT 512u
#define YUME_MAX_JSON_POINTER 256u

typedef int32_t yume_status;

enum {
    YUME_STATUS_OK = 0,
    YUME_STATUS_EOF = 1,
    YUME_STATUS_INVALID_ARGUMENT = -1,
    YUME_STATUS_BUFFER_TOO_SMALL = -2,
    YUME_STATUS_INTERNAL_ERROR = -3,
    YUME_STATUS_INVALID_STATE = -4,
    YUME_STATUS_TIMEOUT = -5,
    YUME_STATUS_WOULD_BLOCK = -6,
    YUME_STATUS_NOT_FOUND = -7,
    YUME_STATUS_PERMISSION_DENIED = -8,
    YUME_STATUS_PARSE_ERROR = -9,
    YUME_STATUS_RESOURCE_EXHAUSTED = -10,
    YUME_STATUS_CANCELLED = -11,
    YUME_STATUS_CLOSED = -12,
    YUME_STATUS_INCOMPATIBLE = -13,
    YUME_STATUS_UNSUPPORTED = -14,
    YUME_STATUS_IO_ERROR = -15
};

enum {
    YUME_ROLE_CLIENT = 1,
    YUME_ROLE_SERVER = 2
};

enum {
    YUME_SERVICE_BYTE_STREAM = 1,
    YUME_SERVICE_PACKET = 2
};

enum {
    YUME_DESTINATION_NONE = 0,
    YUME_DESTINATION_HOSTNAME = 1,
    YUME_DESTINATION_IPV4 = 2,
    YUME_DESTINATION_IPV6 = 3
};

enum {
    YUME_ENDPOINT_CREATED = 1,
    YUME_ENDPOINT_STARTING = 2,
    YUME_ENDPOINT_RUNNING = 3,
    YUME_ENDPOINT_STOPPING = 4,
    YUME_ENDPOINT_STOPPED = 5,
    YUME_ENDPOINT_FAILED = 6
};

enum {
    YUME_LOG_TRACE = 1,
    YUME_LOG_DEBUG = 2,
    YUME_LOG_INFO = 3,
    YUME_LOG_WARNING = 4,
    YUME_LOG_ERROR = 5
};

enum {
    YUME_EVENT_ENDPOINT_STATE = 1
};

enum {
    YUME_DIAGNOSTIC_JSON_POINTER_TRUNCATED = 1u << 0,
    YUME_DIAGNOSTIC_MESSAGE_TRUNCATED = 1u << 1
};

typedef struct yume_runtime yume_runtime;
typedef struct yume_config yume_config;
typedef struct yume_endpoint yume_endpoint;
typedef struct yume_stream yume_stream;
typedef struct yume_packet yume_packet;

typedef struct yume_string_view {
    const char* data;
    size_t size;
} yume_string_view;

typedef struct yume_build_info {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t feature_flags;
    char product_version[YUME_MAX_VERSION_TEXT];
    char crypto_backend[YUME_MAX_PROVIDER_NAME];
    char compiler[YUME_MAX_PROVIDER_NAME];
} yume_build_info;

#define YUME_BUILD_INFO_MIN_SIZE offsetof(yume_build_info, compiler)

typedef struct yume_compatibility {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t ytp_version;
    uint32_t config_schema;
    uint32_t evidence_profile_version;
    char product_version[YUME_MAX_VERSION_TEXT];
    char ytp_name[YUME_MAX_VERSION_TEXT];
    char suite[YUME_MAX_SUITE_NAME];
    char crypto_backend[YUME_MAX_PROVIDER_NAME];
    char secure_channel_provider[YUME_MAX_PROVIDER_NAME];
    char front_door_provider[YUME_MAX_PROVIDER_NAME];
    char carrier_provider[YUME_MAX_PROVIDER_NAME];
    char session_component[YUME_MAX_PROVIDER_NAME];
    char session_security_provider[YUME_MAX_PROVIDER_NAME];
    char evidence_profile[YUME_MAX_PROFILE_NAME];
} yume_compatibility;

#define YUME_COMPATIBILITY_MIN_SIZE \
    offsetof(yume_compatibility, secure_channel_provider)

typedef struct yume_status_info {
    size_t struct_size;
    uint32_t abi_version;
    yume_status code;
    char name[48];
} yume_status_info;

#define YUME_STATUS_INFO_MIN_SIZE offsetof(yume_status_info, name)

typedef struct yume_diagnostic {
    size_t struct_size;
    uint32_t abi_version;
    yume_status status;
    uint32_t flags;
    char json_pointer[YUME_MAX_JSON_POINTER];
    char message[YUME_MAX_DIAGNOSTIC_TEXT];
} yume_diagnostic;

#define YUME_DIAGNOSTIC_MIN_SIZE offsetof(yume_diagnostic, json_pointer)

typedef struct yume_peer_identity {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t authenticated;
    uint32_t role;
    uint32_t capability_flags;
    uint8_t composite_fingerprint_sha256[32];
    /* Opaque transport-level label for the authenticated peer. YUME assigns
     * it no application meaning: it is not a device, account, user, or
     * enrollment record. An embedder that needs those concepts owns them. */
    char peer_label[YUME_MAX_IDENTITY_TEXT];
    char service[YUME_MAX_SERVICE_NAME + 1u];
} yume_peer_identity;

#define YUME_PEER_IDENTITY_MIN_SIZE offsetof(yume_peer_identity, peer_label)

typedef struct yume_log_record {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t level;
    uint64_t timestamp_ns;
    yume_string_view component;
    yume_string_view message;
} yume_log_record;

typedef struct yume_event {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t type;
    uint32_t endpoint_state;
    uint64_t endpoint_id;
    yume_status status;
} yume_event;

/*
 * Callback arguments and their pointed-to strings are valid only for the
 * duration of the call. Callbacks run without YUME state or diagnostic locks
 * held; event delivery for one endpoint is lifecycle-ordered. Re-entry is
 * limited to side-effect-free version/status queries and
 * yume_handle_get_diagnostic(). Lifecycle and I/O calls return
 * YUME_STATUS_INVALID_STATE; void destroy calls are ignored.
 */
typedef void (*yume_log_callback)(const yume_log_record* record,
                                  void* user_data);
typedef void (*yume_event_callback)(const yume_event* event,
                                    void* user_data);

typedef struct yume_runtime_options {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t executor_threads;
    uint32_t max_pending_callbacks;
    yume_log_callback log_callback;
    yume_event_callback event_callback;
    void* callback_user_data;
    /* Directory that relative credential paths inside a configuration
     * document resolve against. The ABI receives configuration as bytes, not
     * as a file, so there is no document location to infer one from. NULL
     * selects the process working directory, which is rarely what an embedded
     * host wants: pass an explicit directory, or use absolute paths. */
    const char* config_base_dir;
} yume_runtime_options;

#define YUME_RUNTIME_OPTIONS_MIN_SIZE \
    offsetof(yume_runtime_options, event_callback)

/*
 * Invoked synchronously after an outbound socket is created and before it is
 * connected. Return nonzero to allow it. Returning zero fails closed. The
 * callback and user_data must remain valid until cleared or endpoint destroy
 * completes. No YUME function may be re-entered from this callback.
 */
typedef int (*yume_socket_protect_callback)(uintptr_t socket_handle,
                                            void* user_data);

typedef struct yume_service_descriptor {
    size_t struct_size;
    uint32_t abi_version;
    yume_string_view name;
    uint32_t kind;
    uint32_t max_concurrent;
    uint32_t max_pending_accepts;
    uint64_t max_queued_bytes;
} yume_service_descriptor;

#define YUME_SERVICE_DESCRIPTOR_MIN_SIZE sizeof(yume_service_descriptor)

typedef struct yume_destination {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t kind;
    uint32_t reserved;
    yume_string_view host;
    uint16_t port;
    uint16_t reserved2;
} yume_destination;

#define YUME_DESTINATION_MIN_SIZE offsetof(yume_destination, host)

typedef struct yume_open_options {
    size_t struct_size;
    uint32_t abi_version;
    yume_string_view service;
    uint32_t kind;
    uint32_t reserved;
    yume_destination destination;
} yume_open_options;

#define YUME_OPEN_OPTIONS_MIN_SIZE offsetof(yume_open_options, destination)

typedef struct yume_accept_options {
    size_t struct_size;
    uint32_t abi_version;
    yume_string_view service;
    uint32_t kind;
    uint32_t reserved;
} yume_accept_options;

#define YUME_ACCEPT_OPTIONS_MIN_SIZE offsetof(yume_accept_options, reserved)

typedef struct yume_packet_view {
    const void* data;
    size_t size;
} yume_packet_view;

typedef struct yume_packet_slot {
    size_t offset;
    size_t size;
} yume_packet_slot;

/* Version and manifest functions are side-effect free and thread-safe. */
YUME_API uint32_t yume_abi_version(void) YUME_NOEXCEPT;
YUME_API yume_status yume_get_build_info(yume_build_info* out,
                                         size_t out_size) YUME_NOEXCEPT;
YUME_API yume_status yume_get_compatibility(yume_compatibility* out,
                                            size_t out_size) YUME_NOEXCEPT;
YUME_API yume_status yume_get_status_info(yume_status code,
                                          yume_status_info* out,
                                          size_t out_size) YUME_NOEXCEPT;

/*
 * Runtime owns bounded executors and callback delivery. Runtime destroy
 * requests cancellation and waits for its child endpoints. Child handle
 * storage remains caller-owned and must still be destroyed. Callers must not
 * race a destroy function with another call using that same handle, use a
 * handle after destroy, or pass an output-handle pointer that aliases an input
 * object or handle.
 */
YUME_API yume_status yume_runtime_create(const yume_runtime_options* options,
                                         yume_runtime** out_runtime)
    YUME_NOEXCEPT;
YUME_API void yume_runtime_destroy(yume_runtime* runtime) YUME_NOEXCEPT;

/*
 * Parsing is strict and copies the complete input. The returned config is
 * immutable, role-tagged, and independent of the input buffer. Unknown keys,
 * aliases, inline private material, provider mismatch, and unsafe combinations
 * fail with a diagnostic containing the first RFC 6901 JSON pointer.
 */
YUME_API yume_status yume_config_parse_json(yume_runtime* runtime,
                                            const void* json,
                                            size_t json_size,
                                            yume_config** out_config)
    YUME_NOEXCEPT;
YUME_API uint32_t yume_config_role(const yume_config* config) YUME_NOEXCEPT;
YUME_API void yume_config_destroy(yume_config* config) YUME_NOEXCEPT;

YUME_API yume_status yume_endpoint_create(yume_runtime* runtime,
                                          const yume_config* config,
                                          yume_endpoint** out_endpoint)
    YUME_NOEXCEPT;
YUME_API yume_status yume_endpoint_set_socket_protector(
    yume_endpoint* endpoint,
    yume_socket_protect_callback callback,
    void* user_data) YUME_NOEXCEPT;
YUME_API yume_status yume_endpoint_register_service(
    yume_endpoint* endpoint,
    const yume_service_descriptor* service) YUME_NOEXCEPT;
YUME_API yume_status yume_endpoint_start(yume_endpoint* endpoint,
                                         uint32_t timeout_ms) YUME_NOEXCEPT;
YUME_API yume_status yume_endpoint_stop(yume_endpoint* endpoint,
                                        uint32_t timeout_ms) YUME_NOEXCEPT;
YUME_API uint32_t yume_endpoint_state(const yume_endpoint* endpoint)
    YUME_NOEXCEPT;

YUME_API yume_status yume_endpoint_open_stream(
    yume_endpoint* endpoint,
    const yume_open_options* options,
    uint32_t timeout_ms,
    yume_stream** out_stream) YUME_NOEXCEPT;
YUME_API yume_status yume_endpoint_accept_stream(
    yume_endpoint* endpoint,
    const yume_accept_options* options,
    uint32_t timeout_ms,
    yume_stream** out_stream) YUME_NOEXCEPT;
YUME_API yume_status yume_endpoint_open_packet(
    yume_endpoint* endpoint,
    const yume_open_options* options,
    uint32_t timeout_ms,
    yume_packet** out_packet) YUME_NOEXCEPT;
YUME_API yume_status yume_endpoint_accept_packet(
    yume_endpoint* endpoint,
    const yume_accept_options* options,
    uint32_t timeout_ms,
    yume_packet** out_packet) YUME_NOEXCEPT;
YUME_API void yume_endpoint_destroy(yume_endpoint* endpoint) YUME_NOEXCEPT;

/*
 * Each stream handle serializes its own operations internally, so calls on one
 * handle from several threads are safe but do not overlap: a blocking read
 * holds the handle for its whole timeout and a concurrent write on the same
 * handle waits. Use separate streams to overlap transfers.
 *
 * A stream permits one reader and one writer concurrently. Reads may be
 * partial. YUME_STATUS_EOF means the peer shut down its write side after all
 * buffered bytes were returned. Writes copy the complete input before
 * returning OK and are admitted all-or-none to bounded queues.
 */
YUME_API yume_status yume_stream_get_peer_identity(
    const yume_stream* stream,
    yume_peer_identity* out,
    size_t out_size) YUME_NOEXCEPT;
YUME_API yume_status yume_stream_read(yume_stream* stream,
                                      void* out,
                                      size_t out_size,
                                      size_t* bytes_read,
                                      uint32_t timeout_ms) YUME_NOEXCEPT;
YUME_API yume_status yume_stream_write(yume_stream* stream,
                                       const void* data,
                                       size_t size,
                                       size_t* bytes_written,
                                       uint32_t timeout_ms) YUME_NOEXCEPT;
YUME_API yume_status yume_stream_shutdown_write(yume_stream* stream,
                                                uint32_t timeout_ms)
    YUME_NOEXCEPT;
YUME_API yume_status yume_stream_close(yume_stream* stream,
                                       uint32_t timeout_ms) YUME_NOEXCEPT;
YUME_API void yume_stream_destroy(yume_stream* stream) YUME_NOEXCEPT;

/* Packet batches are all-or-none on write and preserve packet boundaries. */
YUME_API yume_status yume_packet_get_peer_identity(
    const yume_packet* packet,
    yume_peer_identity* out,
    size_t out_size) YUME_NOEXCEPT;
YUME_API yume_status yume_packet_write_batch(yume_packet* packet,
                                             const yume_packet_view* packets,
                                             size_t packet_count,
                                             size_t* packets_written,
                                             uint32_t timeout_ms) YUME_NOEXCEPT;
YUME_API yume_status yume_packet_read_batch(yume_packet* packet,
                                            void* storage,
                                            size_t storage_size,
                                            yume_packet_slot* slots,
                                            size_t slot_count,
                                            size_t* packets_read,
                                            size_t* required_storage,
                                            uint32_t timeout_ms) YUME_NOEXCEPT;
YUME_API yume_status yume_packet_close(yume_packet* packet,
                                       uint32_t timeout_ms) YUME_NOEXCEPT;
YUME_API void yume_packet_destroy(yume_packet* packet) YUME_NOEXCEPT;

/*
 * Copies a handle-scoped diagnostic. A successful operation clears the
 * handle's prior diagnostic. The function is the only ABI call allowed from
 * log/event callbacks. Pass runtime, config, endpoint, stream, or packet.
 */
YUME_API yume_status yume_handle_get_diagnostic(const void* handle,
                                                yume_diagnostic* out,
                                                size_t out_size) YUME_NOEXCEPT;

#ifdef __cplusplus
}  /* extern "C" */
#endif

#undef YUME_NOEXCEPT

#endif  /* YUME_YUME_H */
