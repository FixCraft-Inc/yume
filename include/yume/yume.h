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

#define YUME_MAX_VERSION_TEXT 32u
#define YUME_MAX_PROVIDER_NAME 32u
#define YUME_MAX_SUITE_NAME 48u
#define YUME_MAX_PROFILE_NAME 64u
#define YUME_MAX_SERVICE_NAME 128u
#define YUME_MAX_IDENTITY_TEXT 96u
#define YUME_MAX_DIAGNOSTIC_TEXT 512u
#define YUME_MAX_JSON_POINTER 256u
#define YUME_MAX_MESSAGE_TEXT 512u
#define YUME_MESSAGE_INSTANCE_TEXT 17u

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
    YUME_EVENT_ENDPOINT_STATE = 1
};

/* A client's session. An endpoint with a device keeps its session up, so it
 * reports CONNECTING and WAITING between sessions. One without makes one
 * attempt per start and reports ENDED once its session has ended. */
enum {
    YUME_SESSION_NONE = 0,
    YUME_SESSION_ACTIVE = 1,
    YUME_SESSION_ENDED = 2,
    YUME_SESSION_CONNECTING = 3,
    YUME_SESSION_WAITING = 4
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
typedef struct yume_kit yume_kit;

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
    uint8_t composite_fingerprint_sha256[32];
    /* Opaque transport-level label for the authenticated peer. YUME assigns
     * it no application meaning: it is not a device, account, user, or
     * enrollment record. An embedder that needs those concepts owns them. */
    char peer_label[YUME_MAX_IDENTITY_TEXT];
    char service[YUME_MAX_SERVICE_NAME + 1u];
} yume_peer_identity;

#define YUME_PEER_IDENTITY_MIN_SIZE offsetof(yume_peer_identity, peer_label)

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
typedef void (*yume_event_callback)(const yume_event* event,
                                    void* user_data);

typedef struct yume_runtime_options {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t max_pending_callbacks;
    yume_event_callback event_callback;
    void* callback_user_data;
    /* Directory that relative credential paths inside a configuration
     * document resolve against. The ABI receives configuration as bytes, not
     * as a file, so there is no document location to infer one from. NULL
     * selects the process working directory, which is rarely what an embedded
     * host wants: pass an explicit directory, or use absolute paths. */
    const char* config_base_dir;
    /* Absolute path of a resolver helper program, which client endpoints
     * start to look up a server host that is a name. The yume-resolver
     * program installed with the SDK serves this role, and pkg-config and CMake
     * package metadata name its location. The file must be owned by root or
     * the effective user and must not be writable by group or others. NULL
     * leaves names unresolvable: such an endpoint fails to start, while a
     * numeric host or endpoint.connect_address never needs the helper. Name
     * lookup runs in that separate process so stopping an endpoint never waits
     * for a system lookup that does not return. */
    const char* resolver_program;
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

/*
 * A point-in-time view of one endpoint. It holds no key, credential or
 * payload. The session, identity and traffic fields describe a client and
 * are zero for a server.
 */
typedef struct yume_endpoint_status {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t role;
    uint32_t state;
    /* One of YUME_SESSION_*. */
    uint32_t session;
    /* The latest failed start, failed attempt or ended session of this
     * handle, or YUME_STATUS_OK when there has been none. A later success
     * does not clear it. Stopping and a cancelled start record nothing. */
    yume_status last_failure;
    /* The session's key epoch while it is active, otherwise 0. */
    uint32_t epoch_bytes;
    /* How long the active session has been up, otherwise 0. */
    uint64_t connected_ms;
    /* While YUME_SESSION_WAITING: the delay before the next attempt. */
    uint64_t retry_ms;
    /* Sessions authenticated since the endpoint last started, and failed
     * attempts since the latest of them. */
    uint64_t sessions;
    uint32_t failed_attempts;
    uint32_t idle_epoch_rotation;
    /* Totals over every session of this endpoint handle. */
    uint64_t payload_bytes_sent;
    uint64_t payload_bytes_received;
    uint64_t record_bytes_sent;
    uint64_t record_bytes_received;
    /* With idle_epoch_rotation above: the configuration's limits that a
     * tuning preset sets. */
    uint32_t max_queued_bytes;
    uint32_t max_epoch_bytes;
    uint32_t credit_returns_per_window;
    /* With a device: what its bridge carries now. */
    uint32_t device_tcp_connections;
    uint32_t device_udp_destinations;
    uint32_t reserved;
    /* The server's verified composite fingerprint while the session is
     * active, otherwise zero bytes. */
    uint8_t peer_fingerprint_sha256[32];
    char last_failure_message[YUME_MAX_DIAGNOSTIC_TEXT];
} yume_endpoint_status;

#define YUME_ENDPOINT_STATUS_MIN_SIZE \
    offsetof(yume_endpoint_status, peer_fingerprint_sha256)

/*
 * A TUN device the application owns, whose traffic a client endpoint carries
 * as one stream OPEN per TCP connection and one packet OPEN per UDP
 * destination. The descriptor reads and writes whole IP packets without a
 * packet-information header. The library duplicates it and sets it
 * non-blocking, which also applies to the caller's copy.
 *
 * Each address pair is the device's own address and a second address that
 * routes to the device and nothing else uses, as IP literals. An empty IPv6
 * pair drops IPv6, an empty packet service drops UDP, and at least one
 * address family is required.
 */
typedef struct yume_device_options {
    size_t struct_size;
    uint32_t abi_version;
    int32_t descriptor;
    uint32_t mtu;
    uint32_t reserved;
    yume_string_view stream_service;
    yume_string_view packet_service;
    yume_string_view ipv4_address;
    yume_string_view ipv4_peer;
    yume_string_view ipv6_address;
    yume_string_view ipv6_peer;
} yume_device_options;

#define YUME_DEVICE_OPTIONS_MIN_SIZE sizeof(yume_device_options)

/* One line an endpoint has said about its lifecycle. */
typedef struct yume_message {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t reserved;
    /* Numbered from 1 in order, or 0 when no line was returned. */
    uint64_t seq;
    /* Lines numbered above the caller's `after` and below seq that the
     * endpoint no longer keeps. */
    uint64_t missed;
    /* Milliseconds since the Unix epoch, UTC. */
    int64_t time_unix_ms;
    /* 16 hexadecimal digits that change when numbering starts again at 1. */
    char instance[YUME_MESSAGE_INSTANCE_TEXT];
    char text[YUME_MAX_MESSAGE_TEXT + 1u];
} yume_message;

#define YUME_MESSAGE_MIN_SIZE offsetof(yume_message, text)

/* One file of an opened kit. path and data point into the kit and stay valid
 * until yume_kit_destroy(). */
typedef struct yume_kit_file {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t executable;
    yume_string_view path;
    const void* data;
    size_t size;
} yume_kit_file;

#define YUME_KIT_FILE_MIN_SIZE sizeof(yume_kit_file)

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
 * Runtime owns callback delivery and coordinates cancellation of child
 * endpoints; a selected transport backend owns its own execution resources.
 * Runtime destroy requests cancellation and waits for its child endpoints.
 * Child handle storage remains caller-owned and must still be destroyed.
 * Callers must not race a destroy function with another call using that same
 * handle, use a handle after destroy, or pass an output-handle pointer that
 * aliases an input object or handle.
 */
YUME_API yume_status yume_runtime_create(const yume_runtime_options* options,
                                         yume_runtime** out_runtime)
    YUME_NOEXCEPT;
YUME_API void yume_runtime_destroy(yume_runtime* runtime) YUME_NOEXCEPT;

/*
 * Parsing is strict and copies the complete input. The returned config is
 * immutable, role-tagged, and independent of the input buffer. Unknown keys,
 * inline private material, provider mismatch, and unsafe combinations fail
 * with a diagnostic.
 *
 * The document is configuration schema 1. It must state "role" and
 * "schema": 1, and it has no key aliases.
 *
 * A refused document reports YUME_STATUS_PARSE_ERROR with an RFC 6901 JSON
 * pointer for a failure attributable to one member, and an empty pointer when
 * the failure belongs to no single member, such as malformed JSON or a
 * document-wide validation failure. Input over 1 MiB reports
 * YUME_STATUS_RESOURCE_EXHAUSTED.
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
/* Attaches a device to a client endpoint, or detaches it with null options.
 * Accepted while the endpoint is CREATED or STOPPED. The device stays
 * attached across stop and start, and the bridge runs while the endpoint is
 * RUNNING. An endpoint with a device keeps its session up: after a start
 * that succeeded it replaces a lost session itself, as yume does, until it
 * is stopped. A server returns UNSUPPORTED and an undeclared service
 * NOT_FOUND. docs/ABI.md, "Device bridge", describes what crosses and its
 * bounds. */
YUME_API yume_status yume_endpoint_set_device(
    yume_endpoint* endpoint, const yume_device_options* options) YUME_NOEXCEPT;
/* Lifecycle timeouts are operation-specific while this ABI is experimental.
 * Client start accepts a finite millisecond deadline, and zero selects its
 * 30 s default. Server start, endpoint stop, and stream/packet close accept
 * only zero because they have no caller-bounded deadline.
 * A stop or destroy on another thread cancels a client start in progress:
 * the start returns YUME_STATUS_CANCELLED and leaves the endpoint STOPPED.
 * Only server endpoints register services. Registrations are made while
 * stopped, must match the immutable configuration, and remain attached across
 * stop and restart.
 * Start is accepted only from CREATED or STOPPED. After a start failure leaves
 * FAILED, call stop(endpoint, 0) to reach STOPPED before retrying. Clearing the
 * external cause alone does not permit a restart from FAILED.
 * Listener setup returns PERMISSION_DENIED for OS permission refusal,
 * INVALID_STATE for an occupied address, INVALID_ARGUMENT for an unavailable
 * local address, RESOURCE_EXHAUSTED for socket resource exhaustion, and
 * IO_ERROR for an otherwise unclassified socket failure. */
YUME_API yume_status yume_endpoint_start(yume_endpoint* endpoint,
                                         uint32_t timeout_ms) YUME_NOEXCEPT;
YUME_API yume_status yume_endpoint_stop(yume_endpoint* endpoint,
                                        uint32_t timeout_ms) YUME_NOEXCEPT;
YUME_API uint32_t yume_endpoint_state(const yume_endpoint* endpoint)
    YUME_NOEXCEPT;

/*
 * Status and messages never wait for a lifecycle call, so both may be read
 * from another thread while a start is in progress. From a callback they
 * return YUME_STATUS_INVALID_STATE.
 *
 * yume_endpoint_read_message copies the oldest kept line numbered above
 * `after`. With none it returns YUME_STATUS_WOULD_BLOCK, seq 0 and the
 * instance. An endpoint keeps its latest 256 lines, each cut to
 * YUME_MAX_MESSAGE_TEXT bytes.
 */
YUME_API yume_status yume_endpoint_get_status(const yume_endpoint* endpoint,
                                              yume_endpoint_status* out,
                                              size_t out_size) YUME_NOEXCEPT;
YUME_API yume_status yume_endpoint_read_message(const yume_endpoint* endpoint,
                                                uint64_t after,
                                                yume_message* out,
                                                size_t out_size) YUME_NOEXCEPT;
/* An endpoint with a device that is waiting to retry starts that attempt
 * now, for an application that learns the network is back. At most one per
 * second takes effect. INVALID_STATE unless the endpoint is RUNNING and has
 * a device. */
YUME_API yume_status yume_endpoint_retry_now(yume_endpoint* endpoint)
    YUME_NOEXCEPT;

/* Clients open a named byte service, optionally with a TCP hostname,
 * IPv4 or IPv6 destination. The server must expose that service through its
 * direct TCP adapter; it resolves hostnames and authorizes every result.
 * Application-accepted named services refuse destination-routed OPENs.
 * Destination and service bytes are copied during the call, including when
 * timeout or cancellation leaves an OPEN settling on the endpoint runner. */
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
 * A stream permits one active reader and one active writer concurrently. The
 * caller must not overlap two operations in the same direction; write-side
 * shutdown is a write-direction operation. A blocking read does not prevent a
 * write or write-side shutdown on another thread. Reads may be partial.
 * YUME_STATUS_EOF means the peer shut down its write side after all buffered
 * bytes were returned. Writes copy the complete input before returning OK and
 * are admitted all-or-none to bounded queues. A single write larger than
 * 256 KiB fails with YUME_STATUS_INVALID_ARGUMENT.
 * For open, accept, read, write, and write-side shutdown, zero polls without
 * waiting and a positive value is a finite relative deadline in milliseconds.
 * A zero-timeout client OPEN returns WOULD_BLOCK without sending OPEN.
 * Once write shutdown is queued, WOULD_BLOCK/TIMEOUT may leave it
 * pending. Retry shutdown to observe completion; later writes are refused.
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

/*
 * Packet channels support named services and destination-routed UDP.
 * Only clients open and only servers accept; a server registers a named packet
 * service before start.
 *
 * A channel permits one reader and one writer concurrently; close cancels
 * both directions without waiting for either application's deadline. Callers
 * must not overlap operations in one direction or race destroy with any call
 * on the same handle. A channel may outlive endpoint stop/destroy; I/O then
 * returns CLOSED and the caller still destroys the channel handle.
 *
 * Writes copy and admit the entire batch or none, preserving packet boundaries.
 * A batch has 1..256 packets, each with 1..65535 bytes, and at most 16 MiB total.
 * limits.max_packet_batch can set a lower count bound; writes above it return
 * RESOURCE_EXHAUSTED and reads return at most that many packets per call.
 * The negotiated channel record bound can be smaller than 65535; a larger
 * packet returns INVALID_ARGUMENT without fragmenting or admitting the batch.
 * Packet delivery remains subject to later channel or session failure.
 *
 * Reads copy as many complete queued packets as fit the storage and slots.
 * If the first packet does not fit, BUFFER_TOO_SMALL leaves it queued and sets
 * required_storage to that packet's size. Later packets are never skipped.
 * Other results set required_storage to zero; unused slots remain untouched.
 * EOF reports authenticated peer write shutdown after queued packets are read.
 * Zero polls; a positive timeout is a relative deadline in milliseconds.
 * A zero-timeout client OPEN returns WOULD_BLOCK without sending OPEN.
 */
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
 * Opens a sealed kit (docs/protocol/SEALED_KIT_1.md) in memory. `code` is
 * the 25-character code as the user typed it, with or without separators,
 * and is not kept. The call derives a key with Argon2id over 64 MiB, so it
 * takes a noticeable time.
 *
 * YUME_STATUS_PERMISSION_DENIED means a wrong code or a file that is not a
 * sealed kit, which cannot be told apart. YUME_STATUS_PARSE_ERROR means the
 * code opened the file but its content is not a valid kit,
 * YUME_STATUS_INVALID_ARGUMENT a missing pointer, an empty file or a code
 * that is not 25 code characters, and YUME_STATUS_RESOURCE_EXHAUSTED a file
 * larger than a sealed kit can be. A failure publishes no handle and leaves
 * its text as the runtime's diagnostic.
 *
 * Files come in path order and yume.json is always present. The kit's layout
 * is validated, its configuration is not. yume_kit_get_file returns
 * YUME_STATUS_NOT_FOUND for an index at or above yume_kit_file_count.
 * yume_kit_destroy wipes the files and accepts null.
 */
YUME_API yume_status yume_kit_open(yume_runtime* runtime, const void* sealed,
                                   size_t sealed_size, const char* code,
                                   size_t code_size,
                                   yume_kit** out_kit) YUME_NOEXCEPT;
YUME_API size_t yume_kit_file_count(const yume_kit* kit) YUME_NOEXCEPT;
YUME_API yume_status yume_kit_get_file(const yume_kit* kit, size_t index,
                                       yume_kit_file* out,
                                       size_t out_size) YUME_NOEXCEPT;
YUME_API void yume_kit_destroy(yume_kit* kit) YUME_NOEXCEPT;

/*
 * Copies a handle-scoped diagnostic. A successful operation clears the
 * handle's prior diagnostic. Event callbacks may call this function and the
 * global version, build, compatibility and status-info queries. Endpoint
 * state returns 0 in a callback; endpoint status and message queries return
 * YUME_STATUS_INVALID_STATE. Pass runtime, config, endpoint, stream, packet,
 * or kit.
 */
YUME_API yume_status yume_handle_get_diagnostic(const void* handle,
                                                yume_diagnostic* out,
                                                size_t out_size) YUME_NOEXCEPT;

#ifdef __cplusplus
}  /* extern "C" */
#endif

#undef YUME_NOEXCEPT

#endif  /* YUME_YUME_H */
