/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
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
extern "C" {
#endif

#define YUME_ABI_VERSION 1u

#define YUME_STATUS_OK 0
#define YUME_STATUS_INVALID_ARGUMENT -1
#define YUME_STATUS_BUFFER_TOO_SMALL -2
#define YUME_STATUS_INTERNAL_ERROR -3
#define YUME_STATUS_NOT_RUNNING -4
#define YUME_STATUS_ALREADY_RUNNING -5
#define YUME_STATUS_TIMEOUT -6
#define YUME_STATUS_NOT_FOUND -7
#define YUME_STATUS_PERMISSION_DENIED -8
#define YUME_STATUS_PARSE_ERROR -9

#define YUME_FEATURE_BASEFWX 0x00000001u
#define YUME_FEATURE_PQ_MLKEM768 0x00000002u
#define YUME_FEATURE_ARGON2ID 0x00000004u
#define YUME_FEATURE_PBKDF2_HKDF 0x00000008u

typedef struct yume_build_info {
    size_t struct_size;
    uint32_t abi_version;
    uint32_t feature_flags;
    const char* yume_version;
    const char* basefwx_version;
    const char* pq_backend;
    const char* argon2_backend;
} yume_build_info;

typedef struct yume_client yume_client;
typedef struct yume_server yume_server;
typedef struct yume_stream yume_stream;

/*
 * ABI conventions:
 * - All handles are opaque and owned by the caller.
 * - Destroy functions accept NULL.
 * - JSON output helpers write a NUL-terminated string to caller-owned memory.
 *   Pass a too-small buffer to receive YUME_STATUS_BUFFER_TOO_SMALL and the
 *   required byte count, including the trailing NUL, in *needed.
 * - Timeout values are milliseconds. A timeout of 0 means poll/no wait for
 *   stream open, accept, and read calls.
 * - Last-error strings are per handle and remain valid until the next
 *   yume_handle_last_error call on the same thread.
 */

YUME_API uint32_t yume_abi_version(void);
YUME_API const char* yume_version(void);
YUME_API uint32_t yume_feature_flags(void);
YUME_API const char* yume_basefwx_version(void);
YUME_API const char* yume_pq_backend(void);
YUME_API const char* yume_argon2_backend(void);
YUME_API int yume_get_build_info(yume_build_info* out, size_t out_size);
YUME_API const char* yume_strerror(int status);

YUME_API yume_client* yume_client_create(void);
YUME_API void yume_client_destroy(yume_client* client);
YUME_API int yume_client_start_json(yume_client* client,
                                    const char* config_json,
                                    const char* base_dir,
                                    uint32_t timeout_ms);
YUME_API int yume_client_start_file(yume_client* client,
                                    const char* config_path,
                                    uint32_t timeout_ms);
YUME_API int yume_client_stop(yume_client* client);
YUME_API int yume_client_status_json(yume_client* client,
                                     char* out,
                                     size_t out_size,
                                     size_t* needed);
YUME_API int yume_client_request_json(yume_client* client,
                                      const char* op,
                                      const char* args_json,
                                      char* out,
                                      size_t out_size,
                                      size_t* needed,
                                      uint32_t timeout_ms);
YUME_API int yume_client_open_stream(yume_client* client,
                                     const char* service,
                                     uint32_t timeout_ms,
                                     yume_stream** out_stream);

YUME_API yume_server* yume_server_create(void);
YUME_API void yume_server_destroy(yume_server* server);
YUME_API int yume_server_start_json(yume_server* server,
                                    const char* config_json,
                                    const char* base_dir);
YUME_API int yume_server_start_file(yume_server* server,
                                    const char* config_path);
YUME_API int yume_server_stop(yume_server* server);
YUME_API int yume_server_status_json(yume_server* server,
                                     char* out,
                                     size_t out_size,
                                     size_t* needed);
YUME_API int yume_server_sessions_json(yume_server* server,
                                       char* out,
                                       size_t out_size,
                                       size_t* needed);
YUME_API int yume_server_register_service(yume_server* server,
                                          const char* service);
YUME_API int yume_server_accept_stream(yume_server* server,
                                       const char* service,
                                       uint32_t timeout_ms,
                                       yume_stream** out_stream);

/*
 * Writes stream metadata JSON. Server-accepted streams include
 * auth_fingerprint_sha256, the authenticated client's Ed25519 SPKI SHA-256
 * fingerprint, which embedders should use for device binding.
 */
YUME_API int yume_stream_peer_json(yume_stream* stream,
                                   char* out,
                                   size_t out_size,
                                   size_t* needed);
YUME_API int yume_stream_read(yume_stream* stream,
                              void* out,
                              size_t out_size,
                              size_t* bytes_read,
                              uint32_t timeout_ms);
YUME_API int yume_stream_write(yume_stream* stream,
                               const void* data,
                               size_t size,
                               size_t* bytes_written,
                               uint32_t timeout_ms);
YUME_API int yume_stream_shutdown_write(yume_stream* stream);
YUME_API int yume_stream_close(yume_stream* stream);
YUME_API void yume_stream_destroy(yume_stream* stream);

YUME_API const char* yume_handle_last_error(const void* handle);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* YUME_YUME_H */
