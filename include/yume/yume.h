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

YUME_API uint32_t yume_abi_version(void);
YUME_API const char* yume_version(void);
YUME_API uint32_t yume_feature_flags(void);
YUME_API const char* yume_basefwx_version(void);
YUME_API const char* yume_pq_backend(void);
YUME_API const char* yume_argon2_backend(void);
YUME_API int yume_get_build_info(yume_build_info* out, size_t out_size);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif  /* YUME_YUME_H */
