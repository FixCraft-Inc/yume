/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "yume/yume.h"

#include "core/security/inner_crypto.hpp"
#include "core/version.hpp"

#include <cstring>
#include <string>

namespace {

const char* basefwx_version_string() {
    static const std::string value(yume::kBasefwxVersion);
    return value.c_str();
}

const char* pq_backend_string() {
    static const std::string value = yume::inner::pq_backend_version();
    return value.c_str();
}

const char* argon2_backend_string() {
    static const std::string value = yume::inner::argon2_backend_version();
    return value.c_str();
}

}  // namespace

extern "C" {

uint32_t yume_abi_version(void) {
    return YUME_ABI_VERSION;
}

const char* yume_version(void) {
    return yume::kVersion;
}

uint32_t yume_feature_flags(void) {
    uint32_t flags = YUME_FEATURE_PBKDF2_HKDF;
#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
    flags |= YUME_FEATURE_BASEFWX;
#endif
    try {
        if (yume::inner::pq_supported()) {
            flags |= YUME_FEATURE_PQ_MLKEM768;
        }
        if (yume::inner::argon2_supported()) {
            flags |= YUME_FEATURE_ARGON2ID;
        }
    } catch (...) {
        return flags;
    }
    return flags;
}

const char* yume_basefwx_version(void) {
    try {
        return basefwx_version_string();
    } catch (...) {
        return "unknown";
    }
}

const char* yume_pq_backend(void) {
    try {
        return pq_backend_string();
    } catch (...) {
        return "unavailable";
    }
}

const char* yume_argon2_backend(void) {
    try {
        return argon2_backend_string();
    } catch (...) {
        return "unavailable";
    }
}

int yume_get_build_info(yume_build_info* out, size_t out_size) {
    if (!out) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (out_size < sizeof(yume_build_info)) {
        return YUME_STATUS_BUFFER_TOO_SMALL;
    }

    try {
        std::memset(out, 0, sizeof(yume_build_info));
        out->struct_size = sizeof(yume_build_info);
        out->abi_version = yume_abi_version();
        out->feature_flags = yume_feature_flags();
        out->yume_version = yume_version();
        out->basefwx_version = yume_basefwx_version();
        out->pq_backend = yume_pq_backend();
        out->argon2_backend = yume_argon2_backend();
        return YUME_STATUS_OK;
    } catch (...) {
        return YUME_STATUS_INTERNAL_ERROR;
    }
}

}  // extern "C"
