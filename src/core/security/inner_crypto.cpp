/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/security/inner_crypto.hpp"
#include "core/security/secret_file.hpp"

#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>

#if YUME_USE_BASEFWX
#include <basefwx/constants.hpp>
#include <basefwx/crypto.hpp>
#if defined(BASEFWX_HAS_OQS) && BASEFWX_HAS_OQS
#include <oqs/oqs.h>
#endif
#endif

namespace yume::inner {

bool generate_pq_keypair(const std::string& private_path,
                         const std::string& public_path,
                         std::string* err) {
#if !YUME_USE_BASEFWX
    if (err) *err = "inner crypto not available: BaseFWX disabled";
    return false;
#else
#if !defined(BASEFWX_HAS_OQS) || !BASEFWX_HAS_OQS
    if (err) *err = "PQ not available (liboqs not enabled in BaseFWX)";
    return false;
#else
    std::string algo_str(basefwx::constants::kMasterPqAlg);
    const char* algo = algo_str.c_str();
    std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)> kem(
        OQS_KEM_new(algo), OQS_KEM_free);
    if (!kem) {
        if (err) *err = "OQS_KEM_new failed";
        return false;
    }
    Bytes pub(kem->length_public_key);
    Bytes priv(kem->length_secret_key);
    struct PrivateKeyWiper {
        Bytes& bytes;
        ~PrivateKeyWiper() { basefwx::crypto::SecureClear(bytes); }
    } private_key_wiper{priv};
    if (OQS_KEM_keypair(kem.get(), pub.data(), priv.data()) != OQS_SUCCESS) {
        if (err) *err = "OQS_KEM_keypair failed";
        return false;
    }
    if (!security::WriteFileExclusive0600(private_path, priv, err)) {
        return false;
    }
    if (!security::WriteFileExclusive0600(public_path, pub, err)) {
        std::error_code remove_error;
        std::filesystem::remove(private_path, remove_error);
        if (remove_error && err) {
            *err += "; could not remove partial private key: " +
                remove_error.message();
        }
        return false;
    }
    return true;
#endif
#endif
}

bool pq_supported() {
#if YUME_USE_BASEFWX && defined(BASEFWX_HAS_OQS) && BASEFWX_HAS_OQS
    return true;
#else
    return false;
#endif
}

}  // namespace yume::inner
