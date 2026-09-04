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

// liboqs is YUME's own dependency, discovered and linked by YUME's CMake
// (target yume_liboqs). It is deliberately NOT reached through BaseFWX's
// PUBLIC link interface and NOT gated on BaseFWX's BASEFWX_HAS_OQS build
// macro. The calls below are YUME's own, so a BaseFWX build that leaves
// liboqs out must not disable them, and the reverse holds too.
#if defined(YUME_HAS_OQS) && YUME_HAS_OQS
#include <oqs/oqs.h>
#endif

// BaseFWX still owns the wiping primitive used for the private key.
#if YUME_USE_BASEFWX
#include <basefwx/crypto.hpp>
#endif

namespace yume::inner {

#if defined(YUME_HAS_OQS) && YUME_HAS_OQS
namespace {

// YUME's protocol decision, not BaseFWX's. facade/keys/keys.cpp labels the
// result "ml-kem-768". Taking the name from basefwx::constants::kMasterPqAlg
// (BaseFWX's .yss master-escrow algorithm) would let a BaseFWX-side change
// silently switch the algorithm YUME generates while the label stayed put.
constexpr const char* kInnerKemAlgorithm = OQS_KEM_alg_ml_kem_768;

}  // namespace
#endif

bool generate_pq_keypair(const std::string& private_path,
                         const std::string& public_path,
                         std::string* err) {
#if !defined(YUME_HAS_OQS) || !YUME_HAS_OQS
    (void)private_path;
    (void)public_path;
    if (err) *err = "PQ not available (YUME was built without liboqs)";
    return false;
#elif !YUME_USE_BASEFWX
    (void)private_path;
    (void)public_path;
    // The private key must never outlive this call in unwiped memory, and the
    // wiping primitive is BaseFWX's. Fail closed rather than write a key out
    // of a buffer nothing clears.
    if (err) *err = "PQ not available (YUME was built without BaseFWX)";
    return false;
#else
    std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)> kem(
        OQS_KEM_new(kInnerKemAlgorithm), OQS_KEM_free);
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
}

bool pq_supported() {
#if defined(YUME_HAS_OQS) && YUME_HAS_OQS && YUME_USE_BASEFWX
    return true;
#else
    return false;
#endif
}

}  // namespace yume::inner
