/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "core/inner_crypto.hpp"

#include <fstream>
#include <stdexcept>

#if YUME_USE_BASEFWX
#include <basefwx/crypto.hpp>
#include <basefwx/pq.hpp>
#endif

namespace yume::inner {

namespace {
constexpr const char kHkdfInfo[] = "yume-inner-v1";

Bytes read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open key file: " + path);
    }
    in.seekg(0, std::ios::end);
    std::streamoff size = in.tellg();
    if (size < 0) {
        throw std::runtime_error("failed to read key file size: " + path);
    }
    in.seekg(0, std::ios::beg);
    Bytes data(static_cast<std::size_t>(size));
    if (!data.empty()) {
        in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!in) {
            throw std::runtime_error("failed to read key file: " + path);
        }
    }
    return data;
}

Bytes load_pq_public_key(const std::string& path) {
#if !YUME_USE_BASEFWX
    (void)path;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    if (!path.empty()) {
        return basefwx::pq::DecodeKeyBytes(read_file(path));
    }
    auto pub = basefwx::pq::LoadMasterPublicKey();
    if (!pub.has_value()) {
        throw std::runtime_error("PQ public key not configured");
    }
    return *pub;
#endif
}

Bytes load_pq_private_key(const std::string& path) {
#if !YUME_USE_BASEFWX
    (void)path;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    if (!path.empty()) {
        return basefwx::pq::DecodeKeyBytes(read_file(path));
    }
    return basefwx::pq::LoadMasterPrivateKey();
#endif
}

Bytes derive_key(const Bytes& shared) {
#if !YUME_USE_BASEFWX
    (void)shared;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    return basefwx::crypto::HkdfSha256(shared, kHkdfInfo, 32);
#endif
}

Bytes build_aad(std::uint8_t frame_type, std::uint8_t stream_id) {
    Bytes aad;
    aad.reserve(6);
    aad.push_back(static_cast<std::uint8_t>('Y'));
    aad.push_back(static_cast<std::uint8_t>('U'));
    aad.push_back(static_cast<std::uint8_t>('M'));
    aad.push_back(static_cast<std::uint8_t>('E'));
    aad.push_back(frame_type);
    aad.push_back(stream_id);
    return aad;
}
}  // namespace

ClientHandshake client_prepare(const Config& cfg) {
    ClientHandshake result;
    if (!cfg.enabled) {
        return result;
    }
#if !YUME_USE_BASEFWX
    (void)cfg;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    Bytes pub = load_pq_public_key(cfg.pq_public_key);
    auto kem = basefwx::pq::KemEncrypt(pub);
    result.enabled = true;
    result.pq_ciphertext = std::move(kem.ciphertext);
    result.key = derive_key(kem.shared);
    return result;
#endif
}

std::optional<Bytes> server_derive_key(const Config& cfg, const Bytes& pq_ciphertext) {
    if (!cfg.enabled) {
        return std::nullopt;
    }
#if !YUME_USE_BASEFWX
    (void)cfg;
    (void)pq_ciphertext;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    Bytes priv = load_pq_private_key(cfg.pq_private_key);
    Bytes shared = basefwx::pq::KemDecrypt(priv, pq_ciphertext);
    return derive_key(shared);
#endif
}

Bytes encrypt_payload(const Bytes& key, std::uint8_t frame_type, std::uint8_t stream_id, const Bytes& plaintext) {
#if !YUME_USE_BASEFWX
    (void)key;
    (void)frame_type;
    (void)stream_id;
    (void)plaintext;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    return basefwx::crypto::AeadEncrypt(key, plaintext, build_aad(frame_type, stream_id));
#endif
}

Bytes decrypt_payload(const Bytes& key, std::uint8_t frame_type, std::uint8_t stream_id, const Bytes& blob) {
#if !YUME_USE_BASEFWX
    (void)key;
    (void)frame_type;
    (void)stream_id;
    (void)blob;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    return basefwx::crypto::AeadDecrypt(key, blob, build_aad(frame_type, stream_id));
#endif
}

}  // namespace yume::inner
