/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "core/inner_crypto.hpp"

#include <fstream>
#include <stdexcept>
#include <filesystem>

#if !defined(_WIN32)
#include <sys/stat.h>
#endif

#if YUME_USE_BASEFWX
#include <basefwx/crypto.hpp>
#include <basefwx/pq.hpp>
#include <basefwx/constants.hpp>
#if defined(BASEFWX_HAS_OQS) && BASEFWX_HAS_OQS
#include <oqs/oqs.h>
#endif
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

bool write_file_bytes(const std::string& path, const Bytes& data, std::string* err) {
    try {
        std::filesystem::path p(path);
        if (p.has_parent_path()) {
            std::error_code ec;
            std::filesystem::create_directories(p.parent_path(), ec);
        }
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            if (err) *err = "failed to open file: " + path;
            return false;
        }
        if (!data.empty()) {
            out.write(reinterpret_cast<const char*>(data.data()),
                      static_cast<std::streamsize>(data.size()));
            if (!out) {
                if (err) *err = "failed to write file: " + path;
                return false;
            }
        }
        out.close();
        if (!out) {
            if (err) *err = "failed to flush file: " + path;
            return false;
        }
#if !defined(_WIN32)
        if (path.find(".key") != std::string::npos) {
            ::chmod(path.c_str(), 0600);
        } else {
            ::chmod(path.c_str(), 0644);
        }
#endif
        return true;
    } catch (const std::exception& ex) {
        if (err) *err = ex.what();
        return false;
    }
}

Bytes derive_key(const Bytes& shared) {
#if !YUME_USE_BASEFWX
    (void)shared;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    return basefwx::crypto::HkdfSha256(shared, kHkdfInfo, 32);
#endif
}

Bytes derive_key_heavy(const Bytes& shared, const Bytes& salt) {
#if !YUME_USE_BASEFWX
    (void)shared;
    (void)salt;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
#if defined(BASEFWX_HAS_ARGON2) && BASEFWX_HAS_ARGON2
    std::string password(reinterpret_cast<const char*>(shared.data()), shared.size());
    return basefwx::crypto::Argon2idHashRaw(password,
                                           salt,
                                           basefwx::constants::kHeavyArgon2TimeCost,
                                           basefwx::constants::kHeavyArgon2MemoryCost,
                                           basefwx::constants::DefaultHeavyArgon2Parallelism(),
                                           32);
#else
    Bytes material = basefwx::crypto::HmacSha256(salt, shared);
    return basefwx::crypto::HkdfSha256(material, kHkdfInfo, 32);
#endif
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
    OQS_KEM* kem = OQS_KEM_new(algo);
    if (!kem) {
        if (err) *err = "OQS_KEM_new failed";
        return false;
    }
    Bytes pub(kem->length_public_key);
    Bytes priv(kem->length_secret_key);
    if (OQS_KEM_keypair(kem, pub.data(), priv.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        if (err) *err = "OQS_KEM_keypair failed";
        return false;
    }
    OQS_KEM_free(kem);
    if (!write_file_bytes(private_path, priv, err)) {
        return false;
    }
    if (!write_file_bytes(public_path, pub, err)) {
        return false;
    }
    return true;
#endif
#endif
}

ClientHandshake client_prepare(const Config& cfg, bool heavy) {
    ClientHandshake result;
    if (!cfg.enabled) {
        return result;
    }
#if !YUME_USE_BASEFWX
    (void)cfg;
    (void)heavy;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    Bytes pub = load_pq_public_key(cfg.pq_public_key);
    auto kem = basefwx::pq::KemEncrypt(pub);
    result.enabled = true;
    result.pq_ciphertext = std::move(kem.ciphertext);
    result.salt = basefwx::crypto::RandomBytes(basefwx::constants::kUserKdfSaltSize);
    result.key = heavy ? derive_key_heavy(kem.shared, result.salt) : derive_key(kem.shared);
    return result;
#endif
}

std::optional<Bytes> server_derive_key(const Config& cfg, const Bytes& pq_ciphertext, const Bytes& salt, bool heavy) {
    if (!cfg.enabled) {
        return std::nullopt;
    }
#if !YUME_USE_BASEFWX
    (void)cfg;
    (void)pq_ciphertext;
    (void)salt;
    (void)heavy;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    Bytes priv = load_pq_private_key(cfg.pq_private_key);
    Bytes shared = basefwx::pq::KemDecrypt(priv, pq_ciphertext);
    return heavy ? derive_key_heavy(shared, salt) : derive_key(shared);
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
