/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/security/crypto.hpp"

#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <cstring>
#include <stdexcept>

namespace yume::crypto {

namespace {
std::runtime_error ssl_error(const std::string& msg) {
    unsigned long err = ERR_get_error();
    char buf[256] = {0};
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::runtime_error(msg + ": " + buf);
}

const EVP_MD* select_digest(EVP_PKEY* key) {
    if (!key) {
        return EVP_sha256();
    }
    int type = EVP_PKEY_base_id(key);
    if (type == EVP_PKEY_ED25519 || type == EVP_PKEY_ED448) {
        return nullptr;  // EdDSA is one-shot without a digest
    }
    return EVP_sha256();
}
}  // namespace

KeyPair load_keypair(const std::string& path_priv, const std::string& path_pub) {
    KeyPair kp;

    if (!path_priv.empty()) {
        BIO* priv_bio = BIO_new_file(path_priv.c_str(), "r");
        if (!priv_bio) {
            throw ssl_error("failed to open private key");
        }
        EVP_PKEY* priv = PEM_read_bio_PrivateKey(priv_bio, nullptr, nullptr, nullptr);
        BIO_free(priv_bio);
        if (!priv) {
            throw ssl_error("failed to read private key");
        }
        kp.private_key.reset(priv);
    }

    if (!path_pub.empty()) {
        BIO* pub_bio = BIO_new_file(path_pub.c_str(), "r");
        if (!pub_bio) {
            throw ssl_error("failed to open public key");
        }
        EVP_PKEY* pub = PEM_read_bio_PUBKEY(pub_bio, nullptr, nullptr, nullptr);
        BIO_free(pub_bio);
        if (!pub) {
            throw ssl_error("failed to read public key");
        }
        kp.public_key.reset(pub);
    } else if (kp.private_key) {
        EVP_PKEY* pub = EVP_PKEY_dup(kp.private_key.get());
        if (!pub) {
            throw ssl_error("failed to derive public key from private key");
        }
        kp.public_key.reset(pub);
    }

    return kp;
}

bool verify_key(EVP_PKEY* pubkey, const Bytes& message, const Bytes& signature) {
    if (!pubkey) {
        return false;
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw ssl_error("failed to allocate verify context");
    }

    const EVP_MD* md = select_digest(pubkey);
    int rc = EVP_DigestVerifyInit(ctx, nullptr, md, nullptr, pubkey);
    if (rc != 1) {
        EVP_MD_CTX_free(ctx);
        throw ssl_error("verify init failed");
    }

    rc = EVP_DigestVerify(ctx,
                          signature.data(), signature.size(),
                          message.data(), message.size());
    EVP_MD_CTX_free(ctx);
    return rc == 1;
}

Bytes sign_message(EVP_PKEY* privkey, const Bytes& message) {
    if (!privkey) {
        throw std::runtime_error("sign_message: missing private key");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw ssl_error("failed to allocate sign context");
    }

    const EVP_MD* md = select_digest(privkey);
    int rc = EVP_DigestSignInit(ctx, nullptr, md, nullptr, privkey);
    if (rc != 1) {
        EVP_MD_CTX_free(ctx);
        throw ssl_error("sign init failed");
    }

    size_t sig_len = 0;
    rc = EVP_DigestSign(ctx, nullptr, &sig_len, message.data(), message.size());
    if (rc != 1) {
        EVP_MD_CTX_free(ctx);
        throw ssl_error("sign size failed");
    }

    Bytes sig(sig_len);
    rc = EVP_DigestSign(ctx, sig.data(), &sig_len, message.data(), message.size());
    EVP_MD_CTX_free(ctx);
    if (rc != 1) {
        throw ssl_error("sign failed");
    }
    sig.resize(sig_len);
    return sig;
}

Bytes generate_session_key(EVP_PKEY* ecdh_local, EVP_PKEY* ecdh_remote, size_t out_len) {
    if (!ecdh_local || !ecdh_remote) {
        throw std::runtime_error("generate_session_key: missing ECDH keys");
    }

    EVP_PKEY_CTX* dctx = EVP_PKEY_CTX_new(ecdh_local, nullptr);
    if (!dctx) {
        throw ssl_error("derive ctx alloc failed");
    }

    if (EVP_PKEY_derive_init(dctx) != 1) {
        EVP_PKEY_CTX_free(dctx);
        throw ssl_error("derive init failed");
    }

    if (EVP_PKEY_derive_set_peer(dctx, ecdh_remote) != 1) {
        EVP_PKEY_CTX_free(dctx);
        throw ssl_error("derive set peer failed");
    }

    size_t secret_len = 0;
    if (EVP_PKEY_derive(dctx, nullptr, &secret_len) != 1) {
        EVP_PKEY_CTX_free(dctx);
        throw ssl_error("derive size failed");
    }

    Bytes secret(secret_len);
    if (EVP_PKEY_derive(dctx, secret.data(), &secret_len) != 1) {
        EVP_PKEY_CTX_free(dctx);
        throw ssl_error("derive failed");
    }
    EVP_PKEY_CTX_free(dctx);
    secret.resize(secret_len);

    EVP_PKEY_CTX* hctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!hctx) {
        throw ssl_error("hkdf ctx alloc failed");
    }

    if (EVP_PKEY_derive_init(hctx) != 1) {
        EVP_PKEY_CTX_free(hctx);
        throw ssl_error("hkdf init failed");
    }

    if (EVP_PKEY_CTX_set_hkdf_md(hctx, EVP_sha256()) != 1) {
        EVP_PKEY_CTX_free(hctx);
        throw ssl_error("hkdf set md failed");
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(hctx, secret.data(), secret.size()) != 1) {
        EVP_PKEY_CTX_free(hctx);
        throw ssl_error("hkdf set key failed");
    }

    const char info[] = "yume-session";
    if (EVP_PKEY_CTX_add1_hkdf_info(hctx,
                                   reinterpret_cast<const unsigned char*>(info),
                                   sizeof(info) - 1) != 1) {
        EVP_PKEY_CTX_free(hctx);
        throw ssl_error("hkdf set info failed");
    }

    Bytes out(out_len);
    size_t derived_len = out_len;
    if (EVP_PKEY_derive(hctx, out.data(), &derived_len) != 1) {
        EVP_PKEY_CTX_free(hctx);
        throw ssl_error("hkdf derive failed");
    }
    EVP_PKEY_CTX_free(hctx);
    out.resize(derived_len);

    return out;
}

EVP_PKEY_ptr generate_x25519_key() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) {
        throw ssl_error("x25519 ctx alloc failed");
    }
    if (EVP_PKEY_keygen_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw ssl_error("x25519 keygen init failed");
    }
    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen(ctx, &key) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw ssl_error("x25519 keygen failed");
    }
    EVP_PKEY_CTX_free(ctx);
    return EVP_PKEY_ptr(key, EVP_PKEY_free);
}

EVP_PKEY_ptr import_x25519_public_key(const Bytes& raw_public_key) {
    EVP_PKEY* key = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519,
        nullptr,
        raw_public_key.data(),
        raw_public_key.size());
    if (!key) {
        throw ssl_error("x25519 raw public key import failed");
    }
    return EVP_PKEY_ptr(key, EVP_PKEY_free);
}

Bytes export_raw_public_key(EVP_PKEY* key) {
    if (!key) {
        throw std::runtime_error("export_raw_public_key: missing key");
    }
    size_t len = 0;
    if (EVP_PKEY_get_raw_public_key(key, nullptr, &len) != 1) {
        throw ssl_error("x25519 public key size query failed");
    }
    Bytes out(len);
    if (EVP_PKEY_get_raw_public_key(key, out.data(), &len) != 1) {
        throw ssl_error("x25519 public key export failed");
    }
    out.resize(len);
    return out;
}

Bytes hkdf_sha256(const Bytes& key_material,
                  std::string_view info,
                  size_t out_len,
                  const Bytes& salt) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!ctx) {
        throw ssl_error("hkdf ctx alloc failed");
    }
    if (EVP_PKEY_derive_init(ctx) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw ssl_error("hkdf init failed");
    }
    if (EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw ssl_error("hkdf set md failed");
    }
    if (!salt.empty() && EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), static_cast<int>(salt.size())) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw ssl_error("hkdf set salt failed");
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, key_material.data(), static_cast<int>(key_material.size())) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw ssl_error("hkdf set key failed");
    }
    if (!info.empty() &&
        EVP_PKEY_CTX_add1_hkdf_info(ctx,
                                    reinterpret_cast<const unsigned char*>(info.data()),
                                    static_cast<int>(info.size())) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw ssl_error("hkdf set info failed");
    }
    Bytes out(out_len);
    size_t derived_len = out_len;
    if (EVP_PKEY_derive(ctx, out.data(), &derived_len) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw ssl_error("hkdf derive failed");
    }
    EVP_PKEY_CTX_free(ctx);
    out.resize(derived_len);
    return out;
}

Bytes encrypt_chacha20(const Bytes& data, const Bytes& key, const Bytes& nonce) {
    if (key.size() != 32) {
        throw std::runtime_error("encrypt_chacha20: key must be 32 bytes");
    }
    if (nonce.size() != 12) {
        throw std::runtime_error("encrypt_chacha20: nonce must be 12 bytes");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw ssl_error("cipher ctx alloc failed");
    }

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw ssl_error("encrypt init failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw ssl_error("set ivlen failed");
    }

    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw ssl_error("encrypt key init failed");
    }

    Bytes out(data.size() + 16);
    int out_len = 0;
    if (EVP_EncryptUpdate(ctx, out.data(), &out_len, data.data(), data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw ssl_error("encrypt update failed");
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, out.data() + out_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw ssl_error("encrypt final failed");
    }
    out_len += final_len;

    unsigned char tag[16] = {0};
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, sizeof(tag), tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw ssl_error("get tag failed");
    }

    EVP_CIPHER_CTX_free(ctx);

    out.resize(out_len + sizeof(tag));
    std::memcpy(out.data() + out_len, tag, sizeof(tag));
    return out;
}

Bytes decrypt_chacha20(const Bytes& data, const Bytes& key, const Bytes& nonce) {
    if (key.size() != 32) {
        throw std::runtime_error("decrypt_chacha20: key must be 32 bytes");
    }
    if (nonce.size() != 12) {
        throw std::runtime_error("decrypt_chacha20: nonce must be 12 bytes");
    }
    if (data.size() < 16) {
        throw std::runtime_error("decrypt_chacha20: data too short");
    }

    const size_t cipher_len = data.size() - 16;
    const unsigned char* tag = data.data() + cipher_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw ssl_error("cipher ctx alloc failed");
    }

    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw ssl_error("decrypt init failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce.size(), nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw ssl_error("set ivlen failed");
    }

    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw ssl_error("decrypt key init failed");
    }

    Bytes out(cipher_len);
    int out_len = 0;
    if (EVP_DecryptUpdate(ctx, out.data(), &out_len, data.data(), cipher_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw ssl_error("decrypt update failed");
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<unsigned char*>(tag)) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw ssl_error("set tag failed");
    }

    int final_len = 0;
    int rc = EVP_DecryptFinal_ex(ctx, out.data() + out_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);
    if (rc != 1) {
        throw std::runtime_error("decrypt failed: authentication check failed");
    }

    out.resize(out_len + final_len);
    return out;
}

Bytes hmac_sha256(const Bytes& data, const Bytes& key) {
    unsigned int len = 0;
    Bytes out(EVP_MAX_MD_SIZE);
    unsigned char* res = HMAC(EVP_sha256(),
                              key.data(), key.size(),
                              data.data(), data.size(),
                              out.data(), &len);
    if (!res) {
        throw ssl_error("hmac failed");
    }
    out.resize(len);
    return out;
}

Bytes random_bytes(size_t len) {
    Bytes out(len);
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        throw ssl_error("rand bytes failed");
    }
    return out;
}

}  // namespace yume::crypto
