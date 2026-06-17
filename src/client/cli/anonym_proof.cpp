/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/cli/anonym_proof.hpp"

#include <algorithm>
#include <cstdlib>
#include <ctime>
#include <string>
#include <string_view>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include "client/cli/cert.hpp"
#include "client/cli/diagnostics.hpp"
#include "core/protocol/runtime_policy.hpp"
#include "util.hpp"

namespace yume::client {
namespace {

constexpr const char kAnonMsgPrefix[] = "YUME-ANON-V1:";
constexpr const char kFixcraftAnonymPubPem[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAtupzLhANnB0VxP51vB/7yYwR+/3/jv4Str9MGLGA+is=\n"
    "-----END PUBLIC KEY-----\n";

void fail(AnonymProofResult* result, std::string detail) {
    result->error_lines.push_back("CRITICAL ERROR");
    result->error_lines.push_back(std::move(detail));
}

bool has_source(const std::vector<std::string>& sources, std::string_view source) {
    return std::find(sources.begin(), sources.end(), std::string(source)) != sources.end();
}

crypto::EVP_PKEY_ptr load_fixcraft_pubkey(const std::string& override_path) {
    if (!override_path.empty()) {
        auto kp = crypto::load_keypair("", override_path);
        return {kp.public_key.release(), EVP_PKEY_free};
    }

    BIO* bio = BIO_new_mem_buf(kFixcraftAnonymPubPem, -1);
    if (!bio) {
        return {nullptr, EVP_PKEY_free};
    }
    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return {key, EVP_PKEY_free};
}

bool verify_signature(EVP_PKEY* key,
                      const crypto::Bytes& message,
                      const std::string& signature_b64,
                      const char* invalid_format_error,
                      const char* invalid_signature_error,
                      AnonymProofResult* result) {
    std::string signature_raw = util::base64_decode(signature_b64);
    if (signature_raw.empty()) {
        fail(result, invalid_format_error);
        return false;
    }
    crypto::Bytes signature(signature_raw.begin(), signature_raw.end());
    if (!crypto::verify_key(key, message, signature)) {
        fail(result, invalid_signature_error);
        return false;
    }
    return true;
}

}  // namespace

AnonymProofResult verify_anonym_proof(const AnonymProofInput& input) {
    AnonymProofResult result;
    result.sub_ok = input.initial_sub_ok;
    result.ca_ok = input.initial_ca_ok;

    const bool fixcraft_present =
        has_source(input.announced_proof_sources, yume::policy::kAnonymProofSourceFixcraft) ||
        !input.sig.empty();
    const bool ca_present =
        has_source(input.announced_proof_sources, yume::policy::kAnonymProofSourceCa) ||
        !input.ca_sig.empty();
    const bool sub_present =
        has_source(input.announced_proof_sources, yume::policy::kAnonymProofSourceSubCa) ||
        !input.sub_sig.empty() || !input.sub_cert_b64.empty();

    if (input.hash.empty() || input.ts.empty() || input.nonce.empty()) {
        fail(&result, "ANONYM PROOF IS INCOMPLETE");
        return result;
    }
    if (input.certfp.empty()) {
        fail(&result, "ANONYM PROOF MISSING CERTIFICATE FINGERPRINT");
        return result;
    }

    long long ts_val = 0;
    try {
        ts_val = std::stoll(input.ts);
    } catch (...) {
        fail(&result, "INVALID TIMESTAMP IN ANONYM PROOF");
        return result;
    }
    const long long now = static_cast<long long>(std::time(nullptr));
    if (std::llabs(now - ts_val) > yume::policy::kAnonymProofWindowSeconds) {
        fail(&result, "ANONYM PROOF EXPIRED OR NOT YET VALID");
        return result;
    }
    if (!input.peer_cert_fingerprint.empty() && input.certfp != input.peer_cert_fingerprint) {
        fail(&result, "ANONYM CERTIFICATE FINGERPRINT MISMATCH");
        return result;
    }

    const std::string message =
        std::string(kAnonMsgPrefix) + input.hash + ":" + input.ts + ":" + input.nonce + ":" + input.certfp;
    crypto::Bytes message_bytes(message.begin(), message.end());

    if (fixcraft_present) {
        if (input.sig.empty()) {
            fail(&result, "FIXCRAFT SIGNATURE MISSING");
            return result;
        }
        crypto::EVP_PKEY_ptr pubkey = load_fixcraft_pubkey(input.anonym_pubkey);
        if (!pubkey) {
            fail(&result, "FAILED TO LOAD EMBEDDED ANONYM PUBLIC KEY");
            return result;
        }
        if (!verify_signature(pubkey.get(),
                              message_bytes,
                              input.sig,
                              "INVALID SIGNATURE FORMAT FROM SERVER",
                              "server anonym proof signature verification failed; treat this server as untrusted and report it",
                              &result)) {
            return result;
        }
        result.fixcraft_ok = true;
        add_verified_source(&result.verified_proof_sources, yume::policy::kAnonymProofSourceFixcraft);
    }

    if (sub_present) {
        if (input.anonym_ca_cert.empty()) {
            fail(&result, "ANONYM SUB CERT PROVIDED BUT NO --anonym-ca-cert SET");
            return result;
        }
        if (input.sub_cert_b64.empty()) {
            fail(&result, "ANONYM SUB CERT MISSING");
            return result;
        }
        if (input.sub_sig.empty()) {
            fail(&result, "ANONYM SUB SIGNATURE MISSING");
            return result;
        }
        const std::string sub_pem = util::base64_decode(input.sub_cert_b64);
        auto sub_cert = load_cert_from_pem(sub_pem);
        if (!sub_cert) {
            fail(&result, "FAILED TO PARSE ANONYM SUB CERT");
            return result;
        }
        auto ca_cert = load_cert_from_file(input.anonym_ca_cert);
        if (!ca_cert) {
            fail(&result, "FAILED TO LOAD ANONYM CA CERT");
            return result;
        }
        if (!is_cert_time_valid(sub_cert.get())) {
            fail(&result, "ANONYM SUB CERT IS EXPIRED OR NOT YET VALID");
            return result;
        }
        if (!verify_cert_signed_by_ca(sub_cert.get(), ca_cert.get())) {
            fail(&result, "ANONYM SUB CERT IS NOT SIGNED BY THE TRUSTED CA");
            return result;
        }
        crypto::EVP_PKEY_ptr sub_key{X509_get_pubkey(sub_cert.get()), EVP_PKEY_free};
        if (!sub_key) {
            fail(&result, "FAILED TO LOAD SUB CERT PUBLIC KEY");
            return result;
        }
        if (!verify_signature(sub_key.get(),
                              message_bytes,
                              input.sub_sig,
                              "INVALID ANONYM SUB SIGNATURE FORMAT",
                              "ANONYM SUB SIGNATURE INVALID",
                              &result)) {
            return result;
        }
        result.sub_pub = std::move(sub_key);
        result.sub_ok = true;
        add_verified_source(&result.verified_proof_sources, yume::policy::kAnonymProofSourceSubCa);
    }

    if (ca_present) {
        if (input.ca_sig.empty()) {
            fail(&result, "ANONYM CA SIGNATURE MISSING");
            return result;
        }
        if (input.anonym_ca_cert.empty()) {
            util::log_warn("anonym CA signature provided but no --anonym-ca-cert set; skipping CA verification");
        } else {
            auto ca_key = load_pubkey_from_cert(input.anonym_ca_cert);
            if (!ca_key) {
                fail(&result, "FAILED TO LOAD ANONYM CA CERT");
                return result;
            }
            if (!verify_signature(ca_key.get(),
                                  message_bytes,
                                  input.ca_sig,
                                  "INVALID ANONYM CA SIGNATURE FORMAT",
                                  "ANONYM CA SIGNATURE INVALID",
                                  &result)) {
                return result;
            }
            result.ca_pub = std::move(ca_key);
            result.ca_ok = true;
            add_verified_source(&result.verified_proof_sources, yume::policy::kAnonymProofSourceCa);
        }
    }

    if (!result.fixcraft_ok && !result.ca_ok && !result.sub_ok) {
        fail(&result, "NO TRUSTED ANONYM PROOF SOURCE COULD BE VERIFIED");
    }
    return result;
}

}  // namespace yume::client
