/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/anonym.hpp"
#include "server/cli/curl_json_transport.hpp"

#include <algorithm>
#include <chrono>
#include <ctime>
#include <stdexcept>
#include <string_view>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "outbound/proxy.hpp"
#include "core/security/crypto.hpp"
#include "core/protocol/runtime_policy.hpp"
#include "server/cli/misc.hpp"
#include "util.hpp"

namespace yume::server::cli {
namespace {

namespace beast = boost::beast;
namespace http = beast::http;

struct TimedIoResult {
    boost::system::error_code error;
    bool timed_out{false};
};

template <typename Initiate, typename Cancel>
TimedIoResult run_until(
        boost::asio::io_context& io,
        std::chrono::steady_clock::time_point deadline,
        Initiate initiate,
        Cancel cancel) {
    TimedIoResult result;
    if (std::chrono::steady_clock::now() >= deadline) {
        result.timed_out = true;
        return result;
    }

    bool done = false;
    boost::asio::steady_timer timer(io);
    timer.expires_at(deadline);
    timer.async_wait([&](const boost::system::error_code& error) {
        if (error || done) {
            return;
        }
        result.timed_out = true;
        try {
            cancel();
        } catch (...) {
        }
    });
    try {
        initiate([&](const boost::system::error_code& error) {
            result.error = error;
            done = true;
            (void)timer.cancel();
        });
    } catch (...) {
        done = true;
        (void)timer.cancel();
        io.restart();
        io.run();
        throw;
    }

    io.restart();
    io.run();
    return result;
}

std::chrono::milliseconds remaining_until(
        std::chrono::steady_clock::time_point deadline) {
    const auto now = std::chrono::steady_clock::now();
    if (now >= deadline) {
        return std::chrono::milliseconds::zero();
    }
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        deadline - now);
}

constexpr const char kAnonMsgPrefix[] = "YUME-ANON-V1:";
constexpr const char kPqMsgPrefix[] = "YUME-PQ-V1:";
constexpr const char kFixcraftAnonymPubPem[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAtupzLhANnB0VxP51vB/7yYwR+/3/jv4Str9MGLGA+is=\n"
    "-----END PUBLIC KEY-----\n";

nlohmann::json post_json_https(const detail::HttpsEndpoint& endpoint,
                               const nlohmann::json& payload,
                               const std::string& token,
                               const std::string& outbound_proxy_url) {
    if (detail::use_curl_for_anonym_https()) {
        return detail::post_json_https_via_curl(
            endpoint, payload, token, outbound_proxy_url);
    }

    detail::validate_http_field_value(token, "operator proof token");

    boost::asio::io_context io;
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls_client);
    ctx.set_options(boost::asio::ssl::context::default_workarounds);
    ctx.set_verify_mode(boost::asio::ssl::verify_peer);
    ctx.set_default_verify_paths();
    if (SSL_CTX_set_min_proto_version(
            ctx.native_handle(), TLS1_2_VERSION) != 1) {
        throw std::runtime_error(
            "failed to set operator proof TLS minimum version");
    }

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream(io, ctx);
    boost::system::error_code address_error;
    (void)boost::asio::ip::make_address(endpoint.host, address_error);
    if (address_error) {
        if (SSL_set_tlsext_host_name(
                stream.native_handle(), endpoint.host.c_str()) != 1 ||
            SSL_set1_host(
                stream.native_handle(), endpoint.host.c_str()) != 1) {
            throw std::runtime_error(
                "failed to bind operator proof TLS to its DNS name");
        }
    } else {
        X509_VERIFY_PARAM* parameters =
            SSL_get0_param(stream.native_handle());
        if (!parameters || X509_VERIFY_PARAM_set1_ip_asc(
                parameters, endpoint.host.c_str()) != 1) {
            throw std::runtime_error(
                "failed to bind operator proof TLS to its IP address");
        }
    }

    constexpr auto kConnectTimeout = std::chrono::seconds(15);
    constexpr auto kRequestTimeout = std::chrono::seconds(30);
    const auto deadline =
        std::chrono::steady_clock::now() + kRequestTimeout;
    if (!outbound_proxy_url.empty()) {
        yume::outbound::proxy::Config proxy_cfg;
        std::string parse_error;
        if (!yume::outbound::proxy::parse_proxy_url(outbound_proxy_url, proxy_cfg, &parse_error)) {
            throw std::runtime_error("outbound proxy: " + parse_error);
        }
        const auto remaining = remaining_until(deadline);
        if (remaining == std::chrono::milliseconds::zero()) {
            throw std::runtime_error("operator proof connection timed out");
        }
        auto dial = yume::outbound::proxy::socks5_dial(
            stream.next_layer(), io, proxy_cfg, endpoint.host,
            std::stoi(endpoint.port), std::min(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    kConnectTimeout),
                remaining));
        if (!dial.ok) {
            throw std::runtime_error(dial.error.empty() ? "outbound proxy failed" : "outbound proxy: " + dial.error);
        }
    } else {
        boost::asio::ip::tcp::resolver resolver(io);
        boost::asio::ip::tcp::resolver::results_type endpoints;
        const auto resolved = run_until(
            io, deadline,
            [&](auto complete) {
                resolver.async_resolve(
                    endpoint.host, endpoint.port,
                    [&, complete](
                            const boost::system::error_code& error,
                            boost::asio::ip::tcp::resolver::results_type value) {
                        if (!error) {
                            endpoints = std::move(value);
                        }
                        complete(error);
                    });
            },
            [&resolver]() { resolver.cancel(); });
        if (resolved.timed_out) {
            throw std::runtime_error("operator proof DNS lookup timed out");
        }
        if (resolved.error) {
            throw std::runtime_error(
                "operator proof DNS lookup failed: " +
                resolved.error.message());
        }
        const auto close_socket = [&stream]() {
            boost::system::error_code ignored;
            stream.lowest_layer().cancel(ignored);
            stream.lowest_layer().close(ignored);
        };
        const auto connected = run_until(
            io, deadline,
            [&](auto complete) {
                boost::asio::async_connect(
                    stream.next_layer(), endpoints,
                    [complete](const boost::system::error_code& error,
                               const boost::asio::ip::tcp::endpoint&) {
                        complete(error);
                    });
            },
            close_socket);
        if (connected.timed_out) {
            throw std::runtime_error("operator proof connection timed out");
        }
        if (connected.error) {
            throw std::runtime_error(
                "operator proof connection failed: " +
                connected.error.message());
        }
    }
    const auto close_socket = [&stream]() {
        boost::system::error_code ignored;
        stream.lowest_layer().cancel(ignored);
        stream.lowest_layer().close(ignored);
    };
    const auto handshake = run_until(
        io, deadline,
        [&](auto complete) {
            stream.async_handshake(
                boost::asio::ssl::stream_base::client,
                [complete](const boost::system::error_code& error) {
                    complete(error);
                });
        },
        close_socket);
    if (handshake.timed_out) {
        throw std::runtime_error("operator proof TLS handshake timed out");
    }
    if (handshake.error) {
        throw std::runtime_error(
            "operator proof TLS handshake failed: " +
            handshake.error.message());
    }

    http::request<http::string_body> request;
    request.version(11);
    request.method(http::verb::post);
    request.target(endpoint.target);
    request.set(http::field::host, detail::https_authority(endpoint));
    request.set(http::field::content_type, "application/json");
    request.set(http::field::connection, "close");
    if (!token.empty()) {
        request.set("X-FC-VERITY-TOKEN", token);
    }
    request.body() = payload.dump();
    request.prepare_payload();

    const auto write_result = run_until(
        io, deadline,
        [&](auto complete) {
            http::async_write(
                stream, request,
                [complete](const boost::system::error_code& error,
                           std::size_t) { complete(error); });
        },
        close_socket);
    if (write_result.timed_out) {
        throw std::runtime_error("operator proof request write timed out");
    }
    if (write_result.error) {
        throw std::runtime_error(
            "operator proof request write failed: " +
            write_result.error.message());
    }

    beast::flat_buffer response_buffer;
    http::response_parser<http::string_body> response_parser;
    response_parser.header_limit(64U * 1024U);
    response_parser.body_limit(1024U * 1024U);
    const auto read_result = run_until(
        io, deadline,
        [&](auto complete) {
            http::async_read(
                stream, response_buffer, response_parser,
                [complete](const boost::system::error_code& error,
                           std::size_t) { complete(error); });
        },
        close_socket);
    if (read_result.timed_out) {
        throw std::runtime_error("operator proof response timed out");
    }
    if (read_result.error) {
        throw std::runtime_error(
            "operator proof response failed: " +
            read_result.error.message());
    }

    auto response = response_parser.release();
    std::string body = std::move(response.body());
    try {
        return nlohmann::json::parse(body);
    } catch (...) {
        throw std::runtime_error("verity API returned invalid JSON");
    }
}

bool verify_anonym_signature(const std::string& hash,
                             const std::string& ts,
                             const std::string& nonce,
                             const std::string& certfp,
                             const std::string& sig_b64) {
    if (hash.empty() || ts.empty() || nonce.empty() || sig_b64.empty()) {
        return false;
    }
    std::string message = std::string(kAnonMsgPrefix) + hash + ":" + ts + ":" + nonce;
    if (!certfp.empty()) {
        message += ":" + certfp;
    }
    yume::crypto::Bytes msg_bytes(message.begin(), message.end());
    if (sig_b64.size() > 128U) {
        return false;
    }
    std::string sig_raw = yume::util::base64_decode(sig_b64);
    if (sig_raw.empty() || yume::util::base64_encode(sig_raw) != sig_b64) {
        return false;
    }
    yume::crypto::Bytes sig_bytes(sig_raw.begin(), sig_raw.end());

    BIO* bio = BIO_new_mem_buf(kFixcraftAnonymPubPem, -1);
    if (!bio) {
        return false;
    }
    EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!key) {
        return false;
    }
    bool ok = false;
    try {
        ok = yume::crypto::verify_key(key, msg_bytes, sig_bytes);
    } catch (...) {
        ok = false;
    }
    EVP_PKEY_free(key);
    return ok;
}

std::string key_alg_label(EVP_PKEY* key) {
    if (!key) {
        return "unknown";
    }
    int type = EVP_PKEY_base_id(key);
    if (type == EVP_PKEY_ED25519) {
        return "ed25519";
    }
    if (type == EVP_PKEY_RSA || type == EVP_PKEY_RSA_PSS) {
        return "rsa";
    }
    if (type == EVP_PKEY_EC) {
        return "ecdsa";
    }
    return "unknown";
}

bool sign_anonym_with_ca(const std::string& hash,
                         const std::string& ts,
                         const std::string& nonce,
                         const std::string& certfp,
                         const std::string& ca_key_path,
                         std::string* out_sig_b64,
                         std::string* out_alg) {
    if (!out_sig_b64 || !out_alg) {
        return false;
    }
    if (hash.empty() || ts.empty() || nonce.empty() || ca_key_path.empty()) {
        return false;
    }
    std::string message = std::string(kAnonMsgPrefix) + hash + ":" + ts + ":" + nonce;
    if (!certfp.empty()) {
        message += ":" + certfp;
    }
    yume::crypto::Bytes msg_bytes(message.begin(), message.end());

    yume::crypto::EVP_PKEY_ptr key{nullptr, EVP_PKEY_free};
    try {
        key = yume::crypto::load_private_key(ca_key_path);
    } catch (...) {
        return false;
    }

    bool ok = false;
    try {
        auto sig = yume::crypto::sign_message(key.get(), msg_bytes);
        if (!sig.empty()) {
            std::string sig_raw(reinterpret_cast<const char*>(sig.data()), sig.size());
            *out_sig_b64 = yume::util::base64_encode(sig_raw);
            *out_alg = key_alg_label(key.get());
            ok = !out_sig_b64->empty();
        }
    } catch (...) {
        ok = false;
    }
    return ok;
}

void add_proof_source(std::vector<std::string>* sources, std::string_view source) {
    if (!sources || source.empty()) {
        return;
    }
    const std::string value(source);
    if (std::find(sources->begin(), sources->end(), value) == sources->end()) {
        sources->push_back(value);
    }
}

bool has_any_anonym_proof(const AnonymProof& proof) {
    return !proof.sig.empty() || !proof.ca_sig.empty() || !proof.sub_sig.empty();
}

}  // namespace

bool anonym_local_sign_default() {
    return true;
}

std::string derive_pq_public_path(const std::string& pq_private_path) {
    if (pq_private_path.empty()) {
        return "";
    }
    std::filesystem::path p(pq_private_path);
    if (p.has_parent_path()) {
        return (p.parent_path() / "pq_public.key").string();
    }
    return "pq_public.key";
}

bool load_pq_public_b64(const std::string& pq_public_path, std::string* out_b64) {
    if (!out_b64 || pq_public_path.empty()) {
        return false;
    }
    try {
        std::string raw = read_file_bytes(pq_public_path);
        if (raw.empty()) {
            return false;
        }
        *out_b64 = yume::util::base64_encode(raw);
        return !out_b64->empty();
    } catch (...) {
        return false;
    }
}

bool sign_pq_pub_with_key(const std::string& pq_pub_b64,
                          const std::string& certfp,
                          const std::string& key_path,
                          std::string* out_sig_b64,
                          std::string* out_alg) {
    if (!out_sig_b64 || !out_alg) {
        return false;
    }
    if (pq_pub_b64.empty() || certfp.empty() || key_path.empty()) {
        return false;
    }
    std::string message = std::string(kPqMsgPrefix) + pq_pub_b64 + ":" + certfp;
    yume::crypto::Bytes msg_bytes(message.begin(), message.end());

    yume::crypto::EVP_PKEY_ptr key{nullptr, EVP_PKEY_free};
    try {
        key = yume::crypto::load_private_key(key_path);
    } catch (...) {
        return false;
    }

    bool ok = false;
    try {
        auto sig = yume::crypto::sign_message(key.get(), msg_bytes);
        if (!sig.empty()) {
            std::string sig_raw(reinterpret_cast<const char*>(sig.data()), sig.size());
            *out_sig_b64 = yume::util::base64_encode(sig_raw);
            *out_alg = key_alg_label(key.get());
            ok = !out_sig_b64->empty();
        }
    } catch (...) {
        ok = false;
    }
    return ok;
}

long long parse_proof_ts(const std::string& ts, long long fallback) {
    if (ts.empty()) {
        return fallback;
    }
    try {
        return std::stoll(ts);
    } catch (...) {
        return fallback;
    }
}

AnonymProof fetch_anonym_proof(const std::string& hash,
                               const std::string& certfp,
                               const std::string& proof_mode,
                               const std::string& api_url,
                               const std::string& token,
                               const std::string& ca_key_path,
                               const std::string& sub_key_path,
                               const std::string& sub_cert_path,
                               const std::string& pq_public_path,
                               const std::string& pq_sign_key_path,
                               bool enable_local_sign,
                               const std::string& outbound_proxy_url) {
    AnonymProof proof;
    proof.hash = hash;
    proof.ts = std::to_string(static_cast<long long>(std::time(nullptr)));
    proof.nonce = yume::util::random_hex(16);
    // random_hex returns empty when the RNG fails; an empty proof nonce would
    // silently remove the replay binding rather than fail the operation.
    if (proof.nonce.empty()) {
        throw std::runtime_error("failed to generate anonym proof nonce");
    }
    proof.certfp = certfp;
    proof.proof_policy = yume::policy::normalize_anonym_proof_mode(proof_mode);
    nlohmann::json req{{"hash", proof.hash},
                       {"ts", proof.ts},
                       {"nonce", proof.nonce},
                       {"prefix", kAnonMsgPrefix}};
    if (!proof.certfp.empty()) {
        req["certfp"] = proof.certfp;
    }
    const bool allow_remote = yume::policy::anonym_proof_mode_allows_remote(proof.proof_policy);
    const bool require_remote = yume::policy::anonym_proof_mode_requires_remote(proof.proof_policy);
    const bool require_local = yume::policy::anonym_proof_mode_requires_local(proof.proof_policy);

    if (allow_remote && !api_url.empty()) {
        const auto endpoint = detail::parse_https_endpoint(api_url);
        auto resp = post_json_https(
            endpoint, req, token, outbound_proxy_url);
        proof.sig = detail::require_operator_proof_signature(resp);
        if (!verify_anonym_signature(proof.hash, proof.ts, proof.nonce, proof.certfp, proof.sig)) {
            throw std::runtime_error("external operator proof signature verification failed");
        }
        add_proof_source(&proof.proof_sources, yume::policy::kAnonymProofSourceFixcraft);
    } else if (require_remote) {
        if (api_url.empty()) {
            throw std::runtime_error("external operator proof mode requires --operator-proof-api");
        }
        throw std::runtime_error("external operator proof transport is disabled by policy");
    }

    if (enable_local_sign && !ca_key_path.empty()) {
        if (!sign_anonym_with_ca(proof.hash, proof.ts, proof.nonce, proof.certfp, ca_key_path,
                                 &proof.ca_sig, &proof.ca_alg)) {
            throw std::runtime_error("operator CA signing failed");
        }
        add_proof_source(&proof.proof_sources, yume::policy::kAnonymProofSourceCa);
    }
    if (enable_local_sign && !sub_key_path.empty()) {
        if (sub_cert_path.empty()) {
            throw std::runtime_error("a delegated server certificate is required with its private key");
        }
        if (!sign_anonym_with_ca(proof.hash, proof.ts, proof.nonce, proof.certfp, sub_key_path,
                                 &proof.sub_sig, &proof.sub_alg)) {
            throw std::runtime_error("delegated server identity signing failed");
        }
        std::string sub_pem = read_file_bytes(sub_cert_path);
        if (sub_pem.empty()) {
            throw std::runtime_error("failed to read delegated server certificate");
        }
        proof.sub_cert_b64 = yume::util::base64_encode(sub_pem);
        if (proof.sub_cert_b64.empty()) {
            throw std::runtime_error("failed to encode delegated server certificate");
        }
        add_proof_source(&proof.proof_sources, yume::policy::kAnonymProofSourceSubCa);
    }
    if (enable_local_sign && !pq_public_path.empty() && !pq_sign_key_path.empty() && !proof.certfp.empty()) {
        if (load_pq_public_b64(pq_public_path, &proof.pq_pub_b64)) {
            if (!sign_pq_pub_with_key(proof.pq_pub_b64, proof.certfp, pq_sign_key_path,
                                      &proof.pq_sig, &proof.pq_alg)) {
                throw std::runtime_error("pq public key signing failed");
            }
        }
    }
    if (require_local && proof.ca_sig.empty() && proof.sub_sig.empty()) {
        throw std::runtime_error("local operator proof mode requires operator CA or delegated certificate signing");
    }
    if (!has_any_anonym_proof(proof)) {
        throw std::runtime_error("no operator identity proof source is available");
    }
    return proof;
}

}  // namespace yume::server::cli
