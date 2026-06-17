/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "server/cli/anonym.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string_view>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "client/proxy/outbound_proxy.hpp"
#include "core/security/crypto.hpp"
#include "core/protocol/runtime_policy.hpp"
#include "server/cli/misc.hpp"
#include "util.hpp"

namespace yume::server_cli {
namespace {

constexpr const char kAnonMsgPrefix[] = "YUME-ANON-V1:";
constexpr const char kPqMsgPrefix[] = "YUME-PQ-V1:";
constexpr const char kFixcraftAnonymPubPem[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAtupzLhANnB0VxP51vB/7yYwR+/3/jv4Str9MGLGA+is=\n"
    "-----END PUBLIC KEY-----\n";

bool parse_env_bool_local(const char* name, bool fallback) {
    const char* raw = std::getenv(name);
    if (!raw || !*raw) {
        return fallback;
    }
    std::string value(raw);
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (value == "1" || value == "true" || value == "yes" || value == "on") {
        return true;
    }
    if (value == "0" || value == "false" || value == "no" || value == "off") {
        return false;
    }
    return fallback;
}

bool use_curl_for_anonym_https() {
#if defined(YUME_STATIC_BUILD) && defined(__linux__)
    return parse_env_bool_local("YUME_ANONYM_USE_CURL", true);
#else
    return parse_env_bool_local("YUME_ANONYM_USE_CURL", false);
#endif
}

std::string shell_quote(const std::string& input) {
    if (input.empty()) {
        return "''";
    }
    std::string out;
    out.reserve(input.size() + 8);
    out.push_back('\'');
    for (char ch : input) {
        if (ch == '\'') {
            out += "'\"'\"'";
        } else {
            out.push_back(ch);
        }
    }
    out.push_back('\'');
    return out;
}

bool command_exists(const std::string& command) {
    if (command.empty()) {
        return false;
    }
    std::string cmd = "command -v " + shell_quote(command) + " >/dev/null 2>&1";
    return std::system(cmd.c_str()) == 0;
}

std::string run_command_capture(const std::string& command, int* status_out) {
    if (status_out) {
        *status_out = -1;
    }
#if defined(_WIN32)
    FILE* pipe = _popen(command.c_str(), "r");
#else
    FILE* pipe = popen(command.c_str(), "r");
#endif
    if (!pipe) {
        throw std::runtime_error("failed to launch command");
    }
    std::string output;
    std::array<char, 1024> buf{};
    while (true) {
        std::size_t n = std::fread(buf.data(), 1, buf.size(), pipe);
        if (n > 0) {
            output.append(buf.data(), n);
        }
        if (n < buf.size()) {
            if (std::feof(pipe) != 0) {
                break;
            }
            if (std::ferror(pipe) != 0) {
                break;
            }
        }
    }
#if defined(_WIN32)
    int status = _pclose(pipe);
#else
    int status = pclose(pipe);
#endif
    if (status_out) {
        *status_out = status;
    }
    return output;
}

nlohmann::json post_json_https_via_curl(const std::string& host,
                                        const std::string& port,
                                        const std::string& target,
                                        const nlohmann::json& payload,
                                        const std::string& token,
                                        const std::string& outbound_proxy_url) {
    if (!command_exists("curl")) {
        throw std::runtime_error("curl is required for anonym HTTPS transport on this build");
    }

    std::string url = "https://" + host;
    if (!port.empty() && port != "443") {
        url += ":" + port;
    }
    if (!target.empty() && target[0] == '/') {
        url += target;
    } else if (!target.empty()) {
        url += "/";
        url += target;
    } else {
        url += "/";
    }

    std::string nonce = yume::util::random_hex(8);
    if (nonce.empty()) {
        nonce = std::to_string(static_cast<long long>(std::time(nullptr)));
    }
    auto tmp_path = std::filesystem::temp_directory_path() / ("yume-anonym-" + nonce + ".json");
    {
        std::ofstream tmp(tmp_path, std::ios::binary | std::ios::trunc);
        if (!tmp) {
            throw std::runtime_error("failed to create curl payload file");
        }
        tmp << payload.dump();
    }

    std::string cmd = "curl --silent --show-error --fail --connect-timeout 10 --max-time 30 "
                      "--header " + shell_quote("Content-Type: application/json") + " ";
    if (!outbound_proxy_url.empty()) {
        std::string curl_proxy = outbound_proxy_url;
        constexpr std::string_view socks5 = "socks5://";
        if (curl_proxy.rfind(socks5, 0) == 0) {
            curl_proxy = "socks5h://" + curl_proxy.substr(socks5.size());
        }
        cmd += "--proxy " + shell_quote(curl_proxy) + " ";
    }
    if (!token.empty()) {
        cmd += "--header " + shell_quote("X-FC-VERITY-TOKEN: " + token) + " ";
    }
    cmd += "--data-binary @" + shell_quote(tmp_path.string()) + " " + shell_quote(url) + " 2>&1";

    int status = -1;
    std::string output;
    try {
        output = run_command_capture(cmd, &status);
    } catch (...) {
        std::error_code ec;
        std::filesystem::remove(tmp_path, ec);
        throw;
    }
    std::error_code ec;
    std::filesystem::remove(tmp_path, ec);

    if (status != 0) {
        if (output.size() > 240) {
            output.resize(240);
            output += "...";
        }
        throw std::runtime_error("curl request failed: " + output);
    }

    try {
        return nlohmann::json::parse(output);
    } catch (...) {
        std::string snippet = output;
        if (snippet.size() > 200) {
            snippet.resize(200);
            snippet += "...";
        }
        throw std::runtime_error("verity API returned invalid JSON: " + snippet);
    }
}

nlohmann::json post_json_https(const std::string& host,
                               const std::string& port,
                               const std::string& target,
                               const nlohmann::json& payload,
                               const std::string& token,
                               const std::string& outbound_proxy_url) {
    if (use_curl_for_anonym_https()) {
        return post_json_https_via_curl(host, port, target, payload, token, outbound_proxy_url);
    }

    boost::asio::io_context io;
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tlsv12_client);
    ctx.set_options(boost::asio::ssl::context::default_workarounds);
    ctx.set_verify_mode(boost::asio::ssl::verify_peer);
    ctx.set_default_verify_paths();

    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream(io, ctx);
    SSL_set_tlsext_host_name(stream.native_handle(), host.c_str());
    if (!outbound_proxy_url.empty()) {
        yume::client::outbound_proxy::Config proxy_cfg;
        std::string parse_error;
        if (!yume::client::outbound_proxy::parse_proxy_url(outbound_proxy_url, proxy_cfg, &parse_error)) {
            throw std::runtime_error("outbound proxy: " + parse_error);
        }
        auto dial = yume::client::outbound_proxy::socks5_dial(stream.next_layer(),
                                                              io,
                                                              proxy_cfg,
                                                              host,
                                                              std::stoi(port),
                                                              std::chrono::milliseconds(15000));
        if (!dial.ok) {
            throw std::runtime_error(dial.error.empty() ? "outbound proxy failed" : "outbound proxy: " + dial.error);
        }
    } else {
        boost::asio::ip::tcp::resolver resolver(io);
        auto endpoints = resolver.resolve(host, port);
        boost::asio::connect(stream.next_layer(), endpoints);
    }
    stream.handshake(boost::asio::ssl::stream_base::client);

    std::string body = payload.dump();
    std::string req =
        "POST " + target + " HTTP/1.1\r\n" +
        "Host: " + host + "\r\n" +
        "Content-Type: application/json\r\n" +
        (token.empty() ? "" : ("X-FC-VERITY-TOKEN: " + token + "\r\n")) +
        "Content-Length: " + std::to_string(body.size()) + "\r\n" +
        "Connection: close\r\n\r\n" +
        body;
    boost::asio::write(stream, boost::asio::buffer(req));

    boost::asio::streambuf resp;
    boost::system::error_code ec;
    boost::asio::read(stream, resp, ec);
    std::istream is(&resp);
    std::string resp_str((std::istreambuf_iterator<char>(is)), std::istreambuf_iterator<char>());

    auto pos = resp_str.find("\r\n\r\n");
    if (pos == std::string::npos) {
        throw std::runtime_error("invalid response from verity API");
    }
    std::string body_str = resp_str.substr(pos + 4);
    try {
        return nlohmann::json::parse(body_str);
    } catch (...) {
        throw std::runtime_error("verity API returned invalid JSON: " + body_str.substr(0, 200));
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
    std::string sig_raw = yume::util::base64_decode(sig_b64);
    if (sig_raw.empty()) {
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

    std::string key_pem;
    try {
        key_pem = read_file_bytes(ca_key_path);
    } catch (...) {
        return false;
    }
    if (key_pem.empty()) {
        return false;
    }

    BIO* bio = BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));
    if (!bio) {
        return false;
    }
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!key) {
        return false;
    }

    bool ok = false;
    try {
        auto sig = yume::crypto::sign_message(key, msg_bytes);
        if (!sig.empty()) {
            std::string sig_raw(reinterpret_cast<const char*>(sig.data()), sig.size());
            *out_sig_b64 = yume::util::base64_encode(sig_raw);
            *out_alg = key_alg_label(key);
            ok = !out_sig_b64->empty();
        }
    } catch (...) {
        ok = false;
    }
    EVP_PKEY_free(key);
    return ok;
}

struct ApiEndpoint {
    std::string host;
    std::string port;
    std::string target;
};

ApiEndpoint parse_api_url(const std::string& url) {
    const std::string prefix = "https://";
    if (url.rfind(prefix, 0) != 0) {
        throw std::runtime_error("anonym_api must be https://");
    }
    std::string rest = url.substr(prefix.size());
    std::string hostport;
    std::string target = "/";
    auto slash = rest.find('/');
    if (slash == std::string::npos) {
        hostport = rest;
    } else {
        hostport = rest.substr(0, slash);
        target = rest.substr(slash);
    }
    std::string host = hostport;
    std::string port = "443";
    auto colon = hostport.find(':');
    if (colon != std::string::npos) {
        host = hostport.substr(0, colon);
        port = hostport.substr(colon + 1);
    }
    return {host, port, target};
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

    std::string key_pem;
    try {
        key_pem = read_file_bytes(key_path);
    } catch (...) {
        return false;
    }
    if (key_pem.empty()) {
        return false;
    }

    BIO* bio = BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));
    if (!bio) {
        return false;
    }
    EVP_PKEY* key = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!key) {
        return false;
    }

    bool ok = false;
    try {
        auto sig = yume::crypto::sign_message(key, msg_bytes);
        if (!sig.empty()) {
            std::string sig_raw(reinterpret_cast<const char*>(sig.data()), sig.size());
            *out_sig_b64 = yume::util::base64_encode(sig_raw);
            *out_alg = key_alg_label(key);
            ok = !out_sig_b64->empty();
        }
    } catch (...) {
        ok = false;
    }
    EVP_PKEY_free(key);
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
        ApiEndpoint ep = parse_api_url(api_url);
        auto resp = post_json_https(ep.host, ep.port, ep.target, req, token, outbound_proxy_url);
        proof.sig = resp.value("sig", "");
        if (proof.sig.empty()) {
            std::string err = resp.value("error", "unknown");
            throw std::runtime_error("anonym signature missing (api error: " + err + ")");
        }
        if (!verify_anonym_signature(proof.hash, proof.ts, proof.nonce, proof.certfp, proof.sig)) {
            throw std::runtime_error("anonym signature verification failed (local check)");
        }
        add_proof_source(&proof.proof_sources, yume::policy::kAnonymProofSourceFixcraft);
    } else if (require_remote) {
        if (api_url.empty()) {
            throw std::runtime_error("anonym proof mode fixcraft requires --anonym-api");
        }
        throw std::runtime_error("fixcraft proof transport is disabled by policy");
    }

    if (enable_local_sign && !ca_key_path.empty()) {
        if (!sign_anonym_with_ca(proof.hash, proof.ts, proof.nonce, proof.certfp, ca_key_path,
                                 &proof.ca_sig, &proof.ca_alg)) {
            throw std::runtime_error("anonym CA signing failed");
        }
        add_proof_source(&proof.proof_sources, yume::policy::kAnonymProofSourceCa);
    }
    if (enable_local_sign && !sub_key_path.empty()) {
        if (sub_cert_path.empty()) {
            throw std::runtime_error("anonym_sub_cert must be set when anonym_sub_key is set");
        }
        if (!sign_anonym_with_ca(proof.hash, proof.ts, proof.nonce, proof.certfp, sub_key_path,
                                 &proof.sub_sig, &proof.sub_alg)) {
            throw std::runtime_error("anonym subkey signing failed");
        }
        std::string sub_pem = read_file_bytes(sub_cert_path);
        if (sub_pem.empty()) {
            throw std::runtime_error("failed to read anonym_sub_cert");
        }
        proof.sub_cert_b64 = yume::util::base64_encode(sub_pem);
        if (proof.sub_cert_b64.empty()) {
            throw std::runtime_error("failed to encode anonym_sub_cert");
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
        throw std::runtime_error("anonym proof mode local requires CA or Sub-CA signing");
    }
    if (!has_any_anonym_proof(proof)) {
        throw std::runtime_error("no anonym proof source is available");
    }
    return proof;
}

}  // namespace yume::server_cli
