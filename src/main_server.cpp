/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include <iostream>
#include <filesystem>
#include <fstream>
#include <utility>
#include <ctime>
#include <thread>
#include <vector>
#include <atomic>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/pem.h>
#include <nlohmann/json.hpp>

#include "core/crypto.hpp"
#include "core/inner_crypto.hpp"
#include "server/manager.hpp"
#include "server/auth.hpp"
#include "util.hpp"

namespace {
constexpr const char kAnonMsgPrefix[] = "YUME-ANON-V1:";
constexpr const char kFixcraftAnonymPubPem[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAtupzLhANnB0VxP51vB/7yYwR+/3/jv4Str9MGLGA+is=\n"
    "-----END PUBLIC KEY-----\n";
constexpr const char kDefaultSecretPath[] = "./.secrets/html_secret";
constexpr int kAnonymRefreshSeconds = 300;
void print_help() {
    std::cout
        << "yumed - YUME server\n\n"
        << "Usage:\n"
        << "  yumed [--config <path>] [options]\n\n"
        << "Options:\n"
        << "  --listen <port>       (override listen_port)\n"
        << "  --cert <path>         (override tls_cert)\n"
        << "  --key <path>          (override tls_key)\n"
        << "  --auth-keys <path>    (override auth_keys)\n"
        << "  --threads <n>         (override threads)\n"
        << "  --obfs                (enable obfuscation)\n"
        << "  --inner               (enable inner PQ crypto)\n"
        << "  --inner-heavy         (heavy KDF, default)\n"
        << "  --inner-light         (lighter KDF)\n"
        << "  --pq-key <path>       (override pq_private_key)\n"
        << "  --allow-exec          (deprecated: EXEC is disabled for safety)\n"
        << "  --real                (serve real HTTP on non-client requests)\n"
        << "  --real-index <path>   (HTML file for /)\n"
        << "  --real-secret <str>   (secret for hidden metadata)\n"
        << "  --real-secret-file <path> (auto-generate/store secret)\n"
        << "  --anonym              (enable anonym mode + proof)\n"
        << "  --anonym-api <url>    (verity API endpoint)\n"
        << "  --anonym-token <str>  (verity API token)\n"
        << "  --anonym-ca-key <path> (CA private key for extra anonym signature)\n"
        << "  --anonym-ca-cert <path> (CA cert matching anonym CA key)\n"
        << "  --anonym-sub-key <path> (sub-CA private key for anonym proof signing)\n"
        << "  --anonym-sub-cert <path> (sub-CA cert to send to clients)\n"
        << "  --keys-list           (list authorized keys)\n"
        << "  --keys-add <pub.pem>  (add authorized key)\n"
        << "  --keys-remove <id>    (remove by fingerprint or alias)\n"
        << "  --keys-alias <id> <alias> (set alias)\n"
        << "  --keys-gen <prefix>   (generate Ed25519 keypair at <prefix>.key/.pub)\n"
        << "  --keys-gen-add        (append generated pubkey to auth_keys)\n"
        << "  --ui                  (interactive server manager)\n"
        << "  --help                (show help)\n\n"
        << "Required config fields:\n"
        << "  listen_port   (int)\n"
        << "  tls_cert      (path)\n"
        << "  tls_key       (path)\n"
        << "  auth_keys     (path)\n\n"
        << "Optional config fields:\n"
        << "  threads       (int)\n"
        << "  obfuscation   (bool)\n"
        << "  inner_crypto  (bool)\n"
        << "  inner_heavy   (bool)\n"
        << "  pq_private_key (path)\n"
        << "  allow_exec    (bool, deprecated)\n"
        << "  real_http     (bool)\n"
        << "  real_index_path (path)\n"
        << "  real_secret   (string)\n";
}

bool file_readable(const std::string& path) {
    if (path.empty()) {
        return false;
    }
    std::error_code ec;
    return std::filesystem::exists(path, ec);
}

bool ensure_dir(const std::string& dir) {
    if (dir.empty()) {
        return false;
    }
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    return !ec;
}

bool write_file_secure(const std::string& path, const std::string& contents) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return false;
    }
    out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    out.close();
    std::error_code ec;
    std::filesystem::permissions(path,
                                 std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, ec);
    return !ec;
}

std::string load_or_create_secret(const std::string& path) {
    std::ifstream in(path);
    if (in) {
        std::string val;
        std::getline(in, val);
        if (!val.empty()) {
            return val;
        }
    }
    std::string secret = yume::util::random_hex(32);
    if (secret.empty()) {
        throw std::runtime_error("failed to generate secret");
    }
    auto dir = std::filesystem::path(path).parent_path().string();
    if (!dir.empty()) {
        ensure_dir(dir);
    }
    if (!write_file_secure(path, secret)) {
        throw std::runtime_error("failed to write secret file");
    }
    return secret;
}

bool generate_ed25519_keypair(const std::string& priv_path, const std::string& pub_path) {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!pctx) {
        return false;
    }
    if (EVP_PKEY_keygen_init(pctx) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(pctx, &pkey) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    EVP_PKEY_CTX_free(pctx);

    BIO* priv = BIO_new_file(priv_path.c_str(), "w");
    BIO* pub = BIO_new_file(pub_path.c_str(), "w");
    if (!priv || !pub) {
        if (priv) BIO_free(priv);
        if (pub) BIO_free(pub);
        EVP_PKEY_free(pkey);
        return false;
    }
    bool ok = PEM_write_bio_PrivateKey(priv, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1 &&
              PEM_write_bio_PUBKEY(pub, pkey) == 1;
    BIO_free(priv);
    BIO_free(pub);
    EVP_PKEY_free(pkey);

    std::error_code ec;
    std::filesystem::permissions(priv_path,
                                 std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, ec);
    return ok;
}
std::string read_file_bytes(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open file: " + path);
    }
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return data;
}

std::string cert_fingerprint_sha256(const std::string& cert_path) {
    std::ifstream in(cert_path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open cert: " + cert_path);
    }
    std::string pem((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) {
        throw std::runtime_error("failed to read cert bio");
    }
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert) {
        throw std::runtime_error("failed to parse cert");
    }
    unsigned char* der = nullptr;
    int len = i2d_X509(cert, &der);
    X509_free(cert);
    if (len <= 0 || !der) {
        if (der) OPENSSL_free(der);
        throw std::runtime_error("failed to encode cert");
    }
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    SHA256(der, static_cast<size_t>(len), hash);
    OPENSSL_free(der);
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2);
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        out.push_back(kHex[(hash[i] >> 4) & 0xF]);
        out.push_back(kHex[hash[i] & 0xF]);
    }
    return out;
}

std::string sha256_hex(const std::string& data) {
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), hash);
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(SHA256_DIGEST_LENGTH * 2);
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        out.push_back(kHex[(hash[i] >> 4) & 0xF]);
        out.push_back(kHex[hash[i] & 0xF]);
    }
    return out;
}

std::string get_self_path(const char* argv0) {
    std::error_code ec;
    auto p = std::filesystem::read_symlink("/proc/self/exe", ec);
    if (!ec) {
        return p.string();
    }
    if (argv0 && argv0[0] != '\0') {
        return std::filesystem::absolute(argv0).string();
    }
    return {};
}

nlohmann::json post_json_https(const std::string& host,
                               const std::string& port,
                               const std::string& target,
                               const nlohmann::json& payload,
                               const std::string& token) {
    boost::asio::io_context io;
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls_client);
    ctx.set_verify_mode(boost::asio::ssl::verify_peer);
    ctx.set_default_verify_paths();

    boost::asio::ip::tcp::resolver resolver(io);
    auto endpoints = resolver.resolve(host, port);
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream(io, ctx);
    SSL_set_tlsext_host_name(stream.native_handle(), host.c_str());
    boost::asio::connect(stream.next_layer(), endpoints);
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

struct AnonymProof {
    std::string hash;
    std::string sig;
    std::string ts;
    std::string nonce;
    std::string certfp;
    std::string ca_sig;
    std::string ca_alg;
    std::string sub_sig;
    std::string sub_alg;
    std::string sub_cert_b64;
};

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

AnonymProof fetch_anonym_proof(const std::string& hash,
                               const std::string& certfp,
                               const std::string& api_url,
                               const std::string& token,
                               const std::string& ca_key_path,
                               const std::string& sub_key_path,
                               const std::string& sub_cert_path) {
    AnonymProof proof;
    proof.hash = hash;
    proof.ts = std::to_string(static_cast<long long>(std::time(nullptr)));
    proof.nonce = yume::util::random_hex(16);
    proof.certfp = certfp;
    nlohmann::json req{{"hash", proof.hash},
                       {"ts", proof.ts},
                       {"nonce", proof.nonce},
                       {"prefix", kAnonMsgPrefix}};
    if (!proof.certfp.empty()) {
        req["certfp"] = proof.certfp;
    }
    ApiEndpoint ep = parse_api_url(api_url);
    auto resp = post_json_https(ep.host, ep.port, ep.target, req, token);
    proof.sig = resp.value("sig", "");
    if (proof.sig.empty()) {
        std::string err = resp.value("error", "unknown");
        throw std::runtime_error("anonym signature missing (api error: " + err + ")");
    }
    if (!verify_anonym_signature(proof.hash, proof.ts, proof.nonce, proof.certfp, proof.sig)) {
        throw std::runtime_error("anonym signature verification failed (local check)");
    }
    if (!ca_key_path.empty()) {
        if (!sign_anonym_with_ca(proof.hash, proof.ts, proof.nonce, proof.certfp, ca_key_path,
                                 &proof.ca_sig, &proof.ca_alg)) {
            throw std::runtime_error("anonym CA signing failed");
        }
    }
    if (!sub_key_path.empty()) {
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
    }
    return proof;
}
}  // namespace

int main(int argc, char** argv) {
    yume::util::init_logging();

    yume::server::ServerConfig cfg;
    std::string config_path = "config/yumed.json";
    bool config_specified = false;
    std::string keys_add;
    std::string keys_remove;
    std::string keys_alias;
    std::string keys_alias_value;
    bool keys_list = false;
    std::string keys_gen;
    bool keys_gen_add = false;
    bool ui_mode = false;
    bool inner_heavy_override = false;
    bool inner_heavy_value = true;
    bool inner_crypto_override = false;
    bool anonym_override = false;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            print_help();
            return 0;
        }
        if (arg == "--config" && i + 1 < argc) {
            config_path = argv[++i];
            config_specified = true;
        } else if (arg == "--listen" && i + 1 < argc) {
            cfg.listen_port = std::stoi(argv[++i]);
        } else if (arg == "--cert" && i + 1 < argc) {
            cfg.tls_cert = argv[++i];
        } else if (arg == "--key" && i + 1 < argc) {
            cfg.tls_key = argv[++i];
        } else if (arg == "--auth-keys" && i + 1 < argc) {
            cfg.auth_keys = argv[++i];
        } else if (arg == "--threads" && i + 1 < argc) {
            cfg.threads = std::stoi(argv[++i]);
        } else if (arg == "--obfs") {
            cfg.obfuscation = true;
        } else if (arg == "--inner") {
            cfg.inner_crypto = true;
            inner_crypto_override = true;
            inner_heavy_override = true;
            inner_heavy_value = true;
        } else if (arg == "--inner-heavy") {
            cfg.inner_crypto = true;
            inner_crypto_override = true;
            inner_heavy_override = true;
            inner_heavy_value = true;
        } else if (arg == "--inner-light") {
            cfg.inner_crypto = true;
            inner_crypto_override = true;
            inner_heavy_override = true;
            inner_heavy_value = false;
        } else if (arg == "--pq-key" && i + 1 < argc) {
            cfg.pq_private_key = yume::util::expand_user(argv[++i]);
            inner_crypto_override = true;
        } else if (arg == "--allow-exec") {
            cfg.allow_exec = true;
        } else if (arg == "--real") {
            cfg.real_http = true;
        } else if (arg == "--real-index" && i + 1 < argc) {
            cfg.real_index_path = argv[++i];
        } else if (arg == "--real-secret" && i + 1 < argc) {
            cfg.real_secret = argv[++i];
        } else if (arg == "--real-secret-file" && i + 1 < argc) {
            cfg.real_secret_file = argv[++i];
        } else if (arg == "--anonym") {
            cfg.anonym = true;
            anonym_override = true;
        } else if (arg == "--anonym-api" && i + 1 < argc) {
            cfg.anonym_api = argv[++i];
        } else if (arg == "--anonym-token" && i + 1 < argc) {
            cfg.anonym_token = argv[++i];
        } else if (arg == "--anonym-ca-key" && i + 1 < argc) {
            cfg.anonym_ca_key = yume::util::expand_user(argv[++i]);
        } else if (arg == "--anonym-ca-cert" && i + 1 < argc) {
            cfg.anonym_ca_cert = yume::util::expand_user(argv[++i]);
        } else if (arg == "--anonym-sub-key" && i + 1 < argc) {
            cfg.anonym_sub_key = yume::util::expand_user(argv[++i]);
        } else if (arg == "--anonym-sub-cert" && i + 1 < argc) {
            cfg.anonym_sub_cert = yume::util::expand_user(argv[++i]);
        } else if (arg == "--keys-add" && i + 1 < argc) {
            keys_add = argv[++i];
        } else if (arg == "--keys-remove" && i + 1 < argc) {
            keys_remove = argv[++i];
        } else if (arg == "--keys-alias" && i + 2 < argc) {
            keys_alias = argv[++i];
            keys_alias_value = argv[++i];
        } else if (arg == "--keys-list") {
            keys_list = true;
        } else if (arg == "--keys-gen" && i + 1 < argc) {
            keys_gen = argv[++i];
        } else if (arg == "--keys-gen-add") {
            keys_gen_add = true;
        } else if (arg == "--ui") {
            ui_mode = true;
        }
    }

    if (config_specified || std::filesystem::exists(config_path)) {
        try {
            auto json = yume::util::read_json_config(config_path);
            if (json.contains("listen_port")) {
                if (cfg.listen_port == 443) {
                    cfg.listen_port = json["listen_port"].get<int>();
                }
            }
            if (json.contains("tls_cert")) {
                if (cfg.tls_cert.empty()) {
                    cfg.tls_cert = json["tls_cert"].get<std::string>();
                }
            }
            if (json.contains("tls_key")) {
                if (cfg.tls_key.empty()) {
                    cfg.tls_key = json["tls_key"].get<std::string>();
                }
            }
            if (json.contains("auth_keys")) {
                if (cfg.auth_keys.empty()) {
                    cfg.auth_keys = json["auth_keys"].get<std::string>();
                }
            }
            if (json.contains("threads")) {
                if (cfg.threads == 4) {
                    cfg.threads = json["threads"].get<int>();
                }
            }
            if (json.contains("obfuscation")) {
                if (!cfg.obfuscation) {
                    cfg.obfuscation = json["obfuscation"].get<bool>();
                }
            }
            if (json.contains("inner_crypto")) {
                if (!inner_crypto_override) {
                    cfg.inner_crypto = json["inner_crypto"].get<bool>();
                }
            }
            if (json.contains("inner_heavy")) {
                cfg.inner_heavy = json["inner_heavy"].get<bool>();
            }
            if (json.contains("pq_private_key")) {
                if (cfg.pq_private_key.empty()) {
                    cfg.pq_private_key = yume::util::expand_user(json["pq_private_key"].get<std::string>());
                }
            }
            if (json.contains("allow_exec")) {
                if (!cfg.allow_exec) {
                    cfg.allow_exec = json["allow_exec"].get<bool>();
                }
            }
            if (json.contains("real_http")) {
                if (!cfg.real_http) {
                    cfg.real_http = json["real_http"].get<bool>();
                }
            }
            if (json.contains("real_index_path")) {
                if (cfg.real_index_path.empty()) {
                    cfg.real_index_path = json["real_index_path"].get<std::string>();
                }
            }
            if (json.contains("real_secret")) {
                if (cfg.real_secret.empty()) {
                    cfg.real_secret = json["real_secret"].get<std::string>();
                }
            }
            if (json.contains("real_secret_file")) {
                if (cfg.real_secret_file.empty()) {
                    cfg.real_secret_file = json["real_secret_file"].get<std::string>();
                }
            }
            if (json.contains("anonym")) {
                if (!anonym_override) {
                    cfg.anonym = json["anonym"].get<bool>();
                }
            }
            if (json.contains("anonym_api")) {
                if (cfg.anonym_api.empty()) {
                    cfg.anonym_api = json["anonym_api"].get<std::string>();
                }
            }
            if (json.contains("anonym_token")) {
                if (cfg.anonym_token.empty()) {
                    cfg.anonym_token = json["anonym_token"].get<std::string>();
                }
            }
            if (json.contains("anonym_ca_key")) {
                if (cfg.anonym_ca_key.empty()) {
                    cfg.anonym_ca_key = yume::util::expand_user(json["anonym_ca_key"].get<std::string>());
                }
            }
            if (json.contains("anonym_ca_cert")) {
                if (cfg.anonym_ca_cert.empty()) {
                    cfg.anonym_ca_cert = yume::util::expand_user(json["anonym_ca_cert"].get<std::string>());
                }
            }
            if (json.contains("anonym_sub_key")) {
                if (cfg.anonym_sub_key.empty()) {
                    cfg.anonym_sub_key = yume::util::expand_user(json["anonym_sub_key"].get<std::string>());
                }
            }
            if (json.contains("anonym_sub_cert")) {
                if (cfg.anonym_sub_cert.empty()) {
                    cfg.anonym_sub_cert = yume::util::expand_user(json["anonym_sub_cert"].get<std::string>());
                }
            }
        } catch (const std::exception& ex) {
            yume::util::log_error(std::string("config load failed: ") + ex.what());
            return 1;
        }
    }
    if (inner_heavy_override) {
        cfg.inner_heavy = inner_heavy_value;
    }

    if (ui_mode) {
        std::cout << "\n\033[1;36mYUME Server Manager\033[0m\n";
        std::cout << "1) Generate keypair\n";
        std::cout << "2) Add public key to auth_keys\n";
        std::cout << "3) Remove key (fingerprint or alias)\n";
        std::cout << "4) Set alias\n";
        std::cout << "5) List keys\n";
        std::cout << "6) Edit config\n";
        std::cout << "0) Exit\n";
        std::cout << "Select: ";
        std::string choice;
        std::getline(std::cin, choice);
        if (choice == "1") {
            std::cout << "Prefix (path without extension): ";
            std::getline(std::cin, keys_gen);
        } else if (choice == "2") {
            std::cout << "Public key path: ";
            std::getline(std::cin, keys_add);
        } else if (choice == "3") {
            std::cout << "Fingerprint or alias: ";
            std::getline(std::cin, keys_remove);
        } else if (choice == "4") {
            std::cout << "Fingerprint or alias: ";
            std::getline(std::cin, keys_alias);
            std::cout << "New alias: ";
            std::getline(std::cin, keys_alias_value);
        } else if (choice == "5") {
            keys_list = true;
        } else if (choice == "6") {
            std::string out_path = "config/yumed.json";
            std::cout << "Config path [config/yumed.json]: ";
            std::string input_path;
            std::getline(std::cin, input_path);
            if (!input_path.empty()) {
                out_path = input_path;
            }
            nlohmann::json json;
            std::ifstream in(out_path);
            if (in) {
                try { in >> json; } catch (...) { json = nlohmann::json::object(); }
            } else {
                json = nlohmann::json::object();
            }
            auto prompt = [&](const std::string& key, const std::string& current) {
                std::cout << key << " [" << current << "]: ";
                std::string v;
                std::getline(std::cin, v);
                return v.empty() ? current : v;
            };
            std::string listen = prompt("listen_port", std::to_string(cfg.listen_port));
            std::string cert = prompt("tls_cert", cfg.tls_cert);
            std::string key = prompt("tls_key", cfg.tls_key);
            std::string auth = prompt("auth_keys", cfg.auth_keys);
            std::string threads = prompt("threads", std::to_string(cfg.threads));
            std::string obfs = prompt("obfuscation (true/false)", cfg.obfuscation ? "true" : "false");
            std::string inner = prompt("inner_crypto (true/false)", cfg.inner_crypto ? "true" : "false");
            std::string inner_heavy = prompt("inner_heavy (true/false)", cfg.inner_heavy ? "true" : "false");
            std::string pq = prompt("pq_private_key", cfg.pq_private_key);
            std::string allow_exec = prompt("allow_exec (true/false)", cfg.allow_exec ? "true" : "false");
            std::string real_http = prompt("real_http (true/false)", cfg.real_http ? "true" : "false");
            std::string real_index = prompt("real_index_path", cfg.real_index_path);
            std::string real_secret_file = prompt("real_secret_file", cfg.real_secret_file);
            std::string anonym = prompt("anonym (true/false)", cfg.anonym ? "true" : "false");
            std::string anonym_api = prompt("anonym_api", cfg.anonym_api);
            std::string anonym_token = prompt("anonym_token", cfg.anonym_token);
            std::string anonym_ca_key = prompt("anonym_ca_key", cfg.anonym_ca_key);
            std::string anonym_ca_cert = prompt("anonym_ca_cert", cfg.anonym_ca_cert);
            std::string anonym_sub_key = prompt("anonym_sub_key", cfg.anonym_sub_key);
            std::string anonym_sub_cert = prompt("anonym_sub_cert", cfg.anonym_sub_cert);

            json["listen_port"] = std::stoi(listen);
            json["tls_cert"] = cert;
            json["tls_key"] = key;
            json["auth_keys"] = auth;
            json["threads"] = std::stoi(threads);
            json["obfuscation"] = (obfs == "true");
            json["inner_crypto"] = (inner == "true");
            json["inner_heavy"] = (inner_heavy == "true");
            if (!pq.empty()) json["pq_private_key"] = pq;
            json["allow_exec"] = (allow_exec == "true");
            json["real_http"] = (real_http == "true");
            if (!real_index.empty()) json["real_index_path"] = real_index;
            if (!real_secret_file.empty()) json["real_secret_file"] = real_secret_file;
            json["anonym"] = (anonym == "true");
            if (!anonym_api.empty()) json["anonym_api"] = anonym_api;
            if (!anonym_token.empty()) json["anonym_token"] = anonym_token;
            if (!anonym_ca_key.empty()) json["anonym_ca_key"] = anonym_ca_key;
            if (!anonym_ca_cert.empty()) json["anonym_ca_cert"] = anonym_ca_cert;
            if (!anonym_sub_key.empty()) json["anonym_sub_key"] = anonym_sub_key;
            if (!anonym_sub_cert.empty()) json["anonym_sub_cert"] = anonym_sub_cert;

            ensure_dir(std::filesystem::path(out_path).parent_path().string());
            std::ofstream out(out_path);
            if (!out) {
                yume::util::log_error("failed to write config: " + out_path);
                return 1;
            }
            out << json.dump(2);
            std::cout << "Saved config: " << out_path << "\n";
            return 0;
        } else {
            return 0;
        }
    }

    if (!(keys_list || !keys_add.empty() || !keys_remove.empty() || !keys_alias.empty() || !keys_gen.empty())) {
        if (cfg.anonym && (cfg.anonym_sub_key.empty() || cfg.anonym_sub_cert.empty())) {
            std::error_code ec;
            std::filesystem::path runtime_dir = std::filesystem::current_path(ec);
            std::filesystem::path exe_dir;
            std::string self_path = get_self_path(argv[0]);
            if (!self_path.empty()) {
                exe_dir = std::filesystem::path(self_path).parent_path();
            }
            auto try_set = [&](std::string& out, const std::filesystem::path& base, const char* name) {
                if (!out.empty() || base.empty()) {
                    return;
                }
                std::filesystem::path cand = base / name;
                if (file_readable(cand.string())) {
                    out = cand.string();
                }
            };
            try_set(cfg.anonym_sub_key, runtime_dir, "anonym_sub.key");
            try_set(cfg.anonym_sub_cert, runtime_dir, "anonym_sub.pem");
            try_set(cfg.anonym_sub_key, exe_dir, "anonym_sub.key");
            try_set(cfg.anonym_sub_cert, exe_dir, "anonym_sub.pem");
            if (!cfg.anonym_sub_key.empty() && !cfg.anonym_sub_cert.empty()) {
                yume::util::log_info("using anonym sub key/cert from runtime directory");
            }
        }
        if (cfg.inner_crypto && cfg.pq_private_key.empty()) {
            std::error_code ec;
            std::filesystem::path runtime_dir = std::filesystem::current_path(ec);
            std::filesystem::path exe_dir;
            std::string self_path = get_self_path(argv[0]);
            if (!self_path.empty()) {
                exe_dir = std::filesystem::path(self_path).parent_path();
            }
            auto try_set = [&](std::string& out, const std::filesystem::path& base, const char* name) {
                if (!out.empty() || base.empty()) {
                    return;
                }
                std::filesystem::path cand = base / name;
                if (file_readable(cand.string())) {
                    out = cand.string();
                }
            };
            try_set(cfg.pq_private_key, runtime_dir, "pq_private.key");
            try_set(cfg.pq_private_key, exe_dir, "pq_private.key");
            if (!cfg.pq_private_key.empty()) {
                yume::util::log_info("using pq_private_key from runtime directory");
            } else {
                std::filesystem::path secret_dir = runtime_dir / ".secrets";
                std::filesystem::path priv_path = secret_dir / "pq_private.key";
                std::filesystem::path pub_path = secret_dir / "pq_public.key";
                std::string err;
                if (yume::inner::generate_pq_keypair(priv_path.string(), pub_path.string(), &err)) {
                    cfg.pq_private_key = priv_path.string();
                    yume::util::log_info("generated PQ keypair at ./.secrets (copy pq_public.key to clients)");
                } else {
                    yume::util::log_warn("PQ keypair generation failed: " + err);
                }
            }
        }
        if (cfg.tls_cert.empty() || cfg.tls_key.empty()) {
            yume::util::log_error("tls_cert and tls_key must be set in config");
            return 1;
        }
        if (cfg.auth_keys.empty()) {
            yume::util::log_error("auth_keys must be set in config");
            return 1;
        }
        if (!file_readable(cfg.tls_cert)) {
            yume::util::log_error("tls_cert not found: " + cfg.tls_cert);
            return 1;
        }
        if (!file_readable(cfg.tls_key)) {
            yume::util::log_error("tls_key not found: " + cfg.tls_key);
            return 1;
        }
        if (!file_readable(cfg.auth_keys)) {
            yume::util::log_error("auth_keys not found: " + cfg.auth_keys);
            return 1;
        }
        if (cfg.inner_crypto && !cfg.pq_private_key.empty() && !file_readable(cfg.pq_private_key)) {
            yume::util::log_error("pq_private_key not found: " + cfg.pq_private_key);
            return 1;
        }
        if (cfg.anonym && !cfg.anonym_ca_key.empty() && !file_readable(cfg.anonym_ca_key)) {
            yume::util::log_error("anonym_ca_key not found: " + cfg.anonym_ca_key);
            return 1;
        }
        if (cfg.anonym && !cfg.anonym_ca_cert.empty() && !file_readable(cfg.anonym_ca_cert)) {
            yume::util::log_error("anonym_ca_cert not found: " + cfg.anonym_ca_cert);
            return 1;
        }
        if (cfg.anonym && !cfg.anonym_sub_key.empty() && !file_readable(cfg.anonym_sub_key)) {
            yume::util::log_error("anonym_sub_key not found: " + cfg.anonym_sub_key);
            return 1;
        }
        if (cfg.anonym && !cfg.anonym_sub_cert.empty() && !file_readable(cfg.anonym_sub_cert)) {
            yume::util::log_error("anonym_sub_cert not found: " + cfg.anonym_sub_cert);
            return 1;
        }
        if (cfg.real_http && !cfg.real_index_path.empty() && !file_readable(cfg.real_index_path)) {
            yume::util::log_error("real_index_path not found: " + cfg.real_index_path);
            return 1;
        }

        if (cfg.auth_keys_meta.empty() && !cfg.auth_keys.empty()) {
            cfg.auth_keys_meta = cfg.auth_keys + ".json";
        }
    }

    if (keys_list || !keys_add.empty() || !keys_remove.empty() || !keys_alias.empty() || !keys_gen.empty()) {
        if (cfg.auth_keys.empty()) {
            std::string default_auth = "/etc/yume/authorized_keys";
            if (ui_mode) {
                std::cout << "auth_keys path [/etc/yume/authorized_keys]: ";
                std::string input;
                std::getline(std::cin, input);
                if (!input.empty()) {
                    default_auth = input;
                }
            }
            cfg.auth_keys = default_auth;
        }
        if (cfg.auth_keys_meta.empty() && !cfg.auth_keys.empty()) {
            cfg.auth_keys_meta = cfg.auth_keys + ".json";
        }
        std::vector<EVP_PKEY*> keys;
        BIO* bio = BIO_new_file(cfg.auth_keys.c_str(), "r");
        if (bio) {
            while (true) {
                EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
                if (!key) {
                    break;
                }
                keys.push_back(key);
            }
            BIO_free(bio);
        }

        if (keys_list) {
            if (!file_readable(cfg.auth_keys)) {
                std::cout << "No auth_keys found at: " << cfg.auth_keys << "\n";
                std::cout << "Use option 2 to add a public key first.\n";
                for (auto* key : keys) EVP_PKEY_free(key);
                return 0;
            }
            nlohmann::json meta = nlohmann::json::object();
            std::ifstream in(cfg.auth_keys_meta);
            if (in) {
                try { in >> meta; } catch (...) { meta = nlohmann::json::object(); }
            }
            for (auto* key : keys) {
                std::string fp = yume::server::fingerprint_pubkey(key);
                auto entry = meta.value(fp, nlohmann::json::object());
                std::string alias = entry.value("alias", "");
                long long last_seen = entry.value("last_seen", 0LL);
                std::cout << fp;
                if (!alias.empty()) std::cout << "  alias=" << alias;
                if (last_seen > 0) std::cout << "  last_seen=" << last_seen;
                std::cout << "\n";
            }
            for (auto* key : keys) EVP_PKEY_free(key);
            return 0;
        }

        if (!keys_add.empty()) {
            auto auth_dir = std::filesystem::path(cfg.auth_keys).parent_path();
            if (!auth_dir.empty()) {
                ensure_dir(auth_dir.string());
            }
            BIO* inbio = BIO_new_file(keys_add.c_str(), "r");
            if (!inbio) {
                yume::util::log_error("failed to open key: " + keys_add);
                return 1;
            }
            EVP_PKEY* key = PEM_read_bio_PUBKEY(inbio, nullptr, nullptr, nullptr);
            BIO_free(inbio);
            if (!key) {
                yume::util::log_error("failed to parse key: " + keys_add);
                return 1;
            }
            BIO* outbio = BIO_new_file(cfg.auth_keys.c_str(), "a");
            if (!outbio) {
                EVP_PKEY_free(key);
                yume::util::log_error("failed to open auth_keys for append");
                return 1;
            }
            PEM_write_bio_PUBKEY(outbio, key);
            BIO_free(outbio);
            std::string fp = yume::server::fingerprint_pubkey(key);
            yume::server::update_auth_meta(cfg.auth_keys_meta, fp, keys_alias_value);
            EVP_PKEY_free(key);
            return 0;
        }

        if (!keys_gen.empty()) {
            std::filesystem::path base = std::filesystem::absolute(keys_gen);
            std::string priv_path = base.string() + ".key";
            std::string pub_path = base.string() + ".pub";
            auto key_dir = base.parent_path();
            if (!key_dir.empty()) {
                ensure_dir(key_dir.string());
            }
            if (!generate_ed25519_keypair(priv_path, pub_path)) {
                yume::util::log_error("failed to generate keypair");
                return 1;
            }
            std::cout << "Generated: " << priv_path << " and " << pub_path << "\n";
            if (keys_gen_add) {
                if (cfg.auth_keys.empty()) {
                    yume::util::log_error("auth_keys must be set to add generated key");
                    return 1;
                }
                auto auth_dir = std::filesystem::path(cfg.auth_keys).parent_path();
                if (!auth_dir.empty()) {
                    ensure_dir(auth_dir.string());
                }
                keys_add = pub_path;
                BIO* inbio = BIO_new_file(keys_add.c_str(), "r");
                if (!inbio) {
                    yume::util::log_error("failed to open key: " + keys_add);
                    return 1;
                }
                EVP_PKEY* key = PEM_read_bio_PUBKEY(inbio, nullptr, nullptr, nullptr);
                BIO_free(inbio);
                if (!key) {
                    yume::util::log_error("failed to parse key: " + keys_add);
                    return 1;
                }
                BIO* outbio = BIO_new_file(cfg.auth_keys.c_str(), "a");
                if (!outbio) {
                    EVP_PKEY_free(key);
                    yume::util::log_error("failed to open auth_keys for append");
                    return 1;
                }
                PEM_write_bio_PUBKEY(outbio, key);
                BIO_free(outbio);
                std::string fp = yume::server::fingerprint_pubkey(key);
                yume::server::update_auth_meta(cfg.auth_keys_meta, fp, keys_alias_value);
                EVP_PKEY_free(key);
            }
            return 0;
        }

        if (!keys_remove.empty() || !keys_alias.empty()) {
            nlohmann::json meta = nlohmann::json::object();
            std::ifstream in(cfg.auth_keys_meta);
            if (in) {
                try { in >> meta; } catch (...) { meta = nlohmann::json::object(); }
            }

            if (!keys_alias.empty()) {
                std::string target = keys_alias;
                for (auto it = meta.begin(); it != meta.end(); ++it) {
                    if (it.value().value("alias", "") == keys_alias) {
                        target = it.key();
                        break;
                    }
                }
                yume::server::update_auth_meta(cfg.auth_keys_meta, target, keys_alias_value);
                for (auto* key : keys) EVP_PKEY_free(key);
                return 0;
            }

            std::vector<EVP_PKEY*> remaining;
            for (auto* key : keys) {
                std::string fp = yume::server::fingerprint_pubkey(key);
                if (fp == keys_remove || meta.value(fp, nlohmann::json::object()).value("alias", "") == keys_remove) {
                    EVP_PKEY_free(key);
                    meta.erase(fp);
                    continue;
                }
                remaining.push_back(key);
            }
            BIO* outbio = BIO_new_file(cfg.auth_keys.c_str(), "w");
            if (!outbio) {
                for (auto* key : remaining) EVP_PKEY_free(key);
                yume::util::log_error("failed to rewrite auth_keys");
                return 1;
            }
            for (auto* key : remaining) {
                PEM_write_bio_PUBKEY(outbio, key);
                EVP_PKEY_free(key);
            }
            BIO_free(outbio);
            std::ofstream meta_out(cfg.auth_keys_meta);
            meta_out << meta.dump(2);
            return 0;
        }
    }

    if (!cfg.inner_crypto) {
        yume::util::log_warn("🔓⛓️‍💥 YOUR SECURITY IS SUFFERING BECAUSE YOU HAVE DISABLED: BASEFWX / PQ");
    }
    if (cfg.anonym && cfg.anonym_ca_key.empty() && !cfg.anonym_ca_cert.empty()) {
        yume::util::log_warn("anonym_ca_cert set but anonym_ca_key is missing; no CA signature will be produced");
    }
    if (cfg.anonym && !cfg.anonym_ca_key.empty() && cfg.anonym_ca_cert.empty()) {
        yume::util::log_warn("anonym_ca_key set but anonym_ca_cert is missing; clients cannot verify CA signature");
    }
    if (cfg.anonym && !cfg.anonym_sub_key.empty() && cfg.anonym_sub_cert.empty()) {
        yume::util::log_warn("anonym_sub_key set but anonym_sub_cert is missing; sub signature cannot be used");
    }
    if (cfg.anonym && cfg.anonym_sub_key.empty() && !cfg.anonym_sub_cert.empty()) {
        yume::util::log_warn("anonym_sub_cert set but anonym_sub_key is missing; no sub signature will be produced");
    }
    if (cfg.listen_port != 443 && !cfg.anonym) {
        yume::util::log_warn("WARNING: running on a port other than 443 reduces stealth and defeats HTTPS disguise.");
    }

    if (cfg.real_http) {
        if (cfg.real_secret.empty()) {
            const std::string secret_path = cfg.real_secret_file.empty() ? kDefaultSecretPath : cfg.real_secret_file;
            try {
                cfg.real_secret = load_or_create_secret(secret_path);
            } catch (const std::exception& ex) {
                yume::util::log_error(std::string("failed to load real_secret: ") + ex.what());
                return 1;
            }
        }
    }

    if (cfg.anonym) {
        if (cfg.anonym_api.empty()) {
            cfg.anonym_api = "https://api.fixcraft.jp/verity";
        }
        try {
            std::string self_path = get_self_path(argv[0]);
            if (self_path.empty()) {
                throw std::runtime_error("failed to locate executable path");
            }
            std::string bin = read_file_bytes(self_path);
            cfg.anonym_hash = sha256_hex(bin);
            if (!cfg.tls_cert.empty()) {
                cfg.anonym_certfp = cert_fingerprint_sha256(cfg.tls_cert);
            }
            auto proof = fetch_anonym_proof(cfg.anonym_hash, cfg.anonym_certfp, cfg.anonym_api,
                                            cfg.anonym_token, cfg.anonym_ca_key,
                                            cfg.anonym_sub_key, cfg.anonym_sub_cert);
            cfg.anonym_sig = proof.sig;
            cfg.anonym_ts = proof.ts;
            cfg.anonym_nonce = proof.nonce;
            cfg.anonym_ca_sig = proof.ca_sig;
            cfg.anonym_ca_alg = proof.ca_alg;
            cfg.anonym_sub_sig = proof.sub_sig;
            cfg.anonym_sub_alg = proof.sub_alg;
            cfg.anonym_sub_cert_b64 = proof.sub_cert_b64;
        } catch (const std::exception& ex) {
            std::cerr << "\033[1;31mANONYM PROOF FAILED: " << ex.what() << "\033[0m\n";
            return 1;
        }
        yume::util::set_logging_enabled(false);
        std::cerr << "\033[1;33mANONYM MODE ACTIVE — logging disabled (only critical notices will show)\033[0m\n";
    }

    boost::asio::io_context io;
    yume::server::Manager manager(io, cfg);
    std::atomic<bool> stop_refresh{false};
    std::thread refresh_thread;
    if (cfg.anonym) {
        refresh_thread = std::thread([&manager, &cfg, &stop_refresh]() {
            while (!stop_refresh.load()) {
                std::this_thread::sleep_for(std::chrono::seconds(kAnonymRefreshSeconds));
                if (stop_refresh.load()) {
                    break;
                }
                try {
                    auto proof = fetch_anonym_proof(cfg.anonym_hash, cfg.anonym_certfp, cfg.anonym_api,
                                                    cfg.anonym_token, cfg.anonym_ca_key,
                                                    cfg.anonym_sub_key, cfg.anonym_sub_cert);
                    manager.update_anonym_proof(proof.hash, proof.sig, proof.ts, proof.nonce,
                                                proof.certfp, proof.ca_sig, proof.ca_alg,
                                                proof.sub_sig, proof.sub_alg, proof.sub_cert_b64);
                } catch (const std::exception& ex) {
                    std::cerr << "\033[1;33mANONYM REFRESH FAILED: " << ex.what() << "\033[0m\n";
                }
            }
        });
    }

    std::atomic<bool> shutting_down{false};
    yume::util::install_signal_handlers([&](int sig) {
        if (sig == SIGTERM) {
            shutting_down.store(true);
        }
        if (shutting_down.exchange(true)) {
            std::cerr << "\033[1;31mforce exit requested\033[0m\n";
            std::_Exit(1);
        }
        if (yume::util::is_logging_enabled()) {
            yume::util::log_info("shutdown requested");
        } else {
            std::cerr << "\033[1;33mshutdown requested\033[0m\n";
        }
        manager.stop();
        io.stop();
        stop_refresh.store(true);
    });

    try {
        manager.start();
    } catch (const std::exception& ex) {
        if (yume::util::is_logging_enabled()) {
            yume::util::log_error(std::string("server start failed: ") + ex.what());
        } else {
            std::cerr << "\033[1;31mserver start failed: " << ex.what() << "\033[0m\n";
        }
        return 1;
    }

    int threads = cfg.threads > 0 ? cfg.threads : 1;
    std::vector<std::thread> workers;
    workers.reserve(static_cast<size_t>(threads));
    for (int i = 0; i < threads; ++i) {
        workers.emplace_back([&]() { io.run(); });
    }
    for (auto& t : workers) {
        t.join();
    }
    stop_refresh.store(true);
    if (refresh_thread.joinable()) {
        refresh_thread.join();
    }

    return 0;
}
