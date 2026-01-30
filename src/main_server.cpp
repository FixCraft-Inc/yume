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
#include <openssl/sha.h>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/pem.h>
#include <nlohmann/json.hpp>

#include "server/manager.hpp"
#include "server/auth.hpp"
#include "util.hpp"

namespace {
constexpr const char kAnonMsgPrefix[] = "YUME-ANON-V1:";
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
        << "  --pq-key <path>       (override pq_private_key)\n"
        << "  --allow-exec          (enable EXEC)\n"
        << "  --real                (serve real HTTP on non-client requests)\n"
        << "  --real-index <path>   (HTML file for /)\n"
        << "  --real-secret <str>   (secret for hidden metadata)\n"
        << "  --anonym              (enable anonym mode + proof)\n"
        << "  --anonym-api <url>    (verity API endpoint)\n"
        << "  --anonym-token <str>  (verity API token)\n"
        << "  --keys-list           (list authorized keys)\n"
        << "  --keys-add <pub.pem>  (add authorized key)\n"
        << "  --keys-remove <id>    (remove by fingerprint or alias)\n"
        << "  --keys-alias <id> <alias> (set alias)\n"
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
        << "  pq_private_key (path)\n"
        << "  allow_exec    (bool)\n"
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

std::string read_file_bytes(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open file: " + path);
    }
    std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return data;
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
    return nlohmann::json::parse(body_str);
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
        } else if (arg == "--pq-key" && i + 1 < argc) {
            cfg.pq_private_key = yume::util::expand_user(argv[++i]);
        } else if (arg == "--allow-exec") {
            cfg.allow_exec = true;
        } else if (arg == "--real") {
            cfg.real_http = true;
        } else if (arg == "--real-index" && i + 1 < argc) {
            cfg.real_index_path = argv[++i];
        } else if (arg == "--real-secret" && i + 1 < argc) {
            cfg.real_secret = argv[++i];
        } else if (arg == "--anonym") {
            cfg.anonym = true;
        } else if (arg == "--anonym-api" && i + 1 < argc) {
            cfg.anonym_api = argv[++i];
        } else if (arg == "--anonym-token" && i + 1 < argc) {
            cfg.anonym_token = argv[++i];
        } else if (arg == "--keys-add" && i + 1 < argc) {
            keys_add = argv[++i];
        } else if (arg == "--keys-remove" && i + 1 < argc) {
            keys_remove = argv[++i];
        } else if (arg == "--keys-alias" && i + 2 < argc) {
            keys_alias = argv[++i];
            keys_alias_value = argv[++i];
        } else if (arg == "--keys-list") {
            keys_list = true;
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
                if (!cfg.inner_crypto) {
                    cfg.inner_crypto = json["inner_crypto"].get<bool>();
                }
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
            if (json.contains("anonym")) {
                if (!cfg.anonym) {
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
        } catch (const std::exception& ex) {
            yume::util::log_error(std::string("config load failed: ") + ex.what());
            return 1;
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
    if (cfg.real_http && !cfg.real_index_path.empty() && !file_readable(cfg.real_index_path)) {
        yume::util::log_error("real_index_path not found: " + cfg.real_index_path);
        return 1;
    }

    if (cfg.auth_keys_meta.empty() && !cfg.auth_keys.empty()) {
        cfg.auth_keys_meta = cfg.auth_keys + ".json";
    }

    if (keys_list || !keys_add.empty() || !keys_remove.empty() || !keys_alias.empty()) {
        if (cfg.auth_keys.empty()) {
            yume::util::log_error("auth_keys must be set for key management");
            return 1;
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

    if (cfg.listen_port != 443 && !cfg.anonym) {
        yume::util::log_warn("WARNING: running on a port other than 443 reduces stealth and defeats HTTPS disguise.");
    }

    if (cfg.anonym) {
        yume::util::set_logging_enabled(false);
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
            cfg.anonym_ts = std::to_string(static_cast<long long>(std::time(nullptr)));
            cfg.anonym_nonce = yume::util::random_hex(16);
            nlohmann::json req{{"hash", cfg.anonym_hash}, {"ts", cfg.anonym_ts}, {"nonce", cfg.anonym_nonce}, {"prefix", kAnonMsgPrefix}};
            ApiEndpoint ep = parse_api_url(cfg.anonym_api);
            auto resp = post_json_https(ep.host, ep.port, ep.target, req, cfg.anonym_token);
            cfg.anonym_sig = resp.value("sig", "");
            if (cfg.anonym_sig.empty()) {
                throw std::runtime_error("anonym signature missing");
            }
        } catch (const std::exception& ex) {
            yume::util::log_error(std::string("anonym proof failed: ") + ex.what());
            return 1;
        }
    }

    boost::asio::io_context io;
    yume::server::Manager manager(io, cfg);

    yume::util::install_signal_handlers([&](int) {
        yume::util::log_info("shutdown requested");
        manager.stop();
        io.stop();
    });

    try {
        manager.start();
    } catch (const std::exception& ex) {
        yume::util::log_error(std::string("server start failed: ") + ex.what());
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

    return 0;
}
