/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include <iostream>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <utility>
#include <ctime>
#include <thread>
#include <vector>
#include <array>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <cctype>
#include <cstdlib>
#include <cstring>
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <io.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/pem.h>
#include <nlohmann/json.hpp>

#include "core/crypto.hpp"
#include "core/http_profile.hpp"
#include "core/identity.hpp"
#include "core/inner_crypto.hpp"
#include "core/runtime_policy.hpp"
#include "core/tls_fingerprint.hpp"
#include "core/tls_stealth.hpp"
#include "core/version.hpp"
#include "client/outbound_proxy.hpp"
#include "server/manager.hpp"
#include "server/auth.hpp"
#include "server/local_runtime.hpp"
#include "util.hpp"

namespace {
constexpr const char kAnonMsgPrefix[] = "YUME-ANON-V1:";
constexpr const char kPqMsgPrefix[] = "YUME-PQ-V1:";
constexpr const char kFixcraftAnonymPubPem[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAtupzLhANnB0VxP51vB/7yYwR+/3/jv4Str9MGLGA+is=\n"
    "-----END PUBLIC KEY-----\n";
constexpr const char kDefaultSecretPath[] = "./.secrets/html_secret";

void print_bash_completion() {
    std::cout << R"(# bash completion for yumed
_yumed_complete() {
  local cur prev
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  local opts="--help -h --version --credits --config --listen --cert --tls_cert --key --tls_key --auth-keys --threads --reverse-port-min --reverse-port-max --dns-server --proxy --obfs --obfs-secret --obfs-pad-multiple --obfs-jitter-ms --tls-handshake-timeout-ms --max-sessions --accept-rate-limit --egress-mbps --inner --no-inner --inner-heavy --inner-light --inner-dual --inner-required --hop --no-hop --hop-interval --pq-key --pq-auto-generate --use-embedded-master --no-embedded-master --allow-exec --allow-local-ip --control-full --real --real-index --real-secret --real-secret-file --anonym --anonym-proof-mode --anonym-api --anonym-token --anonym-ca-key --anonym-ca-cert --anonym-sub-key --anonym-sub-cert --server-name --server-id --relay-enable --relay-disable --directory-enable --directory-disable --operator-keys --federation-enable --federation-auth-key --federation-anonym-ca --peer --cluster-join --cluster-bootstrap --public-node --hide-in-the-crowd --upstream-response --upstream-response-dir --upstream-response-ttl --attach-local --keys-list --keys-add --keys-remove --keys-alias --keys-gen --keys-gen-add --ui --boring --timing --completion --root"
  local file_opts="--config --cert --tls_cert --key --tls_key --auth-keys --pq-key --real-index --real-secret-file --anonym-ca-key --anonym-ca-cert --anonym-sub-key --anonym-sub-cert --federation-auth-key --federation-anonym-ca --keys-add --keys-gen"
  case "$prev" in
    --completion)
      COMPREPLY=( $(compgen -W "bash" -- "$cur") )
      return 0
      ;;
  esac
  for opt in $file_opts; do
    if [[ "$prev" == "$opt" ]]; then
      COMPREPLY=( $(compgen -f -- "$cur") )
      return 0
    fi
  done
  if [[ "$cur" == -* ]]; then
    COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
    return 0
  fi
  COMPREPLY=()
}
complete -F _yumed_complete yumed
)";
}

void print_version() {
    std::cout
        << "yumed " << yume::kVersion << "\n"
        << "BaseFWX: " << yume::kBasefwxVersion << "\n"
        << "OpenSSL: " << OpenSSL_version(OPENSSL_VERSION) << "\n"
        << "PQ/ML-KEM: " << yume::inner::pq_backend_version() << "\n"
        << "Argon2id: " << yume::inner::argon2_backend_version() << "\n"
        << "PBKDF2/HKDF fallback: " << (yume::inner::pbkdf2_supported() ? "available" : "unavailable") << "\n";
}

void print_credits() {
    std::cout
        << "YUME credits\n"
        << "Author: F1xGOD - founder, lead developer, and designer of Yume and BaseFWX.\n"
        << "Engineering partners:\n"
        << "  Claude (Anthropic) - Yume/BaseFWX engineering partner.\n"
        << "  ChatGPT / Codex - implementation and debugging support.\n"
        << "Core open-source components:\n"
        << "  BaseFWX - GPL-3.0\n"
        << "  liboqs (Open Quantum Safe) - MIT\n"
        << "  OpenSSL - Apache-2.0\n"
        << "  Boost.Asio - Boost Software License 1.0\n"
        << "  nlohmann/json - MIT\n"
        << "  spdlog - MIT\n"
        << "  zstd - BSD-3-Clause\n";
}

void print_help() {
    std::cout
        << "yumed - YUME server\n\n"
        << "Usage:\n"
        << "  yumed [--config <path>] [options]\n"
        << "  yumed completion bash\n"
        << "  yumed --help\n"
        << "  yumed --version\n"
        << "  yumed --credits\n\n"
        << "Core:\n"
        << "  --config <path>          Config file\n"
        << "  --listen <port>          Override listen_port (binds 0.0.0.0:<port>)\n"
        << "  --listen <addr>:<port>   Bind specifically to <addr>:<port>\n"
        << "                             (use [::1]:443 / [::]:443 for IPv6).\n"
        << "                             Under --public-node, addresses in\n"
        << "                             RFC 1918 / loopback / link-local /\n"
        << "                             CGNAT / IPv6 ULA are refused at startup.\n"
        << "  --cert <path>            TLS certificate\n"
        << "  --key <path>             TLS private key\n"
        << "  --auth-keys <path>       Override auth_keys\n"
        << "  --threads <n>            Worker thread count (0 = auto)\n"
        << "  --reverse-port-min <p>   Reverse listen minimum (default "
        << yume::policy::kReversePortMinDefault << ")\n"
        << "  --reverse-port-max <p>   Reverse listen maximum (default "
        << yume::policy::kReversePortMaxDefault << ")\n"
        << "  --dns-server <ip>        Direct DNS resolver for outbound opens\n"
        << "  --proxy <socks5://...>   Route server outbound TCP through SOCKS5\n"
        << "  --obfs                   Enable obfuscation\n"
        << "  --obfs-pad-multiple <N>  Pad every outbound frame payload to a\n"
        << "                             multiple of N bytes (0-256, default 0).\n"
        << "                             Defeats per-packet size classifiers.\n"
        << "                             Requires the same yume version on the\n"
        << "                             client (kFlagPadded support).\n"
        << "  --obfs-jitter-ms <ms>    Defer each batched write by a uniform\n"
        << "                             random 0..ms delay (default 0). Breaks\n"
        << "                             the inter-arrival ML signature at the\n"
        << "                             cost of added latency.\n"
        << "  --tls-handshake-timeout-ms <ms>\n"
        << "                           Close the socket if the TLS handshake\n"
        << "                             doesn't complete in this many ms.\n"
        << "                             Slow-loris guard. 0 = no deadline\n"
        << "                             (legacy). --public-node defaults to\n"
        << "                             10000 when unset.\n"
        << "  --max-sessions <N>       Hard cap on simultaneously-tracked\n"
        << "                             sessions. New accepts past the cap are\n"
        << "                             closed immediately (looks like a busy\n"
        << "                             nginx). 0 = unlimited. --public-node\n"
        << "                             defaults to 4096 when unset.\n"
        << "  --accept-rate-limit <N>  Cap on accepts per second over a 1 s\n"
        << "                             rolling window. Refused accepts close\n"
        << "                             immediately. 0 = unlimited.\n"
        << "                             --public-node defaults to 100 when unset.\n"
        << "  --egress-mbps <N>        Weighted fair egress cap across auth keys.\n"
        << "                             0 = disabled. One active key can use the\n"
        << "                             full cap; equal active keys split it.\n"
        << "                             auth_keys_meta priority 1..100 controls\n"
        << "                             weighted shares (default 50).\n"
        << "  --allow-local-ip         Allow private/loopback destinations\n"
        << "  --control-full           Allow full server-side network control\n"
        << "  --root                   Keep root privileges after bind/listen\n"
        << "  --boring                 Minimal logs\n"
        << "  --timing                 Emit lightweight timing diagnostics\n\n"
        << "Security:\n"
        << "  --inner                  Enable inner PQ crypto\n"
        << "  --no-inner               Disable inner PQ crypto and hopping\n"
        << "  --inner-heavy            Heavy KDF mode\n"
        << "  --inner-light            Light KDF mode\n"
        << "  --inner-dual             Accept heavy and light clients\n"
        << "  --inner-required         Reject clients without inner crypto\n"
        << "  --hop / --no-hop         Inner key hopping on/off\n"
        << "  --hop-interval <ms>      Hop interval\n"
        << "  --pq-key <path>          PQ private key\n"
        << "  --pq-auto-generate       Generate a PQ keypair when needed\n"
        << "  --use-embedded-master    Allow embedded BaseFWX master fallback\n"
        << "  --no-embedded-master     Disable embedded BaseFWX master fallback\n\n"
        << "HTTP / Anonym:\n"
        << "  --real                   Serve real HTTP for non-client requests\n"
        << "  --real-index <path>      HTML file for /\n"
        << "  --real-secret <str>      Hidden metadata secret\n"
        << "  --real-secret-file <path> Load or create secret file\n"
        << "  --anonym                 Enable anonym mode\n"
        << "  --anonym-proof-mode <m>  auto, local, or fixcraft\n"
        << "  --anonym-api <url>       Verity API URL\n"
        << "  --anonym-token <str>     Verity API token\n"
        << "  --anonym-ca-key <path>   Anonym CA private key\n"
        << "  --anonym-ca-cert <path>  Anonym CA certificate\n"
        << "  --anonym-sub-key <path>  Anonym sub-CA private key\n"
        << "  --anonym-sub-cert <path> Anonym sub-CA certificate\n\n"
        << "Relay and Runtime:\n"
        << "  --server-name <name>     Server name\n"
        << "  --server-id <32hex>      Stable server endpoint ID\n"
        << "  --relay-enable           Enable client relay features\n"
        << "  --relay-disable          Disable client relay features\n"
        << "  --directory-enable       Enable endpoint directory\n"
        << "  --directory-disable      Disable endpoint directory\n"
        << "  --operator-keys <path>   Operator key metadata\n"
        << "  --federation-enable      Enable static federation mode\n"
        << "  --federation-auth-key <path> Ed25519 key used for peer AUTH\n"
        << "  --federation-anonym-ca <path> CA used to verify peer servers\n"
        << "  --peer <json>            Add a federation peer (raw JSON form)\n"
        << "  --cluster-join <spec>    Join cluster via short form; implies --federation-enable.\n"
        << "                             spec: [id@]host[:port][?pin=<sha256>]\n"
        << "                             e.g. alice@alice.example.com:443\n"
        << "                                  alice.example.com (id+port defaulted)\n"
        << "                             repeat for multiple peers\n"
        << "  --cluster-bootstrap      Mark this node as a cluster entry point;\n"
        << "                             federation enabled but no outbound --peer required\n"
        << "                             (other servers will dial in via --cluster-join)\n"
        << "  --public-node            Hardening preset for an internet-facing yumed.\n"
        << "                             Rejects --allow-exec / --allow-local-ip /\n"
        << "                             --control-full / --no-inner; requires --auth-keys;\n"
        << "                             logs what is and is not yet enforced.\n"
        << "                             Also implicitly sets --hide-in-the-crowd nginx\n"
        << "                             when no profile is otherwise selected.\n"
        << "  --hide-in-the-crowd <p>  HTTP-layer disguise profile for the disguise\n"
        << "                             responses this daemon emits when probed.\n"
        << "                             Values: nginx, nginx-stable, apache, caddy,\n"
        << "                             cloudflare, express, gunicorn, none, yumed\n"
        << "                             (default: yumed; nginx under --public-node).\n"
        << "  --upstream-response <p>  Replay a pre-captured real HTTP/1.x response\n"
        << "                             byte-identically when probed. Capture with\n"
        << "                             `curl -i https://real-site/notfound > resp.http`\n"
        << "                             once and point this flag at it. Wins over\n"
        << "                             --hide-in-the-crowd when both are set.\n"
        << "  --upstream-response-dir <d>\n"
        << "                           Like --upstream-response but loads every\n"
        << "                             *.http / *.response in the directory and\n"
        << "                             picks one at random per probe. Defeats\n"
        << "                             'probe twice, get identical bytes' replay\n"
        << "                             checks. Wins over --upstream-response when\n"
        << "                             both are set.\n"
        << "  --upstream-response-ttl <s>\n"
        << "                           When used with --upstream-response-dir, reloads\n"
        << "                             the directory every <s> seconds so operators\n"
        << "                             can drop new captures in without restarting.\n"
        << "                             0 = load once at startup (default).\n"
        << "  --attach-local           Attach to a local yumed\n\n"
        << "Key Management:\n"
        << "  --keys-list              List authorized keys\n"
        << "  --keys-add <pub.pem>     Add authorized key\n"
        << "  --keys-remove <id>       Remove by fingerprint or alias\n"
        << "  --keys-alias <id> <a>    Set alias\n"
        << "  --keys-gen <prefix>      Generate Ed25519 keypair (<prefix>.key/.pub)\n"
        << "  --keys-gen-add           Append generated public key to auth_keys\n"
        << "  auth_keys_meta supports federation_peer_id, priority, and permissions.{allow_local_ip,control_full,allow_exec,allow_chat,allow_file,allow_bytes,allow_inbound_admin,allow_outbound_admin}\n"
        << "  --ui                     Interactive server manager\n\n"
        << "Other:\n"
        << "  completion bash\n"
        << "  -h, --help               Show help\n"
        << "  --version                Show version and compiled crypto capabilities\n"
        << "  --credits                Show credits and bundled component acknowledgements\n";
}

std::string trim_copy(std::string s) {
    auto is_space = [](unsigned char ch) { return std::isspace(ch) != 0; };
    while (!s.empty() && is_space(static_cast<unsigned char>(s.front()))) {
        s.erase(s.begin());
    }
    while (!s.empty() && is_space(static_cast<unsigned char>(s.back()))) {
        s.pop_back();
    }
    return s;
}

bool prompt_attach_existing(const std::string& kind) {
    #if defined(_WIN32)
    if (_isatty(_fileno(stdin)) == 0) {
        return false;
    }
    #else
    if (isatty(fileno(stdin)) == 0) {
        return false;
    }
    #endif
    std::cout << kind << " is already running. Attach to the existing instance? [Y/n] " << std::flush;
    std::string answer;
    if (!std::getline(std::cin, answer)) {
        return true;
    }
    answer = trim_copy(answer);
    if (answer.empty()) {
        return true;
    }
    std::transform(answer.begin(), answer.end(), answer.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return answer == "y" || answer == "yes";
}

bool stdin_is_tty() {
#if defined(_WIN32)
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(fileno(stdin)) != 0;
#endif
}

std::string effective_server_instance_key(const yume::server::ServerConfig& cfg, const std::string& config_path) {
    if (!cfg.ipc_path.empty()) {
        return cfg.ipc_path;
    }
    if (!cfg.server_id.empty()) {
        return cfg.server_id;
    }
    return yume::identity::derive_instance_key(
        std::to_string(cfg.listen_port) + "|" + cfg.tls_cert + "|" + cfg.auth_keys + "|" + config_path);
}

nlohmann::json request_local_server_runtime(const std::string& socket_path,
                                           const std::string& op,
                                           const nlohmann::json& args,
                                           std::string* error) {
    return yume::server::LocalRuntime::request(
        socket_path,
        nlohmann::json{{"op", op}, {"args", args}},
        error,
        10000);
}

int run_local_server_attach(const std::string& socket_path, bool non_interactive) {
    std::string error;
    if (non_interactive) {
        auto resp = request_local_server_runtime(socket_path, "runtime.status", nlohmann::json::object(), &error);
        if (!error.empty() || !resp.value("ok", false)) {
            yume::util::log_error(error.empty() ? resp.value("error", "status failed") : error);
            return 1;
        }
        std::cout << resp["result"].dump(2) << std::endl;
        return 0;
    }

    yume::util::log_info("Attached to existing yumed runtime");
    yume::util::log_info("Attached console: help | status | sessions | directory | peers | federation | disconnect <endpoint-id> | stop | quit");
    for (;;) {
        std::string line;
        if (!std::getline(std::cin, line)) {
            return 0;
        }
        line = trim_copy(line);
        if (line.empty()) {
            continue;
        }
        if (line == "help") {
            yume::util::log_info("Commands: help | status | sessions | directory | peers | federation | disconnect <endpoint-id> | stop | quit");
            continue;
        }
        if (line == "quit" || line == "exit") {
            return 0;
        }
        if (line == "status") {
            auto resp = request_local_server_runtime(socket_path, "runtime.status", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                yume::util::log_warn(error.empty() ? resp.value("error", "status failed") : error);
                error.clear();
            } else {
                std::cout << resp["result"].dump(2) << std::endl;
            }
            continue;
        }
        if (line == "sessions") {
            auto resp = request_local_server_runtime(socket_path, "runtime.sessions", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                yume::util::log_warn(error.empty() ? resp.value("error", "sessions failed") : error);
                error.clear();
            } else {
                std::cout << resp["result"].dump(2) << std::endl;
            }
            continue;
        }
        if (line == "directory") {
            auto resp = request_local_server_runtime(socket_path, "directory.list", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                yume::util::log_warn(error.empty() ? resp.value("error", "directory failed") : error);
                error.clear();
                continue;
            }
            for (const auto& entry : resp["result"]) {
                std::cout << entry.value("endpoint_id", "") << " "
                          << entry.value("display_name", "")
                          << " kind=" << entry.value("endpoint_kind", "")
                          << " relay=" << entry.value("relay_mode", "")
                          << std::endl;
            }
            continue;
        }
        if (line == "peers" || line == "federation") {
            auto resp = request_local_server_runtime(socket_path, "federation.status", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                yume::util::log_warn(error.empty() ? resp.value("error", "federation failed") : error);
                error.clear();
            } else {
                const auto& result = resp["result"];
                if (!result.value("enabled", false)) {
                    std::cout << "federation disabled\n";
                    continue;
                }
                if (!result.contains("peer_status") || result["peer_status"].empty()) {
                    std::cout << "federation enabled, no peer status\n";
                    continue;
                }
                for (const auto& peer : result["peer_status"]) {
                    std::cout << peer.value("id", "")
                              << " state=" << peer.value("state", "")
                              << " ready=" << (peer.value("ready", false) ? "yes" : "no")
                              << " channels=" << peer.value("channels_active", 0)
                              << " last_handshake=" << peer.value("last_handshake_ts", 0LL);
                    const std::string last_error = peer.value("last_error", "");
                    if (!last_error.empty()) {
                        std::cout << " error=" << last_error;
                    }
                    std::cout << std::endl;
                }
            }
            continue;
        }
        if (line.rfind("disconnect ", 0) == 0) {
            auto resp = request_local_server_runtime(socket_path, "runtime.disconnect",
                                                     {{"endpoint_id", trim_copy(line.substr(11))}}, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                yume::util::log_warn(error.empty() ? resp.value("error", "disconnect failed") : error);
                error.clear();
            }
            continue;
        }
        if (line == "stop") {
            auto resp = request_local_server_runtime(socket_path, "runtime.stop", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                yume::util::log_warn(error.empty() ? resp.value("error", "stop failed") : error);
                error.clear();
            }
            return 0;
        }
        yume::util::log_warn("unknown command: " + line);
    }
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
#if defined(_WIN32)
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        return std::string(buf, len);
    }
#elif defined(__APPLE__)
    uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);
    if (size > 0) {
        std::string out(size, '\0');
        if (_NSGetExecutablePath(out.data(), &size) == 0) {
            auto end = out.find('\0');
            if (end != std::string::npos) {
                out.resize(end);
            }
            std::error_code ec;
            return std::filesystem::absolute(out, ec).string();
        }
    }
#else
    std::error_code ec;
    auto p = std::filesystem::read_symlink("/proc/self/exe", ec);
    if (!ec) {
        return p.string();
    }
#endif
    if (argv0 && argv0[0] != '\0') {
        return std::filesystem::absolute(argv0).string();
    }
    return {};
}

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
    // Talking to public HTTPS endpoints (anonym verity push) — TLS 1.2+ keeps
    // us compatible with the broadest set of well-known CAs/CDNs while still
    // rejecting SSLv3/TLS1.0/1.1.
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

bool parse_env_bool(const char* name, bool fallback) {
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

// Translates the --cluster-join short form into the JSON peer entry
// the existing FederationManager::parse_peer consumer expects.
//
// Accepted shapes:
//   alice                          → {"id":"alice","url":"yume://alice:443"}
//   alice:8443                     → {"id":"alice","url":"yume://alice:8443"}
//   alice@alice.example.com        → {"id":"alice","url":"yume://alice.example.com:443"}
//   alice@alice.example.com:8443   → {"id":"alice","url":"yume://alice.example.com:8443"}
//   alice@alice.example.com:8443?pin=sha256:abc
//                                   → ...,"tls_pin":"sha256:abc"
//
// IPv6 hosts must be bracketed: alice@[2001:db8::1]:443
//
// Throws std::runtime_error on invalid input; the caller is the CLI
// flag handler which will log and exit non-zero.
std::string expand_cluster_join_spec(const std::string& spec) {
    if (spec.empty()) {
        throw std::runtime_error("--cluster-join argument is empty");
    }
    std::string body = spec;
    std::string pin;
    auto qpos = body.find('?');
    if (qpos != std::string::npos) {
        std::string query = body.substr(qpos + 1);
        body.resize(qpos);
        // Only `pin=` is recognised today. Quietly ignore unknown
        // keys so future query parameters don't break old binaries.
        std::size_t cursor = 0;
        while (cursor < query.size()) {
            auto amp = query.find('&', cursor);
            std::string pair = query.substr(cursor, amp == std::string::npos ? std::string::npos : amp - cursor);
            cursor = amp == std::string::npos ? query.size() : amp + 1;
            auto eq = pair.find('=');
            if (eq == std::string::npos) continue;
            std::string key = pair.substr(0, eq);
            std::string val = pair.substr(eq + 1);
            if (key == "pin") {
                pin = std::move(val);
            }
        }
    }
    std::string id;
    std::string hostport = body;
    auto at = body.find('@');
    if (at != std::string::npos) {
        id = body.substr(0, at);
        hostport = body.substr(at + 1);
    }
    // Detect bracketed IPv6 and split on the FIRST colon after the
    // closing bracket. For non-bracketed forms, the rightmost colon
    // separates host and port (so plain `alice` or `alice:443` work).
    std::string host;
    int port = 443;
    if (!hostport.empty() && hostport.front() == '[') {
        auto close = hostport.find(']');
        if (close == std::string::npos) {
            throw std::runtime_error("--cluster-join: unmatched '[' in " + spec);
        }
        host = hostport.substr(1, close - 1);
        if (close + 1 < hostport.size()) {
            if (hostport[close + 1] != ':') {
                throw std::runtime_error("--cluster-join: expected ':port' after ']' in " + spec);
            }
            try {
                port = std::stoi(hostport.substr(close + 2));
            } catch (const std::exception&) {
                throw std::runtime_error("--cluster-join: invalid port in " + spec);
            }
        }
    } else {
        auto colon = hostport.rfind(':');
        if (colon == std::string::npos) {
            host = hostport;
        } else {
            host = hostport.substr(0, colon);
            try {
                port = std::stoi(hostport.substr(colon + 1));
            } catch (const std::exception&) {
                throw std::runtime_error("--cluster-join: invalid port in " + spec);
            }
        }
    }
    if (host.empty()) {
        throw std::runtime_error("--cluster-join: empty host in " + spec);
    }
    if (port <= 0 || port > 65535) {
        throw std::runtime_error("--cluster-join: port out of range in " + spec);
    }
    if (id.empty()) {
        id = host;
    }
    nlohmann::json peer;
    peer["id"] = id;
    peer["url"] = std::string("yume://") + (host.find(':') != std::string::npos
                                                ? "[" + host + "]"
                                                : host) +
                  ":" + std::to_string(port);
    if (!pin.empty()) {
        peer["tls_pin"] = pin;
    }
    return peer.dump();
}

bool anonym_local_sign_default() {
    return true;
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
    std::string proof_policy;
    std::vector<std::string> proof_sources;
    std::string pq_pub_b64;
    std::string pq_sig;
    std::string pq_alg;
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
}  // namespace

int main(int argc, char** argv) {
    yume::util::init_logging();

    yume::server::ServerConfig cfg;
    std::string cli_cwd;
    {
        std::error_code ec;
        auto cwd = std::filesystem::current_path(ec);
        if (!ec) {
            cli_cwd = cwd.string();
        }
    }
    auto resolve_cli_path = [&](const std::string& value) {
        return yume::util::resolve_path(value, cli_cwd, "");
    };
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
    bool inner_dual_override = false;
    bool inner_required_override = false;
    bool inner_hop_override = false;
    bool inner_hop_value = true;
    bool hop_interval_override = false;
    bool anonym_override = false;
    bool anonym_proof_mode_override = false;
    bool pq_auto_generate_override = false;
    bool allow_embedded_master_override = false;
    // Track whether operator explicitly set the new hardening knobs so
    // the --public-node defaults don't overwrite them.
    bool tls_handshake_timeout_override = false;
    bool max_sessions_override = false;
    bool accept_rate_limit_override = false;
    bool egress_mbps_override = false;
    bool relay_enable_override = false;
    bool directory_enable_override = false;
    bool attach_local = false;
    bool keep_root = false;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "completion" || arg == "--completion") && i + 1 < argc) {
            std::string shell = argv[++i];
            if (shell == "bash") {
                print_bash_completion();
                return 0;
            }
            yume::util::log_error("unsupported completion shell: " + shell);
            return 1;
        }
        if (arg == "--help" || arg == "-h") {
            print_help();
            return 0;
        }
        if (arg == "--version") {
            print_version();
            return 0;
        }
        if (arg == "--credits") {
            print_credits();
            return 0;
        }
        if (arg == "--config" && i + 1 < argc) {
            config_path = argv[++i];
            config_specified = true;
        } else if (arg == "--listen" && i + 1 < argc) {
            // Two forms:
            //   --listen 443           → bind 0.0.0.0:443 (legacy)
            //   --listen 1.2.3.4:443   → bind specifically to that IP
            //   --listen [::1]:443     → IPv6 with bracket syntax
            //   --listen [::]:443      → IPv6 any
            std::string raw = argv[++i];
            std::string addr_part;
            std::string port_part;
            if (!raw.empty() && raw.front() == '[') {
                // [addr]:port form
                auto rbr = raw.find(']');
                if (rbr == std::string::npos || rbr + 2 > raw.size() || raw[rbr + 1] != ':') {
                    yume::util::log_error("--listen: bracket form must be [addr]:port");
                    return 1;
                }
                addr_part = raw.substr(1, rbr - 1);
                port_part = raw.substr(rbr + 2);
            } else {
                auto colon = raw.rfind(':');
                if (colon == std::string::npos) {
                    // Port-only legacy form
                    port_part = raw;
                } else {
                    addr_part = raw.substr(0, colon);
                    port_part = raw.substr(colon + 1);
                }
            }
            try {
                cfg.listen_port = std::stoi(port_part);
            } catch (const std::exception&) {
                yume::util::log_error("--listen: cannot parse port '" + port_part + "'");
                return 1;
            }
            if (cfg.listen_port < 1 || cfg.listen_port > 65535) {
                yume::util::log_error("--listen: port out of range 1..65535: " + port_part);
                return 1;
            }
            cfg.listen_address = addr_part;
        } else if (arg == "--reverse-port-min" && i + 1 < argc) {
            cfg.reverse_port_min = std::stoi(argv[++i]);
        } else if (arg == "--reverse-port-max" && i + 1 < argc) {
            cfg.reverse_port_max = std::stoi(argv[++i]);
        } else if (arg == "--dns-server" && i + 1 < argc) {
            cfg.dns_server = argv[++i];
        } else if (arg == "--proxy" && i + 1 < argc) {
            cfg.outbound_proxy_url = argv[++i];
        } else if ((arg == "--cert" || arg == "--tls_cert") && i + 1 < argc) {
            cfg.tls_cert = resolve_cli_path(argv[++i]);
        } else if ((arg == "--key" || arg == "--tls_key") && i + 1 < argc) {
            cfg.tls_key = resolve_cli_path(argv[++i]);
        } else if (arg == "--auth-keys" && i + 1 < argc) {
            cfg.auth_keys = resolve_cli_path(argv[++i]);
        } else if (arg == "--threads" && i + 1 < argc) {
            cfg.threads = std::stoi(argv[++i]);
        } else if (arg == "--obfs") {
            cfg.obfuscation = true;
        } else if (arg == "--no-obfs") {
            cfg.obfuscation = false;
        } else if (arg == "--obfs-secret" && i + 1 < argc) {
            cfg.obfs_secret = argv[++i];
        } else if (arg == "--obfs-pad-multiple" && i + 1 < argc) {
            int parsed = std::atoi(argv[++i]);
            if (parsed < 0) parsed = 0;
            if (parsed > 256) parsed = 256;
            cfg.obfs_pad_multiple = static_cast<std::uint16_t>(parsed);
        } else if (arg == "--obfs-jitter-ms" && i + 1 < argc) {
            int parsed = std::atoi(argv[++i]);
            if (parsed < 0) parsed = 0;
            cfg.obfs_jitter_ms = static_cast<std::uint32_t>(parsed);
        } else if (arg == "--tls-handshake-timeout-ms" && i + 1 < argc) {
            int parsed = std::atoi(argv[++i]);
            if (parsed < 0) parsed = 0;
            cfg.tls_handshake_timeout_ms = static_cast<std::uint32_t>(parsed);
            tls_handshake_timeout_override = true;
        } else if (arg == "--max-sessions" && i + 1 < argc) {
            int parsed = std::atoi(argv[++i]);
            if (parsed < 0) parsed = 0;
            cfg.max_sessions = static_cast<std::uint32_t>(parsed);
            max_sessions_override = true;
        } else if (arg == "--accept-rate-limit" && i + 1 < argc) {
            int parsed = std::atoi(argv[++i]);
            if (parsed < 0) parsed = 0;
            cfg.accept_rate_limit = static_cast<std::uint32_t>(parsed);
            accept_rate_limit_override = true;
        } else if (arg == "--egress-mbps" && i + 1 < argc) {
            int parsed = std::atoi(argv[++i]);
            if (parsed < 0) parsed = 0;
            cfg.egress_mbps = static_cast<std::uint32_t>(parsed);
            egress_mbps_override = true;
        } else if (arg == "--inner") {
            yume::util::log_warn("--inner is deprecated; use --inner-heavy or --inner-light");
            cfg.inner_crypto = true;
            inner_crypto_override = true;
            inner_heavy_override = true;
            inner_heavy_value = true;
        } else if (arg == "--no-inner") {
            cfg.inner_crypto = false;
            cfg.inner_dual = false;
            cfg.inner_required = false;
            cfg.inner_hop = false;
            inner_crypto_override = true;
            inner_dual_override = true;
            inner_required_override = true;
            inner_hop_override = true;
            inner_hop_value = false;
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
        } else if (arg == "--inner-dual") {
            cfg.inner_crypto = true;
            cfg.inner_dual = true;
            inner_crypto_override = true;
            inner_dual_override = true;
        } else if (arg == "--inner-required") {
            cfg.inner_crypto = true;
            cfg.inner_required = true;
            inner_crypto_override = true;
            inner_required_override = true;
        } else if (arg == "--hop") {
            cfg.inner_hop = true;
            inner_hop_override = true;
            inner_hop_value = true;
        } else if (arg == "--no-hop") {
            cfg.inner_hop = false;
            inner_hop_override = true;
            inner_hop_value = false;
        } else if (arg == "--hop-interval" && i + 1 < argc) {
            cfg.hop_interval_ms = static_cast<std::uint32_t>(std::stoul(argv[++i]));
            hop_interval_override = true;
        } else if (arg == "--pq-key" && i + 1 < argc) {
            cfg.pq_private_key = resolve_cli_path(argv[++i]);
            inner_crypto_override = true;
        } else if (arg == "--pq-auto-generate") {
            cfg.pq_auto_generate = true;
            pq_auto_generate_override = true;
        } else if (arg == "--use-embedded-master") {
            cfg.allow_embedded_master = true;
            allow_embedded_master_override = true;
        } else if (arg == "--no-embedded-master") {
            cfg.allow_embedded_master = false;
            allow_embedded_master_override = true;
        } else if (arg == "--allow-exec") {
            cfg.allow_exec = true;
        } else if (arg == "--allow-local-ip") {
            cfg.allow_local_ip = true;
        } else if (arg == "--control-full") {
            cfg.control_full = true;
        } else if (arg == "--real") {
            cfg.real_http = true;
        } else if (arg == "--real-index" && i + 1 < argc) {
            cfg.real_index_path = resolve_cli_path(argv[++i]);
        } else if (arg == "--real-secret" && i + 1 < argc) {
            cfg.real_secret = argv[++i];
        } else if (arg == "--real-secret-file" && i + 1 < argc) {
            cfg.real_secret_file = resolve_cli_path(argv[++i]);
        } else if (arg == "--anonym") {
            cfg.anonym = true;
            anonym_override = true;
        } else if (arg == "--anonym-proof-mode" && i + 1 < argc) {
            cfg.anonym_proof_mode = argv[++i];
            anonym_proof_mode_override = true;
        } else if (arg == "--anonym-api" && i + 1 < argc) {
            cfg.anonym_api = argv[++i];
        } else if (arg == "--anonym-token" && i + 1 < argc) {
            cfg.anonym_token = argv[++i];
        } else if (arg == "--anonym-ca-key" && i + 1 < argc) {
            cfg.anonym_ca_key = resolve_cli_path(argv[++i]);
        } else if (arg == "--anonym-ca-cert" && i + 1 < argc) {
            cfg.anonym_ca_cert = resolve_cli_path(argv[++i]);
        } else if (arg == "--anonym-sub-key" && i + 1 < argc) {
            cfg.anonym_sub_key = resolve_cli_path(argv[++i]);
        } else if (arg == "--anonym-sub-cert" && i + 1 < argc) {
            cfg.anonym_sub_cert = resolve_cli_path(argv[++i]);
        } else if (arg == "--server-name" && i + 1 < argc) {
            cfg.server_name = argv[++i];
        } else if (arg == "--server-id" && i + 1 < argc) {
            cfg.server_id = argv[++i];
        } else if (arg == "--relay-enable") {
            cfg.relay_enable = true;
            relay_enable_override = true;
        } else if (arg == "--relay-disable") {
            cfg.relay_enable = false;
            relay_enable_override = true;
        } else if (arg == "--directory-enable") {
            cfg.directory_enable = true;
            directory_enable_override = true;
        } else if (arg == "--directory-disable") {
            cfg.directory_enable = false;
            directory_enable_override = true;
        } else if (arg == "--allow-remote-server-admin") {
            yume::util::log_warn("--allow-remote-server-admin was never wired to a check; flag removed (ignored)");
        } else if (arg == "--operator-keys" && i + 1 < argc) {
            cfg.operator_keys = resolve_cli_path(argv[++i]);
        } else if (arg == "--federation-enable") {
            cfg.federation_enable = true;
        } else if (arg == "--federation-auth-key" && i + 1 < argc) {
            cfg.federation_auth_key = resolve_cli_path(argv[++i]);
        } else if (arg == "--federation-anonym-ca" && i + 1 < argc) {
            cfg.federation_anonym_ca = resolve_cli_path(argv[++i]);
        } else if (arg == "--peer" && i + 1 < argc) {
            cfg.federation_peers.push_back(argv[++i]);
        } else if (arg == "--cluster-join" && i + 1 < argc) {
            const std::string spec = argv[++i];
            try {
                cfg.federation_peers.push_back(expand_cluster_join_spec(spec));
            } catch (const std::exception& ex) {
                yume::util::log_error(ex.what());
                return 1;
            }
            cfg.federation_enable = true;
        } else if (arg == "--cluster-bootstrap") {
            cfg.federation_enable = true;
            cfg.cluster_bootstrap = true;
        } else if (arg == "--public-node") {
            cfg.public_node = true;
        } else if (arg == "--hide-in-the-crowd" && i + 1 < argc) {
            cfg.http_profile = argv[++i];
        } else if (arg == "--upstream-response" && i + 1 < argc) {
            cfg.upstream_response_file = resolve_cli_path(argv[++i]);
        } else if (arg == "--upstream-response-dir" && i + 1 < argc) {
            cfg.upstream_response_dir = resolve_cli_path(argv[++i]);
        } else if (arg == "--upstream-response-ttl" && i + 1 < argc) {
            int parsed = std::atoi(argv[++i]);
            if (parsed < 0) parsed = 0;
            cfg.upstream_response_ttl_s = static_cast<std::uint32_t>(parsed);
        } else if (arg == "--attach-local") {
            attach_local = true;
        } else if (arg == "--root") {
            keep_root = true;
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
        } else if (arg == "--boring") {
            cfg.boring = true;
        } else if (arg == "--timing") {
            yume::util::set_timing_enabled(true);
        } else {
            yume::util::log_error("unknown or incomplete option: " + arg);
            return 1;
        }
    }
    std::string exe_dir;
    {
        std::string self_path = get_self_path(argv[0]);
        if (!self_path.empty()) {
            exe_dir = std::filesystem::path(self_path).parent_path().string();
        }
    }
    config_path = yume::util::expand_user(config_path);
    if (!config_specified && !exe_dir.empty()) {
        std::filesystem::path cfg_path(config_path);
        if (!std::filesystem::exists(cfg_path)) {
            std::filesystem::path cand = std::filesystem::path(exe_dir) / cfg_path;
            if (std::filesystem::exists(cand)) {
                config_path = cand.string();
            }
        }
    }
    std::string config_dir;
    if (config_specified || std::filesystem::exists(config_path)) {
        std::error_code ec;
        auto cfg_abs = std::filesystem::absolute(config_path, ec);
        if (!ec) {
            config_dir = cfg_abs.parent_path().string();
        } else {
            config_dir = std::filesystem::path(config_path).parent_path().string();
        }
    }
    auto resolve_cfg_path = [&](const std::string& value) {
        return yume::util::resolve_path(value, config_dir, exe_dir);
    };

    if (config_specified || std::filesystem::exists(config_path)) {
        try {
            auto json = yume::util::read_json_config(config_path);
            if (json.contains("listen_port")) {
                if (cfg.listen_port == 443) {
                    cfg.listen_port = json["listen_port"].get<int>();
                }
            }
            if (json.contains("reverse_port_min")) {
                if (cfg.reverse_port_min == yume::policy::kReversePortMinDefault) {
                    cfg.reverse_port_min = json["reverse_port_min"].get<int>();
                }
            }
            if (json.contains("reverse_port_max")) {
                if (cfg.reverse_port_max == yume::policy::kReversePortMaxDefault) {
                    cfg.reverse_port_max = json["reverse_port_max"].get<int>();
                }
            }
            if (json.contains("dns_server")) {
                if (cfg.dns_server.empty()) {
                    cfg.dns_server = json["dns_server"].get<std::string>();
                }
            }
            if (json.contains("tls_cert")) {
                if (cfg.tls_cert.empty()) {
                    cfg.tls_cert = resolve_cfg_path(json["tls_cert"].get<std::string>());
                }
            }
            if (json.contains("tls_key")) {
                if (cfg.tls_key.empty()) {
                    cfg.tls_key = resolve_cfg_path(json["tls_key"].get<std::string>());
                }
            }
            if (json.contains("auth_keys")) {
                if (cfg.auth_keys.empty()) {
                    cfg.auth_keys = resolve_cfg_path(json["auth_keys"].get<std::string>());
                }
            }
            if (json.contains("threads")) {
                if (cfg.threads == 0) {
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
            if (json.contains("inner_dual")) {
                if (!inner_dual_override) {
                    cfg.inner_dual = json["inner_dual"].get<bool>();
                }
            }
            if (json.contains("inner_required")) {
                if (!inner_required_override) {
                    cfg.inner_required = json["inner_required"].get<bool>();
                }
            }
            if (json.contains("inner_hop")) {
                if (!inner_hop_override) {
                    cfg.inner_hop = json["inner_hop"].get<bool>();
                }
            }
            if (json.contains("hop_interval_ms")) {
                if (!hop_interval_override) {
                    cfg.hop_interval_ms = static_cast<std::uint32_t>(json["hop_interval_ms"].get<int>());
                }
            }
            if (json.contains("inner_heavy")) {
                cfg.inner_heavy = json["inner_heavy"].get<bool>();
            }
            if (json.contains("pq_private_key")) {
                if (cfg.pq_private_key.empty()) {
                    cfg.pq_private_key = resolve_cfg_path(json["pq_private_key"].get<std::string>());
                }
            }
            if (json.contains("pq_auto_generate")) {
                if (!pq_auto_generate_override) {
                    cfg.pq_auto_generate = json["pq_auto_generate"].get<bool>();
                }
            }
            if (json.contains("use_embedded_master")) {
                if (!allow_embedded_master_override) {
                    cfg.allow_embedded_master = json["use_embedded_master"].get<bool>();
                }
            }
            if (json.contains("allow_exec")) {
                if (!cfg.allow_exec) {
                    cfg.allow_exec = json["allow_exec"].get<bool>();
                }
            }
            if (json.contains("allow_local_ip")) {
                cfg.allow_local_ip = json["allow_local_ip"].get<bool>();
            }
            if (json.contains("control_full")) {
                cfg.control_full = json["control_full"].get<bool>();
            }
            if (json.contains("real_http")) {
                if (!cfg.real_http) {
                    cfg.real_http = json["real_http"].get<bool>();
                }
            }
            if (json.contains("real_index_path")) {
                if (cfg.real_index_path.empty()) {
                    cfg.real_index_path = resolve_cfg_path(json["real_index_path"].get<std::string>());
                }
            }
            if (json.contains("real_secret")) {
                if (cfg.real_secret.empty()) {
                    cfg.real_secret = json["real_secret"].get<std::string>();
                }
            }
            if (json.contains("real_secret_file")) {
                if (cfg.real_secret_file.empty()) {
                    cfg.real_secret_file = resolve_cfg_path(json["real_secret_file"].get<std::string>());
                }
            }
            if (json.contains("obfs_secret")) {
                if (cfg.obfs_secret.empty()) {
                    cfg.obfs_secret = json["obfs_secret"].get<std::string>();
                }
            }
            if (json.contains("obfs_pad_multiple") && cfg.obfs_pad_multiple == 0) {
                int v = json["obfs_pad_multiple"].get<int>();
                if (v < 0) v = 0;
                if (v > 256) v = 256;
                cfg.obfs_pad_multiple = static_cast<std::uint16_t>(v);
            }
            if (json.contains("obfs_jitter_ms") && cfg.obfs_jitter_ms == 0) {
                int v = json["obfs_jitter_ms"].get<int>();
                if (v < 0) v = 0;
                cfg.obfs_jitter_ms = static_cast<std::uint32_t>(v);
            }
            if (json.contains("tls_handshake_timeout_ms") && !tls_handshake_timeout_override) {
                int v = json["tls_handshake_timeout_ms"].get<int>();
                if (v < 0) v = 0;
                cfg.tls_handshake_timeout_ms = static_cast<std::uint32_t>(v);
            }
            if (json.contains("max_sessions") && !max_sessions_override) {
                int v = json["max_sessions"].get<int>();
                if (v < 0) v = 0;
                cfg.max_sessions = static_cast<std::uint32_t>(v);
            }
            if (json.contains("accept_rate_limit") && !accept_rate_limit_override) {
                int v = json["accept_rate_limit"].get<int>();
                if (v < 0) v = 0;
                cfg.accept_rate_limit = static_cast<std::uint32_t>(v);
            }
            if (json.contains("egress_mbps") && !egress_mbps_override) {
                int v = json["egress_mbps"].get<int>();
                if (v < 0) v = 0;
                cfg.egress_mbps = static_cast<std::uint32_t>(v);
            }
            if (json.contains("upstream_response_dir") && cfg.upstream_response_dir.empty()) {
                cfg.upstream_response_dir = resolve_cfg_path(json["upstream_response_dir"].get<std::string>());
            }
            if (json.contains("upstream_response_ttl") && cfg.upstream_response_ttl_s == 0) {
                int v = json["upstream_response_ttl"].get<int>();
                if (v < 0) v = 0;
                cfg.upstream_response_ttl_s = static_cast<std::uint32_t>(v);
            }
            if (json.contains("boring")) {
                cfg.boring = json["boring"].get<bool>();
            }
            if (json.contains("anonym")) {
                if (!anonym_override) {
                    cfg.anonym = json["anonym"].get<bool>();
                }
            }
            if (json.contains("anonym_proof_mode") && !anonym_proof_mode_override) {
                cfg.anonym_proof_mode = json["anonym_proof_mode"].get<std::string>();
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
                    cfg.anonym_ca_key = resolve_cfg_path(json["anonym_ca_key"].get<std::string>());
                }
            }
            if (json.contains("anonym_ca_cert")) {
                if (cfg.anonym_ca_cert.empty()) {
                    cfg.anonym_ca_cert = resolve_cfg_path(json["anonym_ca_cert"].get<std::string>());
                }
            }
            if (json.contains("anonym_sub_key")) {
                if (cfg.anonym_sub_key.empty()) {
                    cfg.anonym_sub_key = resolve_cfg_path(json["anonym_sub_key"].get<std::string>());
                }
            }
            if (json.contains("anonym_sub_cert")) {
                if (cfg.anonym_sub_cert.empty()) {
                    cfg.anonym_sub_cert = resolve_cfg_path(json["anonym_sub_cert"].get<std::string>());
                }
            }
            if (json.contains("server_name") && cfg.server_name.empty()) {
                cfg.server_name = json["server_name"].get<std::string>();
            }
            if (json.contains("server_id") && cfg.server_id.empty()) {
                cfg.server_id = json["server_id"].get<std::string>();
            }
            if (json.contains("outbound_proxy") && cfg.outbound_proxy_url.empty()) {
                cfg.outbound_proxy_url = json["outbound_proxy"].get<std::string>();
            }
            if (json.contains("relay_enable") && !relay_enable_override) {
                cfg.relay_enable = json["relay_enable"].get<bool>();
            }
            if (json.contains("directory_enable") && !directory_enable_override) {
                cfg.directory_enable = json["directory_enable"].get<bool>();
            }
            if (json.contains("ipc_enable")) {
                cfg.ipc_enable = json["ipc_enable"].get<bool>();
            }
            if (json.contains("ipc_path") && cfg.ipc_path.empty()) {
                cfg.ipc_path = resolve_cfg_path(json["ipc_path"].get<std::string>());
            }
            if (json.contains("federation_enable") && !cfg.federation_enable) {
                cfg.federation_enable = json["federation_enable"].get<bool>();
            }
            if (json.contains("federation_peers") && cfg.federation_peers.empty()) {
                for (const auto& peer : json["federation_peers"]) {
                    cfg.federation_peers.push_back(peer.dump());
                }
            }
            if (json.contains("federation_auth_key") && cfg.federation_auth_key.empty()) {
                cfg.federation_auth_key = resolve_cfg_path(json["federation_auth_key"].get<std::string>());
            }
            if (json.contains("federation_anonym_ca") && cfg.federation_anonym_ca.empty()) {
                cfg.federation_anonym_ca = resolve_cfg_path(json["federation_anonym_ca"].get<std::string>());
            }
            if (json.contains("operator_keys") && cfg.operator_keys.empty()) {
                cfg.operator_keys = resolve_cfg_path(json["operator_keys"].get<std::string>());
            }
            if (json.contains("operator_keys_meta") && cfg.operator_keys_meta.empty()) {
                cfg.operator_keys_meta = resolve_cfg_path(json["operator_keys_meta"].get<std::string>());
            }
        } catch (const std::exception& ex) {
            yume::util::log_error(std::string("config load failed: ") + ex.what());
            return 1;
        }
    }
    if (!cfg.tls_cert.empty()) {
        cfg.tls_cert = resolve_cfg_path(cfg.tls_cert);
    }
    if (!cfg.tls_key.empty()) {
        cfg.tls_key = resolve_cfg_path(cfg.tls_key);
    }
    if (!cfg.auth_keys.empty()) {
        cfg.auth_keys = resolve_cfg_path(cfg.auth_keys);
    }
    if (!cfg.pq_private_key.empty()) {
        cfg.pq_private_key = resolve_cfg_path(cfg.pq_private_key);
    }
    if (!cfg.real_index_path.empty()) {
        cfg.real_index_path = resolve_cfg_path(cfg.real_index_path);
    }
    if (!cfg.real_secret_file.empty()) {
        cfg.real_secret_file = resolve_cfg_path(cfg.real_secret_file);
    }
    if (!cfg.anonym_ca_key.empty()) {
        cfg.anonym_ca_key = resolve_cfg_path(cfg.anonym_ca_key);
    }
    if (!cfg.anonym_ca_cert.empty()) {
        cfg.anonym_ca_cert = resolve_cfg_path(cfg.anonym_ca_cert);
    }
    if (!cfg.anonym_sub_key.empty()) {
        cfg.anonym_sub_key = resolve_cfg_path(cfg.anonym_sub_key);
    }
    if (!cfg.anonym_sub_cert.empty()) {
        cfg.anonym_sub_cert = resolve_cfg_path(cfg.anonym_sub_cert);
    }
    if (!cfg.operator_keys.empty()) {
        cfg.operator_keys = resolve_cfg_path(cfg.operator_keys);
    }
    if (!cfg.operator_keys_meta.empty()) {
        cfg.operator_keys_meta = resolve_cfg_path(cfg.operator_keys_meta);
    }
    if (!cfg.federation_auth_key.empty()) {
        cfg.federation_auth_key = resolve_cfg_path(cfg.federation_auth_key);
    }
    if (!cfg.federation_anonym_ca.empty()) {
        cfg.federation_anonym_ca = resolve_cfg_path(cfg.federation_anonym_ca);
    }
    if (cfg.dns_server.empty()) {
        const char* dns_env = std::getenv("YUME_DNS_SERVER");
        if (dns_env && *dns_env) {
            cfg.dns_server = dns_env;
        }
    }
    if (!cfg.dns_server.empty()) {
        yume::util::log_info("server outbound DNS override: " + cfg.dns_server);
    }
#if !defined(_WIN32)
    if (cfg.dns_server.empty() && !std::filesystem::exists("/etc/resolv.conf")) {
        yume::util::log_warn(
            "/etc/resolv.conf is missing; server-side DNS may be slow. "
            "Use --dns-server 1.1.1.1 or set YUME_DNS_SERVER=1.1.1.1 to bypass system DNS.");
    }
#endif
    if (inner_heavy_override) {
        cfg.inner_heavy = inner_heavy_value;
    }
    if (cfg.inner_dual || cfg.inner_required) {
        cfg.inner_crypto = true;
    }
    if (inner_hop_override) {
        cfg.inner_hop = inner_hop_value;
    }
    if (cfg.inner_hop) {
        cfg.inner_crypto = true;
        cfg.inner_required = true;
        if (cfg.hop_interval_ms == 0) {
            cfg.hop_interval_ms = 500;
        }
    }
    if (cfg.hop_interval_ms > 0) {
        if (cfg.hop_interval_ms < 250) {
            cfg.hop_interval_ms = 250;
        } else if (cfg.hop_interval_ms > 1000) {
            cfg.hop_interval_ms = 1000;
        }
    }
    cfg.reverse_port_min = std::clamp(cfg.reverse_port_min, 1, 65535);
    cfg.reverse_port_max = std::clamp(cfg.reverse_port_max, 1, 65535);
    if (cfg.reverse_port_min > cfg.reverse_port_max) {
        std::swap(cfg.reverse_port_min, cfg.reverse_port_max);
        yume::util::log_warn("reverse_port_min > reverse_port_max; swapped values");
    }
    cfg.anonym_proof_mode = yume::policy::normalize_anonym_proof_mode(cfg.anonym_proof_mode);

#if !YUME_FEATURE_EXEC
    if (cfg.allow_exec) {
        yume::util::log_warn(
            "--allow-exec ignored: build was configured without -DYUME_FEATURE_EXEC=ON; "
            "rebuild with that option to enable server-side command execution");
    }
#endif
#if !YUME_FEATURE_LAN_BRIDGE
    if (cfg.allow_local_ip) {
        yume::util::log_warn(
            "--allow-local-ip ignored: build was configured without -DYUME_FEATURE_LAN_BRIDGE=ON; "
            "rebuild with that option to enable LAN/private-IP bridging");
    }
#endif
#if !YUME_FEATURE_FULL_CONTROL
    if (cfg.control_full) {
        yume::util::log_warn(
            "--control-full ignored: build was configured without -DYUME_FEATURE_FULL_CONTROL=ON; "
            "rebuild with that option to enable unrestricted address bridging");
    }
#endif
    if ((cfg.allow_exec || cfg.allow_local_ip || cfg.control_full) && cfg.auth_keys_meta.empty()) {
        yume::util::log_warn(
            "dangerous server feature enabled but no auth_keys_meta is configured; "
            "no key will inherit these permissions until you create the meta file and grant per-key access "
            "(see docs/PERMISSIONS.md)");
    }
    if (cfg.federation_enable &&
        (cfg.federation_auth_key.empty() || cfg.federation_anonym_ca.empty())) {
        yume::util::log_error("federation requires --federation-auth-key and --federation-anonym-ca");
        return 1;
    }
    if (cfg.federation_enable && !cfg.cluster_bootstrap && cfg.federation_peers.empty()) {
        yume::util::log_error("federation requires at least one --peer or --cluster-join; pass --cluster-bootstrap if this node is a cluster entry point");
        return 1;
    }

    if (!cfg.http_profile.empty()) {
        if (!yume::http_profile::server(cfg.http_profile).has_value()) {
            std::string supported;
            for (const auto& n : yume::http_profile::server_names()) {
                if (!supported.empty()) supported += ", ";
                supported += n;
            }
            yume::util::log_error("--hide-in-the-crowd: unknown server profile '" + cfg.http_profile +
                                  "'. Supported: " + supported);
            return 1;
        }
    }

    if (!cfg.upstream_response_file.empty()) {
        // Load the captured response once at startup. Normalise lone
        // \n into \r\n so operators who captured with `curl -i` (which
        // strips the on-wire \r) still produce valid HTTP wire bytes
        // when we replay. Already-\r\n stays unchanged.
        std::ifstream in(cfg.upstream_response_file, std::ios::binary);
        if (!in) {
            yume::util::log_error("--upstream-response: cannot open " + cfg.upstream_response_file);
            return 1;
        }
        std::stringstream ss; ss << in.rdbuf();
        std::string raw = ss.str();
        std::string normalized;
        normalized.reserve(raw.size() + raw.size() / 16);
        for (std::size_t i = 0; i < raw.size(); ++i) {
            char c = raw[i];
            if (c == '\n' && (i == 0 || raw[i - 1] != '\r')) {
                normalized += '\r';
            }
            normalized += c;
        }
        if (normalized.rfind("HTTP/1.", 0) != 0) {
            yume::util::log_error("--upstream-response: " + cfg.upstream_response_file +
                                  " does not start with 'HTTP/1.' — expected a captured HTTP/1.x response");
            return 1;
        }
        cfg.upstream_response_bytes = std::move(normalized);
        yume::util::log_info("--upstream-response: loaded " +
                             std::to_string(cfg.upstream_response_bytes.size()) +
                             " bytes from " + cfg.upstream_response_file +
                             " (replayed verbatim to non-yume probes)");
    }

    if (!cfg.upstream_response_dir.empty()) {
        namespace fs = std::filesystem;
        std::error_code ec;
        if (!fs::is_directory(cfg.upstream_response_dir, ec)) {
            yume::util::log_error("--upstream-response-dir: " + cfg.upstream_response_dir +
                                  " is not a directory");
            return 1;
        }
        if (!cfg.upstream_response_file.empty()) {
            yume::util::log_warn("--upstream-response-dir overrides --upstream-response " +
                                 cfg.upstream_response_file + " (single-file capture will be ignored)");
        }
    }

    if (cfg.obfs_pad_multiple > 0) {
        yume::util::log_info("--obfs-pad-multiple " + std::to_string(cfg.obfs_pad_multiple) +
                             ": every outbound frame payload is padded to a multiple of this size. " +
                             "Connecting clients MUST run a yume build that knows kFlagPadded (>= 1.0 post-padding); " +
                             "older clients will fail to parse the stream.");
    }
    if (cfg.obfs_jitter_ms > 0) {
        yume::util::log_info("--obfs-jitter-ms " + std::to_string(cfg.obfs_jitter_ms) +
                             ": each batched write is deferred by 0.." +
                             std::to_string(cfg.obfs_jitter_ms) +
                             " ms. Adds latency, breaks the constant-cadence ML signature.");
    }

    if (cfg.public_node) {
        // --public-node: hardening preset for an internet-facing yumed.
        // Refuses flags that expose dangerous capabilities and requires
        // explicit auth setup. The existing silent-downgrade warnings
        // for --allow-local-ip / --control-full become hard errors here
        // so operators can't accidentally ship a "public" node that
        // also tries to bridge to LAN or expose full address control.
        if (cfg.http_profile.empty()) {
            cfg.http_profile = "nginx";
            yume::util::log_info("--public-node: defaulting --hide-in-the-crowd to 'nginx' (pass --hide-in-the-crowd <profile> to override)");
        }
        // --public-node hardening defaults. Each respects an explicit
        // operator override (CLI flag or JSON config); only fills in
        // the safe-by-default value when the operator left it at 0.
        if (!tls_handshake_timeout_override && cfg.tls_handshake_timeout_ms == 0) {
            cfg.tls_handshake_timeout_ms = 10000;
            yume::util::log_info("--public-node: defaulting --tls-handshake-timeout-ms to 10000 (pass --tls-handshake-timeout-ms 0 to disable)");
        }
        if (!max_sessions_override && cfg.max_sessions == 0) {
            cfg.max_sessions = 4096;
            yume::util::log_info("--public-node: defaulting --max-sessions to 4096 (pass --max-sessions <N> to override; 0 = unlimited)");
        }
        if (!accept_rate_limit_override && cfg.accept_rate_limit == 0) {
            cfg.accept_rate_limit = 100;
            yume::util::log_info("--public-node: defaulting --accept-rate-limit to 100/s (pass --accept-rate-limit <N> to override; 0 = unlimited)");
        }
        // Refuse to bind to a private / loopback / link-local address
        // when the operator declared this is an internet-facing node.
        // Empty listen_address = "bind any" (0.0.0.0) which is the
        // operator's clear intent to be internet-facing, so it's
        // allowed. Only explicit addr binds are checked.
        if (!cfg.listen_address.empty()) {
            boost::system::error_code addr_ec;
            auto addr = boost::asio::ip::make_address(cfg.listen_address, addr_ec);
            if (addr_ec) {
                yume::util::log_error("--public-node: --listen address '" +
                                      cfg.listen_address + "' does not parse: " +
                                      addr_ec.message());
                return 1;
            }
            bool refuse = false;
            std::string reason;
            if (addr.is_loopback()) {
                refuse = true; reason = "loopback (127.0.0.0/8 or ::1)";
            } else if (addr.is_unspecified()) {
                // 0.0.0.0 / :: are the explicit "any" forms — allowed,
                // operator just wrote them out longhand.
            } else if (addr.is_v4()) {
                const auto v4 = addr.to_v4();
                const auto bytes = v4.to_bytes();
                const uint32_t ip = (uint32_t(bytes[0]) << 24) | (uint32_t(bytes[1]) << 16) |
                                    (uint32_t(bytes[2]) << 8)  |  uint32_t(bytes[3]);
                // RFC 1918 ranges + link-local (169.254/16) + CGNAT
                // (100.64/10). Public CGNAT addresses can legitimately
                // back internet-facing services in some ISP setups,
                // but the typical case is a misconfigured edge router;
                // err on the side of refusing.
                if ((ip & 0xFF000000u) == 0x0A000000u)  { refuse = true; reason = "RFC 1918 (10.0.0.0/8)"; }
                if ((ip & 0xFFF00000u) == 0xAC100000u)  { refuse = true; reason = "RFC 1918 (172.16.0.0/12)"; }
                if ((ip & 0xFFFF0000u) == 0xC0A80000u)  { refuse = true; reason = "RFC 1918 (192.168.0.0/16)"; }
                if ((ip & 0xFFFF0000u) == 0xA9FE0000u)  { refuse = true; reason = "link-local (169.254.0.0/16)"; }
                if ((ip & 0xFFC00000u) == 0x64400000u)  { refuse = true; reason = "CGNAT (100.64.0.0/10)"; }
            } else if (addr.is_v6()) {
                const auto v6 = addr.to_v6();
                if (v6.is_link_local()) {
                    refuse = true; reason = "IPv6 link-local (fe80::/10)";
                }
                // ULA fc00::/7 — bytes[0] in {0xFC, 0xFD}.
                const auto bytes = v6.to_bytes();
                if ((bytes[0] & 0xFE) == 0xFC) {
                    refuse = true; reason = "IPv6 ULA (fc00::/7)";
                }
            }
            if (refuse) {
                yume::util::log_error("--public-node: refusing to bind --listen " +
                                      cfg.listen_address + " (" + reason +
                                      "). A public node must not bind to a private/loopback range. "
                                      "Either drop --public-node, or set --listen to a public address (or just the port).");
                return 1;
            }
            yume::util::log_info("--public-node: --listen " + cfg.listen_address +
                                 " passes private-range check");
        }
#ifndef _WIN32
        // Lock the process umask to 0077 BEFORE anything writes a
        // file or creates a directory. Subsequent secret-key writes
        // (PQ keypair under ./.secrets), IPC socket creates, config
        // dirs etc all inherit owner-only mode so other local users
        // can't read them. Set unconditionally under --public-node;
        // no override knob — operators who want world-readable
        // secret files on a public-facing host should reconsider.
        const mode_t prior = umask(0077);
        yume::util::log_info(
            std::string("--public-node: process umask set to 0077 (was 0") +
            std::to_string(prior >> 6 & 7) +
            std::to_string(prior >> 3 & 7) +
            std::to_string(prior & 7) +
            "); subsequent secret files and IPC socket will be 0600/0700");
#endif
        std::vector<std::string> violations;
        if (cfg.allow_exec) {
            violations.emplace_back("--allow-exec is forbidden by --public-node (server-side exec on a public node is a remote-shell hole)");
        }
        if (cfg.allow_local_ip) {
            violations.emplace_back("--allow-local-ip is forbidden by --public-node (LAN bridging from a public endpoint exposes the host's private network)");
        }
        if (cfg.control_full) {
            violations.emplace_back("--control-full is forbidden by --public-node (unrestricted address bridging from a public endpoint is a relay hole)");
        }
        if (!cfg.inner_crypto) {
            violations.emplace_back("--no-inner is forbidden by --public-node (inner crypto is the only post-handshake confidentiality; a public node MUST require it)");
        }
        if (cfg.auth_keys.empty()) {
            violations.emplace_back("--public-node requires --auth-keys to be set (otherwise the daemon accepts no clients, or worse, accepts everyone if you later loosen this)");
        }
        if (!violations.empty()) {
            yume::util::log_error("--public-node violations:");
            for (const auto& v : violations) {
                yume::util::log_error("  - " + v);
            }
            return 1;
        }
        yume::util::log_info("--public-node active; the following protections are enforced at startup:");
        yume::util::log_info("  - dangerous capability flags (--allow-exec / --allow-local-ip / --control-full) are rejected");
        yume::util::log_info("  - inner crypto required (no plaintext transport)");
        yume::util::log_info("  - --auth-keys required (no anonymous-relay accidents)");
        yume::util::log_info("  - Argon2 caps locked to safe defaults (env vars can only RAISE, never lower)");
        yume::util::log_info("  - private-IP bind refusal (--listen explicit-addr in RFC 1918 / loopback / link-local / ULA → startup error)");
        yume::util::log_info("  - TLS handshake deadline (--tls-handshake-timeout-ms; default 10s, slow-loris guard)");
        yume::util::log_info("  - accept-side rate-limit + max-concurrent-session cap (--accept-rate-limit 100/s, --max-sessions 4096)");
        yume::util::log_info("  - process umask locked to 0077 (secret files + IPC socket land at 0600/0700)");
    }

    auto require_readable = [&](const char* label, const std::string& path) {
        if (path.empty()) {
            return true;
        }
        if (!file_readable(path)) {
            yume::util::log_error(std::string(label) + " not found: " + path);
            return false;
        }
        return true;
    };

    const bool key_management_only =
        keys_list || !keys_add.empty() || !keys_remove.empty()
        || !keys_alias.empty() || !keys_gen.empty();

    if (!key_management_only) {
        if (!require_readable("tls_cert", cfg.tls_cert)) {
            return 1;
        }
        if (!require_readable("tls_key", cfg.tls_key)) {
            return 1;
        }
        if (!require_readable("auth_keys", cfg.auth_keys)) {
            return 1;
        }
        if (!require_readable("pq_private_key", cfg.pq_private_key)) {
            return 1;
        }
        if (!require_readable("real_index_path", cfg.real_index_path)) {
            return 1;
        }
        if (!require_readable("real_secret_file", cfg.real_secret_file)) {
            return 1;
        }
        if (!require_readable("anonym_ca_key", cfg.anonym_ca_key)) {
            return 1;
        }
        if (!require_readable("anonym_ca_cert", cfg.anonym_ca_cert)) {
            return 1;
        }
        if (!require_readable("anonym_sub_key", cfg.anonym_sub_key)) {
            return 1;
        }
        if (!require_readable("anonym_sub_cert", cfg.anonym_sub_cert)) {
            return 1;
        }
        if (!require_readable("federation_auth_key", cfg.federation_auth_key)) {
            return 1;
        }
        if (!require_readable("federation_anonym_ca", cfg.federation_anonym_ca)) {
            return 1;
        }
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
            std::string reverse_min = prompt("reverse_port_min", std::to_string(cfg.reverse_port_min));
            std::string reverse_max = prompt("reverse_port_max", std::to_string(cfg.reverse_port_max));
            std::string cert = prompt("tls_cert", cfg.tls_cert);
            std::string key = prompt("tls_key", cfg.tls_key);
            std::string auth = prompt("auth_keys", cfg.auth_keys);
            std::string threads = prompt("threads", std::to_string(cfg.threads));
            std::string obfs = prompt("obfuscation (true/false)", cfg.obfuscation ? "true" : "false");
            std::string inner = prompt("inner_crypto (true/false)", cfg.inner_crypto ? "true" : "false");
            std::string inner_heavy = prompt("inner_heavy (true/false)", cfg.inner_heavy ? "true" : "false");
            std::string inner_dual = prompt("inner_dual (true/false)", cfg.inner_dual ? "true" : "false");
            std::string inner_required = prompt("inner_required (true/false)", cfg.inner_required ? "true" : "false");
            std::string inner_hop = prompt("inner_hop (true/false)", cfg.inner_hop ? "true" : "false");
            std::string hop_interval = prompt("hop_interval_ms", std::to_string(cfg.hop_interval_ms));
            std::string pq = prompt("pq_private_key", cfg.pq_private_key);
            std::string pq_auto_generate = prompt("pq_auto_generate (true/false)", cfg.pq_auto_generate ? "true" : "false");
            std::string use_embedded_master = prompt("use_embedded_master (true/false)", cfg.allow_embedded_master ? "true" : "false");
            std::string allow_exec = prompt("allow_exec (true/false)", cfg.allow_exec ? "true" : "false");
            std::string allow_local_ip = prompt("allow_local_ip (true/false)", cfg.allow_local_ip ? "true" : "false");
            std::string control_full = prompt("control_full (true/false)", cfg.control_full ? "true" : "false");
            std::string real_http = prompt("real_http (true/false)", cfg.real_http ? "true" : "false");
            std::string real_index = prompt("real_index_path", cfg.real_index_path);
            std::string real_secret_file = prompt("real_secret_file", cfg.real_secret_file);
            std::string anonym = prompt("anonym (true/false)", cfg.anonym ? "true" : "false");
            std::string anonym_proof_mode = prompt("anonym_proof_mode", cfg.anonym_proof_mode);
            std::string anonym_api = prompt("anonym_api", cfg.anonym_api);
            std::string anonym_token = prompt("anonym_token", cfg.anonym_token);
            std::string anonym_ca_key = prompt("anonym_ca_key", cfg.anonym_ca_key);
            std::string anonym_ca_cert = prompt("anonym_ca_cert", cfg.anonym_ca_cert);
            std::string anonym_sub_key = prompt("anonym_sub_key", cfg.anonym_sub_key);
            std::string anonym_sub_cert = prompt("anonym_sub_cert", cfg.anonym_sub_cert);
            std::string outbound_proxy = prompt("outbound_proxy", cfg.outbound_proxy_url);
            std::string federation_enable = prompt("federation_enable (true/false)", cfg.federation_enable ? "true" : "false");
            std::string federation_auth_key = prompt("federation_auth_key", cfg.federation_auth_key);
            std::string federation_anonym_ca = prompt("federation_anonym_ca", cfg.federation_anonym_ca);
            std::string federation_peer = prompt("federation_peer_json", cfg.federation_peers.empty() ? "" : cfg.federation_peers.front());

            json["listen_port"] = std::stoi(listen);
            json["reverse_port_min"] = std::stoi(reverse_min);
            json["reverse_port_max"] = std::stoi(reverse_max);
            json["tls_cert"] = cert;
            json["tls_key"] = key;
            json["auth_keys"] = auth;
            json["threads"] = std::stoi(threads);
            json["obfuscation"] = (obfs == "true");
            json["inner_crypto"] = (inner == "true");
            json["inner_heavy"] = (inner_heavy == "true");
            json["inner_dual"] = (inner_dual == "true");
            json["inner_required"] = (inner_required == "true");
            json["inner_hop"] = (inner_hop == "true");
            json["hop_interval_ms"] = std::stoi(hop_interval);
            if (!pq.empty()) json["pq_private_key"] = pq;
            json["pq_auto_generate"] = (pq_auto_generate == "true");
            json["use_embedded_master"] = (use_embedded_master == "true");
            json["allow_exec"] = (allow_exec == "true");
            json["allow_local_ip"] = (allow_local_ip == "true");
            json["control_full"] = (control_full == "true");
            json["real_http"] = (real_http == "true");
            if (!real_index.empty()) json["real_index_path"] = real_index;
            if (!real_secret_file.empty()) json["real_secret_file"] = real_secret_file;
            json["anonym"] = (anonym == "true");
            json["anonym_proof_mode"] = yume::policy::normalize_anonym_proof_mode(anonym_proof_mode);
            if (!anonym_api.empty()) json["anonym_api"] = anonym_api;
            if (!anonym_token.empty()) json["anonym_token"] = anonym_token;
            if (!anonym_ca_key.empty()) json["anonym_ca_key"] = anonym_ca_key;
            if (!anonym_ca_cert.empty()) json["anonym_ca_cert"] = anonym_ca_cert;
            if (!anonym_sub_key.empty()) json["anonym_sub_key"] = anonym_sub_key;
            if (!anonym_sub_cert.empty()) json["anonym_sub_cert"] = anonym_sub_cert;
            if (!outbound_proxy.empty()) json["outbound_proxy"] = outbound_proxy;
            json["federation_enable"] = (federation_enable == "true");
            if (!federation_auth_key.empty()) json["federation_auth_key"] = federation_auth_key;
            if (!federation_anonym_ca.empty()) json["federation_anonym_ca"] = federation_anonym_ca;
            if (!federation_peer.empty()) json["federation_peers"] = nlohmann::json::array({nlohmann::json::parse(federation_peer)});

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
            std::filesystem::path exe_path_dir;
            std::string self_path = get_self_path(argv[0]);
            if (!self_path.empty()) {
                exe_path_dir = std::filesystem::path(self_path).parent_path();
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
            try_set(cfg.anonym_sub_key, exe_path_dir, "anonym_sub.key");
            try_set(cfg.anonym_sub_cert, exe_path_dir, "anonym_sub.pem");
            if (!cfg.anonym_sub_key.empty() && !cfg.anonym_sub_cert.empty()) {
                yume::util::log_info("using anonym sub key/cert from runtime directory");
            }
        }
        if (cfg.inner_crypto && cfg.pq_private_key.empty()) {
            std::error_code ec;
            std::filesystem::path runtime_dir = std::filesystem::current_path(ec);
            std::filesystem::path exe_path_dir;
            std::string self_path = get_self_path(argv[0]);
            if (!self_path.empty()) {
                exe_path_dir = std::filesystem::path(self_path).parent_path();
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
            try_set(cfg.pq_private_key, exe_path_dir, "pq_private.key");
            std::filesystem::path secret_dir = runtime_dir / ".secrets";
            try_set(cfg.pq_private_key, secret_dir, "pq_private.key");
            if (!cfg.pq_private_key.empty()) {
                yume::util::log_info("using discovered pq_private_key: " + cfg.pq_private_key);
            } else if (cfg.pq_auto_generate) {
                std::filesystem::path priv_path = secret_dir / "pq_private.key";
                std::filesystem::path pub_path = secret_dir / "pq_public.key";
                std::string err;
                if (yume::inner::generate_pq_keypair(priv_path.string(), pub_path.string(), &err)) {
                    cfg.pq_private_key = priv_path.string();
                    yume::util::log_info("generated PQ keypair at ./.secrets (copy pq_public.key to clients)");
                } else {
                    yume::util::log_error("PQ keypair generation failed: " + err);
                    return 1;
                }
            }
        }
        const bool validate_pq_on_start =
            parse_env_bool("YUME_VALIDATE_PQ_ON_START", cfg.pq_auto_generate);
        if (cfg.inner_crypto && !cfg.pq_private_key.empty() && validate_pq_on_start) {
            std::string pq_public_path = derive_pq_public_path(cfg.pq_private_key);
            if (file_readable(cfg.pq_private_key) && file_readable(pq_public_path)) {
                std::string err;
                if (!yume::inner::validate_pq_keypair(cfg.pq_private_key, pq_public_path, &err)) {
                    if (!cfg.pq_auto_generate) {
                        yume::util::log_error("PQ keypair mismatch: " + err +
                                              " (run with --pq-auto-generate to regenerate)");
                        return 1;
                    }
                    yume::util::log_warn("PQ keypair mismatch; regenerating: " + err);
                    if (!yume::inner::generate_pq_keypair(cfg.pq_private_key, pq_public_path, &err)) {
                        yume::util::log_error("PQ keypair regeneration failed: " + err);
                        return 1;
                    }
                    yume::util::log_info("regenerated PQ keypair at " + pq_public_path);
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
        if (cfg.inner_crypto && cfg.pq_private_key.empty() && !cfg.allow_embedded_master) {
            yume::util::log_error(
                "inner_crypto enabled but pq_private_key is not set "
                "(set --pq-key, provide pq_private.key, enable --pq-auto-generate, or use --use-embedded-master)");
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
            yume::server::AuthKeyPolicyMap policies;
            std::ifstream in(cfg.auth_keys_meta);
            if (in) {
                try { in >> meta; } catch (...) { meta = nlohmann::json::object(); }
            }
            try {
                policies = yume::server::load_auth_policies(cfg.auth_keys_meta);
            } catch (const std::exception& ex) {
                yume::util::log_error(std::string("failed to parse auth_keys_meta: ") + ex.what());
                for (auto* free_key : keys) EVP_PKEY_free(free_key);
                return 1;
            }
            for (auto* key : keys) {
                std::string fp = yume::server::fingerprint_pubkey(key);
                auto entry = meta.value(fp, nlohmann::json::object());
                std::string alias = entry.value("alias", "");
                long long last_seen = entry.value("last_seen", 0LL);
                yume::server::AuthKeyPolicy policy;
                auto it = policies.find(fp);
                if (it != policies.end()) {
                    policy = it->second;
                }
                std::cout << fp;
                if (!alias.empty()) std::cout << "  alias=" << alias;
                if (last_seen > 0) std::cout << "  last_seen=" << last_seen;
                if (!policy.empty()) std::cout << "  policy=" << yume::server::summarize_auth_policy(policy);
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
        if (cfg.boring) {
            yume::util::log_warn("Security warning: BASEFWX / PQ disabled");
        } else {
            yume::util::log_warn("🔓⛓️‍💥 YOUR SECURITY IS SUFFERING BECAUSE YOU HAVE DISABLED: BASEFWX / PQ");
        }
    } else if (cfg.allow_embedded_master && cfg.pq_private_key.empty()) {
        yume::util::log_warn("using embedded BaseFWX master PQ key fallback (explicitly enabled)");
    } else if (cfg.allow_embedded_master) {
        yume::util::log_warn(
            "embedded BaseFWX master PQ keypair enabled; connection security depends on basefwx-bundled keys "
            "(disable with --no-embedded-master if you also provide --pq-key)");
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
    if (cfg.anonym && yume::policy::anonym_proof_mode_requires_remote(cfg.anonym_proof_mode) && cfg.anonym_api.empty()) {
        yume::util::log_warn("anonym proof mode is fixcraft but anonym_api is not set");
    }
    if (cfg.anonym && yume::policy::anonym_proof_mode_requires_local(cfg.anonym_proof_mode) &&
        cfg.anonym_ca_key.empty() && cfg.anonym_sub_key.empty()) {
        yume::util::log_warn("anonym proof mode is local but no anonym_ca_key or anonym_sub_key is configured");
    }
    if (!cfg.anonym && (!cfg.anonym_sub_key.empty() || !cfg.anonym_sub_cert.empty())) {
        yume::util::log_warn(
            "anonym_sub_key/anonym_sub_cert are set but --anonym is disabled; server mode is normal "
            "and anonym proof mode is OFF. Add --anonym if clients require anonym proof");
    }
    if (cfg.listen_port != 443 && !cfg.anonym) {
        yume::util::log_warn("WARNING: running on a port other than 443 reduces stealth and defeats HTTPS disguise.");
    }
    const std::string effective_inner_mode =
        !cfg.inner_crypto ? "off"
        : cfg.inner_dual ? "dual"
        : cfg.inner_heavy ? "heavy"
        : "light";
    const std::string hop_state =
        cfg.inner_hop ? "on (" + std::to_string(cfg.hop_interval_ms) + "ms)"
                      : "off";
    yume::util::log_info("effective inner mode: " + effective_inner_mode +
                         "; hopping: " + hop_state +
                         "; required: " + (cfg.inner_required ? "yes" : "no"));

    // TLS JA3 self-check: generate our own ClientHello via in-memory
    // BIO, compute JA3, compare against the per-profile baseline. Catches
    // silent drift when OpenSSL is upgraded between builds — if the
    // observed JA3 stops matching any known browser cluster the daemon
    // logs loudly so operators see it on the next restart.
    {
        // Baselines captured 2026-05 on the build-host build
        // (OpenSSL 3.5, Debian 13). Each is the MD5 of the
        // standard JA3 string produced by compute_self_fingerprint
        // for that profile against the current registry data. A
        // future OpenSSL upgrade or profile-data edit that changes
        // these will fire a "DRIFT" warning at every startup, which
        // is exactly what we want — silent drift away from a known
        // browser cluster is the failure mode the self-check exists
        // to catch.
        struct Baseline { yume::tls_fingerprint::BrowserProfile profile; const char* name; const char* expected_ja3; };
        constexpr Baseline kBaselines[] = {
            {yume::tls_fingerprint::BrowserProfile::CHROME_135,  "chrome",  "51dc1deffb716cb50b5b0e5449c4e28f"},
            {yume::tls_fingerprint::BrowserProfile::FIREFOX_126, "firefox", "b2f1f8aa44e9d9510358e21055e2a3c2"},
            {yume::tls_fingerprint::BrowserProfile::SAFARI_17,   "safari",  "96244ebd33ea0991b081300f27a9a6b3"},
        };
        for (const auto& b : kBaselines) {
            auto self = yume::tls_stealth::compute_self_fingerprint(b.profile);
            if (!self.has_value()) {
                yume::util::log_warn(std::string("ja3 self-check ") + b.name + ": could not generate ClientHello");
                continue;
            }
            const std::string& got = self->ja3_hash;
            if (*b.expected_ja3 == '\0') {
                yume::util::log_info(std::string("ja3 self-check ") + b.name + ": " + got +
                                     " (no pinned baseline — record this hash if it should be pinned)");
            } else if (got == b.expected_ja3) {
                yume::util::log_info(std::string("ja3 self-check ") + b.name + ": " + got + " (matches baseline)");
            } else {
                yume::util::log_warn(std::string("ja3 self-check ") + b.name +
                                     ": DRIFT — observed " + got +
                                     " vs pinned " + b.expected_ja3 +
                                     ". OpenSSL extension order may have changed; verify the JA3 still falls in the browser cluster before publishing.");
            }
        }
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

    std::atomic<long long> anonym_last_ts{0};
    const char* anonym_local_sign_env = std::getenv("YUME_ANONYM_LOCAL_SIGN");
    const bool anonym_local_sign =
        parse_env_bool("YUME_ANONYM_LOCAL_SIGN", anonym_local_sign_default());

    if (cfg.anonym) {
        if (!anonym_local_sign && (!cfg.anonym_ca_key.empty() || !cfg.anonym_sub_key.empty())) {
            if (anonym_local_sign_env && *anonym_local_sign_env) {
                yume::util::log_warn("anonym local signing is disabled by YUME_ANONYM_LOCAL_SIGN=0");
            } else {
                yume::util::log_warn("anonym local signing is disabled by default on this build/platform (set YUME_ANONYM_LOCAL_SIGN=1 to force)");
            }
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
            std::string pq_public_path;
            if (cfg.inner_crypto && !cfg.pq_private_key.empty()) {
                pq_public_path = derive_pq_public_path(cfg.pq_private_key);
            }
            std::string pq_sign_key = !cfg.anonym_sub_key.empty() ? cfg.anonym_sub_key : cfg.anonym_ca_key;
            auto proof = fetch_anonym_proof(cfg.anonym_hash, cfg.anonym_certfp, cfg.anonym_proof_mode, cfg.anonym_api,
                                            cfg.anonym_token, cfg.anonym_ca_key,
                                            cfg.anonym_sub_key, cfg.anonym_sub_cert,
                                            pq_public_path, pq_sign_key, anonym_local_sign,
                                            cfg.outbound_proxy_url);
            cfg.anonym_sig = proof.sig;
            cfg.anonym_ts = proof.ts;
            cfg.anonym_nonce = proof.nonce;
            cfg.anonym_proof_mode = proof.proof_policy;
            cfg.anonym_proof_sources = proof.proof_sources;
            cfg.anonym_ca_sig = proof.ca_sig;
            cfg.anonym_ca_alg = proof.ca_alg;
            cfg.anonym_sub_sig = proof.sub_sig;
            cfg.anonym_sub_alg = proof.sub_alg;
            cfg.anonym_sub_cert_b64 = proof.sub_cert_b64;
            cfg.pq_pub_b64 = proof.pq_pub_b64;
            cfg.pq_sig = proof.pq_sig;
            cfg.pq_alg = proof.pq_alg;
            anonym_last_ts.store(parse_proof_ts(proof.ts, static_cast<long long>(std::time(nullptr))),
                                 std::memory_order_relaxed);
        } catch (const std::exception& ex) {
            std::cerr << "\033[1;31mANONYM PROOF FAILED: " << ex.what() << "\033[0m\n";
            return 1;
        }
        yume::util::set_logging_enabled(false);
        std::cerr << "\033[1;33mANONYM MODE ACTIVE: client metadata logging disabled\033[0m\n";
    }
    if (!cfg.anonym) {
        if (cfg.anonym_certfp.empty() && !cfg.tls_cert.empty()) {
            try {
                cfg.anonym_certfp = cert_fingerprint_sha256(cfg.tls_cert);
            } catch (const std::exception& ex) {
                yume::util::log_warn(std::string("failed to compute cert fingerprint for PQ signing: ") + ex.what());
            }
        }
        std::string pq_public_path;
        if (cfg.inner_crypto && !cfg.pq_private_key.empty()) {
            pq_public_path = derive_pq_public_path(cfg.pq_private_key);
        }
        if (!pq_public_path.empty() && cfg.pq_pub_b64.empty()) {
            std::string pq_pub_b64;
            if (load_pq_public_b64(pq_public_path, &pq_pub_b64)) {
                cfg.pq_pub_b64 = pq_pub_b64;
                std::string pq_sign_key;
                if (!cfg.anonym_sub_key.empty() && !cfg.anonym_sub_cert.empty()) {
                    pq_sign_key = cfg.anonym_sub_key;
                    if (cfg.anonym_sub_cert_b64.empty()) {
                        try {
                            std::string sub_pem = read_file_bytes(cfg.anonym_sub_cert);
                            cfg.anonym_sub_cert_b64 = yume::util::base64_encode(sub_pem);
                        } catch (const std::exception& ex) {
                            yume::util::log_warn(std::string("failed to read anonym_sub_cert: ") + ex.what());
                        }
                    }
                }
                if (pq_sign_key.empty() && !cfg.anonym_ca_key.empty()) {
                    pq_sign_key = cfg.anonym_ca_key;
                }
                if (cfg.anonym_certfp.empty()) {
                    yume::util::log_warn("PQ OTA disabled: TLS cert fingerprint missing");
                } else if (pq_sign_key.empty()) {
                    yume::util::log_warn("PQ OTA disabled: anonym_sub_key/anonym_ca_key not set");
                } else if (!sign_pq_pub_with_key(pq_pub_b64, cfg.anonym_certfp, pq_sign_key,
                                                 &cfg.pq_sig, &cfg.pq_alg)) {
                    yume::util::log_warn("PQ OTA disabled: pq public key signing failed");
                }
            } else {
                yume::util::log_warn("PQ public key not readable; OTA PQ disabled");
            }
        }
    }

    const std::string local_instance_key = effective_server_instance_key(cfg, config_path);
    const std::string local_runtime_path = cfg.ipc_path.empty()
        ? yume::server::LocalRuntime::socket_path_for(local_instance_key)
        : cfg.ipc_path;
    const bool local_runtime_exists =
        cfg.ipc_enable && yume::server::LocalRuntime::available(local_runtime_path);
    if (cfg.ipc_enable && local_runtime_exists) {
        const bool should_attach = attach_local || prompt_attach_existing("yumed");
        if (should_attach) {
            return run_local_server_attach(local_runtime_path, !stdin_is_tty());
        }
        yume::util::log_error("yumed is already running for this instance; use --attach-local to interact with it");
        return 1;
    } else if (attach_local) {
        yume::util::log_error("no running yumed instance was found for this configuration");
        return 1;
    }

    unsigned int hw = std::thread::hardware_concurrency();
    int threads = cfg.threads > 0 ? cfg.threads : static_cast<int>(hw > 0 ? hw : 1);
    boost::asio::io_context io(threads);
    yume::server::Manager manager(io, cfg);
    std::atomic<bool> stop_refresh{false};
    std::mutex refresh_mu;
    std::condition_variable refresh_cv;
    std::thread refresh_thread;
    auto local_runtime = std::make_shared<yume::server::LocalRuntime>(
        local_runtime_path,
        &manager,
        [&]() {
            manager.stop();
            io.stop();
            stop_refresh.store(true);
            refresh_cv.notify_all();
        });
    if (cfg.anonym) {
        refresh_thread = std::thread([&manager, &cfg, &stop_refresh, &anonym_last_ts, &refresh_mu, &refresh_cv, anonym_local_sign]() {
            auto compute_delay = [&]() -> int {
                const long long now = static_cast<long long>(std::time(nullptr));
                const long long last = anonym_last_ts.load(std::memory_order_relaxed);
                if (last <= 0) {
                    return yume::policy::kAnonymRefreshMinSeconds;
                }
                const long long age = now - last;
                const long long target = static_cast<long long>(
                    yume::policy::kAnonymProofWindowSeconds - yume::policy::kAnonymRefreshLeadSeconds);
                long long delay = target - age;
                if (delay < yume::policy::kAnonymRefreshMinSeconds) {
                    delay = yume::policy::kAnonymRefreshMinSeconds;
                }
                if (delay > yume::policy::kAnonymRefreshSeconds) {
                    delay = yume::policy::kAnonymRefreshSeconds;
                }
                return static_cast<int>(delay);
            };

            while (!stop_refresh.load()) {
                const int delay_s = compute_delay();
                std::unique_lock<std::mutex> lock(refresh_mu);
                if (refresh_cv.wait_for(lock, std::chrono::seconds(delay_s), [&stop_refresh]() {
                        return stop_refresh.load();
                    })) {
                    break;
                }
                lock.unlock();
                try {
                    std::string pq_public_path;
                    if (cfg.inner_crypto && !cfg.pq_private_key.empty()) {
                        pq_public_path = derive_pq_public_path(cfg.pq_private_key);
                    }
                    std::string pq_sign_key = !cfg.anonym_sub_key.empty() ? cfg.anonym_sub_key : cfg.anonym_ca_key;
                    auto proof = fetch_anonym_proof(cfg.anonym_hash, cfg.anonym_certfp, cfg.anonym_proof_mode, cfg.anonym_api,
                                                    cfg.anonym_token, cfg.anonym_ca_key,
                                                    cfg.anonym_sub_key, cfg.anonym_sub_cert,
                                                    pq_public_path, pq_sign_key, anonym_local_sign,
                                                    cfg.outbound_proxy_url);
                    cfg.anonym_ts = proof.ts;
                    manager.update_anonym_proof(proof.hash, proof.sig, proof.ts, proof.nonce,
                                                proof.certfp, proof.proof_policy, proof.proof_sources,
                                                proof.ca_sig, proof.ca_alg,
                                                proof.sub_sig, proof.sub_alg, proof.sub_cert_b64,
                                                proof.pq_pub_b64, proof.pq_sig, proof.pq_alg);
                    anonym_last_ts.store(parse_proof_ts(proof.ts, static_cast<long long>(std::time(nullptr))),
                                         std::memory_order_relaxed);
                } catch (const std::exception& ex) {
                    std::cerr << "\033[1;33mANONYM REFRESH FAILED: " << ex.what() << "\033[0m\n";
                    anonym_last_ts.store(0, std::memory_order_relaxed);
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
            yume::util::log_info("Stopping...");
        } else {
            std::cerr << "\033[1;33mStopping...\033[0m\n";
        }
        local_runtime->stop();
        manager.stop();
        stop_refresh.store(true);
        refresh_cv.notify_all();
        std::thread([&io]() {
            std::this_thread::sleep_for(std::chrono::milliseconds(1500));
            io.stop();
        }).detach();
    });

    try {
        std::string ipc_error;
        if (cfg.ipc_enable && !local_runtime->start(&ipc_error)) {
            yume::util::log_warn("local attach disabled: " + ipc_error);
        }
        manager.start();
        if (!keep_root) {
            std::string drop_error;
            std::string drop_summary;
            if (!yume::util::drop_privileges(&drop_error, &drop_summary)) {
                throw std::runtime_error("failed to drop privileges: " + drop_error);
            }
            if (!drop_summary.empty()) {
                if (yume::util::is_logging_enabled()) {
                    yume::util::log_info(drop_summary);
                } else {
                    std::cerr << "\033[1;33mPrivileges dropped after bind/listen\033[0m\n";
                }
            }
        }
    } catch (const std::exception& ex) {
        local_runtime->stop();
        manager.stop();
        if (yume::util::is_logging_enabled()) {
            yume::util::log_error(std::string("server start failed: ") + ex.what());
        } else {
            std::cerr << "\033[1;31mserver start failed: " << ex.what() << "\033[0m\n";
        }
        stop_refresh.store(true);
        refresh_cv.notify_all();
        if (refresh_thread.joinable()) {
            refresh_thread.join();
        }
        return 1;
    }

    std::vector<std::thread> workers;
    workers.reserve(static_cast<size_t>(threads));
    for (int i = 0; i < threads; ++i) {
        workers.emplace_back([&]() { io.run(); });
    }
    for (auto& t : workers) {
        t.join();
    }
    stop_refresh.store(true);
    refresh_cv.notify_all();
    if (refresh_thread.joinable()) {
        refresh_thread.join();
    }
    local_runtime->stop();

    return 0;
}
