/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/entry.hpp"

#include <iostream>
#include <filesystem>
#include <algorithm>
#include <utility>
#include <ctime>
#include <thread>
#include <vector>
#include <atomic>
#include <condition_variable>
#include <cerrno>
#include <mutex>
#include <stop_token>
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
#include <sys/stat.h>
#include <unistd.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif
#include "server/cli/help.hpp"
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

#include "core/protocol/runtime_policy.hpp"
#include "core/app_codec/codec.hpp"
#include "server/runtime/manager.hpp"
#include "server/cli/anonym.hpp"
#include "server/cli/args.hpp"
#include "server/cli/cluster.hpp"
#include "server/cli/config_load.hpp"
#include "server/cli/key.hpp"
#include "server/runtime/local_runtime.hpp"
#include "server/cli/local.hpp"
#include "server/cli/misc.hpp"
#include "server/cli/runtime_prep.hpp"
#include "server/cli/startup_checks.hpp"
#include "util.hpp"

namespace {
constexpr const char kDefaultSecretPath[] = "./.secrets/html_secret";

using yume::server::cli::anonym_local_sign_default;
using yume::server::cli::derive_pq_public_path;
using yume::server::cli::expand_cluster_join_spec;
using yume::server::cli::fetch_anonym_proof;
using yume::server::cli::cert_fingerprint_sha256;
using yume::server::cli::get_self_path;
using yume::server::cli::load_server_config_file_and_resolve_paths;
using yume::server::cli::load_pq_public_b64;
using yume::server::cli::parse_proof_ts;
using yume::server::cli::prepare_server_runtime_files;
using yume::server::cli::read_file_bytes;
using yume::server::cli::resolve_filter_list_spec_path;
using yume::server::cli::run_server_key_command;
using yume::server::cli::run_server_manager_ui;
using yume::server::cli::ServerConfigLoadContext;
using yume::server::cli::ServerConfigOverrides;
using yume::server::cli::ServerKeyCommand;
using yume::server::cli::sha256_hex;
using yume::server::cli::sign_pq_pub_with_key;
using yume::server::cli::StartupCheckOptions;
using yume::server::cli::prepare_server_startup_config;

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

#if !defined(_WIN32)
bool parse_unsigned_env(const char* name, unsigned long* out) {
    if (!out) {
        return false;
    }
    const char* raw = std::getenv(name);
    if (!raw || !*raw) {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    unsigned long value = std::strtoul(raw, &end, 10);
    if (errno != 0 || !end || *end != '\0') {
        return false;
    }
    *out = value;
    return true;
}

bool sudo_drop_target(uid_t* uid, gid_t* gid) {
    unsigned long raw_uid = 0;
    unsigned long raw_gid = 0;
    if (!parse_unsigned_env("SUDO_UID", &raw_uid) ||
        !parse_unsigned_env("SUDO_GID", &raw_gid) ||
        raw_uid == 0) {
        return false;
    }
    if (uid) {
        *uid = static_cast<uid_t>(raw_uid);
    }
    if (gid) {
        *gid = static_cast<gid_t>(raw_gid);
    }
    return true;
}

void repair_drop_target_file(const std::filesystem::path& path,
                             uid_t uid,
                             gid_t gid,
                             mode_t mode,
                             const char* label) {
    if (path.empty()) {
        return;
    }
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        return;
    }
    if (::chown(path.c_str(), uid, gid) != 0) {
        yume::util::log_warn(std::string("failed to chown ") + label + " for privilege drop: " +
                             path.string() + " (" + std::strerror(errno) + ")");
    }
    if (::chmod(path.c_str(), mode) != 0) {
        yume::util::log_warn(std::string("failed to chmod ") + label + " for privilege drop: " +
                             path.string() + " (" + std::strerror(errno) + ")");
    }
}

void repair_pq_key_ownership_for_drop(const yume::server::ServerConfig& cfg, bool keep_root) {
    if (keep_root || cfg.pq_private_key.empty() || ::geteuid() != 0) {
        return;
    }

    uid_t uid = 0;
    gid_t gid = 0;
    if (!sudo_drop_target(&uid, &gid)) {
        return;
    }

    std::filesystem::path priv_path(cfg.pq_private_key);
    std::filesystem::path pub_path(derive_pq_public_path(cfg.pq_private_key));
    std::filesystem::path key_dir = priv_path.parent_path();
    if (!key_dir.empty()) {
        repair_drop_target_file(key_dir, uid, gid, 0700, "PQ key directory");
    }
    repair_drop_target_file(priv_path, uid, gid, 0600, "PQ private key");
    repair_drop_target_file(pub_path, uid, gid, 0644, "PQ public key");
}
#endif

struct OperatorProofState final {
    std::atomic<long long> last_timestamp_{0};
    bool local_sign_{false};
};

struct OperatorProofRuntime final {
    std::mutex mutex_;
    std::condition_variable condition_;
    std::jthread thread_;

    void request_stop() noexcept {
        thread_.request_stop();
        condition_.notify_all();
    }
};

class ServerWorkerPool final {
public:
    ServerWorkerPool(boost::asio::io_context& io,
                     yume::server::Manager& manager,
                     yume::server::LocalRuntime& local_runtime,
                     OperatorProofRuntime& operator_proof)
        : io_(io),
          manager_(manager),
          local_runtime_(local_runtime),
          operator_proof_(operator_proof) {}

    ServerWorkerPool(const ServerWorkerPool&) = delete;
    ServerWorkerPool& operator=(const ServerWorkerPool&) = delete;

    ~ServerWorkerPool() noexcept {
        if (active_) rollback();
    }

    bool start(int thread_count, std::string* error) noexcept {
        active_ = true;
        try {
            workers_.reserve(static_cast<std::size_t>(thread_count));
            for (int index = 0; index < thread_count; ++index) {
                workers_.emplace_back([this]() { io_.run(); });
            }
            return true;
        } catch (const std::exception& ex) {
            rollback();
            if (error) {
                *error = std::string("server worker start failed: ") +
                         ex.what();
            }
        } catch (...) {
            rollback();
            if (error) {
                *error = "server worker start failed: unknown error";
            }
        }
        return false;
    }

    void wait() {
        for (auto& worker : workers_) {
            worker.join();
        }
        active_ = false;
    }

private:
    void rollback() noexcept {
        try { local_runtime_.stop(); } catch (...) {}
        try { manager_.stop(); } catch (...) {}
        try { io_.stop(); } catch (...) {}
        for (auto& worker : workers_) {
            try {
                if (worker.joinable()) worker.join();
            } catch (...) {
            }
        }
        operator_proof_.request_stop();
        active_ = false;
    }

    boost::asio::io_context& io_;
    yume::server::Manager& manager_;
    yume::server::LocalRuntime& local_runtime_;
    OperatorProofRuntime& operator_proof_;
    std::vector<std::thread> workers_;
    bool active_{false};
};
}  // namespace

namespace yume::server {

int Server::run(int argc, char** argv) {
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
    yume::server::cli::ServerCliParseResult cli_args;
    if (!yume::server::cli::parse_server_cli_args(argc, argv, cli_cwd, cfg, &cli_args)) {
        return 1;
    }
    if (cli_args.handled) {
        return cli_args.exit_code;
    }
    ServerConfigLoadContext config_context = cli_args.config_context;
    {
        std::string self_path = get_self_path(argv[0]);
        if (!self_path.empty()) {
            config_context.exe_dir = std::filesystem::path(self_path).parent_path().string();
        }
    }

    ServerConfigOverrides config_overrides = cli_args.config_overrides;
    ServerKeyCommand key_command = cli_args.key_command;
    const bool attach_local = cli_args.attach_local;
    const bool keep_root = cli_args.keep_root;

    if (!load_server_config_file_and_resolve_paths(cfg, config_context, config_overrides)) {
        return 1;
    }
    const std::string config_path = config_context.config_path;
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
    if (cfg.inner_dual || cfg.inner_required) {
        cfg.inner_crypto = true;
    }
    cfg.reverse_port_min = std::clamp(cfg.reverse_port_min, 1, 65535);
    cfg.reverse_port_max = std::clamp(cfg.reverse_port_max, 1, 65535);
    if (cfg.reverse_port_min > cfg.reverse_port_max) {
        std::swap(cfg.reverse_port_min, cfg.reverse_port_max);
        yume::util::log_warn("reverse_port_min > reverse_port_max; swapped values");
    }
    cfg.anonym_proof_mode = yume::policy::normalize_anonym_proof_mode(cfg.anonym_proof_mode);

    const bool key_management_only = key_command.ui || key_command.has_action();
    StartupCheckOptions startup_checks;
    startup_checks.tls_handshake_timeout_overridden = config_overrides.tls_handshake_timeout;
    startup_checks.accept_rate_limit_overridden = config_overrides.accept_rate_limit;
    startup_checks.key_management_only = key_management_only;
    startup_checks.default_secret_path = kDefaultSecretPath;
    if (!prepare_server_startup_config(cfg, startup_checks)) {
        return 1;
    }

    if (key_command.ui) {
        auto result = run_server_manager_ui(cfg, key_command);
        if (result.handled) {
            return result.exit_code;
        }
    }
    if (key_command.has_action()) {
        auto result = run_server_key_command(cfg, key_command);
        if (result.handled) {
            return result.exit_code;
        }
    }

    if (prepare_server_runtime_files(cfg, argv[0], false) != 0) {
        return 1;
    }

    OperatorProofState operator_proof_state;
    auto& anonym_last_ts = operator_proof_state.last_timestamp_;
    const char* anonym_local_sign_env = std::getenv("YUME_ANONYM_LOCAL_SIGN");
    operator_proof_state.local_sign_ =
        parse_env_bool("YUME_ANONYM_LOCAL_SIGN", anonym_local_sign_default());
    const bool anonym_local_sign = operator_proof_state.local_sign_;

    if (cfg.anonym) {
        if (!anonym_local_sign && (!cfg.anonym_ca_key.empty() || !cfg.anonym_sub_key.empty())) {
            if (anonym_local_sign_env && *anonym_local_sign_env) {
                yume::util::log_warn("local operator proof signing is disabled by YUME_ANONYM_LOCAL_SIGN=0");
            } else {
                yume::util::log_warn("local operator proof signing is disabled by default on this build/platform (set YUME_ANONYM_LOCAL_SIGN=1 to force)");
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
            std::cerr << "\033[1;31mOPERATOR IDENTITY PROOF FAILED: " << ex.what() << "\033[0m\n";
            return 1;
        }
        yume::util::set_logging_enabled(false);
        std::cerr << "\033[1;33mOPERATOR IDENTITY MODE ACTIVE: this build disables client metadata logging, but clients must still trust the operator\033[0m\n";
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

    const std::string local_instance_key = yume::server::cli::effective_server_instance_key(cfg, config_path);
    const std::string local_runtime_path = cfg.ipc_path.empty()
        ? yume::server::LocalRuntime::socket_path_for(local_instance_key)
        : cfg.ipc_path;
    const bool local_runtime_exists =
        cfg.ipc_enable && yume::server::LocalRuntime::available(local_runtime_path);
    if (cfg.ipc_enable && local_runtime_exists) {
        const bool should_attach = attach_local || yume::server::cli::prompt_attach_existing("yumed");
        if (should_attach) {
            return yume::server::cli::run_local_server_attach(
                local_runtime_path,
                !yume::server::cli::stdin_is_tty());
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
    // The refresher is constructed after Manager, so its jthread always joins
    // before Manager is destroyed on normal return or stack unwinding.
    OperatorProofRuntime operator_proof;
    auto& refresh_mu = operator_proof.mutex_;
    auto& refresh_cv = operator_proof.condition_;
    auto& refresh_thread = operator_proof.thread_;
    // Scope ownership starts before signal registration and privilege-drop
    // preparation, both of which may throw. jthread therefore requests stop
    // and joins the refresher during every later stack-unwind path.
    auto local_runtime = std::make_shared<yume::server::LocalRuntime>(
        local_runtime_path,
        &manager,
        [&]() {
            manager.stop();
            io.stop();
            operator_proof.request_stop();
        });
    if (cfg.anonym) {
        refresh_thread = std::jthread(
            [&manager, &cfg, &anonym_last_ts, &refresh_mu, &refresh_cv,
             anonym_local_sign](std::stop_token stop_token) {
            // request_stop() alone does not wake std::condition_variable.
            // Bind notification to the token so jthread destruction cannot
            // wait for the normal refresh interval.
            std::stop_callback wake_refresh_wait(
                stop_token, [&refresh_cv]() { refresh_cv.notify_all(); });
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

            while (!stop_token.stop_requested()) {
                const int delay_s = compute_delay();
                std::unique_lock<std::mutex> lock(refresh_mu);
                if (refresh_cv.wait_for(lock, std::chrono::seconds(delay_s),
                                        [&stop_token]() {
                        return stop_token.stop_requested();
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
                    std::cerr << "\033[1;33mOPERATOR IDENTITY PROOF REFRESH FAILED: " << ex.what() << "\033[0m\n";
                    anonym_last_ts.store(0, std::memory_order_relaxed);
                }
            }
        });
    }

    ShutdownRequestLatch shutdown_requests;
    boost::asio::steady_timer shutdown_deadline(io);
    yume::util::SignalHandlerRegistration signal_handler([&](int) {
        if (shutdown_requests.request() == ShutdownRequest::Force) {
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
        operator_proof.request_stop();
        // Keep the deadline owned by Server::run. A detached thread capturing
        // io could otherwise outlive this stack frame when the manager drains
        // early. The pending wait also keeps io.run() alive long enough for
        // orderly session-close handlers before enforcing the bound.
        shutdown_deadline.expires_after(std::chrono::milliseconds(1500));
        shutdown_deadline.async_wait(
            [&io](const boost::system::error_code& error) {
                if (!error) {
                    io.stop();
                }
            });
    });

#if !defined(_WIN32)
    repair_pq_key_ownership_for_drop(cfg, keep_root);
#endif

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
        operator_proof.request_stop();
        return 1;
    }

    auto report_worker_start_error = [&](const std::string& message) {
        if (yume::util::is_logging_enabled()) {
            yume::util::log_error(message);
        } else {
            std::cerr << message << '\n';
        }
    };
    ServerWorkerPool workers(io, manager, *local_runtime, operator_proof);
    std::string worker_start_error;
    if (!workers.start(threads, &worker_start_error)) {
        report_worker_start_error(worker_start_error);
        return 1;
    }
    workers.wait();
    operator_proof.request_stop();
    local_runtime->stop();

    return 0;
}

}  // namespace yume::server
