/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include <iostream>
#include <thread>
#include <vector>

#include "server/manager.hpp"
#include "util.hpp"

int main(int argc, char** argv) {
    yume::util::init_logging();

    std::string config_path = "config/yumed.json";
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--config" && i + 1 < argc) {
            config_path = argv[++i];
        }
    }

    yume::server::ServerConfig cfg;
    try {
        auto json = yume::util::read_json_config(config_path);
        if (json.contains("listen_port")) {
            cfg.listen_port = json["listen_port"].get<int>();
        }
        if (json.contains("tls_cert")) {
            cfg.tls_cert = json["tls_cert"].get<std::string>();
        }
        if (json.contains("tls_key")) {
            cfg.tls_key = json["tls_key"].get<std::string>();
        }
        if (json.contains("auth_keys")) {
            cfg.auth_keys = json["auth_keys"].get<std::string>();
        }
        if (json.contains("threads")) {
            cfg.threads = json["threads"].get<int>();
        }
        if (json.contains("obfuscation")) {
            cfg.obfuscation = json["obfuscation"].get<bool>();
        }
        if (json.contains("inner_crypto")) {
            cfg.inner_crypto = json["inner_crypto"].get<bool>();
        }
        if (json.contains("pq_private_key")) {
            cfg.pq_private_key = yume::util::expand_user(json["pq_private_key"].get<std::string>());
        }
        if (json.contains("allow_exec")) {
            cfg.allow_exec = json["allow_exec"].get<bool>();
        }
    } catch (const std::exception& ex) {
        yume::util::log_error(std::string("config load failed: ") + ex.what());
        return 1;
    }

    if (cfg.tls_cert.empty() || cfg.tls_key.empty()) {
        yume::util::log_error("tls_cert and tls_key must be set");
        return 1;
    }
    if (cfg.auth_keys.empty()) {
        yume::util::log_error("auth_keys must be set");
        return 1;
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
