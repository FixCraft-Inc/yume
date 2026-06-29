/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/commands/relay_secret.hpp"

#include <cstdlib>
#include <string>
#include <utility>

#include "client/cli/entry.hpp"
#include "client/cli/connect/cert.hpp"
#include "client/cli/config/input.hpp"
#include "client/relay/secret.hpp"
#include "util.hpp"

namespace yume::client {
namespace {

bool prompt_relay_password(const std::string& purpose,
                           bool confirm,
                           std::string* password,
                           std::string* error) {
    const std::string prompt = purpose.empty()
        ? "Relay password: "
        : "Relay password for " + purpose + ": ";
    std::string first;
    if (!prompt_hidden_input(prompt, &first, error)) {
        return false;
    }
    if (first.empty()) {
        if (error) {
            *error = "relay password cannot be empty";
        }
        return false;
    }
    if (!confirm) {
        if (password) {
            *password = std::move(first);
        }
        return true;
    }
    std::string second;
    if (!prompt_hidden_input("Confirm relay password: ", &second, error)) {
        return false;
    }
    if (first != second) {
        if (error) {
            *error = "relay password confirmation did not match";
        }
        return false;
    }
    if (password) {
        *password = std::move(first);
    }
    return true;
}

}  // namespace

bool resolve_relay_secret(const ClientConfig& cfg,
                          const std::string& explicit_password,
                          const std::string& purpose,
                          std::string* relay_secret_b64,
                          std::string* error) {
    if (!relay_secret_b64) {
        if (error) {
            *error = "relay secret output is null";
        }
        return false;
    }

    const std::string relay_key_file = cfg.relay_key_file.empty()
        ? std::string()
        : util::expand_user(cfg.relay_key_file);
    const bool has_key_file = !relay_key_file.empty();
    const bool key_file_exists = has_key_file && file_exists(relay_key_file);

    auto persist_secret = [&](const std::string& secret_b64) -> bool {
        if (!has_key_file || key_file_exists) {
            return true;
        }
        std::string persist_error;
        if (!write_relay_secret_file(relay_key_file, secret_b64, &persist_error)) {
            if (error) {
                *error = persist_error;
            }
            return false;
        }
        util::log_info("stored relay key at " + relay_key_file);
        return true;
    };

    if (!explicit_password.empty()) {
        *relay_secret_b64 = derive_relay_secret_b64(explicit_password);
        return persist_secret(*relay_secret_b64);
    }

    if (key_file_exists) {
        return load_relay_secret_file(relay_key_file, relay_secret_b64, error);
    }

    const char* env_pw = std::getenv("YUME_RELAY_PASSWORD");
    if (env_pw && *env_pw) {
        *relay_secret_b64 = derive_relay_secret_b64(env_pw);
        return persist_secret(*relay_secret_b64);
    }

    if (cfg.non_interactive || !is_tty_stdin()) {
        if (error) {
            if (has_key_file) {
                *error = "relay key file not found: " + relay_key_file;
            } else {
                *error = "relay password required (set YUME_RELAY_PASSWORD or configure relay_key_file)";
            }
        }
        return false;
    }

    std::string password;
    if (!prompt_relay_password(purpose, has_key_file && !key_file_exists, &password, error)) {
        return false;
    }
    *relay_secret_b64 = derive_relay_secret_b64(password);
    return persist_secret(*relay_secret_b64);
}

}  // namespace yume::client
