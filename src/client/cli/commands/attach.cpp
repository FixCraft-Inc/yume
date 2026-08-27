/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/commands/attach.hpp"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <optional>
#include <sstream>

#include <nlohmann/json.hpp>

#include "client/cli/entry.hpp"
#include "client/cli/config/args.hpp"
#include "client/cli/config/input.hpp"
#include "client/cli/commands/relay_secret.hpp"
#include "client/relay/secret.hpp"
#include "client/runtime/local_runtime.hpp"
#include "core/security/identity.hpp"
#include "util.hpp"

namespace yume::client {
namespace {

void print_local_client_attach_help() {
    util::log_info("Attached console: help | whoami | status | directory | contacts | forget <endpoint-id> | invites | chat <peer> | send <text> | send-file <peer> <path> | send-bytes <peer> <path> | accept <invite|from> [password] | reject <invite|from> [reason] | history [peer] | history-delete <peer|all> | admin attach <peer> | admin status | admin sessions | admin stop | quit");
}

nlohmann::json request_local_client_runtime(const std::string& socket_path,
                                           const std::string& op,
                                           nlohmann::json args,
                                           std::string* error) {
    // This wrapper owns the request copy passed to the socket transport. Move
    // secret-bearing arguments into it and wipe both objects on every exit;
    // the caller remains responsible for its original password/key buffer.
    RelayRequestSecretsWiper args_wiper(args);
    nlohmann::json request{
        {"op", op},
        {"args", nlohmann::json::object()},
    };
    RelayRequestSecretsWiper request_wiper(request);
    request["args"] = std::move(args);
    return yume::client::LocalRuntime::request(
        socket_path,
        request,
        error,
        10000);
}

std::optional<nlohmann::json> SelectPendingInvite(
    const nlohmann::json& invites,
    const std::string& selector,
    bool* ambiguous) {
    if (ambiguous) *ambiguous = false;
    if (!invites.is_array()) return std::nullopt;
    for (const auto& invite : invites) {
        if (invite.value("invite_id", "") == selector) return invite;
    }
    std::optional<nlohmann::json> match;
    for (const auto& invite : invites) {
        if (invite.value("from_id", "") != selector &&
            invite.value("from_display_name", "") != selector) {
            continue;
        }
        if (match) {
            if (ambiguous) *ambiguous = true;
            return std::nullopt;
        }
        match = invite;
    }
    return match;
}

std::string TransferInviteSummary(const nlohmann::json& invite) {
    const std::string kind = invite.value("channel_kind", "");
    if (kind != "file" && kind != "bytes") return {};
    if (invite.contains("metadata") && invite["metadata"].is_object()) {
        const auto& metadata = invite["metadata"];
        if (metadata.contains("name") && metadata["name"].is_string() &&
            metadata.contains("size") &&
            metadata["size"].is_number_unsigned()) {
            return " name=" + metadata["name"].get<std::string>() +
                " size=" +
                std::to_string(metadata["size"].get<std::uint64_t>());
        }
    }
    return " metadata=invalid";
}

}  // namespace

bool prompt_attach_existing(const std::string& kind) {
    if (!is_tty_stdin()) {
        return true;
    }
    util::clear_status_line();
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

std::string effective_client_instance_key(const ClientConfig& cfg, const ParsedArgs& args) {
    if (!cfg.instance_name.empty()) {
        return cfg.instance_name;
    }
    return yume::identity::derive_instance_key(
        cfg.server + "|" + std::to_string(cfg.port) + "|" + cfg.identity + "|" + args.config_path);
}

int run_local_client_attach(const std::string& socket_path, const ParsedArgs& args, const ClientConfig& cfg) {
    std::string error;

    if (args.directory_mode) {
        auto resp = request_local_client_runtime(socket_path, "directory.list", nlohmann::json::object(), &error);
        if (!error.empty() || !resp.value("ok", false)) {
            util::log_error(error.empty() ? resp.value("error", "directory request failed") : error);
            return 1;
        }
        for (const auto& entry : resp["result"]) {
            std::cout << entry.value("endpoint_id", "")
                      << " " << entry.value("display_name", "")
                      << " kind=" << entry.value("endpoint_kind", "")
                      << " relay=" << entry.value("relay_mode", "")
                      << " platform=" << entry.value("client_platform", "unknown")
                      << " variant=" << entry.value("client_variant", "unknown")
                      << " chat=" << (entry.value("allow_chat", true) ? "yes" : "no")
                      << " file=" << (entry.value("allow_file", true) ? "yes" : "no")
                      << " bytes=" << (entry.value("allow_bytes", true) ? "yes" : "no")
                      << "\n";
        }
        return 0;
    }
    if (!args.chat_target.empty()) {
        std::string relay_secret_b64;
        RelaySecretWiper relay_secret_wiper(relay_secret_b64);
        if (!resolve_relay_secret(cfg, "", "chat with " + args.chat_target, &relay_secret_b64, &error)) {
            util::log_error(error);
            return 1;
        }
        auto resp = request_local_client_runtime(socket_path, "chat.open",
                                                 {{"peer", args.chat_target}, {"relay_secret", relay_secret_b64}}, &error);
        if (!error.empty() || !resp.value("ok", false)) {
            util::log_error(error.empty() ? resp.value("error", "chat open failed") : error);
            return 1;
        }
        return 0;
    }
    if (!args.file_target.empty()) {
        std::string relay_secret_b64;
        RelaySecretWiper relay_secret_wiper(relay_secret_b64);
        if (!resolve_relay_secret(cfg, "", "file send to " + args.file_target, &relay_secret_b64, &error)) {
            util::log_error(error);
            return 1;
        }
        auto resp = request_local_client_runtime(socket_path, "file.send",
                                                 {{"peer", args.file_target}, {"path", args.file_path}, {"relay_secret", relay_secret_b64}}, &error);
        if (!error.empty() || !resp.value("ok", false)) {
            util::log_error(error.empty() ? resp.value("error", "file send failed") : error);
            return 1;
        }
        return 0;
    }
    if (!args.bytes_target.empty()) {
        std::string relay_secret_b64;
        RelaySecretWiper relay_secret_wiper(relay_secret_b64);
        if (!resolve_relay_secret(cfg, "", "bytes send to " + args.bytes_target, &relay_secret_b64, &error)) {
            util::log_error(error);
            return 1;
        }
        auto resp = request_local_client_runtime(socket_path, "bytes.send",
                                                 {{"peer", args.bytes_target}, {"path", args.bytes_path}, {"relay_secret", relay_secret_b64}}, &error);
        if (!error.empty() || !resp.value("ok", false)) {
            util::log_error(error.empty() ? resp.value("error", "bytes send failed") : error);
            return 1;
        }
        return 0;
    }
    if (!args.admin_target.empty()) {
        auto resp = request_local_client_runtime(socket_path, "admin.attach",
                                                 {{"peer", args.admin_target}}, &error);
        if (!error.empty() || !resp.value("ok", false)) {
            util::log_error(error.empty() ? resp.value("error", "admin attach failed") : error);
            return 1;
        }
        return 0;
    }

    if (cfg.non_interactive || !is_tty_stdin()) {
        auto resp = request_local_client_runtime(socket_path, "runtime.status", nlohmann::json::object(), &error);
        if (!error.empty() || !resp.value("ok", false)) {
            util::log_error(error.empty() ? resp.value("error", "status failed") : error);
            return 1;
        }
        std::cout << resp["result"].dump(2) << std::endl;
        return 0;
    }

    util::log_info("Attached to existing yume runtime");
    print_local_client_attach_help();
#if !defined(_WIN32)
    std::optional<InteractiveLineReader> line_reader;
    if (is_tty_stdin()) {
        line_reader.emplace();
    }
#endif
    for (;;) {
        std::string line;
        RelaySecretWiper line_wiper(line);
#if !defined(_WIN32)
        if (line_reader.has_value()) {
            for (;;) {
                if (line_reader->read_line(&line, 250)) {
                    break;
                }
                if (!std::cin.good() && std::cin.eof()) {
                    return 0;
                }
            }
        } else
#endif
        if (!std::getline(std::cin, line)) {
            return 0;
        }
        line = trim_copy(line);
        if (line.empty()) {
            continue;
        }
        if (line == "help") {
            print_local_client_attach_help();
            continue;
        }
        if (line == "quit" || line == "exit") {
            return 0;
        }
        if (line == "whoami") {
            auto resp = request_local_client_runtime(socket_path, "runtime.info", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "runtime info failed") : error);
                error.clear();
                continue;
            }
            std::cout << resp["result"].dump(2) << std::endl;
            continue;
        }
        if (line == "status") {
            auto resp = request_local_client_runtime(socket_path, "runtime.status", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "status failed") : error);
                error.clear();
                continue;
            }
            std::cout << resp["result"].dump(2) << std::endl;
            continue;
        }
        if (line == "directory") {
            auto resp = request_local_client_runtime(socket_path, "directory.list", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "directory failed") : error);
                error.clear();
                continue;
            }
            for (const auto& entry : resp["result"]) {
                std::cout << entry.value("endpoint_id", "") << " "
                          << entry.value("display_name", "")
                          << " kind=" << entry.value("endpoint_kind", "")
                          << " relay=" << entry.value("relay_mode", "")
                          << " platform=" << entry.value("client_platform", "unknown")
                          << " variant=" << entry.value("client_variant", "unknown")
                          << " chat=" << (entry.value("allow_chat", true) ? "yes" : "no")
                          << " file=" << (entry.value("allow_file", true) ? "yes" : "no")
                          << " bytes=" << (entry.value("allow_bytes", true) ? "yes" : "no")
                          << std::endl;
            }
            continue;
        }
        if (line == "contacts") {
            auto resp = request_local_client_runtime(socket_path, "contacts.list", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "contacts failed") : error);
                error.clear();
                continue;
            }
            const auto& result = resp["result"];
            if (!result.value("directory_available", false)) {
                // Trust is local, presence is not. Say which half is missing
                // rather than showing every contact as offline.
                util::log_warn("directory unavailable; presence is unknown: " +
                               result.value("directory_error", "unknown error"));
            }
            for (const auto& contact : result["contacts"]) {
                std::cout << contact.value("endpoint_id", "") << " "
                          << contact.value("display_name", "")
                          << " trust=" << contact.value("trust_source", "")
                          << " presence=" << (!contact.value("in_directory", false)
                                                  ? "unknown"
                                                  : (contact.value("online", false) ? "online" : "offline"));
                if (contact.value("configured_mismatch", false)) {
                    std::cout << " CONFIGURED-PIN-MISMATCH";
                }
                std::cout << std::endl;
            }
            continue;
        }
        if (line == "forget") {
            util::log_warn("usage: forget <endpoint-id>");
            continue;
        }
        if (line.rfind("forget ", 0) == 0) {
            auto resp = request_local_client_runtime(
                socket_path, "contacts.forget",
                {{"endpoint_id", trim_copy(line.substr(7))}}, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "forget failed") : error);
                error.clear();
                continue;
            }
            util::log_info(resp["result"].value("removed", false)
                               ? "contact forgotten"
                               : "no learned trust was stored for that peer");
            continue;
        }
        if (line == "invites") {
            auto resp = request_local_client_runtime(socket_path, "invite.list", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "invite list failed") : error);
                error.clear();
                continue;
            }
            for (const auto& invite : resp["result"]) {
                std::cout << invite.value("invite_id", "") << " from="
                          << (invite.value("from_display_name", "").empty()
                                  ? invite.value("from_id", "")
                                  : invite.value("from_display_name", ""))
                          << " kind=" << invite.value("channel_kind", "")
                          << TransferInviteSummary(invite)
                          << std::endl;
            }
            continue;
        }
        if (line == "chat") {
            util::log_warn("usage: chat <peer>");
            continue;
        }
        if (line.rfind("chat ", 0) == 0) {
            const std::string peer = trim_copy(line.substr(5));
            if (peer.empty()) {
                util::log_warn("usage: chat <peer>");
                continue;
            }
            std::string relay_secret_b64;
            RelaySecretWiper relay_secret_wiper(relay_secret_b64);
            if (!resolve_relay_secret(cfg, "", "chat with " + peer, &relay_secret_b64, &error)) {
                util::log_warn(error);
                error.clear();
                continue;
            }
            auto resp = request_local_client_runtime(socket_path, "chat.open",
                                                     {{"peer", peer}, {"relay_secret", relay_secret_b64}}, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "chat open failed") : error);
                error.clear();
            }
            continue;
        }
        if (line == "send-file") {
            util::log_warn("usage: send-file <peer> <path>");
            continue;
        }
        if (line.rfind("send-file ", 0) == 0) {
            std::string peer;
            std::string path;
            split_first_token(line.substr(10), &peer, &path);
            if (peer.empty() || path.empty()) {
                util::log_warn("usage: send-file <peer> <path>");
                continue;
            }
            std::string relay_secret_b64;
            RelaySecretWiper relay_secret_wiper(relay_secret_b64);
            if (!resolve_relay_secret(cfg, "", "file send to " + peer, &relay_secret_b64, &error)) {
                util::log_warn(error);
                error.clear();
                continue;
            }
            auto resp = request_local_client_runtime(socket_path, "file.send",
                                                     {{"peer", peer}, {"path", path}, {"relay_secret", relay_secret_b64}}, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "file send failed") : error);
                error.clear();
            }
            continue;
        }
        if (line == "send-bytes") {
            util::log_warn("usage: send-bytes <peer> <path>");
            continue;
        }
        if (line.rfind("send-bytes ", 0) == 0) {
            std::string peer;
            std::string path;
            split_first_token(line.substr(11), &peer, &path);
            if (peer.empty() || path.empty()) {
                util::log_warn("usage: send-bytes <peer> <path>");
                continue;
            }
            std::string relay_secret_b64;
            RelaySecretWiper relay_secret_wiper(relay_secret_b64);
            if (!resolve_relay_secret(cfg, "", "bytes send to " + peer, &relay_secret_b64, &error)) {
                util::log_warn(error);
                error.clear();
                continue;
            }
            auto resp = request_local_client_runtime(socket_path, "bytes.send",
                                                     {{"peer", peer}, {"path", path}, {"relay_secret", relay_secret_b64}}, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "bytes send failed") : error);
                error.clear();
            }
            continue;
        }
        if (line.rfind("send ", 0) == 0) {
            auto resp = request_local_client_runtime(socket_path, "chat.send",
                                                     {{"text", trim_copy(line.substr(5))}}, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "chat send failed") : error);
                error.clear();
            }
            continue;
        }
        if (line == "accept") {
            util::log_warn("usage: accept <invite|from> [password]");
            continue;
        }
        if (line.rfind("accept ", 0) == 0) {
            std::string invite_id;
            std::string password;
            RelaySecretWiper password_wiper(password);
            split_first_token(line.substr(7), &invite_id, &password);
            if (invite_id.empty()) {
                util::log_warn("usage: accept <invite|from> [password]");
                continue;
            }
            std::string relay_secret_b64;
            RelaySecretWiper relay_secret_wiper(relay_secret_b64);
            auto invites = request_local_client_runtime(
                socket_path, "invite.list", nlohmann::json::object(), &error);
            if (!error.empty() || !invites.value("ok", false)) {
                util::log_warn(error.empty()
                    ? invites.value("error", "invite lookup failed") : error);
                error.clear();
                continue;
            }
            bool ambiguous = false;
            const auto pending = SelectPendingInvite(
                invites.value("result", nlohmann::json::array()),
                invite_id, &ambiguous);
            if (!pending) {
                util::log_warn(ambiguous
                    ? "invite selector is ambiguous" : "invite not found");
                continue;
            }
            if (pending->value("requires_password", true)) {
                if (!resolve_relay_secret(cfg, password,
                                          "accept invite " + invite_id,
                                          &relay_secret_b64, &error)) {
                    util::log_warn(error);
                    error.clear();
                    continue;
                }
            } else if (!password.empty()) {
                util::log_warn("admin invites do not accept a relay password");
                continue;
            }
            auto resp = request_local_client_runtime(socket_path, "invite.accept",
                                                     {{"invite_selector", invite_id}, {"relay_secret", relay_secret_b64}}, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "invite accept failed") : error);
                error.clear();
            }
            continue;
        }
        if (line == "reject") {
            util::log_warn("usage: reject <invite|from> [reason]");
            continue;
        }
        if (line.rfind("reject ", 0) == 0) {
            std::istringstream iss(line.substr(7));
            std::string invite_id;
            iss >> invite_id;
            std::string reason;
            std::getline(iss, reason);
            auto resp = request_local_client_runtime(socket_path, "invite.reject",
                                                     {{"invite_selector", invite_id}, {"reason", trim_copy(reason)}}, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "invite reject failed") : error);
                error.clear();
            }
            continue;
        }
        if (line.rfind("history-delete ", 0) == 0) {
            std::string arg = trim_copy(line.substr(15));
            nlohmann::json req_args = nlohmann::json::object();
            if (arg != "all" && !arg.empty()) {
                req_args["peer_id"] = arg;
            } else if (arg == "all") {
                req_args["all"] = true;
            }
            auto resp = request_local_client_runtime(socket_path, "history.delete", req_args, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "history delete failed") : error);
                error.clear();
            }
            continue;
        }
        if (line.rfind("history", 0) == 0) {
            std::string arg = trim_copy(line.substr(7));
            nlohmann::json req_args = nlohmann::json::object();
            if (!arg.empty()) {
                req_args["peer_id"] = arg;
            }
            auto resp = request_local_client_runtime(socket_path, "history.list", req_args, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "history failed") : error);
                error.clear();
                continue;
            }
            const auto result = resp.find("result");
            if (result == resp.end() || !result->is_object() ||
                !result->contains("items") ||
                !(*result)["items"].is_array() ||
                !result->contains("available") ||
                !(*result)["available"].is_boolean() ||
                !result->contains("truncated") ||
                !(*result)["truncated"].is_boolean() ||
                !result->contains("error") ||
                !(*result)["error"].is_string()) {
                util::log_warn("history response was malformed");
                continue;
            }
            if (!result->value("available", false)) {
                util::log_warn(result->value(
                    "error", "history storage is unavailable"));
            }
            for (const auto& item : (*result)["items"]) {
                if (!item.is_object()) {
                    util::log_warn("history response contained a malformed item");
                    continue;
                }
                std::cout << item.value("direction", "?") << " "
                          << item.value("peer_name", item.value("peer_id", ""))
                          << " " << item.value("text", "") << std::endl;
            }
            if (result->value("truncated", false)) {
                util::log_warn("history output is truncated");
            }
            continue;
        }
        if (line.rfind("admin attach ", 0) == 0) {
            auto resp = request_local_client_runtime(socket_path, "admin.attach",
                                                     {{"peer", trim_copy(line.substr(13))}}, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "admin attach failed") : error);
                error.clear();
            }
            continue;
        }
        if (line == "admin status" || line == "admin sessions" || line == "admin stop") {
            const std::string op =
                (line == "admin stop") ? "admin.stop" :
                ((line == "admin sessions") ? "admin.sessions" : "admin.status");
            auto resp = request_local_client_runtime(socket_path, op, nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "admin request failed") : error);
                error.clear();
                continue;
            }
            std::cout << resp["result"].dump(2) << std::endl;
            continue;
        }
        util::log_warn("unknown command: " + line);
    }
}

}  // namespace yume::client
