/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/cli/commands/console.hpp"

#include <cstdint>
#include <iostream>
#include <sstream>
#include <utility>

#include <nlohmann/json.hpp>

#include "client/cli/config/input.hpp"
#include "client/cli/commands/relay_secret.hpp"
#include "client/cli/commands/io_runtime.hpp"
#include "client/relay/runtime.hpp"
#include "client/transport/tunnel.hpp"
#include "core/protocol/control_protocol.hpp"
#include "util.hpp"

namespace yume::client {

InteractiveConsoleSession::InteractiveConsoleSession(std::shared_ptr<std::atomic<bool>> stop,
                                                     std::thread worker)
    : stop_(std::move(stop)), worker_(std::move(worker)) {}

InteractiveConsoleSession::InteractiveConsoleSession(InteractiveConsoleSession&& other) noexcept
    : stop_(std::move(other.stop_)), worker_(std::move(other.worker_)) {}

InteractiveConsoleSession& InteractiveConsoleSession::operator=(InteractiveConsoleSession&& other) noexcept {
    if (this != &other) {
        stop();
        stop_ = std::move(other.stop_);
        worker_ = std::move(other.worker_);
    }
    return *this;
}

InteractiveConsoleSession::~InteractiveConsoleSession() {
    stop();
}

InteractiveConsoleSession::operator bool() const noexcept {
    return static_cast<bool>(stop_);
}

void InteractiveConsoleSession::stop() {
    if (stop_) {
        stop_->store(true);
    }
    if (worker_.joinable()) {
        worker_.join();
    }
    stop_.reset();
}

bool should_enable_interactive_console(const ClientConfig& cfg,
                                       const ParsedArgs& args,
                                       bool use_reverse) {
    return !cfg.non_interactive &&
           is_tty_stdin() &&
           parse_env_bool("YUME_COMMAND_CONSOLE", true) &&
           args.run_cmd.empty() &&
           args.exec_cmd.empty() &&
           !args.list_controlled &&
           (cfg.socks_port > 0 || use_reverse || args.lport > 0 ||
            args.control_mode ||
            args.directory_mode || !args.chat_target.empty() ||
            !args.file_target.empty() || !args.bytes_target.empty() ||
            !args.admin_target.empty());
}

InteractiveConsoleSession start_interactive_console(
    std::atomic<bool>& stop_requested,
    const ClientConfig& cfg,
    std::shared_ptr<Tunnel> tunnel,
    std::shared_ptr<RelayRuntime> relay_runtime,
    InteractiveConsoleSession::StatusBuilder status_block_builder,
    InteractiveConsoleSession::DisconnectCallback request_disconnect) {
    auto console_stop = std::make_shared<std::atomic<bool>>(false);
    util::log_info("Interactive console ready. Type help + Enter.");
    util::log_info("Console: help | whoami | status | directory | invites | chat <peer> | send <text> | send-file <peer> <path> | send-bytes <peer> <path> | accept <invite|from> [password] | reject <invite|from> [reason] | history [peer] | history-delete <peer|all> | admin attach <peer> | exec <cmd> | quit");
#if !defined(_WIN32)
    auto line_reader = std::make_shared<InteractiveLineReader>();
#endif
    std::thread console_thread([console_stop,
                                &stop_requested,
                                tunnel = std::move(tunnel),
                                status_block_builder = std::move(status_block_builder),
                                relay_runtime = std::move(relay_runtime),
                                request_disconnect = std::move(request_disconnect),
                                cfg
#if !defined(_WIN32)
                                , line_reader
#endif
                                ]() {
        while (!console_stop->load()) {
            std::string line;
#if !defined(_WIN32)
            if (!line_reader->read_line(&line, 250)) {
                if (stop_requested.load()) {
                    break;
                }
                if (!std::cin.good() && std::cin.eof()) {
                    break;
                }
                continue;
            }
#else
            if (!read_stdin_line_with_timeout(&line, 250)) {
                if (stop_requested.load()) {
                    break;
                }
                if (!std::cin.good() && std::cin.eof()) {
                    break;
                }
                continue;
            }
#endif
            line = trim_copy(line);
            if (line.empty()) {
                continue;
            }
            if (line == "help") {
                util::log_info("Commands: help | whoami | status | directory | invites | chat <peer> | send <text> | send-file <peer> <path> | send-bytes <peer> <path> | accept <invite|from> [password] | reject <invite|from> [reason] | history [peer] | history-delete <peer|all> | admin attach <peer> | admin status | admin sessions | admin stop | exec <cmd> | quit");
                continue;
            }
            if (line == "whoami") {
                auto self = relay_runtime->self_info();
                util::log_info("id=" + self.endpoint_id + " name=" + self.display_name + " relay=" + control::to_string(self.relay_mode));
                continue;
            }
            if (line == "status") {
                if (status_block_builder) {
                    util::clear_status_line();
                    std::cout << status_block_builder() << std::flush;
                } else {
                    util::log_info("status is not available yet");
                }
                std::cout << "\n" << relay_runtime->status_json().dump(2) << std::endl;
                continue;
            }
            if (line == "directory") {
                std::string error;
                auto entries = relay_runtime->request_directory(&error);
                if (!error.empty()) {
                    util::log_warn(error);
                    continue;
                }
                for (const auto& entry : entries) {
                    std::cout << entry.endpoint_id << " " << entry.display_name
                              << " kind=" << control::to_string(entry.endpoint_kind)
                              << " relay=" << control::to_string(entry.relay_mode)
                              << " platform=" << entry.client_platform
                              << " variant=" << entry.client_variant
                              << " chat=" << (entry.allow_chat ? "yes" : "no")
                              << " file=" << (entry.allow_file ? "yes" : "no")
                              << " bytes=" << (entry.allow_bytes ? "yes" : "no")
                              << std::endl;
                }
                continue;
            }
            if (line == "invites") {
                auto invites = relay_runtime->pending_invites();
                if (invites.empty()) {
                    util::log_info("no pending invites");
                    continue;
                }
                for (const auto& invite : invites) {
                    std::cout << invite.invite_id << " from="
                              << (invite.from_display_name.empty() ? invite.from_endpoint_id : invite.from_display_name)
                              << " kind=" << control::to_string(invite.channel_kind) << std::endl;
                }
                continue;
            }
            if (line == "chat") {
                util::log_warn("usage: chat <peer>");
                continue;
            }
            if (line.rfind("chat ", 0) == 0) {
                auto rest = trim_copy(line.substr(5));
                if (rest.empty()) {
                    util::log_warn("usage: chat <peer>");
                    continue;
                }
                std::string relay_secret_b64;
                std::string error;
                if (!resolve_relay_secret(cfg, "", "chat with " + rest, &relay_secret_b64, &error)) {
                    util::log_warn(error);
                    continue;
                }
                if (!relay_runtime->open_chat(rest, relay_secret_b64, &error)) {
                    util::log_warn(error);
                } else {
                    util::log_info("chat invite sent to " + rest);
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
                std::string error;
                if (!resolve_relay_secret(cfg, "", "file send to " + peer, &relay_secret_b64, &error)) {
                    util::log_warn(error);
                    continue;
                }
                if (!relay_runtime->send_file(peer, path, relay_secret_b64, &error)) {
                    util::log_warn(error);
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
                std::string error;
                if (!resolve_relay_secret(cfg, "", "bytes send to " + peer, &relay_secret_b64, &error)) {
                    util::log_warn(error);
                    continue;
                }
                if (!relay_runtime->send_bytes_path(peer, path, relay_secret_b64, &error)) {
                    util::log_warn(error);
                }
                continue;
            }
            if (line.rfind("send ", 0) == 0) {
                std::string error;
                if (!relay_runtime->send_chat(trim_copy(line.substr(5)), &error)) {
                    util::log_warn(error);
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
                split_first_token(line.substr(7), &invite_id, &password);
                if (invite_id.empty()) {
                    util::log_warn("usage: accept <invite|from> [password]");
                    continue;
                }
                std::string relay_secret_b64;
                std::string error;
                if (!resolve_relay_secret(cfg, password, "accept invite " + invite_id, &relay_secret_b64, &error)) {
                    util::log_warn(error);
                    continue;
                }
                if (!relay_runtime->accept_invite(invite_id, relay_secret_b64, &error)) {
                    util::log_warn(error);
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
                std::string error;
                if (!relay_runtime->reject_invite(invite_id, trim_copy(reason), &error)) {
                    util::log_warn(error);
                }
                continue;
            }
            if (line.rfind("history-delete ", 0) == 0) {
                std::string arg = trim_copy(line.substr(15));
                nlohmann::json req{{"op", "history.delete"}, {"args", nlohmann::json::object()}};
                if (arg != "all" && !arg.empty()) {
                    req["args"]["peer_id"] = arg;
                }
                relay_runtime->handle_local_request(req);
                util::log_info("history deleted");
                continue;
            }
            if (line.rfind("history", 0) == 0) {
                std::string arg = trim_copy(line.substr(7));
                nlohmann::json req{{"op", "history.list"}, {"args", nlohmann::json::object()}};
                if (!arg.empty()) {
                    req["args"]["peer_id"] = arg;
                }
                auto resp = relay_runtime->handle_local_request(req);
                if (!resp.value("ok", false)) {
                    util::log_warn(resp.value("error", "history failed"));
                    continue;
                }
                for (const auto& item : resp["result"]) {
                    std::cout << item.value("direction", "?") << " "
                              << item.value("peer_name", item.value("peer_id", "")) << " "
                              << item.value("text", "") << std::endl;
                }
                continue;
            }
            if (line.rfind("admin attach ", 0) == 0) {
                std::string peer = trim_copy(line.substr(13));
                std::string error;
                if (!relay_runtime->admin_attach(peer, &error)) {
                    util::log_warn(error);
                }
                continue;
            }
            if (line == "admin status" || line == "admin sessions" || line == "admin stop") {
                const std::string local_op =
                    (line == "admin stop") ? "admin.stop" :
                    ((line == "admin sessions") ? "admin.sessions" : "admin.status");
                auto resp = relay_runtime->handle_local_request({{"op", local_op}, {"args", nlohmann::json::object()}});
                if (!resp.value("ok", false)) {
                    util::log_warn(resp.value("error", "admin request failed"));
                } else {
                    std::cout << resp["result"].dump(2) << std::endl;
                }
                continue;
            }
            if (line == "quit" || line == "exit" || line == "stop") {
                request_disconnect("console stop", "im disconnecting", true);
                break;
            }
            if (line.rfind("exec ", 0) == 0) {
                std::string cmd = trim_copy(line.substr(5));
                if (cmd.empty()) {
                    util::log_warn("usage: exec <command>");
                    continue;
                }
                uint8_t stream_id = tunnel->reserve_stream_id();
                if (stream_id == 0) {
                    util::log_warn("no stream id available for exec");
                    continue;
                }
                tunnel->register_stream(
                    stream_id,
                    [stream_id](const Tunnel::Bytes& data) {
                        std::cout.write(reinterpret_cast<const char*>(data.data()), data.size());
                        std::cout.flush();
                    },
                    [stream_id](const std::string& reason) {
                        std::string message = "exec stream " + std::to_string(static_cast<int>(stream_id)) + " closed";
                        if (!reason.empty()) {
                            message += ": " + reason;
                        }
                        util::log_info(message);
                    });
                tunnel->send_exec(stream_id, cmd);
                util::log_info("exec sent on stream " + std::to_string(static_cast<int>(stream_id)));
                continue;
            }
            util::log_warn("unknown command: " + line);
        }
    });
    return InteractiveConsoleSession(console_stop, std::move(console_thread));
}

}  // namespace yume::client
