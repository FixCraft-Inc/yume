/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "client/cli/entry.hpp"
#include "facade/model/status.hpp"

namespace yume::facade {

class TrafficMeter;

// High-level non-blocking client lifecycle. Starts the real yume client in
// process while keeping the CLI TLS/auth path as the source of truth. start()
// and stop() only admit/signal work on the caller; destruction performs the
// final synchronous join.
class ClientSession {
public:
    explicit ClientSession(client::ClientConfig cfg);
    ~ClientSession();

    ClientSession(ClientSession const&) = delete;
    ClientSession& operator=(ClientSession const&) = delete;

    bool start(std::string* err = nullptr);
    void stop();

    bool running() const noexcept;
    ClientStatus status() const;
    TrafficMeter const& traffic() const noexcept;

    // Update the configuration. Only meaningful when not running.
    void set_config(client::ClientConfig cfg);
    client::ClientConfig config() const;

    struct DirectoryEntry {
        std::string endpoint_id;
        std::string display_name;
        std::string endpoint_kind;
        std::string relay_mode;
        std::string client_platform;
        std::string client_variant;
        bool allow_chat{false};
        bool allow_file{false};
        bool allow_bytes{false};
    };
    std::vector<DirectoryEntry> directory(std::string* err = nullptr) const;

    struct ChatMessage {
        std::string channel_id;
        std::string from_endpoint_id;
        std::string text;
        std::chrono::system_clock::time_point ts;
        bool outgoing{false};
    };

    // Chat uses the configured owner-only relay_key_file. open_chat() returns
    // the pending/active channel id; send/close reject a different channel.
    std::string open_chat(std::string const& peer_endpoint_id, std::string* err);
    void close_chat(std::string const& channel_id);
    bool send_chat(std::string const& channel_id, std::string const& text,
                   std::string* err = nullptr);
    std::vector<ChatMessage> chat_history(std::string const& channel_id,
                                          std::size_t max = 200) const;

    using StatusCallback = std::function<void(ClientStatus const&)>;
    // Status callbacks are serialized, never run under the lifecycle mutex,
    // and may re-enter start()/stop(). Exceptions are contained by the facade.
    // As with any member callback, the owner must keep this session alive until
    // the callback returns.
    void set_status_callback(StatusCallback cb);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::facade
