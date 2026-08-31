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

#include <nlohmann/json.hpp>

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

    // True while any lifecycle work is in flight, so start() would be
    // refused. running() alone is not enough: stop() deliberately returns
    // before teardown completes, leaving a window where the runtime is no
    // longer running but a restart is still rejected. Consumers that offer a
    // reconnect control need this to know when it becomes usable.
    bool busy() const noexcept;

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

    struct Contact {
        std::string endpoint_id;
        std::string display_name;
        std::string fingerprint;
        std::string trust_source;
        std::string endpoint_kind;
        std::string relay_mode;
        bool explicit_marker{false};
        bool configured_mismatch{false};
        bool in_directory{false};
        bool online{false};
        bool remote{false};
    };
    struct ContactList {
        std::vector<Contact> contacts;
        bool directory_available{false};
        std::string directory_error;
    };
    ContactList list_contacts(std::string* err = nullptr) const;
    bool forget_contact(std::string const& endpoint_id,
                        bool* removed = nullptr,
                        std::string* err = nullptr) const;

    struct ChatMessage {
        std::string channel_id;
        // Incoming rows carry the canonical peer endpoint. Outgoing rows use
        // the local endpoint when runtime status is readable, and otherwise
        // leave this empty while preserving outgoing=true.
        std::string from_endpoint_id;
        std::string text;
        std::chrono::system_clock::time_point ts;
        bool outgoing{false};
    };
    struct ChatHistoryResult {
        std::vector<ChatMessage> messages;
        // Storage unreadability is not a transport failure: callers can keep
        // the active chat usable while presenting storage_error separately.
        bool available{false};
        bool truncated{false};
        std::string storage_error;
    };

    // Chat uses the configured owner-only relay_key_file. open_chat() returns
    // the pending/active channel id; send/close reject a different channel.
    std::string open_chat(std::string const& peer_endpoint_id, std::string* err);
    void close_chat(std::string const& channel_id);
    bool send_chat(std::string const& channel_id, std::string const& text,
                   std::string* err = nullptr);
    // max is the exact server-side item bound and must be in 1..1000.
    // history.list transport, envelope, and schema failures are reported
    // through err; storage availability and truncation remain typed result
    // state. A failed best-effort local-sender lookup only leaves outgoing
    // from_endpoint_id empty.
    ChatHistoryResult chat_history(std::string const& channel_id,
                                   std::size_t max = 200,
                                   std::string* err = nullptr) const;

    using StatusCallback = std::function<void(ClientStatus const&)>;
    // Status callbacks are serialized, never run under the lifecycle mutex,
    // and may re-enter start()/stop(). Exceptions are contained by the facade.
    // As with any member callback, the owner must keep this session alive until
    // the callback returns.
    void set_status_callback(StatusCallback cb);

private:
    friend struct ClientSessionHistoryTestPeer;

    static ChatHistoryResult parse_chat_history_response(
        nlohmann::json const& response,
        std::string const& channel_id,
        std::optional<std::string> const& expected_peer_id,
        std::size_t max,
        std::string* err);

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::facade
