/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace yume::client {

struct ChatHistoryEntry {
    std::int64_t ts_ms{0};
    std::string peer_id;
    std::string peer_name;
    std::string direction;
    std::string text;
};

struct HistoryListResult {
    HistoryListResult() = default;
    HistoryListResult(const HistoryListResult&) = delete;
    HistoryListResult& operator=(const HistoryListResult&) = delete;
    HistoryListResult(HistoryListResult&&) noexcept = default;
    HistoryListResult& operator=(HistoryListResult&& other) noexcept;
    ~HistoryListResult() noexcept;

    bool available{true};
    bool truncated{false};
    std::string error;
    std::vector<ChatHistoryEntry> items;
};

class HistoryStore {
public:
    HistoryStore(std::filesystem::path root_dir, std::string instance_key);

    bool enabled() const;
    // Optional audit persistence must never fail an otherwise valid relay.
    // Entries outside the exact stored schema or safe record-size bound, plus
    // protection and I/O failures, are therefore dropped here; list_chat()
    // reports current readability, not an acknowledgement of prior appends.
    void append_chat(const ChatHistoryEntry& entry);
    // Returns the newest records, ordered oldest-to-newest and bounded by
    // both `limit` and a safe plaintext-response budget. Either bound sets
    // `truncated`. Protection, I/O, and record-integrity failures are explicit
    // so callers never confuse an unreadable history with a genuinely empty
    // one.
    HistoryListResult list_chat(
        const std::optional<std::string>& peer_id = std::nullopt,
        std::size_t limit = 200U) const;
    // Idempotent for an absent log, but never reports success after a
    // validation, unlink, or durability failure.
    bool delete_chat(
        const std::optional<std::string>& peer_id = std::nullopt,
        std::string* error = nullptr);

private:
    std::filesystem::path key_path() const;
    std::filesystem::path chat_path_for_peer(const std::string& peer_id) const;
    std::vector<std::uint8_t> load_or_create_key() const;
    std::string encrypt_line(const std::string& line) const;
    std::string decrypt_line(const std::string& line) const;

    std::filesystem::path root_dir_;
    std::string instance_key_;
    mutable std::mutex mutex_;
};

}  // namespace yume::client
