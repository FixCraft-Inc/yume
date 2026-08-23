/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

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

class HistoryStore {
public:
    HistoryStore(std::filesystem::path root_dir, std::string instance_key);

    bool enabled() const;
    void append_chat(const ChatHistoryEntry& entry);
    std::vector<ChatHistoryEntry> list_chat(const std::optional<std::string>& peer_id = std::nullopt) const;
    void delete_chat(const std::optional<std::string>& peer_id = std::nullopt);

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
