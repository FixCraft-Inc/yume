#include "client/relay/history.hpp"

#include <fstream>

#include <nlohmann/json.hpp>

#include "core/security/crypto.hpp"
#include "util.hpp"

namespace yume::client {

namespace {
constexpr const char* kHistoryKeyFile = "history.key";
}

HistoryStore::HistoryStore(std::filesystem::path root_dir, std::string instance_key)
    : root_dir_(std::move(root_dir))
    , instance_key_(std::move(instance_key)) {}

bool HistoryStore::enabled() const {
    return !root_dir_.empty() && !instance_key_.empty();
}

void HistoryStore::append_chat(const ChatHistoryEntry& entry) {
    if (!enabled() || entry.peer_id.empty()) {
        return;
    }
    std::error_code ec;
    std::filesystem::create_directories(root_dir_ / instance_key_, ec);
    nlohmann::json json{
        {"ts_ms", entry.ts_ms},
        {"peer_id", entry.peer_id},
        {"peer_name", entry.peer_name},
        {"direction", entry.direction},
        {"text", entry.text},
    };
    std::ofstream out(chat_path_for_peer(entry.peer_id), std::ios::app | std::ios::binary);
    if (!out) {
        return;
    }
    out << encrypt_line(json.dump()) << "\n";
}

std::vector<ChatHistoryEntry> HistoryStore::list_chat(const std::optional<std::string>& peer_id) const {
    std::vector<ChatHistoryEntry> out;
    if (!enabled()) {
        return out;
    }
    const auto instance_dir = root_dir_ / instance_key_;
    std::error_code ec;
    if (!std::filesystem::exists(instance_dir, ec)) {
        return out;
    }
    auto consume_file = [&](const std::filesystem::path& path) {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            return;
        }
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty()) {
                continue;
            }
            try {
                auto plain = decrypt_line(line);
                auto json = nlohmann::json::parse(plain);
                ChatHistoryEntry entry;
                entry.ts_ms = json.value("ts_ms", 0LL);
                entry.peer_id = json.value("peer_id", "");
                entry.peer_name = json.value("peer_name", "");
                entry.direction = json.value("direction", "");
                entry.text = json.value("text", "");
                out.push_back(std::move(entry));
            } catch (...) {
            }
        }
    };
    if (peer_id.has_value()) {
        consume_file(chat_path_for_peer(*peer_id));
        return out;
    }
    for (const auto& entry : std::filesystem::directory_iterator(instance_dir, ec)) {
        if (ec || !entry.is_regular_file()) {
            continue;
        }
        if (entry.path().filename() == kHistoryKeyFile) {
            continue;
        }
        consume_file(entry.path());
    }
    return out;
}

void HistoryStore::delete_chat(const std::optional<std::string>& peer_id) {
    if (!enabled()) {
        return;
    }
    std::error_code ec;
    if (peer_id.has_value()) {
        std::filesystem::remove(chat_path_for_peer(*peer_id), ec);
        return;
    }
    auto dir = root_dir_ / instance_key_;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (ec || !entry.is_regular_file()) {
            continue;
        }
        if (entry.path().filename() == kHistoryKeyFile) {
            continue;
        }
        std::filesystem::remove(entry.path(), ec);
    }
}

std::filesystem::path HistoryStore::key_path() const {
    return root_dir_ / instance_key_ / kHistoryKeyFile;
}

std::filesystem::path HistoryStore::chat_path_for_peer(const std::string& peer_id) const {
    return root_dir_ / instance_key_ / ("chat-" + peer_id + ".log");
}

std::vector<std::uint8_t> HistoryStore::load_or_create_key() const {
    auto path = key_path();
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    std::ifstream in(path, std::ios::binary);
    if (in) {
        std::string encoded;
        std::getline(in, encoded);
        std::string raw = yume::util::base64_decode(encoded);
        if (raw.size() == 32) {
            return std::vector<std::uint8_t>(raw.begin(), raw.end());
        }
    }
    auto key = yume::crypto::random_bytes(32);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (out) {
        out << yume::util::base64_encode(std::string(key.begin(), key.end()));
        out.close();
        std::filesystem::permissions(path,
                                     std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                     std::filesystem::perm_options::replace,
                                     ec);
    }
    return key;
}

std::string HistoryStore::encrypt_line(const std::string& line) const {
    auto key = load_or_create_key();
    auto nonce = yume::crypto::random_bytes(12);
    yume::crypto::Bytes plain(line.begin(), line.end());
    auto blob = yume::crypto::encrypt_chacha20(plain, key, nonce);
    std::string packed;
    packed.reserve(nonce.size() + blob.size());
    packed.append(reinterpret_cast<const char*>(nonce.data()), static_cast<std::streamsize>(nonce.size()));
    packed.append(reinterpret_cast<const char*>(blob.data()), static_cast<std::streamsize>(blob.size()));
    return yume::util::base64_encode(packed);
}

std::string HistoryStore::decrypt_line(const std::string& line) const {
    auto raw = yume::util::base64_decode(line);
    if (raw.size() < 12) {
        throw std::runtime_error("history line too short");
    }
    auto key = load_or_create_key();
    yume::crypto::Bytes nonce(raw.begin(), raw.begin() + 12);
    yume::crypto::Bytes blob(raw.begin() + 12, raw.end());
    auto plain = yume::crypto::decrypt_chacha20(blob, key, nonce);
    return std::string(plain.begin(), plain.end());
}

}  // namespace yume::client
