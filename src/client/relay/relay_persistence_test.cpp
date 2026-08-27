/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/relay/history.hpp"
#include "client/relay/secret.hpp"

#include <cassert>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <vector>

#include "core/security/crypto.hpp"
#include "core/security/secure_erase.hpp"
#include "core/security/secret_file.hpp"
#include "util.hpp"

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

#if !defined(_WIN32)
class TempDirectory {
public:
    TempDirectory() {
        constexpr std::size_t kMaxTempPatternBytes = 4096;
        std::error_code temp_error;
        const auto temp_root = std::filesystem::temp_directory_path(temp_error);
        if (temp_error) {
            throw std::system_error(temp_error,
                                    "resolve relay-test temporary directory");
        }
        std::string pattern =
            (temp_root / "yume-relay-persistence-test-XXXXXX").string();
        if (pattern.size() + 1 > kMaxTempPatternBytes) {
            throw std::runtime_error(
                "relay-test temporary directory pattern is too long");
        }
        char* made = ::mkdtemp(pattern.data());
        if (!made) {
            throw std::system_error(errno, std::generic_category(),
                                    "create relay-test temporary directory");
        }
        path_ = made;
    }
    ~TempDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }
    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

mode_t mode_of(const std::filesystem::path& path) {
    struct stat info {};
    assert(::lstat(path.c_str(), &info) == 0);
    return info.st_mode & 0777;
}

std::string read_all(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

class TestBytesWiper {
public:
    explicit TestBytesWiper(std::vector<std::uint8_t>& value) noexcept
        : value_(value) {}
    TestBytesWiper(const TestBytesWiper&) = delete;
    TestBytesWiper& operator=(const TestBytesWiper&) = delete;
    ~TestBytesWiper() { yume::security::secure_erase(value_); }

private:
    std::vector<std::uint8_t>& value_;
};

void write_authenticated_history_record(
        const std::filesystem::path& key_path,
        const std::filesystem::path& log_path,
        std::string plaintext) {
    using namespace yume;
    using namespace yume::client;

    RelaySecretWiper plaintext_wiper{plaintext};
    std::string encoded_key = read_all(key_path);
    RelaySecretWiper encoded_key_wiper{encoded_key};
    std::string raw_key = util::base64_decode(encoded_key);
    RelaySecretWiper raw_key_wiper{raw_key};
    assert(raw_key.size() == 32U);

    crypto::Bytes key(raw_key.begin(), raw_key.end());
    TestBytesWiper key_wiper{key};
    crypto::Bytes plaintext_bytes(plaintext.begin(), plaintext.end());
    TestBytesWiper plaintext_bytes_wiper{plaintext_bytes};
    const auto nonce = crypto::random_bytes(12U);
    const auto encrypted =
        crypto::encrypt_chacha20(plaintext_bytes, key, nonce);

    std::string packed;
    packed.reserve(nonce.size() + encrypted.size());
    packed.append(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    packed.append(
        reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
    const std::string encoded = util::base64_encode(packed);
    {
        std::ofstream output(log_path,
                             std::ios::binary | std::ios::trunc);
        output << encoded << '\n';
        output.flush();
        assert(output.good());
    }
    assert(::chmod(log_path.c_str(), 0600) == 0);
}
#endif

}  // namespace

int main() {
    using namespace yume;
    using namespace yume::client;

    std::string erasable = "relay-secret-material";
    erasable.reserve(128);
    wipe_relay_secret(erasable);
    assert(erasable.empty());

#if defined(_WIN32)
    HistoryStore history("ignored", "instance");
    assert(!history.enabled());
    std::string error;
    assert(!history.delete_chat(std::nullopt, &error));
    assert(!error.empty());
    return 0;
#else
    TempDirectory temp;
    const std::string secret_b64 =
        util::base64_encode(std::string(32, static_cast<char>(0x42)));
    std::string error;
    assert(validate_relay_secret_b64(secret_b64, &error));
    assert(error.empty());
    assert(!validate_relay_secret_b64(secret_b64 + "!", &error));
    assert(!validate_relay_secret_b64(" " + secret_b64, &error));
    assert(!validate_relay_secret_b64(
        secret_b64.substr(0, secret_b64.size() - 1), &error));
    std::string noncanonical_alias = secret_b64;
    constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const auto final_value = alphabet.find(
        noncanonical_alias[noncanonical_alias.size() - 2]);
    assert(final_value != std::string_view::npos && final_value % 4U == 0U);
    noncanonical_alias[noncanonical_alias.size() - 2] =
        alphabet[final_value + 1U];
    assert(!validate_relay_secret_b64(noncanonical_alias, &error));
    const auto relay_key = temp.path() / "relay-key.json";
    assert(write_relay_secret_file(relay_key, secret_b64, &error));
    assert(error.empty());
    assert(mode_of(relay_key) == (S_IRUSR | S_IWUSR));

    std::string loaded = "old-value-that-must-be-overwritten";
    assert(load_relay_secret_file(relay_key, &loaded, &error));
    assert(loaded == secret_b64);
    assert(!write_relay_secret_file(relay_key, secret_b64, &error));
    assert(load_relay_secret_file(relay_key, &loaded, &error));
    assert(loaded == secret_b64);

    assert(::chmod(relay_key.c_str(), 0644) == 0);
    assert(!load_relay_secret_file(relay_key, &loaded, &error));
    assert(::chmod(relay_key.c_str(), 0600) == 0);

    const auto relay_link = temp.path() / "relay-link.json";
    assert(::symlink(relay_key.c_str(), relay_link.c_str()) == 0);
    assert(!load_relay_secret_file(relay_link, &loaded, &error));
    assert(!write_relay_secret_file(relay_link, secret_b64, &error));

    const auto legacy_key = temp.path() / "relay-key-v1.txt";
    const std::vector<std::uint8_t> legacy_bytes(
        secret_b64.begin(), secret_b64.end());
    assert(security::WriteFileExclusive0600(
        legacy_key, std::span<const std::uint8_t>(legacy_bytes), &error));
    assert(load_relay_secret_file(legacy_key, &loaded, &error));
    assert(loaded == secret_b64);

    const auto rejected_history_root =
        temp.path() / "history-rejected-append";
    HistoryStore rejected_history(rejected_history_root, "instance");
    rejected_history.append_chat(
        {1, "", "Missing peer", "in", "must not persist"});
    rejected_history.append_chat(
        {2, "peer", "Invalid direction", "sideways", "must not persist"});
    std::string oversized_history_text(512U * 1024U, 'x');
    rejected_history.append_chat(
        {3, "peer", "Oversized", "in", oversized_history_text});
    wipe_relay_secret(oversized_history_text);
    assert(!std::filesystem::exists(rejected_history_root));

    const auto history_root = temp.path() / "history";
    HistoryStore history(history_root, "instance_a");
    assert(history.enabled());
    history.append_chat({1, "peer_a", "Peer A", "out", "first secret text"});
    history.append_chat({2, "peer_b", "Peer B", "in", "second secret text"});
    history.append_chat(
        {3, "invalid_direction", "Invalid", "sideways", "must not persist"});
    const auto instance_dir = history_root / "instance_a";
    const auto history_key = instance_dir / "history.key";
    const auto peer_a_log = instance_dir / "chat-peer_a.log";
    const auto peer_b_log = instance_dir / "chat-peer_b.log";
    assert(mode_of(history_root) == S_IRWXU);
    assert(mode_of(instance_dir) == S_IRWXU);
    assert(mode_of(history_key) == (S_IRUSR | S_IWUSR));
    assert(mode_of(peer_a_log) == (S_IRUSR | S_IWUSR));
    assert(!std::filesystem::exists(
        instance_dir / "chat-invalid_direction.log"));
    assert(read_all(peer_a_log).find("first secret text") == std::string::npos);

    auto peer_a = history.list_chat("peer_a");
    assert(peer_a.available && peer_a.items.size() == 1);
    assert(peer_a.items.front().text == "first secret text");
    auto all = history.list_chat();
    assert(all.available && all.items.size() == 2);
    assert(all.items[0].ts_ms == 1 && all.items[1].ts_ms == 2);
    auto latest = history.list_chat(std::nullopt, 1U);
    assert(latest.available && latest.truncated &&
           latest.items.size() == 1 && latest.items[0].ts_ms == 2);
    assert(!history.list_chat(std::nullopt, 0U).available);
    assert(!history.list_chat(std::nullopt, 1001U).available);

    error.clear();
    assert(history.delete_chat("peer_a", &error));
    assert(error.empty());
    assert(!std::filesystem::exists(peer_a_log));
    assert(std::filesystem::exists(peer_b_log));
    assert(history.delete_chat(std::nullopt, &error));
    assert(error.empty());
    assert(!std::filesystem::exists(peer_b_log));
    assert(std::filesystem::exists(history_key));

    const auto bounded_root = temp.path() / "history-bounded-result";
    HistoryStore bounded_history(bounded_root, "bounded");
    std::string large_history_text(300U * 1024U, 'x');
    bounded_history.append_chat(
        {1, "peer", "Peer", "out", large_history_text});
    bounded_history.append_chat(
        {2, "peer", "Peer", "in", large_history_text});
    const auto bounded_items = bounded_history.list_chat("peer", 1000U);
    assert(bounded_items.available && bounded_items.truncated);
    assert(bounded_items.items.size() == 1U);
    assert(bounded_items.items.front().ts_ms == 2);
    wipe_relay_secret(large_history_text);

    const auto relocated_root = temp.path() / "history-relocated";
    HistoryStore relocated_history(relocated_root, "relocated");
    relocated_history.append_chat(
        {1, "original", "Original", "in", "bound to original log"});
    const auto relocated_instance = relocated_root / "relocated";
    std::filesystem::rename(
        relocated_instance / "chat-original.log",
        relocated_instance / "chat-renamed.log");
    const auto relocated = relocated_history.list_chat("renamed");
    assert(!relocated.available && !relocated.error.empty() &&
           relocated.items.empty());

    const auto schema_root = temp.path() / "history-schema";
    HistoryStore schema_history(schema_root, "schema");
    schema_history.append_chat(
        {1, "schema_peer", "Schema", "in", "valid"});
    const auto schema_instance = schema_root / "schema";
    const auto schema_key = schema_instance / "history.key";
    const auto schema_log = schema_instance / "chat-schema_peer.log";
    write_authenticated_history_record(
        schema_key, schema_log,
        R"({"ts_ms":1,"peer_id":"schema_peer","peer_name":"Schema","direction":"in","text":"hidden","extra":true})");
    const auto extra_field = schema_history.list_chat("schema_peer");
    assert(!extra_field.available && !extra_field.error.empty() &&
           extra_field.items.empty());
    error.clear();
    assert(schema_history.delete_chat("schema_peer", &error));
    assert(error.empty() && !std::filesystem::exists(schema_log));

    schema_history.append_chat(
        {2, "schema_peer", "Schema", "out", "valid again"});
    write_authenticated_history_record(
        schema_key, schema_log,
        R"({"ts_ms":2,"peer_id":"schema_peer","peer_name":"Schema","direction":"sideways","text":"hidden"})");
    const auto invalid_stored_direction =
        schema_history.list_chat("schema_peer");
    assert(!invalid_stored_direction.available &&
           !invalid_stored_direction.error.empty() &&
           invalid_stored_direction.items.empty());
    error.clear();
    assert(schema_history.delete_chat("schema_peer", &error));
    assert(error.empty() && !std::filesystem::exists(schema_log));

    schema_history.append_chat(
        {3, "schema_peer", "Schema", "in", "valid once more"});
    write_authenticated_history_record(
        schema_key, schema_log,
        R"({"ts_ms":18446744073709551615,"peer_id":"schema_peer","peer_name":"Schema","direction":"in","text":"hidden"})");
    const auto unsigned_stored_timestamp =
        schema_history.list_chat("schema_peer");
    assert(!unsigned_stored_timestamp.available &&
           !unsigned_stored_timestamp.error.empty() &&
           unsigned_stored_timestamp.items.empty());
    error.clear();
    assert(schema_history.delete_chat("schema_peer", &error));
    assert(error.empty() && !std::filesystem::exists(schema_log));

    history.append_chat({3, "../outside", "Traversal", "in", "contained"});
    assert(!std::filesystem::exists(temp.path() / "outside.log"));
    assert(history.list_chat("../outside").items.size() == 1);

    const auto victim = temp.path() / "victim";
    {
        std::ofstream output(victim);
        output << "unchanged";
    }
    const auto evil_log = instance_dir / "chat-evil.log";
    assert(::symlink(victim.c_str(), evil_log.c_str()) == 0);
    history.append_chat({4, "evil", "Evil", "out", "must not follow"});
    assert(read_all(victim) == "unchanged");
    const auto unsafe_symlink = history.list_chat("evil");
    assert(!unsafe_symlink.available && !unsafe_symlink.error.empty() &&
           unsafe_symlink.items.empty());
    assert(!history.delete_chat("evil", &error));
    assert(!error.empty());
    assert(read_all(victim) == "unchanged");

    history.append_chat({5, "mode_peer", "Mode", "in", "private"});
    const auto mode_log = instance_dir / "chat-mode_peer.log";
    assert(::chmod(mode_log.c_str(), 0644) == 0);
    const auto before_unsafe_append = read_all(mode_log);
    history.append_chat({6, "mode_peer", "Mode", "in", "rejected"});
    assert(read_all(mode_log) == before_unsafe_append);
    const auto unsafe_mode = history.list_chat("mode_peer");
    assert(!unsafe_mode.available && !unsafe_mode.error.empty() &&
           unsafe_mode.items.empty());
    error.clear();
    assert(!history.delete_chat("mode_peer", &error));
    assert(!error.empty());
    assert(std::filesystem::exists(mode_log));

    const auto fifo_root = temp.path() / "history-fifo";
    HistoryStore fifo_history(fifo_root, "fifo");
    assert(fifo_history.list_chat().available);
    const auto fifo_log = fifo_root / "fifo" / "chat-pipe.log";
    assert(::mkfifo(fifo_log.c_str(), 0600) == 0);
    const auto fifo_result = fifo_history.list_chat("pipe");
    assert(!fifo_result.available && !fifo_result.error.empty());
    error.clear();
    assert(!fifo_history.delete_chat("pipe", &error));
    assert(!error.empty());

    const auto oversized_root = temp.path() / "history-oversized-delete";
    HistoryStore oversized_history(oversized_root, "oversized");
    assert(oversized_history.list_chat().available);
    const auto oversized_log =
        oversized_root / "oversized" / "chat-oversized.log";
    {
        std::ofstream output(oversized_log, std::ios::binary);
        assert(output.good());
    }
    assert(::chmod(oversized_log.c_str(), 0600) == 0);
    std::filesystem::resize_file(
        oversized_log, 65U * 1024U * 1024U);
    error.clear();
    assert(oversized_history.delete_chat("oversized", &error));
    assert(error.empty());
    assert(!std::filesystem::exists(oversized_log));

    const auto symlink_root = temp.path() / "history-link";
    assert(::symlink(history_root.c_str(), symlink_root.c_str()) == 0);
    HistoryStore linked_history(symlink_root, "linked");
    linked_history.append_chat({7, "peer", "Peer", "in", "blocked"});
    assert(!std::filesystem::exists(history_root / "linked"));

    const auto concurrent_root = temp.path() / "concurrent";
    std::vector<std::thread> writers;
    for (int i = 0; i < 8; ++i) {
        writers.emplace_back([concurrent_root, i]() {
            HistoryStore writer(concurrent_root, "shared");
            writer.append_chat({i, "peer", "Peer", "out",
                                "message-" + std::to_string(i)});
        });
    }
    for (auto& writer : writers) writer.join();
    HistoryStore concurrent(concurrent_root, "shared");
    const auto concurrent_items = concurrent.list_chat("peer");
    assert(concurrent_items.available &&
           concurrent_items.items.size() == 8);

    const auto scan_root = temp.path() / "history-scan-bound";
    HistoryStore scan_history(scan_root, "bounded");
    assert(scan_history.list_chat().available);
    const auto scan_instance = scan_root / "bounded";
    for (std::size_t index = 0; index < 1025U; ++index) {
        const auto path = scan_instance /
            ("chat-scan-" + std::to_string(index) + ".log");
        {
            std::ofstream output(path, std::ios::binary);
            assert(output.good());
        }
        assert(::chmod(path.c_str(), 0600) == 0);
    }
    const auto scan_limited = scan_history.list_chat();
    assert(!scan_limited.available && !scan_limited.error.empty());
    error.clear();
    assert(!scan_history.delete_chat(std::nullopt, &error));
    assert(!error.empty());
    assert(std::filesystem::exists(scan_instance / "chat-scan-0.log"));
    assert(std::filesystem::exists(scan_instance / "chat-scan-1024.log"));

    wipe_relay_secret(loaded);
    return 0;
#endif
}
