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
#include <system_error>
#include <thread>
#include <vector>

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
    return 0;
#else
    TempDirectory temp;
    const std::string secret_b64 =
        util::base64_encode(std::string(32, static_cast<char>(0x42)));
    std::string error;
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

    const auto history_root = temp.path() / "history";
    HistoryStore history(history_root, "instance_a");
    assert(history.enabled());
    history.append_chat({1, "peer_a", "Peer A", "out", "first secret text"});
    history.append_chat({2, "peer_b", "Peer B", "in", "second secret text"});
    const auto instance_dir = history_root / "instance_a";
    const auto history_key = instance_dir / "history.key";
    const auto peer_a_log = instance_dir / "chat-peer_a.log";
    const auto peer_b_log = instance_dir / "chat-peer_b.log";
    assert(mode_of(history_root) == S_IRWXU);
    assert(mode_of(instance_dir) == S_IRWXU);
    assert(mode_of(history_key) == (S_IRUSR | S_IWUSR));
    assert(mode_of(peer_a_log) == (S_IRUSR | S_IWUSR));
    assert(read_all(peer_a_log).find("first secret text") == std::string::npos);

    auto peer_a = history.list_chat("peer_a");
    assert(peer_a.size() == 1);
    assert(peer_a.front().text == "first secret text");
    auto all = history.list_chat();
    assert(all.size() == 2);
    assert(all[0].ts_ms == 1 && all[1].ts_ms == 2);

    history.delete_chat("peer_a");
    assert(!std::filesystem::exists(peer_a_log));
    assert(std::filesystem::exists(peer_b_log));
    history.delete_chat();
    assert(!std::filesystem::exists(peer_b_log));
    assert(std::filesystem::exists(history_key));

    history.append_chat({3, "../outside", "Traversal", "in", "contained"});
    assert(!std::filesystem::exists(temp.path() / "outside.log"));
    assert(history.list_chat("../outside").size() == 1);

    const auto victim = temp.path() / "victim";
    {
        std::ofstream output(victim);
        output << "unchanged";
    }
    const auto evil_log = instance_dir / "chat-evil.log";
    assert(::symlink(victim.c_str(), evil_log.c_str()) == 0);
    history.append_chat({4, "evil", "Evil", "out", "must not follow"});
    assert(read_all(victim) == "unchanged");
    assert(history.list_chat("evil").empty());
    history.delete_chat("evil");
    assert(read_all(victim) == "unchanged");

    history.append_chat({5, "mode_peer", "Mode", "in", "private"});
    const auto mode_log = instance_dir / "chat-mode_peer.log";
    assert(::chmod(mode_log.c_str(), 0644) == 0);
    const auto before_unsafe_append = read_all(mode_log);
    history.append_chat({6, "mode_peer", "Mode", "in", "rejected"});
    assert(read_all(mode_log) == before_unsafe_append);
    assert(history.list_chat("mode_peer").empty());

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
    assert(concurrent.list_chat("peer").size() == 8);

    wipe_relay_secret(loaded);
    return 0;
#endif
}
