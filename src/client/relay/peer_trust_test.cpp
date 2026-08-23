/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/relay/peer_trust.hpp"

#include <atomic>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

#include "core/security/crypto.hpp"

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

namespace relay_v2 = yume::client::relay_v2;
using Bytes = yume::crypto::Bytes;

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

template <typename Function>
void ExpectFailure(Function&& function, const char* message) {
    bool failed = false;
    try {
        std::forward<Function>(function)();
    } catch (const std::exception&) {
        failed = true;
    }
    Check(failed, message);
}

relay_v2::PeerTrustConfig Config(
        const std::filesystem::path& directory,
        relay_v2::PeerTrustMode mode = relay_v2::PeerTrustMode::Tofu,
        relay_v2::ExplicitPeerPins pins = {}) {
    relay_v2::PeerTrustConfig config;
    config.directory = directory;
    config.mode = mode;
    config.explicit_pins = std::move(pins);
    return config;
}

[[maybe_unused]] void TestInputValidation(const std::filesystem::path& root) {
    Check(relay_v2::IsValidPeerEndpointId(
              "00112233445566778899aabbccddeeff"),
          "local endpoint ID was rejected");
    Check(relay_v2::IsValidPeerEndpointId(
              "federation-peer:00112233445566778899aabbccddeeff"),
          "federated endpoint ID was rejected");
    Check(!relay_v2::IsValidPeerEndpointId(""),
          "empty endpoint ID was accepted");
    Check(!relay_v2::IsValidPeerEndpointId("../peer"),
          "traversal endpoint ID was accepted");
    Check(!relay_v2::IsValidPeerEndpointId("peer/child"),
          "slash endpoint ID was accepted");
    Check(!relay_v2::IsValidPeerEndpointId("."),
          "dot endpoint ID was accepted");
    Check(!relay_v2::IsValidPeerEndpointId(std::string(256, 'a')),
          "oversized endpoint ID was accepted");

    Check(relay_v2::IsCanonicalCompositeFingerprint(std::string(64, 'a')),
          "canonical fingerprint was rejected");
    Check(!relay_v2::IsCanonicalCompositeFingerprint(std::string(63, 'a')),
          "short fingerprint was accepted");
    Check(!relay_v2::IsCanonicalCompositeFingerprint(std::string(64, 'A')),
          "uppercase fingerprint was accepted as canonical");
    Check(!relay_v2::IsCanonicalCompositeFingerprint(std::string(64, 'z')),
          "non-hex fingerprint was accepted");

    ExpectFailure(
        [] { relay_v2::PeerTrustStore store(Config({})); },
        "empty trust directory was accepted");
    ExpectFailure(
        [] {
            relay_v2::PeerTrustStore store(Config("relative/trust"));
        },
        "relative trust directory was accepted");
    ExpectFailure(
        [&] {
            relay_v2::PeerTrustStore store(
                Config(root / "parent" / ".." / "trust"));
        },
        "trust-directory traversal was accepted");
    ExpectFailure(
        [&] {
            auto config = Config(root / "invalid-mode");
            config.mode = static_cast<relay_v2::PeerTrustMode>(99);
            relay_v2::PeerTrustStore store(std::move(config));
        },
        "invalid trust mode was accepted");
    ExpectFailure(
        [&] {
            relay_v2::PeerTrustStore store(Config(
                root / "invalid-pin", relay_v2::PeerTrustMode::Pinned,
                {{"../peer", std::string(64, 'a')}}));
        },
        "invalid configured endpoint ID was accepted");
    ExpectFailure(
        [&] {
            relay_v2::PeerTrustStore store(Config(
                root / "invalid-fingerprint",
                relay_v2::PeerTrustMode::Pinned,
                {{"peer", std::string(64, 'A')}}));
        },
        "noncanonical configured fingerprint was accepted");
}

#if !defined(_WIN32)

class TempDirectory {
public:
    TempDirectory() {
        std::error_code error;
        const auto temp_root = std::filesystem::temp_directory_path(error);
        if (error) {
            throw std::system_error(error,
                                    "resolve peer-trust test directory");
        }
        std::string pattern =
            (temp_root / "yume-peer-trust-test-XXXXXX").string();
        char* made = ::mkdtemp(pattern.data());
        if (made == nullptr) {
            throw std::system_error(errno, std::generic_category(),
                                    "create peer-trust test directory");
        }
        path_ = made;
    }

    ~TempDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

mode_t ModeOf(const std::filesystem::path& path) {
    struct stat info {};
    if (::lstat(path.c_str(), &info) != 0) {
        throw std::system_error(errno, std::generic_category(),
                                "stat peer-trust test path");
    }
    return info.st_mode & 0777;
}

std::string ReadAll(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("open peer-trust test file");
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

void Overwrite(const std::filesystem::path& path,
               std::string_view content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("overwrite peer-trust test file");
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    if (!output) throw std::runtime_error("write peer-trust test file");
}

std::filesystem::path RecordPath(const std::filesystem::path& directory,
                                 std::string_view endpoint_id,
                                 std::string_view suffix) {
    return directory /
        (yume::crypto::sha256_hex(endpoint_id) + std::string(suffix));
}

std::string Fingerprint(const Bytes& identity) {
    auto parsed = yume::crypto::parse_composite_identity(identity);
    Check(parsed.valid(), "test composite identity failed to parse");
    return yume::crypto::composite_fingerprint(parsed);
}

#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX

struct Identities {
    yume::crypto::CompositeKeyPair first{
        yume::crypto::generate_composite_keypair()};
    yume::crypto::CompositeKeyPair second{
        yume::crypto::generate_composite_keypair()};
    Bytes first_encoded{yume::crypto::encode_composite_identity(
        first.classical.public_key.get(), first.pq.public_key.get())};
    Bytes second_encoded{yume::crypto::encode_composite_identity(
        second.classical.public_key.get(), second.pq.public_key.get())};
    std::string first_fingerprint{Fingerprint(first_encoded)};
    std::string second_fingerprint{Fingerprint(second_encoded)};
};

void TestTofuAndProtectedFiles(const std::filesystem::path& root,
                               const Identities& identities) {
    constexpr std::string_view endpoint =
        "00112233445566778899aabbccddeeff";
    const auto trust_directory = root / "tofu-parent" / "trust";
    relay_v2::PeerTrustStore store(Config(trust_directory));

    const auto unpinned = store.precheck(endpoint, identities.first_encoded);
    Check(!unpinned.pin_persisted && unpinned.commit_required,
          "TOFU precheck did not report an uncommitted identity");
    Check(!unpinned.explicit_authorized,
          "TOFU identity became explicitly authorized");
    Check(!std::filesystem::exists(trust_directory),
          "read-only precheck created trust state for an unsolicited invite");

    const auto committed =
        store.commit_verified(endpoint, identities.first_encoded);
    Check(committed.pin_persisted && !committed.commit_required,
          "TOFU identity was not durably committed");
    Check(committed.fingerprint == identities.first_fingerprint,
          "TOFU commit returned the wrong fingerprint");
    Check(ModeOf(trust_directory) == S_IRWXU,
          "trust directory was not created with mode 0700");

    const auto pin_path = RecordPath(trust_directory, endpoint, ".pin");
    const auto marker_path =
        RecordPath(trust_directory, endpoint, ".explicit");
    Check(std::filesystem::exists(pin_path), "TOFU pin was not created");
    Check(!std::filesystem::exists(marker_path),
          "TOFU created an explicit marker");
    Check(ModeOf(pin_path) == (S_IRUSR | S_IWUSR),
          "TOFU pin was not created with mode 0600");
    const std::string original = ReadAll(pin_path);
    Check(original.find(std::string(endpoint)) != std::string::npos,
          "pin record does not bind its endpoint ID");
    Check(original.find(identities.first_fingerprint) != std::string::npos,
          "pin record does not bind its composite fingerprint");
    Check(original.find("PUBLIC KEY") == std::string::npos,
          "trust store retained full identity bytes");

    const auto trusted = store.precheck(endpoint, identities.first_encoded);
    Check(trusted.pin_persisted && !trusted.commit_required,
          "persisted TOFU pin was not recognized");
    ExpectFailure(
        [&] {
            (void)store.precheck(
                endpoint, identities.first_encoded,
                relay_v2::PeerTrustRequirement::Admin);
        },
        "plain TOFU pin authorized an admin channel");
    ExpectFailure(
        [&] { (void)store.precheck(endpoint, identities.second_encoded); },
        "persisted TOFU mismatch was accepted");
    ExpectFailure(
        [&] {
            (void)store.commit_verified(endpoint, identities.second_encoded);
        },
        "persisted TOFU pin was replaced by a mismatch");
    Check(ReadAll(pin_path) == original,
          "mismatched commit changed the persisted pin");

    Bytes noncanonical = identities.first_encoded;
    noncanonical.push_back('\n');
    ExpectFailure(
        [&] { (void)store.precheck(endpoint, noncanonical); },
        "noncanonical composite identity was accepted");
    ExpectFailure(
        [&] { (void)store.precheck("../outside", identities.first_encoded); },
        "traversal endpoint was accepted by the store");
    Check(!std::filesystem::exists(root / "outside.pin"),
          "endpoint traversal escaped the trust directory");

    Check(::chmod(trust_directory.c_str(), 0755) == 0,
          "failed to make test trust directory unsafe");
    ExpectFailure(
        [&] { (void)store.precheck(endpoint, identities.first_encoded); },
        "world-accessible trust directory was accepted");
    Check(::chmod(trust_directory.c_str(), 0700) == 0,
          "failed to restore test trust-directory mode");

    Check(::chmod(pin_path.c_str(), 0644) == 0,
          "failed to make test pin unsafe");
    ExpectFailure(
        [&] { (void)store.precheck(endpoint, identities.first_encoded); },
        "world-readable pin was accepted");
    Check(::chmod(pin_path.c_str(), 0600) == 0,
          "failed to restore test pin mode");

    const auto hardlink = root / "pin-hardlink";
    Check(::link(pin_path.c_str(), hardlink.c_str()) == 0,
          "failed to create test pin hardlink");
    ExpectFailure(
        [&] { (void)store.precheck(endpoint, identities.first_encoded); },
        "multiply-linked pin was accepted");
    Check(::unlink(hardlink.c_str()) == 0,
          "failed to remove test pin hardlink");
    Check(store.precheck(endpoint, identities.first_encoded).pin_persisted,
          "pin remained unusable after hardlink removal");

    std::string wrong_binding = original;
    const auto endpoint_offset = wrong_binding.find(std::string(endpoint));
    Check(endpoint_offset != std::string::npos,
          "test pin record did not contain its endpoint");
    wrong_binding.replace(endpoint_offset, endpoint.size(),
                          std::string(endpoint.size(), 'a'));
    Overwrite(pin_path, wrong_binding);
    ExpectFailure(
        [&] { (void)store.precheck(endpoint, identities.first_encoded); },
        "pin record bound to a different endpoint was accepted");
    Overwrite(pin_path, original);

    const auto victim = root / "pin-symlink-victim";
    Overwrite(victim, "unchanged");
    Check(::unlink(pin_path.c_str()) == 0,
          "failed to remove pin before symlink test");
    Check(::symlink(victim.c_str(), pin_path.c_str()) == 0,
          "failed to install pin symlink test fixture");
    ExpectFailure(
        [&] {
            (void)store.commit_verified(endpoint, identities.first_encoded);
        },
        "pin symlink was followed or replaced");
    Check(ReadAll(victim) == "unchanged",
          "pin symlink victim was modified");
}

void TestExplicitAndPinnedPolicy(const std::filesystem::path& root,
                                 const Identities& identities) {
    constexpr std::string_view endpoint =
        "peer-alpha:ffeeddccbbaa99887766554433221100";
    const auto trust_directory = root / "explicit";
    relay_v2::PeerTrustStore tofu(Config(trust_directory));
    (void)tofu.commit_verified(endpoint, identities.first_encoded);
    ExpectFailure(
        [&] {
            (void)tofu.precheck(
                endpoint, identities.first_encoded,
                relay_v2::PeerTrustRequirement::Admin);
        },
        "TOFU-only identity authorized admin before OOB promotion");

    relay_v2::PeerTrustStore explicit_store(Config(
        trust_directory, relay_v2::PeerTrustMode::Tofu,
        {{std::string(endpoint), identities.first_fingerprint}}));
    const auto pre = explicit_store.precheck(
        endpoint, identities.first_encoded,
        relay_v2::PeerTrustRequirement::Admin);
    Check(pre.pin_persisted && pre.explicit_authorized &&
              pre.commit_required,
          "configured OOB pin was not eligible for exact promotion");
    const auto marker_path =
        RecordPath(trust_directory, endpoint, ".explicit");
    Check(!std::filesystem::exists(marker_path),
          "OOB precheck wrote an explicit marker");

    const auto promoted = explicit_store.commit_verified(
        endpoint, identities.first_encoded,
        relay_v2::PeerTrustRequirement::Admin);
    Check(promoted.pin_persisted && promoted.explicit_authorized &&
              !promoted.commit_required,
          "OOB pin was not durably promoted");
    Check(ModeOf(marker_path) == (S_IRUSR | S_IWUSR),
          "explicit marker was not created with mode 0600");

    relay_v2::PeerTrustStore without_config(Config(trust_directory));
    Check(without_config.precheck(
              endpoint, identities.first_encoded,
              relay_v2::PeerTrustRequirement::Admin).explicit_authorized,
          "durable explicit marker did not authorize admin");

    const std::string original_pin = ReadAll(
        RecordPath(trust_directory, endpoint, ".pin"));
    const std::string original_marker = ReadAll(marker_path);
    relay_v2::PeerTrustStore changed_config(Config(
        trust_directory, relay_v2::PeerTrustMode::Pinned,
        {{std::string(endpoint), identities.second_fingerprint}}));
    ExpectFailure(
        [&] {
            (void)changed_config.commit_verified(
                endpoint, identities.second_encoded,
                relay_v2::PeerTrustRequirement::Admin);
        },
        "changed configured pin replaced an explicit identity");
    Check(ReadAll(RecordPath(trust_directory, endpoint, ".pin")) ==
              original_pin &&
              ReadAll(marker_path) == original_marker,
          "configured mismatch changed durable trust state");

    Check(::chmod(marker_path.c_str(), 0644) == 0,
          "failed to make explicit marker unsafe");
    ExpectFailure(
        [&] { (void)without_config.precheck(endpoint, identities.first_encoded); },
        "world-readable explicit marker was ignored");
    Check(::chmod(marker_path.c_str(), 0600) == 0,
          "failed to restore explicit marker mode");

    const auto orphan_directory = root / "orphan-marker";
    Check(::mkdir(orphan_directory.c_str(), 0700) == 0,
          "failed to create orphan-marker directory");
    const auto orphan_marker =
        RecordPath(orphan_directory, endpoint, ".explicit");
    std::filesystem::copy_file(marker_path, orphan_marker);
    Check(::chmod(orphan_marker.c_str(), 0600) == 0,
          "failed to protect orphan explicit marker");
    relay_v2::PeerTrustStore orphan_store(Config(orphan_directory));
    ExpectFailure(
        [&] { (void)orphan_store.precheck(endpoint, identities.first_encoded); },
        "explicit marker without its bound pin was accepted");

    const auto marker_victim = root / "marker-symlink-victim";
    Overwrite(marker_victim, "unchanged");
    Check(::unlink(marker_path.c_str()) == 0,
          "failed to remove marker before symlink test");
    Check(::symlink(marker_victim.c_str(), marker_path.c_str()) == 0,
          "failed to install explicit-marker symlink fixture");
    ExpectFailure(
        [&] { (void)without_config.precheck(endpoint, identities.first_encoded); },
        "explicit-marker symlink was followed");
    Check(ReadAll(marker_victim) == "unchanged",
          "explicit-marker symlink victim was modified");
    Check(::unlink(marker_path.c_str()) == 0,
          "failed to remove explicit-marker symlink fixture");
    Overwrite(marker_path, original_marker);
    Check(::chmod(marker_path.c_str(), 0600) == 0,
          "failed to restore explicit marker after symlink test");

    const auto pinned_directory = root / "pinned";
    relay_v2::PeerTrustStore pinned_empty(Config(
        pinned_directory, relay_v2::PeerTrustMode::Pinned));
    ExpectFailure(
        [&] { (void)pinned_empty.precheck(endpoint, identities.first_encoded); },
        "pinned mode admitted an unknown identity");
    ExpectFailure(
        [&] {
            (void)pinned_empty.commit_verified(
                endpoint, identities.first_encoded);
        },
        "pinned mode committed an unknown identity");

    const auto configured_directory = root / "configured-pinned";
    relay_v2::PeerTrustStore pinned_configured(Config(
        configured_directory, relay_v2::PeerTrustMode::Pinned,
        {{std::string(endpoint), identities.first_fingerprint}}));
    const auto configured_pre = pinned_configured.precheck(
        endpoint, identities.first_encoded,
        relay_v2::PeerTrustRequirement::Admin);
    Check(configured_pre.explicit_authorized &&
              configured_pre.commit_required,
          "pinned OOB identity was not admitted for verification");
    Check(!std::filesystem::exists(configured_directory),
          "pinned precheck persisted an unsolicited identity");
    (void)pinned_configured.commit_verified(
        endpoint, identities.first_encoded,
        relay_v2::PeerTrustRequirement::Admin);
}

void TestDirectorySymlinks(const std::filesystem::path& root,
                           const Identities& identities) {
    constexpr std::string_view endpoint = "peer-symlink";
    const auto target = root / "symlink-target";
    Check(::mkdir(target.c_str(), 0700) == 0,
          "failed to create symlink target directory");
    const auto link = root / "trust-link";
    Check(::symlink(target.c_str(), link.c_str()) == 0,
          "failed to create trust-directory symlink");
    relay_v2::PeerTrustStore linked(Config(link));
    ExpectFailure(
        [&] { (void)linked.precheck(endpoint, identities.first_encoded); },
        "trust-directory symlink was followed on precheck");
    ExpectFailure(
        [&] {
            (void)linked.commit_verified(endpoint, identities.first_encoded);
        },
        "trust-directory symlink was followed on commit");
    Check(std::filesystem::is_empty(target),
          "trust-directory symlink target was modified");

    const auto nested = root / "nested-link";
    Check(::symlink(target.c_str(), nested.c_str()) == 0,
          "failed to create parent-component symlink");
    relay_v2::PeerTrustStore nested_store(Config(nested / "child"));
    ExpectFailure(
        [&] {
            (void)nested_store.commit_verified(
                endpoint, identities.first_encoded);
        },
        "parent-component symlink was followed");

    const auto public_directory = root / "public-trust";
    Check(::mkdir(public_directory.c_str(), 0700) == 0,
          "failed to create public trust fixture");
    Check(::chmod(public_directory.c_str(), 0755) == 0,
          "failed to make public trust fixture unsafe");
    relay_v2::PeerTrustStore public_store(Config(public_directory));
    ExpectFailure(
        [&] {
            (void)public_store.commit_verified(
                endpoint, identities.first_encoded);
        },
        "world-accessible existing trust directory was accepted");

    const auto writable_parent = root / "writable-parent";
    Check(::mkdir(writable_parent.c_str(), 0700) == 0,
          "failed to create writable ancestor fixture");
    Check(::chmod(writable_parent.c_str(), 0777) == 0,
          "failed to make ancestor world-writable");
    relay_v2::PeerTrustStore writable_parent_store(
        Config(writable_parent / "trust"));
    ExpectFailure(
        [&] {
            (void)writable_parent_store.commit_verified(
                endpoint, identities.first_encoded);
        },
        "world-writable non-sticky trust ancestor was accepted");
    Check(!std::filesystem::exists(writable_parent / "trust"),
          "unsafe trust ancestor was modified");

    Check(::chmod(writable_parent.c_str(), 0770) == 0,
          "failed to make ancestor group-writable");
    ExpectFailure(
        [&] {
            (void)writable_parent_store.commit_verified(
                endpoint, identities.first_encoded);
        },
        "group-writable trust ancestor was accepted");
}

void TestConcurrentFirstWriters(const std::filesystem::path& root,
                                const Identities& identities) {
    constexpr std::string_view endpoint = "concurrent-peer";
    const auto same_directory = root / "concurrent-same";
    relay_v2::PeerTrustStore same_store(Config(same_directory));
    std::atomic<int> same_successes{0};
    std::atomic<int> same_failures{0};
    std::vector<std::thread> writers;
    for (int index = 0; index < 8; ++index) {
        writers.emplace_back([&] {
            try {
                (void)same_store.commit_verified(
                    endpoint, identities.first_encoded);
                same_successes.fetch_add(1, std::memory_order_relaxed);
            } catch (...) {
                same_failures.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    for (auto& writer : writers) writer.join();
    Check(same_successes.load() == 8 && same_failures.load() == 0,
          "concurrent identical first writers did not converge");
    Check(same_store.precheck(endpoint, identities.first_encoded).pin_persisted,
          "concurrent identical first writers left no durable pin");

    const auto different_directory = root / "concurrent-different";
    relay_v2::PeerTrustStore different_store(Config(different_directory));
    std::atomic<int> ready{0};
    std::atomic<bool> start{false};
    std::atomic<bool> first_succeeded{false};
    std::atomic<bool> second_succeeded{false};
    std::atomic<int> failures{0};
    const auto writer = [&](const Bytes& identity,
                            std::atomic<bool>& succeeded) {
        ready.fetch_add(1, std::memory_order_release);
        while (!start.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        try {
            (void)different_store.commit_verified(endpoint, identity);
            succeeded.store(true, std::memory_order_release);
        } catch (...) {
            failures.fetch_add(1, std::memory_order_relaxed);
        }
    };
    std::thread first(writer, std::cref(identities.first_encoded),
                      std::ref(first_succeeded));
    std::thread second(writer, std::cref(identities.second_encoded),
                       std::ref(second_succeeded));
    while (ready.load(std::memory_order_acquire) != 2) {
        std::this_thread::yield();
    }
    start.store(true, std::memory_order_release);
    first.join();
    second.join();
    Check(first_succeeded.load() != second_succeeded.load(),
          "different concurrent first writers did not select one identity");
    Check(failures.load() == 1,
          "different concurrent first writers did not reject one mismatch");
    if (first_succeeded.load()) {
        Check(different_store.precheck(
                  endpoint, identities.first_encoded).pin_persisted,
              "first concurrent winner was not persisted");
        ExpectFailure(
            [&] {
                (void)different_store.precheck(
                    endpoint, identities.second_encoded);
            },
            "second concurrent identity was also trusted");
    } else {
        Check(different_store.precheck(
                  endpoint, identities.second_encoded).pin_persisted,
              "second concurrent winner was not persisted");
        ExpectFailure(
            [&] {
                (void)different_store.precheck(
                    endpoint, identities.first_encoded);
            },
            "first concurrent identity was also trusted");
    }
}

#endif  // YUME_USE_BASEFWX
#endif  // !_WIN32

}  // namespace

int main() {
#if defined(_WIN32)
    ExpectFailure(
        [] {
            relay_v2::PeerTrustStore store(
                Config("ignored", relay_v2::PeerTrustMode::Pinned));
        },
        "Windows trust store did not fail closed");
#else
    TempDirectory temp;
    TestInputValidation(temp.path());
#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
    const Identities identities;
    TestTofuAndProtectedFiles(temp.path(), identities);
    TestExplicitAndPinnedPolicy(temp.path(), identities);
    TestDirectorySymlinks(temp.path(), identities);
    TestConcurrentFirstWriters(temp.path(), identities);
#endif
#endif
    std::cout << "relay_peer_trust_test ok\n";
    return 0;
}
