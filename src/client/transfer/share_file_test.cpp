/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/transfer/share_file.hpp"

#include <basefwx/fwxaes.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <utility>
#include <vector>

#ifndef _WIN32
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

std::string read_text(const std::filesystem::path& path) {
    std::ifstream input(path);
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

std::vector<std::uint8_t> encode_document(
        const nlohmann::json& document,
        const std::string& password) {
    const std::string serialised = document.dump();
    const std::vector<std::uint8_t> plaintext(
        serialised.begin(), serialised.end());
    const auto encrypted =
        basefwx::fwxaes::EncryptRaw(plaintext, password);
    // Fill a size-checked destination directly. GCC 11 can misdiagnose the
    // vector::insert growth path below this fixed header as an overread when
    // Release inlining and -Werror are enabled.
    constexpr std::size_t kHeaderSize = 12U;
    std::vector<std::uint8_t> output(kHeaderSize + encrypted.size());
    std::size_t offset = 0;
    for (const std::uint8_t byte : std::array<std::uint8_t, kHeaderSize>{
             'Y', 'U', 'M', 'E', 'S', 'H', 'R', 'E',
             yume::share::kFormatVersion,
             static_cast<std::uint8_t>(yume::share::BundleType::Backup),
             0, 0}) {
        output[offset++] = byte;
    }
    for (const std::uint8_t byte : encrypted) {
        output[offset++] = byte;
    }
    return output;
}

nlohmann::json decrypt_document(
        const std::vector<std::uint8_t>& encoded,
        const std::string& password) {
    assert(encoded.size() > 12U);
    const std::vector<std::uint8_t> encrypted(
        encoded.begin() + 12, encoded.end());
    const auto plaintext =
        basefwx::fwxaes::DecryptRaw(encrypted, password);
    return nlohmann::json::parse(plaintext.begin(), plaintext.end());
}

nlohmann::json minimal_document() {
    return {
        {"magic", "yume-share"},
        {"version", yume::share::kFormatVersion},
        {"type", "backup"},
        {"server", {{"host", "relay.example.test"}, {"port", 443}}},
        {"client_settings", nlohmann::json::object()},
    };
}

void expect_decode_rejected(const nlohmann::json& document,
                            const std::string& password) {
    std::string error;
    const auto encoded = encode_document(document, password);
    assert(!yume::share::decode_share(encoded, password, &error));
    assert(!error.empty());
}

void test_bundle_sensitive_lifecycle() {
    yume::share::ShareBundle source;
    source.server_host = "lifecycle.example.test";
    source.auth_private_key_pem = "private-key-material";
    source.obfs_secret = std::string(64, 'a');
    source.inner_psk = std::string(64, 'b');

    yume::share::ShareBundle copied(source);
    assert(copied.auth_private_key_pem == source.auth_private_key_pem);
    assert(copied.obfs_secret == source.obfs_secret);
    assert(copied.inner_psk == source.inner_psk);

    yume::share::ShareBundle assigned;
    assigned.auth_private_key_pem = "old-private-key";
    assigned.obfs_secret = "old-secret";
    assigned.inner_psk = "old-psk";
    assigned = source;
    assert(assigned.auth_private_key_pem == source.auth_private_key_pem);
    assert(assigned.obfs_secret == source.obfs_secret);
    assert(assigned.inner_psk == source.inner_psk);

    yume::share::ShareBundle moved(std::move(copied));
    assert(copied.auth_private_key_pem.empty());
    assert(copied.obfs_secret.empty());
    assert(copied.inner_psk.empty());
    assert(moved.auth_private_key_pem == source.auth_private_key_pem);

    yume::share::ShareBundle move_assigned;
    move_assigned.auth_private_key_pem = "replaced-private-key";
    move_assigned.obfs_secret = "replaced-secret";
    move_assigned.inner_psk = "replaced-psk";
    move_assigned = std::move(moved);
    assert(moved.auth_private_key_pem.empty());
    assert(moved.obfs_secret.empty());
    assert(moved.inner_psk.empty());
    move_assigned.clear_secrets();
    assert(move_assigned.auth_private_key_pem.empty());
    assert(move_assigned.obfs_secret.empty());
    assert(move_assigned.inner_psk.empty());
}

void set_test_home(const std::filesystem::path& home) {
#ifdef _WIN32
    assert(_putenv_s("HOME", home.string().c_str()) == 0);
#else
    assert(::setenv("HOME", home.string().c_str(), 1) == 0);
#endif
}

void write_text(const std::filesystem::path& path,
                const std::string& content) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
    output.close();
    assert(output);
}

#ifndef _WIN32

std::filesystem::path make_private_home(
        const std::filesystem::path& root,
        const std::string& name) {
    const auto home = root / name;
    assert(std::filesystem::create_directories(home));
    assert(::chmod(home.c_str(), 0700) == 0);
    return home;
}

void make_private_directory(const std::filesystem::path& path) {
    assert(std::filesystem::create_directory(path));
    assert(::chmod(path.c_str(), 0700) == 0);
}

void prepare_managed_parent(const std::filesystem::path& home) {
    const auto yume = home / ".yume";
    make_private_directory(yume);
    make_private_directory(yume / "imported");
}

void assert_private_directory(const std::filesystem::path& path) {
    struct stat info {};
    assert(::lstat(path.c_str(), &info) == 0);
    assert(S_ISDIR(info.st_mode));
    assert((info.st_mode & 07777) == 0700);
    assert(info.st_uid == ::geteuid());
}

void assert_private_regular(const std::filesystem::path& path) {
    struct stat info {};
    assert(::lstat(path.c_str(), &info) == 0);
    assert(S_ISREG(info.st_mode));
    assert((info.st_mode & 07777) == 0600);
    assert(info.st_uid == ::geteuid());
    assert(info.st_nlink == 1);
}

bool same_object(const struct stat& lhs, const struct stat& rhs) {
    return lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino;
}

bool has_staging_directory(const std::filesystem::path& imported_root) {
    for (const auto& entry :
         std::filesystem::directory_iterator(imported_root)) {
        if (entry.path().filename().string().starts_with(".import-tmp.")) {
            return true;
        }
    }
    return false;
}

void expect_apply_rejected(const yume::share::ShareBundle& bundle,
                           std::string* error) {
    yume::share::ApplyResult result;
    result.target_dir = "unchanged-sentinel";
    assert(!yume::share::apply_imported_bundle(bundle, &result, error));
    assert(error && !error->empty());
    assert(result.target_dir == "unchanged-sentinel");
}

void test_share_file_boundaries(const std::filesystem::path& root) {
    const auto destination = root / "exclusive.yss";
    const std::vector<std::uint8_t> contents{'y', 's', 's'};
    std::string error;
    assert(yume::share::write_share_file_exclusive(
        destination, contents, &error));
    assert(error.empty());
    assert_private_regular(destination);

    const std::vector<std::uint8_t> replacement{'x'};
    assert(!yume::share::write_share_file_exclusive(
        destination, replacement, &error));
    std::vector<std::uint8_t> read_back;
    assert(yume::share::read_share_file(destination, &read_back, &error));
    assert(read_back == contents);

    const auto victim = root / "share-victim";
    write_text(victim, "unchanged");
    const auto link = root / "share-link.yss";
    std::filesystem::create_symlink(victim, link);
    assert(!yume::share::write_share_file_exclusive(
        link, replacement, &error));
    assert(!yume::share::read_share_file(link, &read_back, &error));
    assert(read_text(victim) == "unchanged");

    const auto oversized = root / "oversized.yss";
    write_text(oversized,
               std::string(yume::share::kMaxShareFileBytes + 1U, 'x'));
    assert(!yume::share::read_share_file(oversized, &read_back, &error));
    assert(error.find("size limit") != std::string::npos);
    assert(read_back.empty());

    const auto refused_output = root / "oversized-output.yss";
    const std::vector<std::uint8_t> oversized_contents(
        yume::share::kMaxShareFileBytes + 1U, 0U);
    assert(!yume::share::write_share_file_exclusive(
        refused_output, oversized_contents, &error));
    assert(!std::filesystem::exists(refused_output));

    const auto partial_output = root / "partial-output.yss";
    const pid_t child = ::fork();
    assert(child >= 0);
    if (child == 0) {
        (void)std::signal(SIGXFSZ, SIG_IGN);
        const rlimit limit{1, 1};
        if (::setrlimit(RLIMIT_FSIZE, &limit) != 0) ::_exit(2);
        std::string child_error;
        const std::vector<std::uint8_t> child_contents(4096U, 0x5aU);
        const bool written = yume::share::write_share_file_exclusive(
            partial_output, child_contents, &child_error);
        ::_exit(!written && !child_error.empty() &&
                       !std::filesystem::exists(partial_output)
                   ? 0
                   : 3);
    }
    int status = 0;
    assert(::waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(!std::filesystem::exists(partial_output));
}

#endif

}  // namespace

int main() {
    namespace fs = std::filesystem;
    using namespace yume::share;

    test_bundle_sensitive_lifecycle();

    ShareBundle bundle;
    bundle.server_host = "192.0.2.10";
    bundle.server_port = 8443;
    bundle.auth_private_key_pem = "test-private-key";
    bundle.anonym_ca_cert_pem = "operator-ca";
    bundle.tls_ca_cert_pem = "tls-ca";
    bundle.tls_server_name = "edge.example.test";
    bundle.tunnel_count = 3;
    bundle.require_operator_identity = true;
    bundle.obfs_secret = std::string(64, 'a');
    bundle.inner_psk = std::string(64, 'b');
    bundle.relay_trust_mode = "pinned";
    bundle.relay_peer_pins.emplace("peer:client", std::string(64, 'A'));

    std::string error;
    assert(encode_share(bundle, std::string(kPasswordMin - 1, 'x'), &error).empty());
    assert(error.find("at least 12") != std::string::npos);

    const std::string password(kPasswordMin, 'x');
    const auto encoded = encode_share(bundle, password, &error);
    assert(!encoded.empty());
    auto malformed_header = encoded;
    malformed_header[9] = 1;
    ShareFileHeader header{};
    assert(!peek_share_header(malformed_header, &header));
    assert(!decode_share(malformed_header, password, &error));
    malformed_header = encoded;
    malformed_header[10] = 1;
    assert(!peek_share_header(malformed_header, &header));
    assert(!decode_share(malformed_header, password, &error));
    const auto decoded = decode_share(encoded, password, &error);
    assert(decoded.has_value());
    assert(decoded->tls_ca_cert_pem == bundle.tls_ca_cert_pem);
    assert(decoded->tls_server_name == bundle.tls_server_name);
    assert(decoded->tunnel_count == 3);
    assert(decoded->require_operator_identity);
    assert(decoded->relay_trust_mode == "pinned");
    assert(decoded->relay_peer_pins.size() == 1);
    assert(decoded->relay_peer_pins.at("peer:client") ==
           std::string(64, 'a'));

    const auto exported_document = decrypt_document(encoded, password);
    const auto& exported_settings = exported_document.at("client_settings");
    assert(exported_settings.at("relay_trust_mode") == "pinned");
    assert(exported_settings.at("relay_peer_pins").at("peer:client") ==
           std::string(64, 'a'));
    assert(!exported_settings.contains("relay_trust_dir"));

    ShareBundle legacy_bundle;
    legacy_bundle.server_host = "192.0.2.11";
    legacy_bundle.anonym_ca_cert_pem = "combined-legacy-ca";
    const auto legacy_encoded = encode_share(legacy_bundle, password, &error);
    const auto legacy_decoded = decode_share(legacy_encoded, password, &error);
    assert(legacy_decoded.has_value());
    assert(legacy_decoded->tls_ca_cert_pem == legacy_bundle.anonym_ca_cert_pem);
    assert(legacy_decoded->relay_trust_mode == "tofu");
    assert(legacy_decoded->relay_peer_pins.empty());

    ShareBundle invalid_bundle = bundle;
    invalid_bundle.relay_trust_mode = "TOFU";
    assert(encode_share(invalid_bundle, password, &error).empty());
    invalid_bundle = bundle;
    invalid_bundle.relay_peer_pins = {
        {"peer/client", std::string(64, 'a')}};
    assert(encode_share(invalid_bundle, password, &error).empty());
    invalid_bundle = bundle;
    invalid_bundle.relay_peer_pins = {
        {"peer:client", std::string(63, 'a')}};
    assert(encode_share(invalid_bundle, password, &error).empty());
    invalid_bundle = bundle;
    invalid_bundle.relay_peer_pins = {
        {std::string(256, 'p'), std::string(64, 'a')}};
    assert(encode_share(invalid_bundle, password, &error).empty());
    invalid_bundle = bundle;
    invalid_bundle.server_host = "../escape";
    assert(encode_share(invalid_bundle, password, &error).empty());
    invalid_bundle = bundle;
    invalid_bundle.server_host = std::string(256, 'h');
    assert(encode_share(invalid_bundle, password, &error).empty());

    BackupInputs backup_inputs;
    backup_inputs.server_host = "backup.example.test";
    backup_inputs.relay_trust_mode = "pinned";
    backup_inputs.relay_peer_pins = {
        {"remote:operator", std::string(64, 'B')}};
    ShareBundle built_bundle;
    assert(build_backup_bundle(
        backup_inputs, &built_bundle, &error));
    assert(built_bundle.relay_trust_mode == "pinned");
    assert(built_bundle.relay_peer_pins.at("remote:operator") ==
           std::string(64, 'b'));
    backup_inputs.relay_trust_mode = "invalid";
    assert(!build_backup_bundle(
        backup_inputs, &built_bundle, &error));

    const auto missing_policy = decode_share(
        encode_document(minimal_document(), password), password, &error);
    assert(missing_policy.has_value());
    assert(missing_policy->relay_trust_mode == "tofu");
    assert(missing_policy->relay_peer_pins.empty());

    auto uppercase_policy = minimal_document();
    uppercase_policy["client_settings"]["relay_trust_mode"] = "pinned";
    uppercase_policy["client_settings"]["relay_peer_pins"] = {
        {"peer:client", std::string(64, 'F')}};
    const auto normalized_policy = decode_share(
        encode_document(uppercase_policy, password), password, &error);
    assert(normalized_policy.has_value());
    assert(normalized_policy->relay_peer_pins.at("peer:client") ==
           std::string(64, 'f'));

    auto malformed = minimal_document();
    malformed["client_settings"]["relay_trust_mode"] = "opportunistic";
    expect_decode_rejected(malformed, password);
    malformed = minimal_document();
    malformed["client_settings"]["relay_trust_mode"] = 1;
    expect_decode_rejected(malformed, password);
    malformed = minimal_document();
    malformed["client_settings"]["relay_peer_pins"] =
        nlohmann::json::array();
    expect_decode_rejected(malformed, password);
    malformed = minimal_document();
    malformed["client_settings"]["relay_peer_pins"] = {
        {"peer/client", std::string(64, 'a')}};
    expect_decode_rejected(malformed, password);
    malformed = minimal_document();
    malformed["client_settings"]["relay_peer_pins"] = {
        {"peer:client", std::string(64, 'g')}};
    expect_decode_rejected(malformed, password);
    malformed = minimal_document();
    malformed["client_settings"]["relay_peer_pins"] = {
        {"peer:client", 7}};
    expect_decode_rejected(malformed, password);
    malformed = minimal_document();
    malformed["client_settings"] = nlohmann::json::array();
    expect_decode_rejected(malformed, password);
    malformed = minimal_document();
    malformed["version"] = yume::share::kFormatVersion + 1;
    expect_decode_rejected(malformed, password);
    malformed = minimal_document();
    malformed["type"] = "future";
    expect_decode_rejected(malformed, password);
    malformed = minimal_document();
    malformed["server"]["host"] = "/tmp/escape";
    expect_decode_rejected(malformed, password);

    const auto unique = std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count());
    const fs::path root =
        fs::temp_directory_path() / ("yume-share-test-" + unique);
    assert(fs::create_directories(root));

#ifdef _WIN32
    const fs::path windows_home = root / "home";
    assert(fs::create_directory(windows_home));
    set_test_home(windows_home);
    ApplyResult unsupported_result;
    unsupported_result.target_dir = "unchanged-sentinel";
    assert(!apply_imported_bundle(
        *decoded, &unsupported_result, &error));
    assert(error.find("unavailable on Windows") != std::string::npos);
    assert(unsupported_result.target_dir == "unchanged-sentinel");
    std::error_code ignored;
    fs::remove_all(root, ignored);
    return 0;
#else
    test_share_file_boundaries(root);
    const fs::path home = make_private_home(root, "home");
    set_test_home(home);

    ApplyResult result;
    assert(apply_imported_bundle(*decoded, &result, &error));
    const auto config = nlohmann::json::parse(read_text(result.config_path));
    assert(config.at("tls_ca_cert") == result.tls_ca_path);
    assert(config.at("anonym_ca_cert") == result.anonym_ca_path);
    assert(config.at("tls_server_name") == bundle.tls_server_name);
    assert(config.at("tunnels") == 3);
    assert(config.at("require_anonym") == true);
    assert(config.at("relay_trust_mode") == "pinned");
    assert(config.at("relay_peer_pins").at("peer:client") ==
           std::string(64, 'a'));
    assert(!config.contains("relay_trust_dir"));
    assert(read_text(result.tls_ca_path) == bundle.tls_ca_cert_pem);
    assert_private_directory(result.target_dir);
    assert_private_regular(result.config_path);
    assert_private_regular(result.identity_path);
    assert_private_regular(result.anonym_ca_path);
    assert_private_regular(result.tls_ca_path);
    assert_private_regular(result.obfs_secret_path);
    assert_private_regular(result.inner_psk_path);

    struct stat first_target {};
    assert(::lstat(result.target_dir.c_str(), &first_target) == 0);
    ShareBundle replacement = *decoded;
    replacement.auth_private_key_pem = "replacement-private-key";
    replacement.anonym_ca_cert_pem.clear();
    replacement.tls_ca_cert_pem = "replacement-tls-ca";
    replacement.inner_psk = std::string(64, 'c');
    ApplyResult replaced;
    assert(apply_imported_bundle(replacement, &replaced, &error));
    struct stat second_target {};
    assert(::lstat(replaced.target_dir.c_str(), &second_target) == 0);
    assert(!same_object(first_target, second_target));
    assert(read_text(replaced.identity_path) ==
           replacement.auth_private_key_pem);
    assert(read_text(replaced.tls_ca_path) == replacement.tls_ca_cert_pem);
    assert(read_text(replaced.inner_psk_path) == replacement.inner_psk);
    assert(replaced.anonym_ca_path.empty());
    assert(!fs::exists(fs::path(replaced.target_dir) / "anonym_ca.pem"));
    const auto replaced_config =
        nlohmann::json::parse(read_text(replaced.config_path));
    assert(!replaced_config.contains("anonym_ca_cert"));
    assert(replaced_config.at("identity") == replaced.identity_path);
    assert(!has_staging_directory(home / ".yume" / "imported"));

    ShareBundle invalid_apply = *decoded;
    invalid_apply.relay_peer_pins = {
        {".", std::string(64, 'a')}};
    ApplyResult rejected_result;
    assert(!apply_imported_bundle(
        invalid_apply, &rejected_result, &error));
    invalid_apply = *decoded;
    invalid_apply.server_host = "../../escape";
    assert(!apply_imported_bundle(
        invalid_apply, &rejected_result, &error));

    // An unsafe existing entry rejects the whole replacement before any new
    // generation is published. The old config and secret remain byte-for-byte
    // intact, and ApplyResult is not partially populated.
    const fs::path atomic_home = make_private_home(root, "atomic-home");
    set_test_home(atomic_home);
    ApplyResult atomic_initial;
    assert(apply_imported_bundle(*decoded, &atomic_initial, &error));
    const std::string old_config = read_text(atomic_initial.config_path);
    const std::string old_identity = read_text(atomic_initial.identity_path);
    struct stat old_target {};
    assert(::lstat(atomic_initial.target_dir.c_str(), &old_target) == 0);
    const fs::path unexpected =
        fs::path(atomic_initial.target_dir) / "unexpected.txt";
    write_text(unexpected, "operator-file");
    assert(::chmod(unexpected.c_str(), 0600) == 0);
    expect_apply_rejected(replacement, &error);
    struct stat unchanged_target {};
    assert(::lstat(atomic_initial.target_dir.c_str(), &unchanged_target) == 0);
    assert(same_object(old_target, unchanged_target));
    assert(read_text(atomic_initial.config_path) == old_config);
    assert(read_text(atomic_initial.identity_path) == old_identity);
    assert(!has_staging_directory(atomic_home / ".yume" / "imported"));

    // Every managed path component is opened relative to a previously opened
    // directory descriptor with O_NOFOLLOW.
    const fs::path component_home =
        make_private_home(root, "component-symlink-home");
    const fs::path component_victim = root / "component-victim";
    make_private_directory(component_victim);
    fs::create_directory_symlink(component_victim,
                                 component_home / ".yume");
    set_test_home(component_home);
    expect_apply_rejected(*decoded, &error);
    assert(fs::is_empty(component_victim));

    const fs::path imported_home =
        make_private_home(root, "imported-symlink-home");
    make_private_directory(imported_home / ".yume");
    const fs::path imported_victim = root / "imported-victim";
    make_private_directory(imported_victim);
    fs::create_directory_symlink(imported_victim,
                                 imported_home / ".yume" / "imported");
    set_test_home(imported_home);
    expect_apply_rejected(*decoded, &error);
    assert(fs::is_empty(imported_victim));

    const fs::path real_parent = root / "real-home-parent";
    const fs::path real_nested_home = real_parent / "nested";
    assert(fs::create_directories(real_nested_home));
    assert(::chmod(real_nested_home.c_str(), 0700) == 0);
    const fs::path home_alias = root / "home-parent-link";
    fs::create_directory_symlink(real_parent, home_alias);
    set_test_home(home_alias / "nested");
    expect_apply_rejected(*decoded, &error);
    assert(fs::is_empty(real_nested_home));

    const fs::path target_link_home =
        make_private_home(root, "target-symlink-home");
    prepare_managed_parent(target_link_home);
    const fs::path target_victim = root / "target-victim";
    make_private_directory(target_victim);
    fs::create_directory_symlink(
        target_victim,
        target_link_home / ".yume" / "imported" /
            decoded->server_host);
    set_test_home(target_link_home);
    expect_apply_rejected(*decoded, &error);
    assert(fs::is_empty(target_victim));

    const fs::path unsafe_directory_home =
        make_private_home(root, "unsafe-directory-home");
    make_private_directory(unsafe_directory_home / ".yume");
    assert(::chmod((unsafe_directory_home / ".yume").c_str(), 0755) == 0);
    set_test_home(unsafe_directory_home);
    expect_apply_rejected(*decoded, &error);

    // Existing final symlinks, hardlinks, and unsafe modes are rejected before
    // the staged replacement can become visible.
    const fs::path file_link_home =
        make_private_home(root, "file-symlink-home");
    set_test_home(file_link_home);
    ApplyResult file_link_initial;
    assert(apply_imported_bundle(*decoded, &file_link_initial, &error));
    const fs::path symlink_victim = root / "symlink-victim.txt";
    write_text(symlink_victim, "victim-must-not-change");
    assert(::chmod(symlink_victim.c_str(), 0600) == 0);
    assert(fs::remove(file_link_initial.identity_path));
    fs::create_symlink(symlink_victim, file_link_initial.identity_path);
    expect_apply_rejected(replacement, &error);
    assert(read_text(symlink_victim) == "victim-must-not-change");

    const fs::path hardlink_home =
        make_private_home(root, "hardlink-home");
    set_test_home(hardlink_home);
    ApplyResult hardlink_initial;
    assert(apply_imported_bundle(*decoded, &hardlink_initial, &error));
    const fs::path hardlink_alias = root / "hardlink-alias.txt";
    fs::create_hard_link(hardlink_initial.identity_path, hardlink_alias);
    expect_apply_rejected(replacement, &error);
    assert(read_text(hardlink_alias) == bundle.auth_private_key_pem);

    const fs::path mode_home = make_private_home(root, "unsafe-mode-home");
    set_test_home(mode_home);
    ApplyResult mode_initial;
    assert(apply_imported_bundle(*decoded, &mode_initial, &error));
    assert(::chmod(mode_initial.identity_path.c_str(), 0644) == 0);
    const std::string mode_identity = read_text(mode_initial.identity_path);
    expect_apply_rejected(replacement, &error);
    assert(read_text(mode_initial.identity_path) == mode_identity);

    std::error_code ignored;
    fs::remove_all(root, ignored);
    return 0;
#endif
}
