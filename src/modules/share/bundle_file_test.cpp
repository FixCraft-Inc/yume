/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "modules/share/bundle_file.hpp"

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>
#include <vector>

#include <basefwx/fwxaes.hpp>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

using namespace yume::share;

const std::string kPassword(kPasswordMin, 'k');

class TempDirectory {
public:
    TempDirectory() {
        std::string pattern =
            (std::filesystem::temp_directory_path() / "yume-share-test-XXXXXX").string();
        if (!::mkdtemp(pattern.data())) {
            throw std::system_error(errno, std::generic_category(), "create share test directory");
        }
        path_ = pattern;
    }
    ~TempDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }
    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

void write_text(const std::filesystem::path& path, const std::string& text) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output << text;
    assert(output.good());
}

std::string read_text(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

nlohmann::json Document() {
    return {{"server", {{"host", "192.0.2.12"}, {"port", 8443}}},
            {"identity", "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----\n"},
            {"pins", nlohmann::json::array({"a", "b"})}};
}

void test_round_trip_and_header() {
    std::string error;
    const auto sealed = seal_share(Document(), BundleType::Backup, kPassword, &error);
    assert(!sealed.empty() && error.empty());
    assert(std::string(sealed.begin(), sealed.begin() + 8) == "YUMESHRE");
    ShareFileHeader header{};
    assert(peek_share_header(sealed, &header));
    assert(header.version == kFormatVersion && header.type == BundleType::Backup);
    // The document never appears in the file.
    assert(std::string(sealed.begin(), sealed.end()).find("secret") == std::string::npos);

    auto opened = open_share(sealed, kPassword, &error);
    assert(opened && *opened == Document());
    JsonSecretWiper wiper(*opened);

    for (const std::size_t offset : {std::size_t{0}, std::size_t{8}, std::size_t{9},
                                     std::size_t{10}, std::size_t{11}}) {
        auto tampered = sealed;
        tampered[offset] ^= 0x01U;
        assert(!peek_share_header(tampered, &header));
        assert(!open_share(tampered, kPassword, &error));
        assert(error.find("not a .yss file") != std::string::npos);
    }
    auto body = sealed;
    body.back() ^= 0x01U;
    assert(!open_share(body, kPassword, &error));
    assert(error.find("decrypt failed") != std::string::npos);
    assert(!open_share(std::vector<std::uint8_t>(sealed.begin(), sealed.begin() + 11),
                       kPassword, &error));
}

void test_password_and_size_rules() {
    std::string error;
    const auto sealed = seal_share(Document(), BundleType::Backup, kPassword, &error);
    assert(!open_share(sealed, std::string(kPasswordMin, 'x'), &error));
    assert(error.find("decrypt failed") != std::string::npos);
    assert(!open_share(sealed, "", &error));
    assert(seal_share(Document(), BundleType::Backup, std::string(kPasswordMin - 1, 'k'),
                      &error).empty());
    assert(error.find("at least 12") != std::string::npos);
    assert(seal_share(Document(), static_cast<BundleType>(7), kPassword, &error).empty());

    // BaseFWX would read the first from a file and strip the second prefix.
    for (const std::string& reference : {"file://" + std::string(kPasswordMin, 'r'),
                                         "password://" + std::string(kPasswordMin, 'r')}) {
        assert(seal_share(Document(), BundleType::Backup, reference, &error).empty());
        assert(error.find("file:// or password://") != std::string::npos);
        assert(!open_share(sealed, reference, &error));
        assert(error.find("file:// or password://") != std::string::npos);
    }
    const std::string embedded = "my file://" + std::string(kPasswordMin, 'e');
    const auto embedded_sealed = seal_share(Document(), BundleType::Backup, embedded, &error);
    assert(!embedded_sealed.empty());
    assert(open_share(embedded_sealed, embedded, &error));

    nlohmann::json huge{{"blob", std::string(kMaxShareFileBytes, 'x')}};
    assert(seal_share(huge, BundleType::Backup, kPassword, &error).empty());
    assert(error.find("16 MiB") != std::string::npos);
    std::vector<std::uint8_t> oversized = sealed;
    oversized.resize(kMaxShareFileBytes + 1U, 0U);
    assert(!open_share(oversized, kPassword, &error));

    // A correct header over a payload that is not JSON. The destination is
    // sized first: GCC 11 misreports vector::insert after a fixed header as an
    // overread in optimized -Werror builds.
    const auto garbage = basefwx::fwxaes::EncryptRaw(
        std::vector<std::uint8_t>{'n', 'o', 't', ' ', 'j', 's', 'o', 'n'}, kPassword);
    std::vector<std::uint8_t> not_json(12U + garbage.size());
    std::copy(sealed.begin(), sealed.begin() + 12, not_json.begin());
    std::copy(garbage.begin(), garbage.end(), not_json.begin() + 12);
    assert(!open_share(not_json, kPassword, &error));
    assert(error.find("not JSON") != std::string::npos);
}

// BaseFWX maps its default "auto" KDF label through BASEFWX_USER_KDF. Sealing
// must neither honour a downgrade nor fail when the variable names a label
// BaseFWX rejects.
void test_kdf_ignores_environment() {
    assert(::setenv("BASEFWX_USER_KDF", "argon2evil", 1) == 0);
    std::string error;
    const auto sealed = seal_share(Document(), BundleType::Backup, kPassword, &error);
    assert(::unsetenv("BASEFWX_USER_KDF") == 0);
    assert(!sealed.empty());
    const auto opened = open_share(sealed, kPassword, &error);
    assert(opened && *opened == Document());
}

void test_wipe_json_strings() {
    nlohmann::json document = Document();
    wipe_json_strings(document);
    assert(document["identity"] == "");
    assert(document["server"]["host"] == "");
    assert(document["server"]["port"] == 8443);
    assert(document["pins"][0] == "" && document["pins"][1] == "");
}

void test_file_boundaries(const std::filesystem::path& root) {
    const auto destination = root / "exclusive.yss";
    const std::vector<std::uint8_t> contents{'y', 's', 's'};
    std::string error;
    assert(write_share_file_exclusive(destination, contents, &error));
    assert(error.empty());
    struct stat info {};
    assert(::lstat(destination.c_str(), &info) == 0);
    assert(S_ISREG(info.st_mode) && (info.st_mode & 07777) == 0600);
    assert(info.st_uid == ::geteuid() && info.st_nlink == 1);

    const std::vector<std::uint8_t> replacement{'x'};
    assert(!write_share_file_exclusive(destination, replacement, &error));
    std::vector<std::uint8_t> read_back;
    assert(read_share_file(destination, &read_back, &error));
    assert(read_back == contents);

    const auto victim = root / "share-victim";
    write_text(victim, "unchanged");
    const auto link = root / "share-link.yss";
    std::filesystem::create_symlink(victim, link);
    assert(!write_share_file_exclusive(link, replacement, &error));
    assert(!read_share_file(link, &read_back, &error));
    assert(read_text(victim) == "unchanged");

    const auto oversized = root / "oversized.yss";
    write_text(oversized, std::string(kMaxShareFileBytes + 1U, 'x'));
    assert(!read_share_file(oversized, &read_back, &error));
    assert(error.find("size limit") != std::string::npos);
    assert(read_back.empty());

    const auto refused_output = root / "oversized-output.yss";
    const std::vector<std::uint8_t> oversized_contents(kMaxShareFileBytes + 1U, 0U);
    assert(!write_share_file_exclusive(refused_output, oversized_contents, &error));
    assert(!std::filesystem::exists(refused_output));

    // A write the file-size limit cuts short leaves no partial file.
    const auto partial_output = root / "partial-output.yss";
    const pid_t child = ::fork();
    assert(child >= 0);
    if (child == 0) {
        (void)std::signal(SIGXFSZ, SIG_IGN);
        const rlimit limit{1, 1};
        if (::setrlimit(RLIMIT_FSIZE, &limit) != 0) ::_exit(2);
        std::string child_error;
        const std::vector<std::uint8_t> child_contents(4096U, 0x5aU);
        const bool written =
            write_share_file_exclusive(partial_output, child_contents, &child_error);
        ::_exit(!written && !child_error.empty() && !std::filesystem::exists(partial_output)
                    ? 0
                    : 3);
    }
    int status = 0;
    assert(::waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(!std::filesystem::exists(partial_output));
}

}  // namespace

int main() {
    test_round_trip_and_header();
    test_password_and_size_rules();
    test_kdf_ignores_environment();
    test_wipe_json_strings();
    TempDirectory temp;
    test_file_boundaries(temp.path());
    return 0;
}
