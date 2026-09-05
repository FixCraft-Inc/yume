/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/filter/ip_filter.hpp"

#include <cassert>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

using yume::server::FilterAction;
using yume::server::FilterListSpec;
using yume::server::FilterMode;
using yume::server::IpFilter;

std::filesystem::path make_temp_dir() {
#if defined(_WIN32)
    auto dir = std::filesystem::temp_directory_path() /
        ("yume-ip-filter-test-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(dir);
    return dir;
#else
    std::string pattern =
        (std::filesystem::temp_directory_path() /
         "yume-ip-filter-test-XXXXXX").string();
    const char* created = ::mkdtemp(pattern.data());
    assert(created != nullptr);
    return created;
#endif
}

#if !defined(_WIN32)

std::string shell_quote(const std::filesystem::path& path) {
    std::string result{"'"};
    for (const char ch : path.string()) {
        if (ch == '\'') {
            result += "'\\''";
        } else {
            result.push_back(ch);
        }
    }
    result.push_back('\'');
    return result;
}

class ScopedEnvironment final {
public:
    ScopedEnvironment(const char* name, const std::string& value)
        : name_(name) {
        if (const char* previous = std::getenv(name); previous != nullptr) {
            previous_ = previous;
        }
        assert(::setenv(name_.c_str(), value.c_str(), 1) == 0);
    }

    ScopedEnvironment(const ScopedEnvironment&) = delete;
    ScopedEnvironment& operator=(const ScopedEnvironment&) = delete;

    ~ScopedEnvironment() {
        if (previous_.has_value()) {
            assert(::setenv(name_.c_str(), previous_->c_str(), 1) == 0);
        } else {
            assert(::unsetenv(name_.c_str()) == 0);
        }
    }

private:
    std::string name_;
    std::optional<std::string> previous_;
};

class ScopedUmask final {
public:
    explicit ScopedUmask(mode_t value) noexcept : previous_(::umask(value)) {}
    ScopedUmask(const ScopedUmask&) = delete;
    ScopedUmask& operator=(const ScopedUmask&) = delete;
    ~ScopedUmask() { (void)::umask(previous_); }

private:
    mode_t previous_;
};

void create_tar_xz(const std::filesystem::path& archive,
                   const std::filesystem::path& source) {
    const std::string command =
        "TAR_OPTIONS='' LC_ALL=C tar -cJf " + shell_quote(archive) +
        " -C " + shell_quote(source) + " .";
    assert(std::system(command.c_str()) == 0);
}

void make_owner_executable(const std::filesystem::path& path) {
    std::filesystem::permissions(
        path,
        std::filesystem::perms::owner_read |
            std::filesystem::perms::owner_write |
            std::filesystem::perms::owner_exec,
        std::filesystem::perm_options::replace);
}

std::filesystem::path only_directory_entry(
    const std::filesystem::path& directory) {
    std::filesystem::path result;
    std::size_t count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        result = entry.path();
        ++count;
    }
    assert(count == 1);
    assert(std::filesystem::is_directory(result));
    return result;
}

#endif

boost::asio::ip::address ip(const char* text) {
    return boost::asio::ip::make_address(text);
}

void write_text(const std::filesystem::path& path, const std::string& text) {
    std::ofstream out(path);
    assert(out);
    out << text;
}

void append_u16_le(std::vector<unsigned char>& out, std::uint16_t value) {
    out.push_back(static_cast<unsigned char>(value & 0xffu));
    out.push_back(static_cast<unsigned char>((value >> 8) & 0xffu));
}

void append_u32_le(std::vector<unsigned char>& out, std::uint32_t value) {
    out.push_back(static_cast<unsigned char>(value & 0xffu));
    out.push_back(static_cast<unsigned char>((value >> 8) & 0xffu));
    out.push_back(static_cast<unsigned char>((value >> 16) & 0xffu));
    out.push_back(static_cast<unsigned char>((value >> 24) & 0xffu));
}

void append_u32_be(std::vector<unsigned char>& out, std::uint32_t value) {
    out.push_back(static_cast<unsigned char>((value >> 24) & 0xffu));
    out.push_back(static_cast<unsigned char>((value >> 16) & 0xffu));
    out.push_back(static_cast<unsigned char>((value >> 8) & 0xffu));
    out.push_back(static_cast<unsigned char>(value & 0xffu));
}

void write_bytes(const std::filesystem::path& path, const std::vector<unsigned char>& data) {
    std::ofstream out(path, std::ios::binary);
    assert(out);
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

void write_country_db(const std::filesystem::path& dir) {
    std::vector<unsigned char> data{'Y', 'G', 'C', '1'};
    append_u32_be(data, 1);
    append_u32_be(data, 0x08080800u);
    append_u32_be(data, 0x080808ffu);
    data.push_back('U');
    data.push_back('S');
    write_bytes(dir / "geoip_country_ipv4.db", data);
}

void write_vpdb(const std::filesystem::path& path) {
    std::vector<unsigned char> data{'V', 'P', 'D', 'B'};
    data.push_back(1);
    data.push_back(0);
    data.push_back(0);
    data.push_back(0);
    append_u32_le(data, 1);  // providers
    append_u32_le(data, 1);  // IPv4 exact
    append_u32_le(data, 1);  // IPv4 ranges
    append_u32_le(data, 0);  // IPv6 exact
    append_u32_le(data, 0);  // IPv6 ranges
    const std::string provider = "testvpn";
    append_u16_le(data, static_cast<std::uint16_t>(provider.size()));
    data.insert(data.end(), provider.begin(), provider.end());
    append_u32_le(data, 0x0a000005u);
    append_u16_le(data, 0);
    append_u32_le(data, 0x0a000100u);
    append_u32_le(data, 0x0a0001ffu);
    append_u16_le(data, 0);
    write_bytes(path, data);
}

void test_conflict_priority_and_country() {
    const auto dir = make_temp_dir();
    write_country_db(dir);
    const auto deny = dir / "deny.json";
    const auto allow = dir / "allow.json";
    write_text(deny, R"({"ips":["203.0.113.0/24"],"countries":["US"]})");
    write_text(allow, R"({"ips":["203.0.113.7","8.8.8.8"]})");

    IpFilter filter;
    filter.configure(FilterMode::Blacklist, FilterMode::Blacklist);
    std::string error;
    assert(filter.load({
        {yume::server::kFilterPlaneEgress, FilterAction::Deny, deny.string()},
        {yume::server::kFilterPlaneEgress, FilterAction::Allow, allow.string()},
    }, (dir / "geoip_country_ipv4.db").string(), 64, &error));

    assert(!filter.check_egress(ip("203.0.113.8")).allowed);
    assert(filter.check_egress(ip("203.0.113.7")).allowed);
    assert(!filter.check_egress(ip("8.8.8.9")).allowed);
    assert(filter.check_egress(ip("8.8.8.8")).allowed);
    std::filesystem::remove_all(dir);
}

void test_equal_specificity_deny_wins() {
    const auto dir = make_temp_dir();
    const auto allow = dir / "allow.json";
    const auto deny = dir / "deny.json";
    write_text(allow, R"({"ips":["198.51.100.10"]})");
    write_text(deny, R"({"ips":["198.51.100.10"]})");

    IpFilter filter;
    filter.configure(FilterMode::Blacklist, FilterMode::Blacklist);
    std::string error;
    assert(filter.load({
        {yume::server::kFilterPlaneEgress, FilterAction::Allow, allow.string()},
        {yume::server::kFilterPlaneEgress, FilterAction::Deny, deny.string()},
    }, "", 64, &error));
    assert(!filter.check_egress(ip("198.51.100.10")).allowed);
    std::filesystem::remove_all(dir);
}

void test_whitelist_default_deny() {
    IpFilter filter;
    filter.configure(FilterMode::Whitelist, FilterMode::Blacklist);
    std::string error;
    assert(filter.load({}, "", 64, &error));
    assert(!filter.check_client(ip("1.1.1.1")).allowed);
    assert(filter.check_egress(ip("1.1.1.1")).allowed);
}

void test_vpdb_v1() {
    const auto dir = make_temp_dir();
    const auto vpdb = dir / "vpn_db.bin";
    write_vpdb(vpdb);

    IpFilter filter;
    filter.configure(FilterMode::Blacklist, FilterMode::Blacklist);
    std::string error;
    assert(filter.load({
        {static_cast<std::uint8_t>(yume::server::kFilterPlaneClient | yume::server::kFilterPlaneEgress),
         FilterAction::Deny,
         vpdb.string()},
    }, "", 64, &error));
    assert(!filter.check_client(ip("10.0.0.5")).allowed);
    assert(!filter.check_egress(ip("10.0.1.100")).allowed);
    assert(filter.check_egress(ip("10.0.2.1")).allowed);
    std::filesystem::remove_all(dir);
}

void test_archive_uses_private_runtime_directory_and_cleans_up() {
#if !defined(_WIN32)
    const auto dir = make_temp_dir();
    const auto source = dir / "source";
    const auto runtime_parent = dir / "runtime";
    std::filesystem::create_directories(source);
    std::filesystem::create_directories(runtime_parent);
    write_text(source / "deny.json", R"({"ips":["192.0.2.44"]})");
    const auto archive = dir / "filter.tar.xz";
    create_tar_xz(archive, source);

    {
        ScopedEnvironment temporary_directory("TMPDIR",
                                               runtime_parent.string());
        {
            ScopedUmask permissive_umask(0);
            IpFilter filter;
            filter.configure(FilterMode::Blacklist, FilterMode::Blacklist);
            std::string error;
            assert(filter.load({
                {yume::server::kFilterPlaneEgress,
                 FilterAction::Deny,
                 archive.string()},
            }, "", 64, &error));
            assert(!filter.check_egress(ip("192.0.2.44")).allowed);

            const auto private_directory =
                only_directory_entry(runtime_parent);
            struct stat status {};
            assert(::stat(private_directory.c_str(), &status) == 0);
            assert((status.st_mode & 0777) == 0700);
        }
        assert(std::filesystem::is_empty(runtime_parent));
    }
    std::filesystem::remove_all(dir);
#endif
}

void test_archive_rejects_symlinks_and_rolls_back() {
#if !defined(_WIN32)
    const auto dir = make_temp_dir();
    const auto source = dir / "source";
    const auto runtime_parent = dir / "runtime";
    std::filesystem::create_directories(source);
    std::filesystem::create_directories(runtime_parent);
    write_text(source / "deny.json", R"({"ips":["192.0.2.45"]})");
    std::filesystem::create_symlink("/tmp", source / "outside-link");
    const auto archive = dir / "filter-with-link.tar.xz";
    create_tar_xz(archive, source);

    {
        ScopedEnvironment temporary_directory("TMPDIR",
                                               runtime_parent.string());
        IpFilter filter;
        filter.configure(FilterMode::Blacklist, FilterMode::Blacklist);
        std::string error;
        assert(!filter.load({
            {yume::server::kFilterPlaneEgress,
             FilterAction::Deny,
             archive.string()},
        }, "", 64, &error));
        assert(error.find("unsupported archive member type 'l'") !=
               std::string::npos);
        assert(std::filesystem::is_empty(runtime_parent));
    }
    std::filesystem::remove_all(dir);
#endif
}

void test_archive_listing_escapes_and_rejects_newlines() {
#if defined(__linux__)
    const auto dir = make_temp_dir();
    const auto source = dir / "source";
    const auto runtime_parent = dir / "runtime";
    std::filesystem::create_directories(source);
    std::filesystem::create_directories(runtime_parent);
    write_text(source / "deny.json", R"({"ips":["192.0.2.47"]})");
    write_text(source / std::filesystem::path("line\nbreak"), "ignored");
    const auto archive = dir / "filter-with-newline.tar.xz";
    create_tar_xz(archive, source);

    {
        ScopedEnvironment temporary_directory("TMPDIR",
                                               runtime_parent.string());
        IpFilter filter;
        filter.configure(FilterMode::Blacklist, FilterMode::Blacklist);
        std::string error;
        assert(!filter.load({
            {yume::server::kFilterPlaneEgress,
             FilterAction::Deny,
             archive.string()},
        }, "", 64, &error));
        assert(error.find("unsafe archive member") != std::string::npos);
        assert(std::filesystem::is_empty(runtime_parent));
    }
    std::filesystem::remove_all(dir);
#endif
}

void test_archive_does_not_inherit_tar_options() {
#if defined(__linux__)
    const auto dir = make_temp_dir();
    const auto source = dir / "source";
    const auto runtime_parent = dir / "runtime";
    std::filesystem::create_directories(source);
    std::filesystem::create_directories(runtime_parent);
    write_text(source / "deny.json", R"({"ips":["192.0.2.48"]})");
    const auto archive = dir / "filter.tar.xz";
    create_tar_xz(archive, source);

    const auto marker = dir / "tar-options-executed";
    const auto checkpoint = dir / "checkpoint";
    write_text(checkpoint,
               "#!/bin/sh\n: > " + shell_quote(marker) + "\n");
    make_owner_executable(checkpoint);

    {
        ScopedEnvironment temporary_directory("TMPDIR",
                                               runtime_parent.string());
        ScopedEnvironment tar_options(
            "TAR_OPTIONS",
            "--checkpoint=1 --checkpoint-action=exec=" +
                checkpoint.string());
        IpFilter filter;
        filter.configure(FilterMode::Blacklist, FilterMode::Blacklist);
        std::string error;
        assert(filter.load({
            {yume::server::kFilterPlaneEgress,
             FilterAction::Deny,
             archive.string()},
        }, "", 64, &error));
        assert(!filter.check_egress(ip("192.0.2.48")).allowed);
        assert(!std::filesystem::exists(marker));
    }
    assert(std::filesystem::is_empty(runtime_parent));
    std::filesystem::remove_all(dir);
#endif
}

void test_archive_validation_and_extraction_use_same_snapshot() {
#if !defined(_WIN32)
    const auto dir = make_temp_dir();
    const auto first_source = dir / "first-source";
    const auto replacement_source = dir / "replacement-source";
    const auto runtime_parent = dir / "runtime";
    const auto wrapper_dir = dir / "bin";
    std::filesystem::create_directories(first_source);
    std::filesystem::create_directories(replacement_source);
    std::filesystem::create_directories(runtime_parent);
    std::filesystem::create_directories(wrapper_dir);
    write_text(first_source / "deny.json",
               R"({"ips":["192.0.2.46"]})");
    write_text(replacement_source / "deny.json",
               R"({"ips":["198.51.100.46"]})");

    const auto archive = dir / "active.tar.xz";
    const auto replacement = dir / "replacement.tar.xz";
    create_tar_xz(archive, first_source);
    create_tar_xz(replacement, replacement_source);

    const std::filesystem::path real_tar = "/usr/bin/tar";
    const std::filesystem::path real_copy = "/usr/bin/cp";
    assert(std::filesystem::is_regular_file(real_tar));
    assert(std::filesystem::is_regular_file(real_copy));
    const auto marker = dir / "archive-replaced";
    const auto wrapper = wrapper_dir / "tar";
    write_text(
        wrapper,
        "#!/bin/sh\n" + shell_quote(real_tar) + " \"$@\"\n" +
            "status=$?\n" +
            "if [ ! -e " + shell_quote(marker) + " ]; then\n" +
            "  : > " + shell_quote(marker) + " || exit 125\n" +
            "  " + shell_quote(real_copy) + " " + shell_quote(replacement) +
            " " + shell_quote(archive) + " || exit 125\n" +
            "fi\n" +
            "exit \"$status\"\n");
    make_owner_executable(wrapper);

    {
        ScopedEnvironment temporary_directory("TMPDIR",
                                               runtime_parent.string());
        const char* original_path = std::getenv("PATH");
        assert(original_path != nullptr);
        ScopedEnvironment executable_path(
            "PATH", wrapper_dir.string() + ":" + original_path);
        IpFilter filter;
        filter.configure(FilterMode::Blacklist, FilterMode::Blacklist);
        std::string error;
        assert(filter.load({
            {yume::server::kFilterPlaneEgress,
             FilterAction::Deny,
             archive.string()},
        }, "", 64, &error));
        assert(std::filesystem::is_regular_file(marker));
        assert(!filter.check_egress(ip("192.0.2.46")).allowed);
        assert(filter.check_egress(ip("198.51.100.46")).allowed);
    }
    assert(std::filesystem::is_empty(runtime_parent));
    std::filesystem::remove_all(dir);
#endif
}

void test_geolite_mmdb_archive_if_available() {
    const std::filesystem::path archive = "GeoLiteCountry.tar.xz";
    if (!std::filesystem::exists(archive)) {
        return;
    }
    const auto dir = make_temp_dir();
    const auto deny = dir / "deny-us.json";
    write_text(deny, R"({"countries":["US"]})");

    IpFilter filter;
    filter.configure(FilterMode::Blacklist, FilterMode::Blacklist);
    std::string error;
    assert(filter.load({
        {yume::server::kFilterPlaneEgress, FilterAction::Deny, deny.string()},
    }, archive.string(), 32, &error));
    assert(!filter.check_egress(ip("8.8.8.8")).allowed);
    assert(filter.check_egress(ip("1.1.1.1")).allowed);
    std::filesystem::remove_all(dir);
}

}  // namespace

int main() {
    test_conflict_priority_and_country();
    test_equal_specificity_deny_wins();
    test_whitelist_default_deny();
    test_vpdb_v1();
    test_archive_uses_private_runtime_directory_and_cleans_up();
    test_archive_rejects_symlinks_and_rolls_back();
    test_archive_listing_escapes_and_rejects_newlines();
    test_archive_does_not_inherit_tar_options();
    test_archive_validation_and_extraction_use_same_snapshot();
    test_geolite_mmdb_archive_if_available();
    return 0;
}
