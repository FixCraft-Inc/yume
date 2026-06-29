/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/filter/ip_filter.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

using yume::server::FilterAction;
using yume::server::FilterListSpec;
using yume::server::FilterMode;
using yume::server::IpFilter;

std::filesystem::path make_temp_dir() {
    auto dir = std::filesystem::temp_directory_path() /
        ("yume-ip-filter-test-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(dir);
    return dir;
}

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
    test_geolite_mmdb_archive_if_available();
    return 0;
}
