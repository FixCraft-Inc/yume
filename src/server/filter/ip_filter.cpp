/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/filter/ip_filter.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <sstream>
#include <stdexcept>
#include <string_view>

#include <nlohmann/json.hpp>

namespace yume::server {

namespace {

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string upper_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return value;
}

std::uint16_t read_u16_le(const std::vector<std::uint8_t>& data, std::size_t& offset) {
    if (offset + 2 > data.size()) throw std::runtime_error("truncated u16");
    const std::uint16_t value = static_cast<std::uint16_t>(
        data[offset] | (static_cast<std::uint16_t>(data[offset + 1]) << 8));
    offset += 2;
    return value;
}

std::uint32_t read_u32_le(const std::vector<std::uint8_t>& data, std::size_t& offset) {
    if (offset + 4 > data.size()) throw std::runtime_error("truncated u32");
    const std::uint32_t value =
        static_cast<std::uint32_t>(data[offset]) |
        (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
        (static_cast<std::uint32_t>(data[offset + 2]) << 16) |
        (static_cast<std::uint32_t>(data[offset + 3]) << 24);
    offset += 4;
    return value;
}

std::uint32_t read_u32_be(std::istream& in, bool* ok) {
    std::array<unsigned char, 4> b{};
    if (!in.read(reinterpret_cast<char*>(b.data()), 4)) {
        *ok = false;
        return 0;
    }
    return (static_cast<std::uint32_t>(b[0]) << 24) |
           (static_cast<std::uint32_t>(b[1]) << 16) |
           (static_cast<std::uint32_t>(b[2]) << 8) |
           static_cast<std::uint32_t>(b[3]);
}

std::uint32_t ipv4_to_u32(const boost::asio::ip::address_v4& address) {
    const auto b = address.to_bytes();
    return (static_cast<std::uint32_t>(b[0]) << 24) |
           (static_cast<std::uint32_t>(b[1]) << 16) |
           (static_cast<std::uint32_t>(b[2]) << 8) |
           static_cast<std::uint32_t>(b[3]);
}

std::optional<boost::asio::ip::address> parse_address(const std::string& text) {
    boost::system::error_code ec;
    auto address = boost::asio::ip::make_address(text, ec);
    if (ec) return std::nullopt;
    return address;
}

std::array<std::uint8_t, 16> ipv6_bytes(const boost::asio::ip::address_v6& address) {
    const auto b = address.to_bytes();
    std::array<std::uint8_t, 16> out{};
    std::copy(b.begin(), b.end(), out.begin());
    return out;
}

int common_prefix32(std::uint32_t a, std::uint32_t b) {
    const std::uint32_t diff = a ^ b;
    if (diff == 0) return 32;
    int bits = 0;
    for (int i = 31; i >= 0; --i) {
        if ((diff & (1u << i)) != 0) break;
        ++bits;
    }
    return bits;
}

int common_prefix128(const std::array<std::uint8_t, 16>& a,
                     const std::array<std::uint8_t, 16>& b) {
    int bits = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        const std::uint8_t diff = static_cast<std::uint8_t>(a[i] ^ b[i]);
        if (diff == 0) {
            bits += 8;
            continue;
        }
        for (int bit = 7; bit >= 0; --bit) {
            if ((diff & (1u << bit)) != 0) return bits;
            ++bits;
        }
    }
    return bits;
}

bool ipv6_less(const std::array<std::uint8_t, 16>& lhs,
               const std::array<std::uint8_t, 16>& rhs) {
    return std::lexicographical_compare(lhs.begin(), lhs.end(), rhs.begin(), rhs.end());
}

void apply_prefix_v6(std::array<std::uint8_t, 16>& start,
                     std::array<std::uint8_t, 16>& end,
                     int prefix) {
    for (int bit = prefix; bit < 128; ++bit) {
        const int byte = bit / 8;
        const int shift = 7 - (bit % 8);
        start[byte] = static_cast<std::uint8_t>(start[byte] & ~(1u << shift));
        end[byte] = static_cast<std::uint8_t>(end[byte] | (1u << shift));
    }
}

std::string shell_quote(const std::filesystem::path& path) {
    std::string s = path.string();
    std::string out = "'";
    for (char c : s) {
        if (c == '\'') {
            out += "'\\''";
        } else {
            out.push_back(c);
        }
    }
    out += "'";
    return out;
}

bool safe_archive_member(const std::string& name) {
    if (name.empty() || name.front() == '/' || name.find('\\') != std::string::npos) {
        return false;
    }
    std::filesystem::path p(name);
    for (const auto& part : p) {
        if (part == "..") return false;
    }
    return true;
}

std::vector<std::filesystem::path> default_country_dirs() {
    return {
        std::filesystem::path("src/gui/assets/geoip"),
        std::filesystem::path("../src/gui/assets/geoip"),
        std::filesystem::path("/usr/share/yume-gui/geoip"),
        std::filesystem::path("/usr/local/share/yume-gui/geoip"),
    };
}

std::optional<std::filesystem::path> find_mmdb_country_file(const std::filesystem::path& dir) {
    namespace fs = std::filesystem;
    std::error_code ec;
    if (fs::is_regular_file(dir, ec) && lower_ascii(dir.extension().string()) == ".mmdb") {
        return dir;
    }
    if (!fs::is_directory(dir, ec)) {
        return std::nullopt;
    }
    for (auto it = fs::recursive_directory_iterator(dir, ec); !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
        if (!it->is_regular_file(ec)) continue;
        const auto filename = lower_ascii(it->path().filename().string());
        if (filename == "geolitecountry.mmdb" ||
            filename == "geolite2-country.mmdb" ||
            lower_ascii(it->path().extension().string()) == ".mmdb") {
            return it->path();
        }
    }
    return std::nullopt;
}

std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open " + path.string());
    in.seekg(0, std::ios::end);
    const auto end = in.tellg();
    if (end < 0) throw std::runtime_error("cannot size " + path.string());
    in.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(end));
    if (!data.empty() && !in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()))) {
        throw std::runtime_error("cannot read " + path.string());
    }
    return data;
}

void maybe_replace_best(std::optional<FilterDecision>& best, FilterDecision candidate) {
    if (!best.has_value() ||
        candidate.specificity > best->specificity ||
        (candidate.specificity == best->specificity &&
         candidate.action == FilterAction::Deny &&
         best->action == FilterAction::Allow)) {
        best = std::move(candidate);
    }
}

}  // namespace

IpFilter::~IpFilter() {
    cleanup_runtime_dir();
}

void IpFilter::configure(FilterMode client_mode, FilterMode egress_mode) {
    client_mode_ = client_mode;
    egress_mode_ = egress_mode;
}

std::optional<FilterMode> IpFilter::parse_mode(const std::string& text) {
    const std::string value = lower_ascii(text);
    if (value == "blacklist" || value == "denylist") return FilterMode::Blacklist;
    if (value == "whitelist" || value == "allowlist") return FilterMode::Whitelist;
    return std::nullopt;
}

std::optional<FilterListSpec> IpFilter::parse_list_spec(const std::string& text, std::string* error) {
    const auto first = text.find(':');
    const auto second = first == std::string::npos ? std::string::npos : text.find(':', first + 1);
    if (first == std::string::npos || second == std::string::npos || second + 1 >= text.size()) {
        if (error) *error = "expected <client|egress|both>:<allow|deny>:<path>";
        return std::nullopt;
    }
    const std::string plane_text = lower_ascii(text.substr(0, first));
    const std::string action_text = lower_ascii(text.substr(first + 1, second - first - 1));
    FilterListSpec spec;
    if (plane_text == "client") {
        spec.planes = kFilterPlaneClient;
    } else if (plane_text == "egress") {
        spec.planes = kFilterPlaneEgress;
    } else if (plane_text == "both") {
        spec.planes = kFilterPlaneClient | kFilterPlaneEgress;
    } else {
        if (error) *error = "unknown filter plane: " + plane_text;
        return std::nullopt;
    }
    if (action_text == "allow" || action_text == "whitelist") {
        spec.action = FilterAction::Allow;
    } else if (action_text == "deny" || action_text == "block" || action_text == "blacklist") {
        spec.action = FilterAction::Deny;
    } else {
        if (error) *error = "unknown filter action: " + action_text;
        return std::nullopt;
    }
    spec.path = text.substr(second + 1);
    return spec;
}

bool IpFilter::load(const std::vector<FilterListSpec>& specs,
                    const std::string& geolite_archive,
                    std::uint32_t memory_mib,
                    std::string* error) {
    if (!load_geolite(geolite_archive, error)) {
        return false;
    }
    const std::size_t cap = static_cast<std::size_t>(memory_mib) * 1024u * 1024u;
    if (memory_mib > 0 && estimated_memory_bytes() > cap) {
        if (error) *error = "filter memory cap exceeded";
        return false;
    }
    for (const auto& spec : specs) {
        if (!load_list_path(spec, memory_mib, error)) {
            return false;
        }
        ++lists_loaded_;
        if (memory_mib > 0 && estimated_memory_bytes() > cap) {
            if (error) *error = "filter memory cap exceeded";
            return false;
        }
    }
    return true;
}

bool IpFilter::active() const {
    return lists_loaded_ > 0 ||
           client_mode_ == FilterMode::Whitelist ||
           egress_mode_ == FilterMode::Whitelist;
}

std::string IpFilter::summary() const {
    return "lists=" + std::to_string(lists_loaded_) +
           " client_rules=" + std::to_string(client_.ipv4.size() + client_.ipv6.size() + client_.countries.size()) +
           " egress_rules=" + std::to_string(egress_.ipv4.size() + egress_.ipv6.size() + egress_.countries.size()) +
           " country_db=" + std::string(geolite_loaded_ ? "on" : "off");
}

FilterDecision IpFilter::check_client(const boost::asio::ip::address& address) const {
    return check(address, client_, client_mode_);
}

FilterDecision IpFilter::check_egress(const boost::asio::ip::address& address) const {
    return check(address, egress_, egress_mode_);
}

FilterDecision IpFilter::check(const boost::asio::ip::address& address,
                               const PlaneRules& rules,
                               FilterMode mode) const {
    std::optional<FilterDecision> best;
    if (address.is_v4()) {
        const std::uint32_t ip = ipv4_to_u32(address.to_v4());
        for (const auto& rule : rules.ipv4) {
            if (ip >= rule.start && ip <= rule.end) {
                maybe_replace_best(best, FilterDecision{
                    rule.action == FilterAction::Allow,
                    true,
                    rule.action,
                    rule.specificity,
                    rule.source,
                });
            }
        }
        if (auto iso = lookup_country(ip); iso.has_value()) {
            for (const auto& rule : rules.countries) {
                if (rule.iso == *iso) {
                    maybe_replace_best(best, FilterDecision{
                        rule.action == FilterAction::Allow,
                        true,
                        rule.action,
                        0,
                        rule.source,
                    });
                }
            }
        }
    } else if (address.is_v6()) {
        const auto ip = ipv6_bytes(address.to_v6());
        for (const auto& rule : rules.ipv6) {
            if (!ipv6_less(ip, rule.start) && !ipv6_less(rule.end, ip)) {
                maybe_replace_best(best, FilterDecision{
                    rule.action == FilterAction::Allow,
                    true,
                    rule.action,
                    rule.specificity,
                    rule.source,
                });
            }
        }
    }
    if (best.has_value()) {
        best->allowed = best->action == FilterAction::Allow;
        return *best;
    }
    if (mode == FilterMode::Whitelist) {
        return FilterDecision{false, false, FilterAction::Deny, -1, "whitelist default deny"};
    }
    return FilterDecision{true, false, FilterAction::Allow, -1, "blacklist default allow"};
}

bool IpFilter::load_list_path(const FilterListSpec& spec, std::uint32_t memory_mib, std::string* error) {
    namespace fs = std::filesystem;
    const fs::path path(spec.path);
    std::error_code ec;
    if (!fs::exists(path, ec)) {
        if (error) *error = "filter list not found: " + spec.path;
        return false;
    }
    const auto suffix = lower_ascii(path.string());
    if (suffix.size() >= 7 && suffix.substr(suffix.size() - 7) == ".tar.xz") {
        auto dir = extract_archive(path, "filter-list", error);
        if (dir.empty()) return false;
        bool loaded = false;
        for (auto it = fs::recursive_directory_iterator(dir, ec); !ec && it != fs::recursive_directory_iterator(); it.increment(ec)) {
            if (!it->is_regular_file(ec)) continue;
            const std::string name = lower_ascii(it->path().filename().string());
            if (name == "vpn_db.bin") {
                if (!load_vpdb(it->path(), spec, error)) return false;
                loaded = true;
            } else if (it->path().extension() == ".json") {
                if (!load_custom_json(it->path(), spec, error)) return false;
                loaded = true;
            }
            const std::size_t cap = static_cast<std::size_t>(memory_mib) * 1024u * 1024u;
            if (memory_mib > 0 && estimated_memory_bytes() > cap) {
                if (error) *error = "filter memory cap exceeded while loading " + spec.path;
                return false;
            }
        }
        if (!loaded) {
            if (error) *error = "filter archive contains no vpn_db.bin or .json list: " + spec.path;
            return false;
        }
        return true;
    }
    if (lower_ascii(path.filename().string()) == "vpn_db.bin") {
        return load_vpdb(path, spec, error);
    }
    return load_custom_json(path, spec, error);
}

bool IpFilter::load_custom_json(const std::filesystem::path& path,
                                const FilterListSpec& spec,
                                std::string* error) {
    try {
        std::ifstream in(path);
        if (!in) throw std::runtime_error("cannot open " + path.string());
        nlohmann::json json;
        in >> json;
        if (auto ips = json.find("ips"); ips != json.end() && ips->is_array()) {
            for (const auto& item : *ips) {
                if (item.is_string()) {
                    add_ip_rule(spec.planes, spec.action, item.get<std::string>(), path.filename().string());
                }
            }
        }
        if (auto countries = json.find("countries"); countries != json.end() && countries->is_array()) {
            for (const auto& item : *countries) {
                if (item.is_string()) {
                    add_country_rule(spec.planes, spec.action, item.get<std::string>(), path.filename().string());
                }
            }
        }
    } catch (const std::exception& ex) {
        if (error) *error = "failed to load filter JSON " + path.string() + ": " + ex.what();
        return false;
    }
    return true;
}

bool IpFilter::load_vpdb(const std::filesystem::path& path,
                         const FilterListSpec& spec,
                         std::string* error) {
    try {
        const auto data = read_file_bytes(path);
        std::size_t offset = 0;
        if (data.size() < 24 || std::string_view(reinterpret_cast<const char*>(data.data()), 4) != "VPDB") {
            throw std::runtime_error("unsupported VPN DB magic");
        }
        offset = 4;
        const std::uint8_t version = data[offset++];
        offset += 3;
        if (version != 1) {
            throw std::runtime_error("unsupported VPN DB version " + std::to_string(version));
        }
        const auto provider_count = read_u32_le(data, offset);
        const auto ipv4_exact_count = read_u32_le(data, offset);
        const auto ipv4_range_count = read_u32_le(data, offset);
        const auto ipv6_exact_count = read_u32_le(data, offset);
        const auto ipv6_range_count = read_u32_le(data, offset);
        std::vector<std::string> providers;
        providers.reserve(provider_count);
        for (std::uint32_t i = 0; i < provider_count; ++i) {
            const auto len = read_u16_le(data, offset);
            if (offset + len > data.size()) throw std::runtime_error("truncated provider name");
            providers.emplace_back(reinterpret_cast<const char*>(data.data() + offset), len);
            offset += len;
        }
        if (providers.empty()) providers.emplace_back("unknown");
        auto provider_name = [&](std::uint16_t idx) -> std::string {
            return "vpn:" + providers[std::min<std::size_t>(idx, providers.size() - 1)];
        };
        for (std::uint32_t i = 0; i < ipv4_exact_count; ++i) {
            const auto ip = read_u32_le(data, offset);
            const auto provider = read_u16_le(data, offset);
            add_ipv4_rule(spec.planes, spec.action, ip, ip, 32, provider_name(provider));
        }
        for (std::uint32_t i = 0; i < ipv4_range_count; ++i) {
            const auto start = read_u32_le(data, offset);
            const auto end = read_u32_le(data, offset);
            const auto provider = read_u16_le(data, offset);
            add_ipv4_rule(spec.planes, spec.action, start, end, common_prefix32(start, end), provider_name(provider));
        }
        for (std::uint32_t i = 0; i < ipv6_exact_count; ++i) {
            if (offset + 16 > data.size()) throw std::runtime_error("truncated IPv6 exact");
            std::array<std::uint8_t, 16> ip{};
            std::copy(data.begin() + static_cast<std::ptrdiff_t>(offset),
                      data.begin() + static_cast<std::ptrdiff_t>(offset + 16),
                      ip.begin());
            offset += 16;
            const auto provider = read_u16_le(data, offset);
            add_ipv6_rule(spec.planes, spec.action, ip, ip, 128, provider_name(provider));
        }
        for (std::uint32_t i = 0; i < ipv6_range_count; ++i) {
            if (offset + 32 > data.size()) throw std::runtime_error("truncated IPv6 range");
            std::array<std::uint8_t, 16> start{};
            std::array<std::uint8_t, 16> end{};
            std::copy(data.begin() + static_cast<std::ptrdiff_t>(offset),
                      data.begin() + static_cast<std::ptrdiff_t>(offset + 16),
                      start.begin());
            offset += 16;
            std::copy(data.begin() + static_cast<std::ptrdiff_t>(offset),
                      data.begin() + static_cast<std::ptrdiff_t>(offset + 16),
                      end.begin());
            offset += 16;
            const auto provider = read_u16_le(data, offset);
            add_ipv6_rule(spec.planes, spec.action, start, end, common_prefix128(start, end), provider_name(provider));
        }
    } catch (const std::exception& ex) {
        if (error) *error = "failed to load VPDB " + path.string() + ": " + ex.what();
        return false;
    }
    return true;
}

bool IpFilter::load_geolite(const std::string& geolite_archive, std::string* error) {
    namespace fs = std::filesystem;
    if (!geolite_archive.empty()) {
        fs::path path(geolite_archive);
        if (!fs::exists(path)) {
            if (error) *error = "GeoLite archive not found: " + geolite_archive;
            return false;
        }
        fs::path dir = path;
        if (lower_ascii(path.string()).size() >= 7 &&
            lower_ascii(path.string()).substr(lower_ascii(path.string()).size() - 7) == ".tar.xz") {
            dir = extract_archive(path, "geolite", error);
            if (dir.empty()) return false;
        }
        if (fs::is_directory(dir) && load_compact_country_db(dir)) {
            return true;
        }
        if (fs::is_regular_file(dir) && dir.filename() == "geoip_country_ipv4.db") {
            return load_compact_country_db(dir.parent_path());
        }
        if (auto mmdb = find_mmdb_country_file(dir); mmdb.has_value()) {
            return load_mmdb_country_db(*mmdb, error);
        }
        if (error) *error = "GeoLite input contains no usable geoip_country_ipv4.db or GeoLiteCountry.mmdb";
        return false;
    }
    for (const auto& dir : default_country_dirs()) {
        if (load_compact_country_db(dir)) {
            return true;
        }
    }
    return true;
}

bool IpFilter::load_compact_country_db(const std::filesystem::path& dir) {
    std::ifstream ranges(dir / "geoip_country_ipv4.db", std::ios::binary);
    if (!ranges) return false;
    char magic[4]{};
    if (!ranges.read(magic, 4)) return false;
    if (magic[0] != 'Y' || magic[1] != 'G' || magic[2] != 'C' || magic[3] != '1') {
        return false;
    }
    bool ok = true;
    const auto count = read_u32_be(ranges, &ok);
    if (!ok || count == 0) return false;
    std::vector<CountryRange> loaded;
    loaded.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        const auto start = read_u32_be(ranges, &ok);
        const auto end = read_u32_be(ranges, &ok);
        char iso[2]{};
        if (!ok || !ranges.read(iso, 2)) return false;
        loaded.push_back(CountryRange{start, end, std::string(iso, 2)});
    }
    countries_ = std::move(loaded);
    geolite_loaded_ = true;
    return true;
}

std::filesystem::path IpFilter::extract_archive(const std::filesystem::path& archive,
                                                const std::string& label,
                                                std::string* error) {
    namespace fs = std::filesystem;
    try {
        if (runtime_dir_.empty()) {
            const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
            runtime_dir_ = fs::temp_directory_path() / ("yume-filter-" + std::to_string(stamp));
            fs::create_directories(runtime_dir_);
        }
        const fs::path target = runtime_dir_ / (label + "-" + std::to_string(lists_loaded_ + 1));
        fs::create_directories(target);

        const fs::path list_path = target / ".members";
        std::string list_cmd = "tar -tf " + shell_quote(archive) + " > " + shell_quote(list_path);
        if (std::system(list_cmd.c_str()) != 0) {
            throw std::runtime_error("tar list failed");
        }
        std::ifstream members(list_path);
        std::string member;
        while (std::getline(members, member)) {
            if (!safe_archive_member(member)) {
                throw std::runtime_error("unsafe archive member: " + member);
            }
        }
        std::string extract_cmd = "tar -xJf " + shell_quote(archive) + " -C " + shell_quote(target);
        if (std::system(extract_cmd.c_str()) != 0) {
            throw std::runtime_error("tar extract failed");
        }
        return target;
    } catch (const std::exception& ex) {
        if (error) *error = "failed to extract " + archive.string() + ": " + ex.what();
        return {};
    }
}

void IpFilter::add_ip_rule(std::uint8_t planes,
                           FilterAction action,
                           const std::string& text,
                           const std::string& source) {
    const auto slash = text.find('/');
    const std::string address_text = slash == std::string::npos ? text : text.substr(0, slash);
    auto parsed = parse_address(address_text);
    if (!parsed.has_value()) return;
    if (parsed->is_v4()) {
        int prefix = 32;
        if (slash != std::string::npos) {
            prefix = std::clamp(std::stoi(text.substr(slash + 1)), 0, 32);
        }
        const std::uint32_t ip = ipv4_to_u32(parsed->to_v4());
        const std::uint32_t mask = prefix == 0 ? 0u : (0xffffffffu << (32 - prefix));
        const std::uint32_t start = ip & mask;
        const std::uint32_t end = start | ~mask;
        add_ipv4_rule(planes, action, start, end, prefix, source);
        return;
    }
    int prefix = 128;
    if (slash != std::string::npos) {
        prefix = std::clamp(std::stoi(text.substr(slash + 1)), 0, 128);
    }
    auto start = ipv6_bytes(parsed->to_v6());
    auto end = start;
    apply_prefix_v6(start, end, prefix);
    add_ipv6_rule(planes, action, start, end, prefix, source);
}

void IpFilter::add_ipv4_rule(std::uint8_t planes,
                             FilterAction action,
                             std::uint32_t start,
                             std::uint32_t end,
                             int specificity,
                             const std::string& source) {
    Ipv4RangeRule rule{std::min(start, end), std::max(start, end), specificity, action, source};
    if ((planes & kFilterPlaneClient) != 0) client_.ipv4.push_back(rule);
    if ((planes & kFilterPlaneEgress) != 0) egress_.ipv4.push_back(rule);
}

void IpFilter::add_ipv6_rule(std::uint8_t planes,
                             FilterAction action,
                             const std::array<std::uint8_t, 16>& start,
                             const std::array<std::uint8_t, 16>& end,
                             int specificity,
                             const std::string& source) {
    Ipv6RangeRule rule{start, end, specificity, action, source};
    if (ipv6_less(rule.end, rule.start)) {
        std::swap(rule.start, rule.end);
    }
    if ((planes & kFilterPlaneClient) != 0) client_.ipv6.push_back(rule);
    if ((planes & kFilterPlaneEgress) != 0) egress_.ipv6.push_back(rule);
}

void IpFilter::add_country_rule(std::uint8_t planes,
                                FilterAction action,
                                const std::string& iso,
                                const std::string& source) {
    std::string normalized = upper_ascii(iso);
    if (normalized.size() != 2) return;
    CountryRule rule{normalized, action, source};
    if ((planes & kFilterPlaneClient) != 0) client_.countries.push_back(rule);
    if ((planes & kFilterPlaneEgress) != 0) egress_.countries.push_back(rule);
}

std::optional<std::string> IpFilter::lookup_country(std::uint32_t ipv4) const {
    if (!countries_.empty()) {
        std::size_t low = 0;
        std::size_t high = countries_.size();
        while (low < high) {
            const std::size_t mid = low + (high - low) / 2;
            const auto& range = countries_[mid];
            if (ipv4 < range.start) {
                high = mid;
            } else if (ipv4 > range.end) {
                low = mid + 1;
            } else {
                return range.iso;
            }
        }
    }
    return lookup_mmdb_country(ipv4);
}

std::size_t IpFilter::estimated_memory_bytes() const {
    return client_.ipv4.size() * sizeof(Ipv4RangeRule) +
           egress_.ipv4.size() * sizeof(Ipv4RangeRule) +
           client_.ipv6.size() * sizeof(Ipv6RangeRule) +
           egress_.ipv6.size() * sizeof(Ipv6RangeRule) +
           client_.countries.size() * sizeof(CountryRule) +
           egress_.countries.size() * sizeof(CountryRule) +
           countries_.size() * sizeof(CountryRange) +
           mmdb_data_.size();
}

void IpFilter::cleanup_runtime_dir() {
    if (runtime_dir_.empty()) return;
    std::error_code ec;
    std::filesystem::remove_all(runtime_dir_, ec);
    runtime_dir_.clear();
}

}  // namespace yume::server
