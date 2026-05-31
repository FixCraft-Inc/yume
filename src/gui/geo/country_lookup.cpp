/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "geo/country_lookup.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <vector>

#if defined(__linux__)
#  include <limits.h>
#  include <unistd.h>
#elif defined(__APPLE__)
#  include <cstdint>
#  include <mach-o/dyld.h>
#endif

namespace yume::gui::geo {

namespace {

struct CountryNames {
    std::string english;
};

struct CountryDb {
    std::vector<std::uint32_t> starts;
    std::vector<std::uint32_t> ends;
    std::vector<std::uint16_t> iso_packed;
    std::unordered_map<std::string, CountryNames> names;
};

std::filesystem::path g_asset_dir;
std::once_flag g_load_once;
CountryDb g_db;
bool g_db_loaded = false;

// Reads a u32 big-endian from a binary stream; matches the
// Kotlin DataInputStream.readInt() the DB was generated against.
bool read_u32_be(std::istream& in, std::uint32_t& out) {
    std::array<unsigned char, 4> b{};
    if (!in.read(reinterpret_cast<char*>(b.data()), 4)) return false;
    out = (std::uint32_t(b[0]) << 24) |
          (std::uint32_t(b[1]) << 16) |
          (std::uint32_t(b[2]) << 8) |
          std::uint32_t(b[3]);
    return true;
}

std::string unescape(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '\\' && i + 1 < value.size()) {
            char c = value[i + 1];
            if (c == 't')      { out.push_back('\t'); ++i; continue; }
            if (c == 'n')      { out.push_back('\n'); ++i; continue; }
            if (c == '\\')     { out.push_back('\\'); ++i; continue; }
        }
        out.push_back(value[i]);
    }
    return out;
}

std::vector<std::filesystem::path> candidate_dirs() {
    std::vector<std::filesystem::path> dirs;
    if (!g_asset_dir.empty()) dirs.push_back(g_asset_dir);

#if defined(__linux__) || defined(__APPLE__)
    std::filesystem::path exe_dir;
#  if defined(__linux__)
    char buf[4096];
    ssize_t n = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = 0;
        exe_dir = std::filesystem::path(buf).parent_path();
    }
#  elif defined(__APPLE__)
    uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);
    if (size > 0) {
        std::string out(size, '\0');
        if (_NSGetExecutablePath(out.data(), &size) == 0) {
            out.resize(std::strlen(out.c_str()));
            std::error_code ec;
            std::filesystem::path resolved = std::filesystem::canonical(out, ec);
            exe_dir = (ec ? std::filesystem::path(out) : resolved).parent_path();
        }
    }
#  endif
    if (!exe_dir.empty()) {
        // Build-tree layout (binary under build/.../src/gui or build/bin).
        dirs.push_back(exe_dir / ".." / ".." / "src" / "gui" / "assets" / "geoip");
        // Installed layout (bindir = .../bin, datadir = .../share).
        dirs.push_back(exe_dir / ".." / "share" / "yume-gui" / "geoip");
        // macOS .app bundle: Yume.app/Contents/MacOS/Yume ->
        // Yume.app/Contents/Resources/geoip.
        dirs.push_back(exe_dir / ".." / "Resources" / "geoip");
        // Portable: geoip sitting next to the executable.
        dirs.push_back(exe_dir / "geoip");
    }
#endif
    dirs.push_back("/usr/share/yume-gui/geoip");
    dirs.push_back("/usr/local/share/yume-gui/geoip");
    return dirs;
}

bool try_load_from(std::filesystem::path const& dir, CountryDb& db) {
    namespace fs = std::filesystem;
    fs::path names_path  = dir / "geoip_country_names.tsv";
    fs::path ranges_path = dir / "geoip_country_ipv4.db";
    std::error_code ec;
    if (!fs::exists(names_path, ec) || !fs::exists(ranges_path, ec)) return false;

    std::ifstream names(names_path);
    if (!names) return false;
    std::string line;
    while (std::getline(names, line)) {
        if (line.empty()) continue;
        // Strip trailing \r — saved on Windows checkouts.
        if (line.back() == '\r') line.pop_back();
        // TSV: iso \t english \t russian \t japanese [\t ukrainian]
        std::size_t first  = line.find('\t');
        if (first == std::string::npos) continue;
        std::size_t second = line.find('\t', first + 1);
        std::string iso = line.substr(0, first);
        std::string english = (second == std::string::npos)
            ? line.substr(first + 1)
            : line.substr(first + 1, second - first - 1);
        db.names[iso] = {unescape(english)};
    }

    std::ifstream ranges(ranges_path, std::ios::binary);
    if (!ranges) return false;
    char magic[4];
    if (!ranges.read(magic, 4)) return false;
    if (magic[0] != 'Y' || magic[1] != 'G' ||
        magic[2] != 'C' || magic[3] != '1') return false;
    std::uint32_t count_raw{};
    if (!read_u32_be(ranges, count_raw)) return false;
    const std::size_t count = count_raw;
    db.starts.resize(count);
    db.ends.resize(count);
    db.iso_packed.resize(count);
    for (std::size_t i = 0; i < count; ++i) {
        if (!read_u32_be(ranges, db.starts[i])) return false;
        if (!read_u32_be(ranges, db.ends[i]))   return false;
        unsigned char b1{}, b2{};
        if (!ranges.read(reinterpret_cast<char*>(&b1), 1)) return false;
        if (!ranges.read(reinterpret_cast<char*>(&b2), 1)) return false;
        db.iso_packed[i] = static_cast<std::uint16_t>(
            (static_cast<std::uint16_t>(b1) << 8) | b2);
    }
    return !db.starts.empty();
}

bool parse_ipv4(std::string const& s, std::uint32_t& out) {
    std::array<int, 4> octets{};
    int idx = 0;
    int cur = 0;
    bool has_digit = false;
    for (char c : s) {
        if (c == '.') {
            if (!has_digit || idx >= 3) return false;
            octets[idx++] = cur;
            cur = 0;
            has_digit = false;
        } else if (c >= '0' && c <= '9') {
            cur = cur * 10 + (c - '0');
            if (cur > 255) return false;
            has_digit = true;
        } else {
            return false;
        }
    }
    if (!has_digit || idx != 3) return false;
    octets[3] = cur;
    out = (std::uint32_t(octets[0]) << 24) |
          (std::uint32_t(octets[1]) << 16) |
          (std::uint32_t(octets[2]) << 8) |
          std::uint32_t(octets[3]);
    return true;
}

int binary_search(CountryDb const& db, std::uint32_t ip) {
    int low = 0;
    int high = static_cast<int>(db.starts.size()) - 1;
    while (low <= high) {
        int mid = (low + high) >> 1;
        std::uint32_t a = db.starts[mid];
        std::uint32_t b = db.ends[mid];
        if (ip < a) high = mid - 1;
        else if (ip > b) low = mid + 1;
        else return mid;
    }
    return -1;
}

std::string flag_emoji(std::string const& iso) {
    if (iso.size() != 2) return {};
    char a = static_cast<char>(std::toupper(static_cast<unsigned char>(iso[0])));
    char b = static_cast<char>(std::toupper(static_cast<unsigned char>(iso[1])));
    if (a < 'A' || a > 'Z' || b < 'A' || b > 'Z') return {};
    auto encode_codepoint = [](char32_t cp, std::string& out) {
        // UTF-8 encoding for the regional indicator range — always 4 bytes.
        out.push_back(static_cast<char>(0xF0 | ((cp >> 18) & 0x07)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6)  & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp         & 0x3F)));
    };
    std::string out;
    encode_codepoint(0x1F1E6 + (a - 'A'), out);
    encode_codepoint(0x1F1E6 + (b - 'A'), out);
    return out;
}

}  // namespace

void set_asset_dir(std::filesystem::path dir) {
    g_asset_dir = std::move(dir);
}

std::optional<CountryMatch> lookup_ipv4(std::string const& address) {
    std::uint32_t ip{};
    if (!parse_ipv4(address, ip)) return std::nullopt;

    std::call_once(g_load_once, []() {
        for (auto const& dir : candidate_dirs()) {
            CountryDb fresh;
            if (try_load_from(dir, fresh)) {
                g_db = std::move(fresh);
                g_db_loaded = true;
                return;
            }
        }
    });
    if (!g_db_loaded) return std::nullopt;

    int idx = binary_search(g_db, ip);
    if (idx < 0) return std::nullopt;
    std::uint16_t packed = g_db.iso_packed[idx];
    char iso_buf[3] = { static_cast<char>((packed >> 8) & 0xFF),
                       static_cast<char>(packed & 0xFF), 0 };
    std::string iso = iso_buf;
    CountryMatch m;
    m.iso_code = iso;
    auto it = g_db.names.find(iso);
    m.display_name = it != g_db.names.end() ? it->second.english : iso;
    m.flag_emoji = flag_emoji(iso);
    return m;
}

}  // namespace yume::gui::geo
