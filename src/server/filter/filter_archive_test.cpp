/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */
#include "server/filter/filter_archive.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string_view>
#include <thread>

#if defined(__linux__)
#include <lzma.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {
using yume::server::FilterArchive;
using yume::server::FilterArchiveLimits;
namespace fs = std::filesystem;

#if defined(__linux__)
using Bytes = std::vector<std::uint8_t>;

struct Fixture {
    fs::path root;
    Fixture() {
        auto pattern = (fs::temp_directory_path() / "yume-archive-test-XXXXXX").string();
        assert(::mkdtemp(pattern.data()));
        root = pattern;
        fs::create_directory(root / "out");
    }
    ~Fixture() { std::error_code ec; fs::remove_all(root, ec); }
};

void write(const fs::path& path, const Bytes& data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    out.close();
    assert(out);
}

Bytes read(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    assert(in);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

Bytes compress(const Bytes& data, std::uint32_t preset = 1) {
    Bytes output(::lzma_stream_buffer_bound(data.size()));
    std::size_t size = 0;
    assert(::lzma_easy_buffer_encode(preset, LZMA_CHECK_CRC64, nullptr,
        data.data(), data.size(), output.data(), &size, output.size()) == LZMA_OK);
    output.resize(size);
    return output;
}

void checksum(Bytes& data, std::size_t offset = 0) {
    std::fill_n(data.begin() + offset + 148, 8, ' ');
    unsigned total = 0;
    for (std::size_t i = offset; i < offset + 512; ++i) total += data[i];
    std::snprintf(reinterpret_cast<char*>(data.data() + offset + 148), 8, "%06o", total);
    data[offset + 155] = ' ';
}

void member(Bytes& tar, std::string_view name, std::string_view content,
            char type = '0', bool gnu = false) {
    assert(name.size() <= 100);
    assert(content.size() <= std::numeric_limits<unsigned>::max());
    const auto offset = tar.size();
    tar.resize(offset + 512, 0);
    std::copy(name.begin(), name.end(), tar.begin() + offset);
    assert(std::snprintf(reinterpret_cast<char*>(tar.data() + offset + 124),
                         12, "%011o", static_cast<unsigned>(content.size())) == 11);
    tar[offset + 156] = static_cast<std::uint8_t>(type);
    const std::string_view magic = gnu ? std::string_view("ustar  \0", 8)
                                      : std::string_view("ustar\0" "00", 8);
    std::copy(magic.begin(), magic.end(), tar.begin() + offset + 257);
    checksum(tar, offset);
    tar.insert(tar.end(), content.begin(), content.end());
    tar.resize((tar.size() + 511) / 512 * 512, 0);
}

Bytes finish(Bytes tar) { tar.resize(tar.size() + 1024, 0); return tar; }

template<class Action>
void rejects(Action action, std::string_view reason) {
    try { action(); }
    catch (const std::runtime_error& error) {
        if (std::string_view(error.what()).find(reason) != std::string_view::npos) return;
        std::fprintf(stderr, "wrong refusal: %s; expected %.*s\n", error.what(),
                     static_cast<int>(reason.size()), reason.data());
        throw;
    }
    throw std::runtime_error("hostile archive was accepted; expected " + std::string(reason));
}

void test_snapshot_and_formats() {
    Fixture f;
    Bytes tar;
    member(tar, "./", "", '5', true);
    member(tar, "metadata", "13 mtime=1.5\n", 'x');
    member(tar, "sub/file", "original");
    write(f.root / "input", compress(finish(tar)));
    auto snapshot = FilterArchive::read(f.root / "input");
    write(f.root / "input", Bytes{0, 1, 2});
    snapshot.extract(f.root / "out");
    assert(read(f.root / "out/sub/file") == Bytes({'o','r','i','g','i','n','a','l'}));
    struct stat status {};
    assert(::stat((f.root / "out/sub/file").c_str(), &status) == 0);
    assert((status.st_mode & 0777) == 0600);
    assert(::stat((f.root / "out/sub").c_str(), &status) == 0);
    assert((status.st_mode & 0777) == 0700);
    rejects([&] { snapshot.extract(f.root / "out"); }, "file operation failed");
    assert(read(f.root / "out/sub/file").size() == 8);
}

void test_hostile_headers() {
    Fixture f;
    const auto reject_tar = [&](Bytes tar, std::string_view reason) {
        write(f.root / "input", compress(tar));
        rejects([&] { (void)FilterArchive::read(f.root / "input"); }, reason);
        assert(fs::is_empty(f.root / "out"));
    };
    for (const auto name : {"../escape", "/absolute", "a/../../escape", "line\nbreak", "a\\b"}) {
        Bytes tar; member(tar, name, "bad"); reject_tar(finish(tar), "unsafe archive member");
    }
    for (const char type : {'1','2','3','4','6'}) {
        Bytes tar; member(tar, "bad", "", type); reject_tar(finish(tar), "unsupported archive member type");
    }
    for (const auto metadata : {"bad", "999 mtime=1\n"}) {
        Bytes tar; member(tar, "pax", metadata, 'x'); member(tar, "data", "ok");
        reject_tar(finish(tar), "header or metadata");
    }
    Bytes tar; member(tar, "file", "payload");
    auto bad = tar; bad[0] ^= 1; reject_tar(finish(bad), "tar");
    bad = tar; bad[124] = 0x80; checksum(bad); reject_tar(finish(bad), "tar");
    bad = tar; member(bad, "./file", "other"); reject_tar(finish(bad), "duplicate");
    bad = tar; member(bad, "file/child", "other"); reject_tar(finish(bad), "conflicting");
    reject_tar(tar, "end marker");
    bad = finish(tar); bad.back() = 1; reject_tar(bad, "after tar end marker");
    bad = finish(tar); bad.resize(bad.size() - 1); reject_tar(bad, "end marker");
    bad = tar; bad.resize(513); reject_tar(bad, "truncated tar member");
    std::string deep;
    for (int i = 0; i < 17; ++i) deep += "a/";
    bad.clear(); member(bad, deep + "file", ""); reject_tar(finish(bad), "depth");
}

void test_limits_and_xz_failures() {
    Fixture f;
    Bytes tar; member(tar, "a", "1234"); member(tar, "sub/b", "5678");
    const auto packed = compress(finish(tar));
    const auto path = f.root / "input";
    write(path, packed);
    const auto limited = [&](FilterArchiveLimits limits, std::string_view reason) {
        rejects([&] { (void)FilterArchive::read(path, limits); }, reason);
    };
    FilterArchiveLimits limits;
    limits.compressed_bytes = packed.size() - 1; limited(limits, "compressed-byte");
    limits = {}; limits.decoded_bytes = 1024; limited(limits, "decoded-byte");
    limits = {}; limits.file_bytes = 3; limited(limits, "payload-byte");
    limits = {}; limits.payload_bytes = 7; limited(limits, "payload-byte");
    limits = {}; limits.members = 1; limited(limits, "member limit");
    limits = {}; limits.filesystem_nodes = 2; limited(limits, "filesystem-node");
    limits = {}; limits.elapsed = std::chrono::milliseconds(0); limited(limits, "elapsed-work");
    limits = {}; limits.compressed_bytes = packed.size(); limits.decoded_bytes = finish(tar).size();
    limits.file_bytes = 4; limits.payload_bytes = 8; limits.members = 2; limits.filesystem_nodes = 3;
    auto exact = FilterArchive::read(path, limits);
    exact.extract(f.root / "out");
    assert(read(f.root / "out/sub/b").size() == 4);
    auto corrupt = packed; corrupt[corrupt.size() / 2] ^= 1;
    write(path, corrupt); rejects([&] { (void)FilterArchive::read(path); }, "XZ");
    corrupt = packed; corrupt.resize(corrupt.size() - 1);
    write(path, corrupt); rejects([&] { (void)FilterArchive::read(path); }, "XZ");
    corrupt = packed; corrupt.push_back(1);
    write(path, corrupt); rejects([&] { (void)FilterArchive::read(path); }, "XZ");
    corrupt = packed; corrupt.insert(corrupt.end(), packed.begin(), packed.end());
    write(path, corrupt); rejects([&] { (void)FilterArchive::read(path); }, "after tar end marker");
    write(path, packed);
    limits = {}; limits.elapsed = std::chrono::milliseconds(100);
    auto expired = FilterArchive::read(path, limits);
    std::this_thread::sleep_for(std::chrono::milliseconds(110));
    rejects([&] { expired.extract(f.root / "out"); }, "elapsed-work");
}

std::string pax_record(std::string_view key, std::string_view value) {
    const auto body = std::string(key) + "=" + std::string(value) + "\n";
    auto length = body.size() + 2;
    while (std::to_string(length).size() + 1 + body.size() != length) {
        length = std::to_string(length).size() + 1 + body.size();
    }
    return std::to_string(length) + " " + body;
}

void test_extended_headers_and_decoder_memory() {
    Fixture f;
    Bytes tar;
    member(tar, "pax", pax_record("path", "../outside"), 'x');
    member(tar, "safe", "payload");
    write(f.root / "input", compress(finish(tar)));
    rejects([&] { (void)FilterArchive::read(f.root / "input"); }, "unsafe archive member");
    tar.clear();
    member(tar, "pax", pax_record("path", "nested/valid") + pax_record("mtime", "1.5"), 'x');
    member(tar, "safe", "payload");
    write(f.root / "input", compress(finish(tar)));
    auto valid = FilterArchive::read(f.root / "input");
    valid.extract(f.root / "out");
    assert(read(f.root / "out/nested/valid").size() == 7);
    auto packed = compress(finish(tar));
    // Change this fixture's LZMA2 dictionary request to 4 GiB and repair only
    // the XZ block-header CRC. The decoder must refuse before allocating it.
    std::size_t filter_offset = 14;
    for (const unsigned flag : {0x40u, 0x80u}) {
        if (packed[13] & flag) {
            while (packed.at(filter_offset++) & 0x80) {}
        }
    }
    assert(packed.at(filter_offset) == 0x21 && packed.at(filter_offset + 1) == 1);
    packed.at(filter_offset + 2) = 40;
    const auto header_size = (static_cast<std::size_t>(packed[12]) + 1) * 4;
    const auto crc = ::lzma_crc32(packed.data() + 12, header_size - 4, 0);
    for (unsigned i = 0; i < 4; ++i) packed[12 + header_size - 4 + i] =
        static_cast<std::uint8_t>(crc >> (8 * i));
    write(f.root / "input", packed);
    rejects([&] { (void)FilterArchive::read(f.root / "input"); }, "decoder memory limit");
}

void test_special_inputs_and_confinement() {
    Fixture f;
    Bytes tar; member(tar, "sub/file", "payload");
    write(f.root / "input", compress(finish(tar)));
    auto snapshot = FilterArchive::read(f.root / "input");
    fs::create_directory(f.root / "outside");
    fs::create_directory_symlink(f.root / "outside", f.root / "out/sub");
    rejects([&] { snapshot.extract(f.root / "out"); }, "confinement");
    assert(fs::is_empty(f.root / "outside"));
    fs::create_symlink(f.root / "input", f.root / "link");
    rejects([&] { (void)FilterArchive::read(f.root / "link"); }, "file operation");
    assert(::mkfifo((f.root / "fifo").c_str(), 0600) == 0);
    rejects([&] { (void)FilterArchive::read(f.root / "fifo"); }, "regular file");
    rejects([&] { (void)FilterArchive::read(f.root / "out"); }, "regular file");
    rejects([&] { (void)FilterArchive::read(fs::path((f.root / "input").string() + std::string("\0tail", 5))); }, "invalid archive path");
}
#endif
}  // namespace

int main() {
#if defined(__linux__)
    test_snapshot_and_formats();
    test_hostile_headers();
    test_limits_and_xz_failures();
    test_extended_headers_and_decoder_memory();
    test_special_inputs_and_confinement();
#else
    try { (void)FilterArchive::read("unavailable.tar.xz"); }
    catch (const std::runtime_error&) { return 0; }
    return 1;
#endif
}
