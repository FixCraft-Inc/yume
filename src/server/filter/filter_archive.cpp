/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */
#include "server/filter/filter_archive.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <limits>
#include <map>
#include <memory>
#include <span>
#include <stdexcept>
#include <string_view>
#include <utility>

#if defined(__linux__)
#include <archive.h>
#include <archive_entry.h>
#include <fcntl.h>
#include <lzma.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace yume::server {
namespace {
[[noreturn]] void refuse(const char* reason) {
    throw std::runtime_error(reason);
}

#if defined(__linux__)
constexpr std::size_t kBlock = 512;
constexpr std::size_t kChunk = 64 * 1024;
constexpr std::size_t kPathDepth = 16;

bool zero(std::span<const std::uint8_t> bytes) {
    return std::all_of(bytes.begin(), bytes.end(), [](auto b) { return b == 0; });
}

std::string safe_path(std::string_view name, bool directory) {
    if (name.size() > 1024 || name.empty() || name.front() == '/') refuse("unsafe archive member");
    for (const unsigned char ch : name) {
        if (ch < 32 || ch == 127 || ch == '\\') refuse("unsafe archive member");
    }
    std::string result;
    std::size_t depth = 0;
    while (!name.empty()) {
        const auto slash = name.find('/');
        const auto component = name.substr(0, slash);
        if (component == ".." || component.size() > 255) refuse("unsafe archive member");
        if (!component.empty() && component != ".") {
            if (++depth > kPathDepth) refuse("archive path depth limit exceeded");
            if (!result.empty()) result += '/';
            result += component;
        }
        if (slash == std::string_view::npos) break;
        name.remove_prefix(slash + 1);
    }
    if (result.empty() && !directory) refuse("unsafe archive member");
    return result;
}

class Descriptor final {
public:
    explicit Descriptor(int fd) : fd_(fd) {
        if (fd < 0) refuse("archive file operation failed");
    }
    ~Descriptor() { if (fd_ >= 0) (void)::close(fd_); }
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    int get() const noexcept { return fd_; }
    void finish_file() {
        if (::close(std::exchange(fd_, -1)) != 0) refuse("archive file close failed");
    }
    void replace(int fd) {
        if (fd < 0) refuse("archive directory confinement failed");
        (void)::close(fd_);
        fd_ = fd;
    }
private:
    int fd_;
};

class XzDecoder final {
public:
    XzDecoder() {
        const auto status = ::lzma_stream_decoder(&stream_, 64 * 1024 * 1024,
            LZMA_CONCATENATED | LZMA_TELL_NO_CHECK | LZMA_TELL_UNSUPPORTED_CHECK);
        if (status != LZMA_OK) {
            ::lzma_end(&stream_);
            refuse("cannot initialize bounded XZ decoder");
        }
    }
    ~XzDecoder() { ::lzma_end(&stream_); }
    XzDecoder(const XzDecoder&) = delete;
    XzDecoder& operator=(const XzDecoder&) = delete;
    lzma_stream& stream() noexcept { return stream_; }
private:
    lzma_stream stream_ = LZMA_STREAM_INIT;
};
#endif
}  // namespace

FilterArchive::FilterArchive(FilterArchiveLimits limits)
    : limits_(limits), started_(std::chrono::steady_clock::now()) {}

void FilterArchive::check_deadline() const {
    if (std::chrono::steady_clock::now() - started_ >= limits_.elapsed) {
        refuse("archive elapsed-work limit exceeded");
    }
}

FilterArchive FilterArchive::read(const std::filesystem::path& path,
                                  FilterArchiveLimits limits) {
#if !defined(__linux__)
    (void)path;
    (void)limits;
    refuse("filter archive extraction requires Linux; use an unpacked list or database");
#else
    FilterArchive archive(limits);
    archive.check_deadline();
    if (path.native().find('\0') != std::string::npos) refuse("invalid archive path");
    {
        Descriptor source(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
        struct stat status {};
        if (::fstat(source.get(), &status) != 0 || !S_ISREG(status.st_mode) || status.st_size < 0) {
            refuse("archive input must be a regular file");
        }
        if (static_cast<std::uintmax_t>(status.st_size) > limits.compressed_bytes) {
            refuse("archive compressed-byte limit exceeded");
        }
        // Pin the complete input before decoding. Replacing the source name later
        // cannot change validation or extraction. Concurrent in-place writes are
        // untrusted input too: all resulting bytes still pass XZ and tar checks.
        std::vector<std::uint8_t> snapshot(static_cast<std::size_t>(status.st_size));
        std::size_t copied = 0;
        while (copied < snapshot.size()) {
            archive.check_deadline();
            const auto count = ::read(source.get(), snapshot.data() + copied,
                                      std::min(kChunk, snapshot.size() - copied));
            if (count < 0 && errno == EINTR) continue;
            if (count <= 0) refuse("archive changed or could not be read");
            copied += static_cast<std::size_t>(count);
        }
        std::uint8_t extra = 0;
        ssize_t tail;
        do {
            archive.check_deadline();
            tail = ::read(source.get(), &extra, 1);
        } while (tail < 0 && errno == EINTR);
        if (tail != 0) refuse("archive changed or could not be read");

        XzDecoder decoder;
        auto& stream = decoder.stream();
        std::array<std::uint8_t, kChunk> output{};
        std::size_t supplied = 0;
        for (;;) {
            archive.check_deadline();
            if (stream.avail_in == 0 && supplied < snapshot.size()) {
                stream.avail_in = std::min(kChunk, snapshot.size() - supplied);
                stream.next_in = snapshot.data() + supplied;
                supplied += stream.avail_in;
            }
            stream.next_out = output.data();
            // Decode at most one byte past the remaining allowance, into fixed
            // scratch storage; never allocate or publish an over-budget chunk.
            stream.avail_out = limits.decoded_bytes - archive.data_.size() < kChunk
                ? limits.decoded_bytes - archive.data_.size() + 1 : kChunk;
            const auto available = stream.avail_out;
            const auto result = ::lzma_code(&stream, supplied == snapshot.size() ? LZMA_FINISH : LZMA_RUN);
            const auto produced = available - stream.avail_out;
            if (produced > limits.decoded_bytes - archive.data_.size()) {
                refuse("archive decoded-byte limit exceeded");
            }
            archive.data_.insert(archive.data_.end(), output.begin(), output.begin() + produced);
            if (result == LZMA_STREAM_END) break;
            if (result != LZMA_OK) refuse("invalid XZ archive or decoder memory limit exceeded");
        }
    }
    archive.validate();
    return archive;
#endif
}

void FilterArchive::validate() {
#if defined(__linux__)
    struct Input {
        const FilterArchive* owner;
        std::span<const std::uint8_t> bytes;
        std::size_t position{0};
    } input{this, data_};
    // libarchive owns tar/PAX interpretation; it never receives compressed data
    // or filesystem authority. Its read callback checks time between bounded
    // chunks, including chains of extended headers inside next_header().
    std::unique_ptr<struct archive, decltype(&::archive_read_free)> reader(
        ::archive_read_new(), &::archive_read_free);
    if (!reader || ::archive_read_support_filter_none(reader.get()) != ARCHIVE_OK ||
        ::archive_read_support_format_tar(reader.get()) != ARCHIVE_OK) {
        refuse("cannot initialize tar reader");
    }
    const auto read_chunk = [](struct archive* handle, void* opaque,
                               const void** buffer) noexcept -> la_ssize_t {
        auto& in = *static_cast<Input*>(opaque);
        if (std::chrono::steady_clock::now() - in.owner->started_ >= in.owner->limits_.elapsed) {
            ::archive_set_error(handle, ETIMEDOUT, "archive elapsed-work limit exceeded");
            return -1;
        }
        const auto count = std::min(kChunk, in.bytes.size() - in.position);
        *buffer = in.bytes.data() + in.position;
        in.position += count;
        return static_cast<la_ssize_t>(count);
    };
    if (::archive_read_open(reader.get(), &input, nullptr, read_chunk, nullptr) != ARCHIVE_OK) {
        refuse("invalid tar archive");
    }
    std::map<std::string, bool> nodes;
    std::vector<std::uint8_t> payload;
    std::array<std::uint8_t, kChunk> scratch{};
    std::size_t count = 0;
    for (;;) {
        check_deadline();
        const auto consumed = ::archive_filter_bytes(reader.get(), 0);
        if (consumed < 0 || static_cast<std::uint64_t>(consumed) > data_.size()) {
            refuse("invalid tar reader position");
        }
        struct archive_entry* entry = nullptr;
        const auto status = ::archive_read_next_header(reader.get(), &entry);
        check_deadline();
        if (status == ARCHIVE_EOF) {
            // libarchive accepts a missing end marker and ignores trailing data.
            // Require two zero blocks and a zero-only tail in our file contract.
            const auto at = (static_cast<std::size_t>(consumed) + kBlock - 1) / kBlock * kBlock;
            if (at > data_.size() || data_.size() - at < 2 * kBlock ||
                (data_.size() - at) % kBlock != 0) refuse("missing or truncated tar end marker");
            for (auto position = at; position < data_.size(); position += kBlock) {
                check_deadline();
                if (!zero(input.bytes.subspan(position, kBlock))) refuse("nonzero data after tar end marker");
            }
            break;
        }
        // Warnings (including malformed or undecodable names) are refusals too.
        if (status != ARCHIVE_OK || !entry) refuse("invalid tar header or metadata");
        if (++count > limits_.members) refuse("archive member limit exceeded");
        const auto type = ::archive_entry_filetype(entry);
        const bool directory = type == AE_IFDIR;
        if ((type != AE_IFREG && !directory) || ::archive_entry_hardlink(entry) ||
            ::archive_entry_symlink(entry) || ::archive_entry_sparse_count(entry) != 0) {
            refuse("unsupported archive member type");
        }
        const auto declared = ::archive_entry_size(entry);
        if (!::archive_entry_size_is_set(entry) || declared < 0 ||
            (directory && declared != 0)) refuse("invalid tar member size");
        if (static_cast<std::uint64_t>(declared) > limits_.file_bytes ||
            static_cast<std::uint64_t>(declared) > limits_.payload_bytes - payload.size()) {
            refuse("archive payload-byte limit exceeded");
        }
        const auto size = static_cast<std::size_t>(declared);
        const char* name = ::archive_entry_pathname(entry);
        if (!name) refuse("unsafe archive member");
        auto path = safe_path(name, directory);
        if (!path.empty()) {
            std::size_t slash = 0;
            for (;;) {
                slash = path.find('/', slash);
                const bool parent = slash != std::string::npos;
                const auto node = path.substr(0, slash);
                const bool is_directory = parent || directory;
                const auto found = nodes.find(node);
                if (found != nodes.end()) {
                    if (!found->second || !is_directory) refuse("duplicate or conflicting archive member");
                } else {
                    if (nodes.size() >= limits_.filesystem_nodes) refuse("archive filesystem-node limit exceeded");
                    nodes.emplace(node, is_directory);
                }
                if (!parent) break;
                ++slash;
            }
            members_.push_back({std::move(path), payload.size(), size, directory});
        }
        std::size_t copied = 0;
        while (copied < size) {
            check_deadline();
            const auto bytes = ::archive_read_data(reader.get(), scratch.data(),
                                                   std::min(kChunk, size - copied));
            if (bytes <= 0) refuse("truncated tar member");
            const auto amount = static_cast<std::size_t>(bytes);
            payload.insert(payload.end(), scratch.begin(), scratch.begin() + amount);
            copied += amount;
        }
        check_deadline();
        if (::archive_read_data(reader.get(), scratch.data(), 1) != 0) {
            refuse("tar member size disagrees with its payload");
        }
    }
    reader.reset();
    data_.swap(payload);
#else
    refuse("filter archive extraction requires Linux");
#endif
}

void FilterArchive::extract(const std::filesystem::path& directory) const {
#if !defined(__linux__)
    (void)directory;
    refuse("filter archive extraction requires Linux");
#else
    check_deadline();
    Descriptor root(::open(directory.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
    for (const auto& member : members_) {
        check_deadline();
        Descriptor parent(::fcntl(root.get(), F_DUPFD_CLOEXEC, 0));
        std::string_view remaining(member.path);
        for (;;) {
            const auto slash = remaining.find('/');
            const std::string component(remaining.substr(0, slash));
            if (slash == std::string_view::npos && !member.directory) {
                Descriptor file(::openat(parent.get(), component.c_str(),
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
                std::size_t written = 0;
                while (written < member.size) {
                    check_deadline();
                    const auto count = ::write(file.get(), data_.data() + member.offset + written,
                        std::min(kChunk, member.size - written));
                    if (count < 0 && errno == EINTR) continue;
                    if (count <= 0) refuse("archive file write failed");
                    written += static_cast<std::size_t>(count);
                }
                file.finish_file();
                break;
            }
            if (::mkdirat(parent.get(), component.c_str(), 0700) != 0 && errno != EEXIST) {
                refuse("archive directory creation failed");
            }
            parent.replace(::openat(parent.get(), component.c_str(),
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW));
            if (slash == std::string_view::npos) break;
            remaining.remove_prefix(slash + 1);
        }
    }
    check_deadline();
#endif
}
}  // namespace yume::server
