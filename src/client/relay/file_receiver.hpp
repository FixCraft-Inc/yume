/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yume::crypto {
class Sha256Stream;
}

namespace yume::client {

inline constexpr std::uint64_t kDefaultRelayMaxReceiveBytes =
    1024ULL * 1024ULL * 1024ULL;
inline constexpr std::size_t kRelayTransferChunkBytes = 32U * 1024U;
inline constexpr std::chrono::minutes kDefaultRelayReceiveTimeout{10};

struct RelayReceiveLimits {
    std::uint64_t max_transfer_bytes{kDefaultRelayMaxReceiveBytes};
    std::size_t max_chunk_bytes{kRelayTransferChunkBytes};
    std::chrono::milliseconds max_duration{kDefaultRelayReceiveTimeout};
};

// Opens every path component without following links, creates missing
// components as 0700, and requires the final directory to be owned by the
// effective user with exact mode 0700. Returns false when the platform cannot
// provide the no-follow/no-clobber semantics required by RelayFileReceiver.
// Call before advertising file/bytes receive capability.
bool PrepareRelayReceiveDirectory(const std::filesystem::path& directory,
                                  std::string* error);

// Strict canonical standard-Base64 decoder for relay chunks. The encoded size
// is rejected before allocation, invalid characters/padding are rejected, and
// decoded output is capped independently.
bool DecodeRelayChunkBase64(std::string_view encoded,
                            std::size_t max_decoded_bytes,
                            std::vector<std::uint8_t>* decoded,
                            std::string* error);

// Move-only, fail-closed streaming destination for an inbound relay transfer.
// On supported POSIX systems the selected directory is opened component by
// component without following links. Bytes land in a private same-directory
// staging file; Finish publishes it atomically without replacing an existing
// destination only after exact-size and SHA-256 verification. Any failure or
// unfinished destruction removes the inode-checked staging entry.
class RelayFileReceiver {
public:
    RelayFileReceiver() = default;
    RelayFileReceiver(const RelayFileReceiver&) = delete;
    RelayFileReceiver& operator=(const RelayFileReceiver&) = delete;
    RelayFileReceiver(RelayFileReceiver&& other) noexcept;
    RelayFileReceiver& operator=(RelayFileReceiver&& other) noexcept;
    ~RelayFileReceiver();

    static bool IsSafeBasename(std::string_view name) noexcept;
    static bool IsCanonicalSha256Digest(std::string_view digest) noexcept;

    bool Begin(const std::filesystem::path& receive_directory,
               std::string_view basename,
               std::uint64_t declared_size,
               std::string_view expected_sha256,
               RelayReceiveLimits limits,
               std::string* error);
    bool Append(std::span<const std::uint8_t> chunk, std::string* error);
    bool Finish(std::string* error);
    void Abort() noexcept;

    bool active() const noexcept { return file_fd_ >= 0; }
    bool complete() const noexcept { return committed_; }
    bool expired() const noexcept;
    std::uint64_t declared_size() const noexcept { return declared_size_; }
    std::uint64_t received_size() const noexcept { return received_size_; }
    const std::filesystem::path& path() const noexcept { return path_; }

private:
    void MoveFrom(RelayFileReceiver&& other) noexcept;
    bool Fail(std::string message, std::string* error) noexcept;

    int directory_fd_{-1};
    int file_fd_{-1};
    std::string basename_;
    std::string staging_basename_;
    std::filesystem::path path_;
    std::uint64_t declared_size_{0};
    std::uint64_t received_size_{0};
    std::string expected_sha256_;
    std::unique_ptr<crypto::Sha256Stream> sha256_;
    RelayReceiveLimits limits_{};
    std::chrono::steady_clock::time_point deadline_{};
    std::uint64_t file_device_{0};
    std::uint64_t file_inode_{0};
    bool committed_{false};
};

}  // namespace yume::client
