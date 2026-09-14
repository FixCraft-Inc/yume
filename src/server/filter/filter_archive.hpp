/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace yume::server {

// Internal extraction policy, separate from the loaded rule-memory budget.
// Smaller budgets let tests exercise the production checks without large files.
struct FilterArchiveLimits {
    std::size_t compressed_bytes{32 * 1024 * 1024};
    std::size_t decoded_bytes{128 * 1024 * 1024};
    std::size_t file_bytes{64 * 1024 * 1024};
    std::size_t payload_bytes{128 * 1024 * 1024};
    std::size_t members{4096};
    std::size_t filesystem_nodes{4096};
    std::chrono::milliseconds elapsed{30000};
};

// A validated in-memory snapshot. No archive path is reopened during extraction.
// Throws on unsupported platforms, malformed input or exhausted budgets. The
// caller owns an exclusive private staging directory and removes it on failure.
class FilterArchive final {
public:
    static FilterArchive read(const std::filesystem::path& path,
                              FilterArchiveLimits limits = {});
    FilterArchive(FilterArchive&&) noexcept = default;
    FilterArchive& operator=(FilterArchive&&) noexcept = default;
    FilterArchive(const FilterArchive&) = delete;
    FilterArchive& operator=(const FilterArchive&) = delete;

    void extract(const std::filesystem::path& directory) const;

private:
    struct Member {
        std::string path;
        std::size_t offset;
        std::size_t size;
        bool directory;
    };
    explicit FilterArchive(FilterArchiveLimits limits);
    void check_deadline() const;
    void validate();

    FilterArchiveLimits limits_;
    std::chrono::steady_clock::time_point started_;
    std::vector<std::uint8_t> data_;
    std::vector<Member> members_;
};

}  // namespace yume::server
