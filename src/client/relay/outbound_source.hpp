/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <span>
#include <string>

namespace yume::client {

// A relay transfer source pinned to one opened, non-symlink regular file.
// Hashing and transmission use this same object so a pathname replacement
// while an invite is pending cannot redirect a transfer to another file.
class RelayOutboundSource {
public:
    static std::shared_ptr<RelayOutboundSource> Open(
        const std::filesystem::path& path,
        std::uint64_t max_bytes,
        std::string* error = nullptr);

    ~RelayOutboundSource();
    RelayOutboundSource(const RelayOutboundSource&) = delete;
    RelayOutboundSource& operator=(const RelayOutboundSource&) = delete;
    RelayOutboundSource(RelayOutboundSource&&) = delete;
    RelayOutboundSource& operator=(RelayOutboundSource&&) = delete;

    std::uint64_t size() const noexcept;
    std::string Sha256Hex(std::string* error = nullptr) const;
    bool ReadExact(std::span<std::uint8_t> output,
                   std::string* error = nullptr);
    bool ValidateSize(std::string* error = nullptr) const;

private:
    struct Impl;
    explicit RelayOutboundSource(std::unique_ptr<Impl> impl);

    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::client
