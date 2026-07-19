/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <vector>

namespace yume::security {

class Secret32 {
public:
    explicit Secret32(std::array<std::uint8_t, 32>&& bytes) noexcept;
    Secret32(const Secret32&) = delete;
    Secret32& operator=(const Secret32&) = delete;
    Secret32(Secret32&& other) noexcept;
    Secret32& operator=(Secret32&& other) noexcept;
    ~Secret32();

    const std::uint8_t* data() const noexcept { return bytes_.data(); }
    static constexpr std::size_t size() noexcept { return 32; }
    std::vector<std::uint8_t> CopyBytes() const;

private:
    void Wipe() noexcept;
    std::array<std::uint8_t, 32> bytes_{};
};

// Linux/POSIX v2 secret-file contract: a regular non-symlink file, no group or
// world permission bits, and exactly 64 lowercase hex bytes with no newline.
// The caller should retain the returned move-only value for the connection or
// process lifetime and avoid materializing strings.
Secret32 LoadSecretFile32(const std::filesystem::path& path);

}  // namespace yume::security
