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
#include <span>
#include <string>
#include <vector>

namespace yume::security {

// Creates or tightens the final directory to an owner-only, non-reparse
// directory. Existing ancestors are not re-permissioned. The final component
// is rejected if it is a symlink/reparse point or is not owned by the current
// POSIX user.
bool ensure_private_directory(const std::filesystem::path& path,
                              std::string* error = nullptr);

enum class PrivateParentPolicy {
    RequireExisting,
    CreateOwnerOnly,
};

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

// Creates a new regular file without following or replacing an existing path.
// POSIX files are mode 0600 from creation onward; Windows files receive a
// protected owner-and-LocalSystem-only DACL at creation. On failure, returns
// false, records a diagnostic when error is non-null, and attempts to remove
// a partial file (including any cleanup failure in the diagnostic).
bool WriteFileExclusive0600(const std::filesystem::path& path,
                            std::span<const std::uint8_t> contents,
                            std::string* error,
                            PrivateParentPolicy parent_policy =
                                PrivateParentPolicy::CreateOwnerOnly);

// Linux/POSIX v2 secret-file contract: a regular non-symlink file, no group or
// world permission bits, and exactly 64 lowercase hex bytes with no newline.
// The caller should retain the returned move-only value for the connection or
// process lifetime and avoid materializing strings.
Secret32 LoadSecretFile32(const std::filesystem::path& path);

// Largest private key file this loader will read into memory.
inline constexpr std::size_t kMaxPrivateKeyFileBytes = 64U * 1024U;

// Reads a private key file under the same POSIX contract as the secret files:
// a regular non-symlink file owned by the effective user, with no group or
// world permission bits, and no larger than kMaxPrivateKeyFileBytes.
//
// The validated descriptor is the one that is read, so there is no window in
// which the checked path and the read path can diverge. Throws on any
// violation; the caller is responsible for wiping the returned bytes.
//
// Windows has no equivalent enforcement yet and this throws there, matching
// LoadSecretFile32. Loosening it to "read whatever the ACL allows" would let
// an unprotected identity file sign a session, so it stays closed until
// protected Windows loading exists.
std::vector<std::uint8_t> ReadPrivateKeyFileStrict(
    const std::filesystem::path& path);

}  // namespace yume::security
