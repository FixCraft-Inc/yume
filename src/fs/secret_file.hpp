/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yume::security {

enum class PrivateParentPolicy {
    RequireExisting,
    CreateOwnerOnly,
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

// Largest private key file this loader will read into memory.
inline constexpr std::size_t kMaxPrivateKeyFileBytes = 64U * 1024U;

// Reads arbitrary private material through the same descriptor-confined
// owner/mode/type checks as private keys. The returned bytes are bounded by
// `maximum_bytes`; callers must wipe them after use. `description` is used in
// diagnostics only and must not contain secret material.
std::vector<std::uint8_t> read_private_file_strict(
    const std::filesystem::path& path,
    std::size_t maximum_bytes,
    std::string_view description);

// Reads a private key file under the POSIX private-file contract: a regular
// non-symlink file owned by the effective user, with no group or world
// permission bits, and no larger than kMaxPrivateKeyFileBytes.
//
// The validated descriptor is the one that is read, so there is no window in
// which the checked path and the read path can diverge. Throws on any
// violation; the caller is responsible for wiping the returned bytes.
//
// Windows has no equivalent enforcement yet and this throws there, as
// read_private_file_strict does. Loosening it to "read whatever the ACL allows"
// would let an unprotected identity file sign a session, so it stays closed
// until protected Windows loading exists.
std::vector<std::uint8_t> ReadPrivateKeyFileStrict(
    const std::filesystem::path& path);

}  // namespace yume::security
