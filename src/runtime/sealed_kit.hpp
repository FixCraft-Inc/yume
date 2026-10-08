/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "engine/status.hpp"

namespace yume::runtime::kit {

// Sealed kit 1: a client kit directory in one file for transfer to another
// device, opened with a generated code.
//
//   file      = salt[16] | nonce[12] | ciphertext | tag[16]
//   key       = Argon2id(code, salt, 3 passes, 64 MiB, 4 lanes,
//                        associated data "yume-kit/1"), 32 bytes
//   ciphertext, tag = AES-256-GCM(key, nonce, plaintext, AAD "yume-kit/1")
//   plaintext = u32 content length | content | zero bytes to a multiple
//               of 1024
//   content   = u8 version 1 | u8 file count | file...
//   file      = u8 path length | path | u8 executable (0 or 1) |
//               u32 size | bytes
//
// Integers are big-endian. Files are sorted by path, and a path is one or
// two components of [A-Za-z0-9._-] that are not "." or "..". The file has
// no plaintext header: it reads as random bytes, and the parameters are
// fixed by the version rather than read from the file. A wrong code and a
// file that is not a sealed kit fail the same tag check.
inline constexpr std::string_view kDomain = "yume-kit/1";
inline constexpr std::uint8_t kContentVersion = 1U;
inline constexpr std::size_t kSaltBytes = 16U;
inline constexpr std::size_t kNonceBytes = 12U;
inline constexpr std::size_t kTagBytes = 16U;
inline constexpr std::size_t kKeyBytes = 32U;
inline constexpr std::uint32_t kArgonPasses = 3U;
inline constexpr std::uint32_t kArgonMemoryKiB = 64U * 1024U;
inline constexpr std::uint32_t kArgonLanes = 4U;
inline constexpr std::size_t kPaddingBlock = 1024U;
inline constexpr std::size_t kMaxFiles = 32U;
inline constexpr std::size_t kMaxPathBytes = 64U;
inline constexpr std::size_t kMaxFileBytes = std::size_t{256} * 1024U;
inline constexpr std::size_t kMaxContentBytes = std::size_t{1024} * 1024U;
inline constexpr std::size_t kMaxSealedBytes = kSaltBytes + kNonceBytes + 4U +
                                               kMaxContentBytes +
                                               kPaddingBlock + kTagBytes;
// A code is 25 characters of Crockford base32, 125 random bits, written in
// five groups of five.
inline constexpr std::size_t kCodeCharacters = 25U;
// What every reader of a typed code says when it does not normalize to a
// code. The number in the text is kCodeCharacters.
inline constexpr std::string_view kBadCodeMessage =
    "the kit code is not 25 code characters";
static_assert(kCodeCharacters == 25U, "kBadCodeMessage names the length");

// Whether a file of this size can be a sealed kit: the salt, nonce and tag
// around one to kMaxContentBytes of whole padding blocks.
constexpr bool sealed_size(std::size_t bytes) noexcept {
    constexpr std::size_t overhead = kSaltBytes + kNonceBytes + kTagBytes;
    return bytes >= overhead + kPaddingBlock && bytes <= kMaxSealedBytes &&
           (bytes - overhead) % kPaddingBlock == 0U;
}

struct KitFile final {
    std::string path;
    bool executable{false};
    std::vector<std::uint8_t> bytes;
};

// The files of one kit. Destruction wipes every file's bytes.
class Kit final {
public:
    Kit() = default;
    Kit(Kit&&) noexcept = default;
    // Nothing reassigns a kit, so there is no replacement path to wipe.
    Kit& operator=(Kit&&) = delete;
    Kit(const Kit&) = delete;
    Kit& operator=(const Kit&) = delete;
    ~Kit() noexcept;

    std::vector<KitFile> files;
};

// A new code from the OpenSSL random generator, 25 characters.
engine::Result<std::string> generate_code();
// The code as the user reads it, "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX".
std::string display_code(std::string_view code);
// The code a user typed: separators and spaces dropped, letters upper-cased,
// O read as 0 and I or L as 1. Nothing unless 25 code characters remain.
std::optional<std::string> normalize_code(std::string_view typed);

// Checks names, order, sizes and counts, and that yume.json is present.
engine::Status check_kit(const Kit& kit);

engine::Result<std::vector<std::uint8_t>> seal(const Kit& kit,
                                               std::string_view code);
// Every failure after the tag check is a malformed kit. A tag failure means
// a wrong code or a file that is not a sealed kit.
engine::Result<Kit> open(std::span<const std::uint8_t> sealed,
                         std::string_view code);

// Reads a kit directory: regular files at its top level and one level below,
// no links or special files, within the kit bounds.
engine::Result<Kit> read_directory(const std::filesystem::path& directory);
// Writes a kit to a new directory. The files are written under a private
// temporary name in the same parent, synced, and renamed into place without
// replacing anything. Secrets are mode 0600, executables 0700 and
// directories 0700. A failure removes the partial copy.
engine::Status write_directory(const Kit& kit,
                               const std::filesystem::path& directory);

}  // namespace yume::runtime::kit
