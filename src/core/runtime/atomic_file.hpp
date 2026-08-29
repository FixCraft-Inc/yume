/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <filesystem>
#include <string>
#include <string_view>

namespace yume::runtime {

enum class ParentDirectoryPolicy {
    RequireExisting,
    Create,
};

enum class FileProtection {
    Inherit,
    OwnerOnly,
};

// Durably replace path with content through an exclusive temporary file in the
// same directory. A failure before the rename leaves an existing destination
// untouched; temporary files are removed on every reported failure path.
bool AtomicWriteFile(const std::filesystem::path& path,
                     std::string_view content,
                     std::string* error = nullptr,
                     ParentDirectoryPolicy parent_policy =
                         ParentDirectoryPolicy::RequireExisting,
                     FileProtection protection = FileProtection::Inherit);

// Remove one file and durably publish the directory-entry change where the
// platform exposes that primitive. A missing path is already the requested
// state and succeeds.
bool DurableRemoveFile(const std::filesystem::path& path,
                       std::string* error = nullptr);

}  // namespace yume::runtime
