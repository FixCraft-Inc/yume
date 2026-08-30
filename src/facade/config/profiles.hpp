/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "client/cli/entry.hpp"

namespace yume::facade::profiles {

inline constexpr std::size_t kMaximumProfileIdBytes = 64U;
inline constexpr std::size_t kMaximumProfileBytes = 1U * 1024U * 1024U;
inline constexpr std::size_t kMaximumDisplayNameBytes = 159U;

// A named saved ClientConfig. Multiple profiles can exist side-by-side;
// one is "active" and gets used by ClientSession when start is invoked.
struct ProfileSummary {
    std::string id;          // safe filename slug
    std::string display_name;
    std::filesystem::path path;
    bool is_active{false};
};

std::filesystem::path profiles_dir();
std::filesystem::path active_pointer_path();

std::vector<ProfileSummary> list(std::string* err = nullptr);

// Returns the id of the currently active profile, or empty if none is
// set. When empty the GUI falls back to ~/.yume/client.json.
std::string active_id(std::string* err = nullptr);
bool set_active(std::string const& id, std::string* err = nullptr);

// Read / write a profile by id. load returns nullopt if the file is
// missing or malformed.
std::optional<client::ClientConfig> load(std::string const& id,
                                         std::string* err = nullptr);
bool save(std::string const& id,
          std::string const& display_name,
          client::ClientConfig const& cfg,
          std::string* err = nullptr);
bool remove(std::string const& id, std::string* err = nullptr);

// Convenience: create a brand-new profile, returning its assigned id.
std::optional<std::string> create(std::string const& display_name,
                                  client::ClientConfig const& cfg,
                                  std::string* err = nullptr);

// Make a filesystem-safe slug from a display name.
std::string slug_from(std::string const& display_name);

}  // namespace yume::facade::profiles
