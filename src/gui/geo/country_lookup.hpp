/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

namespace yume::gui::geo {

// Result of looking up an IPv4 in the embedded GeoIP database. We keep
// the surface intentionally small: ISO 3166-1 alpha-2 + display name +
// unicode flag emoji built from the regional indicator code points.
struct CountryMatch {
    std::string iso_code;
    std::string display_name;
    std::string flag_emoji;
};

// Loads the database lazily on first lookup. The DB and names file are
// expected at src/gui/assets/geoip/ during development, and at one of
// the standard install paths in production. Returns nullopt if the
// address isn't a valid public IPv4, isn't in the table, or the DB
// couldn't be loaded.
std::optional<CountryMatch> lookup_ipv4(std::string const& address);

// Override the asset directory used for lookup. Useful for tests and
// for cases where the binary is run from a non-standard prefix. Call
// before the first lookup_ipv4().
void set_asset_dir(std::filesystem::path dir);

}  // namespace yume::gui::geo
