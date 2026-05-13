/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace yume::facade::secure_materials {

inline constexpr char kDefaultAnonymCaId[] = "embedded-anonym-ca";

enum class MaterialType {
    AnonymCa,
    AuthKey,
};

struct MaterialSummary {
    std::string id;
    std::string display_name;
    MaterialType type{MaterialType::AnonymCa};
    std::string source_label;
    std::string fingerprint;
    std::filesystem::path path;
    bool imported_encrypted{false};
    bool is_default{false};
    long long created_at_epoch_ms{0};
};

std::filesystem::path store_dir();
std::filesystem::path ensure_default_anonym_ca(std::string* err = nullptr);

std::vector<MaterialSummary> list(MaterialType type, std::string* err = nullptr);
std::optional<MaterialSummary> get(std::string const& id, std::string* err = nullptr);
std::optional<std::filesystem::path> material_path(std::string const& id,
                                                   std::string* err = nullptr);

bool import_text(MaterialType type,
                 std::string const& display_name,
                 std::string const& pem_text,
                 MaterialSummary* out = nullptr,
                 std::string* err = nullptr);

bool import_file(MaterialType type,
                 std::string const& display_name,
                 std::filesystem::path const& source_path,
                 MaterialSummary* out = nullptr,
                 std::string* err = nullptr);

bool remove(std::string const& id, std::string* err = nullptr);

char const* type_label(MaterialType type);

}  // namespace yume::facade::secure_materials
