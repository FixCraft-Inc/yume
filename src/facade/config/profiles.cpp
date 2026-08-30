/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/config/profiles.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <span>
#include <system_error>

#include <nlohmann/json.hpp>

#include "core/encoding/hex.hpp"
#include "core/runtime/atomic_file.hpp"
#include "core/runtime/bounded_file.hpp"
#include "core/runtime/file_transaction_lock.hpp"
#include "core/security/crypto.hpp"
#include "core/security/secret_file.hpp"
#include "facade/config/config_io.hpp"

namespace yume::facade::profiles {
namespace {

using nlohmann::json;

constexpr std::size_t kFallbackRandomBytes = 8U;
constexpr unsigned kMaximumCollisionSuffix = 10000U;

std::filesystem::path active_marker() {
    return profiles_dir() / "active";
}

std::filesystem::path profile_path(std::string_view id) {
    return profiles_dir() / (std::string(id) + ".json");
}

std::filesystem::path mutation_resource() {
    return profiles_dir() / ".mutations";
}

bool is_valid_id(std::string_view id) {
    if (id.empty() || id.size() > kMaximumProfileIdBytes) {
        return false;
    }
    for (const char character : id) {
        const bool alphanumeric =
            (character >= 'a' && character <= 'z') ||
            (character >= '0' && character <= '9');
        if (!alphanumeric && character != '-') return false;
    }
    return true;
}

bool validate_id(std::string_view id, std::string* error) {
    if (is_valid_id(id)) return true;
    if (error) {
        *error = "profile id must be 1..64 lowercase ASCII letters, digits, "
                 "or hyphens";
    }
    return false;
}

bool ensure_profiles_directory(std::string* error) {
    return security::ensure_private_directory(profiles_dir(), error);
}

bool inspect_profile_destination(const std::filesystem::path& path,
                                 std::string* error) {
    std::error_code status_error;
    const auto status = std::filesystem::symlink_status(path, status_error);
    if (status_error == std::errc::no_such_file_or_directory ||
        status.type() == std::filesystem::file_type::not_found) {
        return true;
    }
    if (status_error) {
        if (error) {
            *error = "cannot inspect profile destination: " +
                     status_error.message();
        }
        return false;
    }
    if (status.type() != std::filesystem::file_type::regular) {
        if (error) *error = "profile destination must be a regular file";
        return false;
    }
    return true;
}

bool inspect_active_destination(std::string* error) {
    std::error_code status_error;
    const auto status = std::filesystem::symlink_status(
        active_marker(), status_error);
    if (status.type() == std::filesystem::file_type::not_found ||
        status_error == std::errc::no_such_file_or_directory) {
        return true;
    }
    if (status_error) {
        if (error) {
            *error = "cannot inspect active profile destination: " +
                     status_error.message();
        }
        return false;
    }
    if (status.type() != std::filesystem::file_type::regular) {
        if (error) {
            *error = "active profile destination must be a regular file";
        }
        return false;
    }
    return true;
}

bool read_active_id(std::string* id, std::string* error) {
    id->clear();
    std::error_code status_error;
    const auto status = std::filesystem::symlink_status(
        active_marker(), status_error);
    if (status_error == std::errc::no_such_file_or_directory ||
        status.type() == std::filesystem::file_type::not_found) {
        return true;
    }
    if (status_error) {
        if (error) {
            *error = "cannot inspect active profile pointer: " +
                     status_error.message();
        }
        return false;
    }

    std::string value;
    if (!runtime::read_text_file_bounded(
            active_marker(), kMaximumProfileIdBytes + 2U, &value, error)) {
        return false;
    }
    while (!value.empty() &&
           (value.back() == '\n' || value.back() == '\r')) {
        value.pop_back();
    }
    if (!is_valid_id(value)) {
        if (error) *error = "active profile pointer contains an invalid id";
        return false;
    }
    std::string profile_contents;
    if (!runtime::read_text_file_bounded(
            profile_path(value), kMaximumProfileBytes,
            &profile_contents, error)) {
        if (error && !error->empty()) {
            *error = "active profile pointer names an invalid profile: " +
                     *error;
        }
        return false;
    }
    *id = std::move(value);
    return true;
}

bool serialize_profile(std::string_view display_name,
                       const client::ClientConfig& config,
                       std::string* serialized,
                       std::string* error) {
    if (display_name.size() > kMaximumDisplayNameBytes) {
        if (error) *error = "profile display name exceeds 159 bytes";
        return false;
    }
    return config_io::serialize_client_json(
        config, display_name, serialized, error);
}

bool save_locked(std::string_view id,
                 std::string_view display_name,
                 const client::ClientConfig& config,
                 std::string* error) {
    std::string serialized;
    if (!serialize_profile(display_name, config, &serialized, error)) {
        return false;
    }
    const auto path = profile_path(id);
    if (!inspect_profile_destination(path, error)) return false;
    return runtime::AtomicWriteFile(
        path, serialized, error,
        runtime::ParentDirectoryPolicy::RequireExisting,
        runtime::FileProtection::OwnerOnly);
}

std::string collision_candidate(std::string_view base, unsigned suffix) {
    const std::string suffix_text = "-" + std::to_string(suffix);
    const std::size_t maximum_base =
        kMaximumProfileIdBytes - suffix_text.size();
    std::string candidate(base.substr(0, maximum_base));
    while (!candidate.empty() && candidate.back() == '-') candidate.pop_back();
    candidate += suffix_text;
    return candidate;
}

}  // namespace

std::filesystem::path profiles_dir() {
    return config_io::default_data_dir() / "profiles";
}

std::filesystem::path active_pointer_path() {
    return active_marker();
}

std::string slug_from(std::string const& display_name) {
    std::string slug;
    slug.reserve(std::min(display_name.size(), kMaximumProfileIdBytes));
    bool separator_pending = false;
    for (const unsigned char character : display_name) {
        if ((character >= 'a' && character <= 'z') ||
            (character >= '0' && character <= '9')) {
            if (separator_pending && !slug.empty() &&
                slug.size() < kMaximumProfileIdBytes) {
                slug.push_back('-');
            }
            separator_pending = false;
            if (slug.size() < kMaximumProfileIdBytes) {
                slug.push_back(static_cast<char>(character));
            }
        } else if (character >= 'A' && character <= 'Z') {
            if (separator_pending && !slug.empty() &&
                slug.size() < kMaximumProfileIdBytes) {
                slug.push_back('-');
            }
            separator_pending = false;
            if (slug.size() < kMaximumProfileIdBytes) {
                slug.push_back(static_cast<char>(
                    std::tolower(static_cast<unsigned char>(character))));
            }
        } else {
            separator_pending = true;
        }
    }
    while (!slug.empty() && slug.back() == '-') slug.pop_back();
    if (!slug.empty()) return slug;

    const crypto::Bytes random = crypto::random_bytes(kFallbackRandomBytes);
    return "profile-" + encoding::hex_lower(random);
}

std::vector<ProfileSummary> list(std::string* error) {
    if (error) error->clear();
    std::vector<ProfileSummary> summaries;
    if (!ensure_profiles_directory(error)) return summaries;

    std::string active;
    if (!read_active_id(&active, error)) return summaries;

    std::error_code iterator_error;
    std::filesystem::directory_iterator iterator(profiles_dir(), iterator_error);
    const std::filesystem::directory_iterator end;
    if (iterator_error) {
        if (error) *error = "cannot enumerate profiles: " + iterator_error.message();
        return summaries;
    }
    for (; iterator != end; iterator.increment(iterator_error)) {
        if (iterator_error) {
            if (error) *error = "cannot enumerate profiles: " + iterator_error.message();
            return {};
        }
        const auto path = iterator->path();
        if (path.extension() != ".json") continue;
        const std::string id = path.stem().string();
        if (!is_valid_id(id)) {
            if (error) *error = "profile directory contains an invalid profile id";
            return {};
        }

        std::string serialized;
        if (!runtime::read_text_file_bounded(
                path, kMaximumProfileBytes, &serialized, error)) {
            return {};
        }
        json root;
        try {
            root = json::parse(serialized);
        } catch (const json::exception& exception) {
            if (error) {
                *error = std::string("invalid profile JSON: ") + exception.what();
            }
            return {};
        }
        if (!root.is_object()) {
            if (error) *error = "profile root must be a JSON object";
            return {};
        }

        ProfileSummary summary;
        summary.path = path;
        summary.id = id;
        summary.display_name = id;
        if (const auto display = root.find("display_name");
            display != root.end()) {
            if (!display->is_string()) {
                if (error) *error = "profile display_name must be a string";
                return {};
            }
            try {
                summary.display_name = display->get<std::string>();
            } catch (const json::exception& exception) {
                if (error) {
                    *error = std::string("invalid profile display_name: ") +
                             exception.what();
                }
                return {};
            }
            if (summary.display_name.size() > kMaximumDisplayNameBytes) {
                if (error) *error = "profile display_name exceeds 159 bytes";
                return {};
            }
        }
        summary.is_active = summary.id == active;
        summaries.push_back(std::move(summary));
    }
    std::sort(summaries.begin(), summaries.end(),
              [](const auto& lhs, const auto& rhs) {
                  return lhs.display_name < rhs.display_name;
              });
    return summaries;
}

std::string active_id(std::string* error) {
    if (error) error->clear();
    if (!ensure_profiles_directory(error)) return {};
    std::string id;
    if (!read_active_id(&id, error)) return {};
    return id;
}

bool set_active(std::string const& id, std::string* error) {
    if (error) error->clear();
    if (!validate_id(id, error) || !ensure_profiles_directory(error)) {
        return false;
    }
    runtime::FileTransactionLock lock;
    if (!lock.Acquire({mutation_resource()}, error)) return false;

    std::string ignored;
    if (!runtime::read_text_file_bounded(
            profile_path(id), kMaximumProfileBytes, &ignored, error)) {
        return false;
    }
    json root;
    try {
        root = json::parse(ignored);
    } catch (const json::exception& exception) {
        if (error) {
            *error = std::string("invalid profile JSON: ") + exception.what();
        }
        return false;
    }
    if (!root.is_object()) {
        if (error) *error = "profile root must be a JSON object";
        return false;
    }
    if (const auto display = root.find("display_name"); display != root.end()) {
        if (!display->is_string()) {
            if (error) *error = "profile display_name must be a string";
            return false;
        }
        try {
            if (display->get_ref<const std::string&>().size() >
                kMaximumDisplayNameBytes) {
                if (error) *error = "profile display_name exceeds 159 bytes";
                return false;
            }
        } catch (const json::exception& exception) {
            if (error) {
                *error = std::string("invalid profile display_name: ") +
                         exception.what();
            }
            return false;
        }
    }
    if (!config_io::parse_client_json(
            ignored, profile_path(id).parent_path(), error)) {
        return false;
    }
    if (!inspect_active_destination(error)) return false;
    return runtime::AtomicWriteFile(
        active_marker(), id, error,
        runtime::ParentDirectoryPolicy::RequireExisting,
        runtime::FileProtection::OwnerOnly);
}

std::optional<client::ClientConfig> load(std::string const& id,
                                         std::string* error) {
    if (error) error->clear();
    if (!validate_id(id, error) || !ensure_profiles_directory(error)) {
        return std::nullopt;
    }
    std::string serialized;
    const auto path = profile_path(id);
    if (!runtime::read_text_file_bounded(
            path, kMaximumProfileBytes, &serialized, error)) {
        return std::nullopt;
    }
    return config_io::parse_client_json(serialized, path.parent_path(), error);
}

bool save(std::string const& id,
          std::string const& display_name,
          client::ClientConfig const& config,
          std::string* error) {
    if (error) error->clear();
    if (!validate_id(id, error) || !ensure_profiles_directory(error)) {
        return false;
    }
    runtime::FileTransactionLock lock;
    if (!lock.Acquire({mutation_resource()}, error)) return false;
    return save_locked(id, display_name, config, error);
}

bool remove(std::string const& id, std::string* error) {
    if (error) error->clear();
    if (!validate_id(id, error) || !ensure_profiles_directory(error)) {
        return false;
    }
    runtime::FileTransactionLock lock;
    if (!lock.Acquire({mutation_resource()}, error)) return false;

    std::string serialized;
    if (!runtime::read_text_file_bounded(
            profile_path(id), kMaximumProfileBytes, &serialized, error)) {
        return false;
    }
    std::string active;
    std::string active_error;
    if (!read_active_id(&active, &active_error)) {
        if (error) *error = active_error;
        return false;
    }
    if (active != id) {
        return runtime::DurableRemoveFile(profile_path(id), error);
    }

    if (!runtime::DurableRemoveFile(active_marker(), error)) return false;
    std::string profile_remove_error;
    if (runtime::DurableRemoveFile(profile_path(id), &profile_remove_error)) {
        return true;
    }

    std::error_code status_error;
    const auto profile_status = std::filesystem::symlink_status(
        profile_path(id), status_error);
    const bool profile_still_exists =
        !status_error &&
        profile_status.type() != std::filesystem::file_type::not_found;
    if (profile_still_exists) {
        const auto active_bytes = std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(id.data()), id.size());
        std::string restore_error;
        if (!security::WriteFileExclusive0600(
                active_marker(), active_bytes, &restore_error)) {
            if (error) {
                *error = profile_remove_error +
                         "; cannot restore active profile pointer: " +
                         restore_error;
            }
            return false;
        }
        if (error) {
            *error = profile_remove_error +
                     "; active profile pointer was restored";
        }
    } else if (error) {
        *error = profile_remove_error;
    }
    return false;
}

std::optional<std::string> create(std::string const& display_name,
                                  client::ClientConfig const& config,
                                  std::string* error) {
    if (error) error->clear();
    if (display_name.size() > kMaximumDisplayNameBytes) {
        if (error) *error = "profile display name exceeds 159 bytes";
        return std::nullopt;
    }
    if (!ensure_profiles_directory(error)) return std::nullopt;

    runtime::FileTransactionLock lock;
    if (!lock.Acquire({mutation_resource()}, error)) return std::nullopt;

    std::string base;
    try {
        base = slug_from(display_name);
    } catch (const std::exception& exception) {
        if (error) {
            *error = std::string("cannot generate profile id: ") + exception.what();
        }
        return std::nullopt;
    }
    std::string serialized;
    if (!serialize_profile(display_name, config, &serialized, error)) {
        return std::nullopt;
    }
    const auto bytes = std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(serialized.data()),
        serialized.size());
    for (unsigned suffix = 0; suffix <= kMaximumCollisionSuffix; ++suffix) {
        const std::string id = suffix == 0 ? base
                                           : collision_candidate(base, suffix);
        const auto path = profile_path(id);
        std::error_code status_error;
        const auto status = std::filesystem::symlink_status(path, status_error);
        const bool missing =
            status.type() == std::filesystem::file_type::not_found ||
            status_error == std::errc::no_such_file_or_directory;
        if (!missing && status_error) {
            if (error) {
                *error = "cannot inspect profile candidate: " +
                         status_error.message();
            }
            return std::nullopt;
        }
        if (!missing) {
            if (status.type() != std::filesystem::file_type::regular) {
                if (error) {
                    *error = "profile candidate must be a regular file";
                }
                return std::nullopt;
            }
            continue;
        }
        std::string create_error;
        if (security::WriteFileExclusive0600(path, bytes, &create_error)) {
            return id;
        }
        status_error.clear();
        const auto after = std::filesystem::symlink_status(path, status_error);
        const bool still_missing =
            after.type() == std::filesystem::file_type::not_found ||
            status_error == std::errc::no_such_file_or_directory;
        if (still_missing || status_error) {
            if (error) *error = create_error;
            return std::nullopt;
        }
        if (after.type() != std::filesystem::file_type::regular) {
            if (error) *error = "profile candidate must be a regular file";
            return std::nullopt;
        }
    }
    if (error) *error = "profile collision suffix attempts exhausted";
    return std::nullopt;
}

}  // namespace yume::facade::profiles
