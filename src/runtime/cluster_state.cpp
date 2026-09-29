/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/cluster_state.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <new>
#include <span>
#include <system_error>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "fs/secret_file.hpp"

namespace yume::runtime::cluster {
namespace {

using engine::Result;
using engine::Status;
using engine::StatusCode;
using Json = nlohmann::json;

bool is_fingerprint(const std::string& value) noexcept {
    return value.size() == 64U &&
           std::all_of(value.begin(), value.end(), [](char character) {
               return (character >= '0' && character <= '9') ||
                      (character >= 'a' && character <= 'f');
           });
}

Result<std::optional<SavedState>> refused(const char* message) {
    return Result<std::optional<SavedState>>(
        Status::diagnostic(StatusCode::InvalidArgument, message));
}

}  // namespace

Result<std::optional<SavedState>> read_state(
    const std::filesystem::path& path) noexcept {
    try {
        std::error_code error;
        const auto status = std::filesystem::symlink_status(path, error);
        if (status.type() == std::filesystem::file_type::not_found) {
            return Result<std::optional<SavedState>>(
                std::optional<SavedState>());
        }
        if (error) return refused("the cluster state file cannot be inspected");
        std::vector<std::uint8_t> bytes;
        try {
            bytes = security::read_private_file_strict(path, kMaxStateBytes,
                                                       "cluster state");
        } catch (const std::bad_alloc&) {
            throw;
        } catch (...) {
            return refused(
                "the cluster state file is not a private regular file of this "
                "user");
        }
        const auto document =
            Json::parse(bytes.begin(), bytes.end(), nullptr, false);
        if (!document.is_object() || document.size() != 3U ||
            !document.contains("schema") || !document.contains("cluster") ||
            !document.contains("serial") ||
            !document["schema"].is_number_unsigned() ||
            document["schema"].get<std::uint64_t>() != 1U ||
            !document["cluster"].is_string() ||
            !document["serial"].is_number_unsigned()) {
            return refused("the cluster state file is malformed");
        }
        SavedState state{document["cluster"].get<std::string>(),
                         document["serial"].get<std::uint64_t>()};
        if (!is_fingerprint(state.cluster) || state.serial == 0U) {
            return refused("the cluster state file is malformed");
        }
        return Result<std::optional<SavedState>>(
            std::optional<SavedState>(std::move(state)));
    } catch (const std::bad_alloc&) {
        return Result<std::optional<SavedState>>(
            Status(StatusCode::ResourceExhausted));
    } catch (...) {
        return Result<std::optional<SavedState>>(Status(StatusCode::Internal));
    }
}

Status write_state(const std::filesystem::path& path,
                   const SavedState& state) noexcept {
    try {
        if (!is_fingerprint(state.cluster) || state.serial == 0U) {
            return Status(StatusCode::InvalidArgument);
        }
        const std::string text = Json{{"schema", 1},
                                      {"cluster", state.cluster},
                                      {"serial", state.serial}}
                                     .dump() +
                                 "\n";
        auto next = path;
        next += ".new";
        // A file left by an interrupted write is replaced.
        if (::unlink(next.c_str()) != 0 && errno != ENOENT) {
            return Status::diagnostic(
                StatusCode::FailedPrecondition,
                "the cluster state file cannot be replaced");
        }
        std::string error;
        const auto* data = reinterpret_cast<const std::uint8_t*>(text.data());
        if (!security::WriteFileExclusive0600(
                next, std::span<const std::uint8_t>(data, text.size()), &error,
                security::PrivateParentPolicy::RequireExisting)) {
            return Status::diagnostic(
                StatusCode::FailedPrecondition,
                "the cluster state file cannot be written: " + error);
        }
        if (std::rename(next.c_str(), path.c_str()) != 0) {
            (void)::unlink(next.c_str());
            return Status::diagnostic(
                StatusCode::FailedPrecondition,
                "the cluster state file cannot be replaced");
        }
        auto parent = path.parent_path();
        if (parent.empty()) parent = ".";
        const int directory =
            ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        const bool flushed = directory >= 0 && ::fsync(directory) == 0;
        if (directory >= 0) (void)::close(directory);
        if (!flushed) {
            return Status::diagnostic(
                StatusCode::FailedPrecondition,
                "the cluster state directory cannot be flushed");
        }
        return Status::success();
    } catch (const std::bad_alloc&) {
        return Status(StatusCode::ResourceExhausted);
    } catch (...) {
        return Status(StatusCode::Internal);
    }
}

}  // namespace yume::runtime::cluster
