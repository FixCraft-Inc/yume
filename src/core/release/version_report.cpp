/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/release/version_report.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <exception>
#include <future>
#include <optional>
#include <string_view>
#include <utility>

#include <openssl/crypto.h>
#include <openssl/opensslv.h>

#include "core/release/github_client.hpp"
#include "core/security/inner_crypto.hpp"
#include "core/version.hpp"

// liboqs reaches this file through YUME's own dependency edge (yume_liboqs),
// inherited from yume_secure_core. It does not depend on BaseFWX's build.
#if defined(YUME_HAS_OQS) && YUME_HAS_OQS
#include <oqs/oqs.h>
#endif

namespace yume::release {
namespace {

struct ProjectInput {
    std::string name;
    std::string installed_version;
    GitHubProject github;
};

std::optional<bool> read_boolean_env(const char* name) {
    const char* raw = std::getenv(name);
    if (!raw || !*raw) {
        return std::nullopt;
    }
    std::string value(raw);
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    if (value == "1" || value == "true" || value == "yes" || value == "on") {
        return true;
    }
    if (value == "0" || value == "false" || value == "no" || value == "off") {
        return false;
    }
    return std::nullopt;
}

ComponentStatus unchecked_status(const ProjectInput& project, std::string note) {
    return evaluate_version_status(project.name, project.installed_version,
                                   std::nullopt, std::nullopt, std::move(note));
}

ComponentStatus checked_status(const ProjectInput& project) {
    try {
        RemoteProjectInfo remote = query_github_project(
            project.github, project.installed_version);
        return evaluate_version_status(
            project.name, project.installed_version,
            remote.latest_stable_release, remote.highest_version_tag,
            std::move(remote.error));
    } catch (const std::exception&) {
        return unchecked_status(project, "Update check unavailable");
    }
}

PqBuildInfo collect_pq_build_info() {
    PqBuildInfo info;
    info.available = yume::inner::pq_supported();
    if (!info.available) {
        info.provider = "Not compiled";
        return info;
    }
    info.provider = "liboqs";
#if defined(YUME_HAS_OQS) && YUME_HAS_OQS && defined(OQS_VERSION_TEXT)
    info.version = OQS_VERSION_TEXT;
#endif
    info.algorithms = "ML-KEM-768, ML-KEM-1024";
    return info;
}

std::string openssl_version_string() {
#if defined(OPENSSL_VERSION_STR)
    return OPENSSL_VERSION_STR;
#else
    const std::string full = OpenSSL_version(OPENSSL_VERSION);
    constexpr std::string_view kPrefix = "OpenSSL ";
    if (full.rfind(kPrefix, 0) != 0) return full;
    const std::size_t begin = kPrefix.size();
    const std::size_t end = full.find(' ', begin);
    return full.substr(begin, end == std::string::npos ? end : end - begin);
#endif
}

std::string openssl_release_date_string() {
#if defined(OPENSSL_RELEASE_DATE)
    return OPENSSL_RELEASE_DATE;
#else
    return {};
#endif
}

}  // namespace

bool update_check_enabled() {
    if (read_boolean_env("YUME_NO_UPDATE_CHECK").value_or(false)) {
        return false;
    }
    return read_boolean_env("YUME_UPDATE_CHECK").value_or(false);
}

VersionReport collect_version_report(bool check_updates) {
    VersionReport report;
    report.openssl_version = openssl_version_string();
    report.openssl_release_date = openssl_release_date_string();
    report.pq = collect_pq_build_info();
    report.inner_suite = "ML-KEM-1024 + X25519 + HKDF-SHA256 + AES-256-GCM";
    report.update_check_attempted = check_updates;

    std::vector<ProjectInput> projects = {
        {"Yume", std::string(yume::kVersion), {"FixCraft-Inc", "yume"}},
        {"BaseFWX", std::string(yume::kBasefwxVersion), {"F1xGOD", "basefwx"}},
    };
    if (report.pq.available && !report.pq.version.empty()) {
        projects.push_back(
            {"liboqs", report.pq.version, {"open-quantum-safe", "liboqs"}});
    } else {
        ProjectInput liboqs{"liboqs", "Not compiled", {"open-quantum-safe", "liboqs"}};
        report.components.push_back(
            unchecked_status(liboqs, "No comparable compiled liboqs version"));
    }

    if (!check_updates) {
        for (const auto& project : projects) {
            report.components.push_back(
                unchecked_status(project, "Update check not requested"));
        }
    } else {
        std::vector<std::future<ComponentStatus>> futures;
        futures.reserve(projects.size());
        for (const auto& project : projects) {
            futures.push_back(std::async(std::launch::async, [project] {
                return checked_status(project);
            }));
        }
        for (auto& future : futures) {
            try {
                report.components.push_back(future.get());
            } catch (const std::exception&) {
                ComponentStatus status;
                status.name = "Unknown component";
                status.installed_version = "Unknown";
                status.note = "Update-check worker unavailable";
                report.components.push_back(std::move(status));
            }
        }
    }

    // The unavailable-liboqs row is inserted early; keep the public ordering
    // stable for CLI and future GUI consumers.
    const auto rank = [](std::string_view name) {
        if (name == "Yume") return 0;
        if (name == "BaseFWX") return 1;
        if (name == "liboqs") return 2;
        return 3;
    };
    std::stable_sort(report.components.begin(), report.components.end(),
                     [&](const ComponentStatus& lhs, const ComponentStatus& rhs) {
                         return rank(lhs.name) < rank(rhs.name);
                     });
    return report;
}

}  // namespace yume::release
