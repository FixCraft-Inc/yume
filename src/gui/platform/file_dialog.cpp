/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "platform/file_dialog.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>

#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace yume::gui::platform {

namespace {

#if !defined(_WIN32)
std::optional<std::filesystem::path> path_lookup(char const* name) {
    char const* raw = std::getenv("PATH");
    if (!raw || !*raw) return std::nullopt;
    std::string paths(raw);
    std::size_t start = 0;
    while (start <= paths.size()) {
        std::size_t end = paths.find(':', start);
        std::string part = paths.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (!part.empty()) {
            std::filesystem::path candidate = std::filesystem::path(part) / name;
            if (::access(candidate.c_str(), X_OK) == 0) return candidate;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return std::nullopt;
}

std::string shell_quote(std::string const& value) {
    std::string out = "'";
    for (char ch : value) {
        if (ch == '\'') out += "'\\''";
        else out.push_back(ch);
    }
    out += "'";
    return out;
}

std::optional<std::string> run_picker(std::string const& command, std::string* err) {
    std::array<char, 512> buf{};
    std::string out;
    FILE* pipe = ::popen(command.c_str(), "r");
    if (!pipe) {
        if (err) *err = "could not start file picker";
        return std::nullopt;
    }
    while (std::fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
        out += buf.data();
    }
    int rc = ::pclose(pipe);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) {
        out.pop_back();
    }
    if (out.empty()) {
        if (err && rc != 0) *err = "file selection cancelled";
        return std::nullopt;
    }
    return out;
}
#endif

}  // namespace

std::optional<std::filesystem::path> open_file_dialog(std::string const& title,
                                                       std::string* err) {
#if defined(_WIN32)
    if (err) *err = "native file picker is not implemented on Windows yet";
    (void)title;
    return std::nullopt;
#else
    if (auto zenity = path_lookup("zenity")) {
        auto picked = run_picker(
            shell_quote(zenity->string()) + " --file-selection --title=" + shell_quote(title),
            err);
        if (picked) return std::filesystem::path(*picked);
        return std::nullopt;
    }
    if (auto kdialog = path_lookup("kdialog")) {
        auto picked = run_picker(
            shell_quote(kdialog->string()) + " --getopenfilename . --title " + shell_quote(title),
            err);
        if (picked) return std::filesystem::path(*picked);
        return std::nullopt;
    }
    if (auto yad = path_lookup("yad")) {
        auto picked = run_picker(
            shell_quote(yad->string()) + " --file-selection --title=" + shell_quote(title),
            err);
        if (picked) return std::filesystem::path(*picked);
        return std::nullopt;
    }
    if (err) *err = "install zenity, kdialog, or yad to use the file picker";
    return std::nullopt;
#endif
}

}  // namespace yume::gui::platform
