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

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <commdlg.h>
#else
#  include <unistd.h>
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
    // Convert UTF-8 title to wide so the picker shows non-ASCII labels.
    std::wstring wtitle;
    if (!title.empty()) {
        int n = MultiByteToWideChar(CP_UTF8, 0, title.c_str(),
                                    static_cast<int>(title.size()),
                                    nullptr, 0);
        if (n > 0) {
            wtitle.resize(static_cast<std::size_t>(n));
            MultiByteToWideChar(CP_UTF8, 0, title.c_str(),
                                static_cast<int>(title.size()),
                                wtitle.data(), n);
        }
    }
    wchar_t buf[MAX_PATH]{};
    OPENFILENAMEW ofn{};
    ofn.lStructSize     = sizeof(ofn);
    ofn.hwndOwner       = GetForegroundWindow();
    ofn.lpstrFile       = buf;
    ofn.nMaxFile        = MAX_PATH;
    ofn.lpstrFilter     = L"All files\0*.*\0";
    ofn.lpstrTitle      = wtitle.empty() ? nullptr : wtitle.c_str();
    ofn.Flags           = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST |
                          OFN_NOCHANGEDIR | OFN_EXPLORER;
    if (!GetOpenFileNameW(&ofn)) {
        DWORD ext = CommDlgExtendedError();
        if (err && ext != 0) {
            char msg[64];
            std::snprintf(msg, sizeof(msg), "file picker error 0x%lx",
                          static_cast<unsigned long>(ext));
            *err = msg;
        }
        return std::nullopt;
    }
    // Back from wide to UTF-8 for the std::filesystem::path constructor.
    int len = WideCharToMultiByte(CP_UTF8, 0, buf, -1,
                                  nullptr, 0, nullptr, nullptr);
    std::string utf8;
    if (len > 1) {
        utf8.resize(static_cast<std::size_t>(len - 1));
        WideCharToMultiByte(CP_UTF8, 0, buf, -1,
                            utf8.data(), len, nullptr, nullptr);
    }
    return std::filesystem::path(utf8);
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

std::optional<std::filesystem::path> save_file_dialog(std::string const& title,
                                                       std::string const& default_name,
                                                       std::string* err) {
#if defined(_WIN32)
    std::wstring wtitle;
    if (!title.empty()) {
        int n = MultiByteToWideChar(CP_UTF8, 0, title.c_str(),
                                    static_cast<int>(title.size()),
                                    nullptr, 0);
        if (n > 0) {
            wtitle.resize(static_cast<std::size_t>(n));
            MultiByteToWideChar(CP_UTF8, 0, title.c_str(),
                                static_cast<int>(title.size()),
                                wtitle.data(), n);
        }
    }
    wchar_t buf[MAX_PATH]{};
    if (!default_name.empty()) {
        int n = MultiByteToWideChar(CP_UTF8, 0, default_name.c_str(),
                                    static_cast<int>(default_name.size()),
                                    buf, MAX_PATH - 1);
        if (n < 0) n = 0;
    }
    OPENFILENAMEW ofn{};
    ofn.lStructSize  = sizeof(ofn);
    ofn.hwndOwner    = GetForegroundWindow();
    ofn.lpstrFile    = buf;
    ofn.nMaxFile     = MAX_PATH;
    ofn.lpstrFilter  = L"Yume secure store\0*.yss\0All files\0*.*\0";
    ofn.lpstrTitle   = wtitle.empty() ? nullptr : wtitle.c_str();
    ofn.Flags        = OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR |
                        OFN_OVERWRITEPROMPT | OFN_EXPLORER;
    ofn.lpstrDefExt  = L"yss";
    if (!GetSaveFileNameW(&ofn)) {
        DWORD ext = CommDlgExtendedError();
        if (err && ext != 0) {
            char msg[64];
            std::snprintf(msg, sizeof(msg), "save picker error 0x%lx",
                          static_cast<unsigned long>(ext));
            *err = msg;
        }
        return std::nullopt;
    }
    int len = WideCharToMultiByte(CP_UTF8, 0, buf, -1,
                                  nullptr, 0, nullptr, nullptr);
    std::string utf8;
    if (len > 1) {
        utf8.resize(static_cast<std::size_t>(len - 1));
        WideCharToMultiByte(CP_UTF8, 0, buf, -1,
                            utf8.data(), len, nullptr, nullptr);
    }
    return std::filesystem::path(utf8);
#else
    const std::string filename_arg = default_name.empty() ? std::string{} : default_name;
    if (auto zenity = path_lookup("zenity")) {
        std::string cmd = shell_quote(zenity->string()) +
            " --file-selection --save --confirm-overwrite --title=" + shell_quote(title);
        if (!filename_arg.empty()) cmd += " --filename=" + shell_quote(filename_arg);
        auto picked = run_picker(cmd, err);
        if (picked) return std::filesystem::path(*picked);
        return std::nullopt;
    }
    if (auto kdialog = path_lookup("kdialog")) {
        std::string cmd = shell_quote(kdialog->string()) + " --getsavefilename " +
            (filename_arg.empty() ? std::string(".") : shell_quote(filename_arg)) +
            " --title " + shell_quote(title);
        auto picked = run_picker(cmd, err);
        if (picked) return std::filesystem::path(*picked);
        return std::nullopt;
    }
    if (auto yad = path_lookup("yad")) {
        std::string cmd = shell_quote(yad->string()) +
            " --file-selection --save --confirm-overwrite --title=" + shell_quote(title);
        if (!filename_arg.empty()) cmd += " --filename=" + shell_quote(filename_arg);
        auto picked = run_picker(cmd, err);
        if (picked) return std::filesystem::path(*picked);
        return std::nullopt;
    }
    if (err) *err = "install zenity, kdialog, or yad to use the save-as picker";
    return std::nullopt;
#endif
}

}  // namespace yume::gui::platform
