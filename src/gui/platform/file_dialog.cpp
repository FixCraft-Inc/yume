/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "platform/file_dialog.hpp"

// On Apple targets the native AppKit pickers live in file_dialog_macos.mm,
// which CMake compiles instead of this file. The guard keeps this translation
// unit empty there as belt-and-suspenders against a double-add.
#if !defined(__APPLE__)

#include <array>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#if defined(_WIN32)
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <commdlg.h>
#else
#  include <unistd.h>
#  define GLFW_INCLUDE_NONE
#  include <GLFW/glfw3.h>
#  include <imgui.h>
#  include <imgui_impl_glfw.h>
#  include <imgui_impl_opengl3.h>
#  include <GL/gl.h>
#endif

namespace yume::gui::platform {

#if !defined(_WIN32)
GLFWwindow* g_dialog_window = nullptr;

void set_dialog_parent_window(void* glfw_window) {
    g_dialog_window = static_cast<GLFWwindow*>(glfw_window);
}

namespace {

struct ImGuiPickerState {
    bool save_mode{false};
    std::string title;
    std::string default_name;
    std::filesystem::path browse_dir;
    char path_buf[1024]{};
    bool finished{false};
    bool cancelled{false};
    std::optional<std::filesystem::path> result;
    std::vector<std::filesystem::path> entries;
};

void refresh_dir_list(ImGuiPickerState& st) {
    st.entries.clear();
    std::error_code ec;
    if (!std::filesystem::exists(st.browse_dir, ec)) {
        st.browse_dir = std::filesystem::current_path(ec);
    }
    for (auto const& entry : std::filesystem::directory_iterator(st.browse_dir, ec)) {
        st.entries.push_back(entry.path());
    }
    std::sort(st.entries.begin(), st.entries.end());
}

void render_picker_modal(ImGuiPickerState& st) {
    ImGui::SetNextWindowSize(ImVec2(520, 420), ImGuiCond_FirstUseEver);
    if (!ImGui::BeginPopupModal(st.save_mode ? "Save file##yume_picker"
                                             : "Open file##yume_picker",
                                nullptr,
                                ImGuiWindowFlags_NoCollapse)) {
        return;
    }
    if (!st.title.empty()) {
        ImGui::TextWrapped("%s", st.title.c_str());
        ImGui::Separator();
    }
    ImGui::Text("Folder: %s", st.browse_dir.string().c_str());
    if (ImGui::Button("Up")) {
        if (st.browse_dir.has_parent_path()) {
            st.browse_dir = st.browse_dir.parent_path();
            refresh_dir_list(st);
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Refresh")) {
        refresh_dir_list(st);
    }
    ImGui::SetNextItemWidth(-1);
    ImGui::InputText("Path", st.path_buf, sizeof(st.path_buf));
    ImGui::BeginChild("##picker_list", ImVec2(0, 220), ImGuiChildFlags_Border);
    for (auto const& entry : st.entries) {
        std::error_code ec;
        const bool is_dir = std::filesystem::is_directory(entry, ec);
        const std::string label =
            (is_dir ? "[dir] " : "      ") + entry.filename().string();
        if (ImGui::Selectable(label.c_str())) {
            if (is_dir) {
                st.browse_dir = entry;
                refresh_dir_list(st);
                std::strncpy(st.path_buf, entry.string().c_str(), sizeof(st.path_buf) - 1);
            } else {
                std::strncpy(st.path_buf, entry.string().c_str(), sizeof(st.path_buf) - 1);
            }
        }
    }
    ImGui::EndChild();
    if (ImGui::Button(st.save_mode ? "Save" : "Open", ImVec2(100, 0))) {
        if (st.path_buf[0] != 0) {
            st.result = std::filesystem::path(st.path_buf);
            st.finished = true;
            ImGui::CloseCurrentPopup();
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Cancel", ImVec2(100, 0))) {
        st.cancelled = true;
        st.finished = true;
        ImGui::CloseCurrentPopup();
    }
    ImGui::EndPopup();
}

std::optional<std::filesystem::path> run_imgui_picker(std::string const& title,
                                                       std::string const& default_name,
                                                       bool save_mode,
                                                       std::string* err) {
    if (!g_dialog_window || !ImGui::GetCurrentContext()) {
        if (err) *err = "internal file picker unavailable";
        return std::nullopt;
    }
    ImGuiPickerState st;
    st.save_mode = save_mode;
    st.title = title;
    st.default_name = default_name;
    std::error_code ec;
    st.browse_dir = std::filesystem::current_path(ec);
    if (save_mode && !default_name.empty()) {
        std::strncpy(st.path_buf, default_name.c_str(), sizeof(st.path_buf) - 1);
    } else {
        std::strncpy(st.path_buf, st.browse_dir.string().c_str(), sizeof(st.path_buf) - 1);
    }
    refresh_dir_list(st);
    const char* popup_id = save_mode ? "Save file##yume_picker" : "Open file##yume_picker";

    while (!st.finished && !glfwWindowShouldClose(g_dialog_window)) {
        glfwPollEvents();
        ImGui_ImplGlfw_NewFrame();
        ImGui_ImplOpenGL3_NewFrame();
        ImGui::NewFrame();
        if (!ImGui::IsPopupOpen(popup_id)) {
            ImGui::OpenPopup(popup_id);
        }
        render_picker_modal(st);
        ImGui::Render();
        int fbw = 0;
        int fbh = 0;
        glfwGetFramebufferSize(g_dialog_window, &fbw, &fbh);
        glViewport(0, 0, fbw, fbh);
        glClearColor(0.08f, 0.08f, 0.10f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(g_dialog_window);
    }
    if (st.cancelled) {
        if (err) *err = "file selection cancelled";
        return std::nullopt;
    }
    return st.result;
}

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

}  // namespace

#endif  // !defined(_WIN32)

#if defined(_WIN32)
void set_dialog_parent_window(void* /*glfw_window*/) {}
#endif

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
    return run_imgui_picker(title, {}, false, err);
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
    return run_imgui_picker(title, default_name, true, err);
#endif
}

}  // namespace yume::gui::platform

#endif  // !__APPLE__
