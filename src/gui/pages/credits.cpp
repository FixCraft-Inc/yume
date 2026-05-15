/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "pages/page.hpp"

#include <imgui.h>

#include "ui/design.hpp"

namespace yume::gui {

namespace {

struct Person {
    char const* name;
    char const* title;
    char const* role;
};

struct Component {
    char const* name;
    char const* role;
    char const* license;
};

struct ComponentGroup {
    char const* heading;
    char const* blurb;
    Component const* items;
    std::size_t count;
};

constexpr Person kPeople[] = {
    {"F1xGOD",
     "Founder & CEO, FixCraft, Inc.",
     "Author. Lead developer and designer of Yume and BaseFWX."},
    {"Claude (Anthropic)",
     "#1 Yume / BaseFWX engineering partner",
     "Dedicated dev on Yume and BaseFWX. Helps with code review, design,"
     " refactors, packaging, and tricky bugs."},
    {"ChatGPT / Codex",
     "Best Employee of the Year",
     "Generalist debug and implementation support across many projects."},
};

constexpr Component kComponentsAll[] = {
    {"BaseFWX",
     "The core Yume crypto engine - outer auth, inner post-quantum tunnel, key formats.",
     "GPL-3.0"},
    {"liboqs (Open Quantum Safe)",
     "Post-quantum primitives (ML-KEM, ML-DSA) consumed through BaseFWX.",
     "MIT"},
};

// Compiled into every desktop binary (CLI + GUI). Not present on Android,
// which uses JVM/Conscrypt equivalents.
constexpr Component kComponentsDesktopCore[] = {
    {"OpenSSL",
     "TLS transport, X.509 parsing, and classical crypto primitives.",
     "Apache-2.0"},
    {"Boost (ASIO, system)",
     "Async network IO that drives the relay, client, and server.",
     "Boost Software License 1.0"},
    {"nlohmann/json",
     "JSON parsing and serialization for configs and protocol payloads.",
     "MIT"},
    {"spdlog",
     "Structured logging across the daemon and CLI.",
     "MIT"},
    {"zstd",
     "Optional inner-frame compression.",
     "BSD-3-Clause"},
};

// Only ever linked into the yume-gui executable.
constexpr Component kComponentsGuiOnly[] = {
    {"Dear ImGui",
     "Immediate-mode UI framework that draws every panel in this app.",
     "MIT"},
    {"GLFW",
     "Window, OpenGL context, and input on Linux / Windows / macOS.",
     "zlib"},
    {"ImPlot",
     "Plotting library kept available for future charts.",
     "MIT"},
    {"FreeType",
     "Font rasterisation for the UI text.",
     "FTL or GPLv2"},
    {"NanoSVG",
     "Rasterises the app icon SVG to multi-size window icons.",
     "zlib"},
    {"stb_image_write",
     "PNG export of the rasterised icon at first launch.",
     "Public domain / MIT"},
    {"libayatana-appindicator",
     "Linux system tray indicator (StatusNotifierItem bridge).",
     "LGPL-3.0"},
    {"Jost",
     "Bundled UI typeface so the GUI renders consistently on every OS"
     " without depending on the host font catalogue. Permissively-licensed"
     " Futura clone that matches the URW Gothic look we originally used"
     " on Linux.",
     "SIL OFL 1.1"},
};

constexpr ComponentGroup kGroups[] = {
    {"Used in every implementation of Yume",
     "Shared by the desktop client, the daemon, and the Android app.",
     kComponentsAll, std::size(kComponentsAll)},
    {"Used in the desktop client and daemon",
     "Linked into the C++ CLI and the desktop GUI. The Android app uses"
     " JVM/Conscrypt equivalents instead.",
     kComponentsDesktopCore, std::size(kComponentsDesktopCore)},
    {"Used only in the desktop GUI",
     "Linked only into yume-gui.",
     kComponentsGuiOnly, std::size(kComponentsGuiOnly)},
};

void license_chip(char const* text) {
    auto const& c = ui::colors();
    ImFont* font = ui::fonts().strong ? ui::fonts().strong : ImGui::GetFont();
    const float font_size = font ? font->FontSize : ImGui::GetFontSize();
    const ImVec2 ts = font
        ? font->CalcTextSizeA(font_size, FLT_MAX, 0.0f, text)
        : ImGui::CalcTextSize(text);
    const float pad_x = ImGui::GetFontSize() * 0.7f;
    const float pad_y = ImGui::GetFontSize() * 0.3f;
    ImVec2 origin = ImGui::GetCursorScreenPos();
    ImVec2 size(ts.x + pad_x * 2, ts.y + pad_y * 2);
    ImDrawList* dl = ImGui::GetWindowDrawList();
    // Brighter background — surface_high reads as a clear chip on the
    // card surface; outline-coloured text was barely legible.
    dl->AddRectFilled(origin, ImVec2(origin.x + size.x, origin.y + size.y),
                      ImGui::GetColorU32(c.surface_high),
                      size.y * 0.5f);
    dl->AddRect(origin, ImVec2(origin.x + size.x, origin.y + size.y),
                ImGui::GetColorU32(c.outline),
                size.y * 0.5f, 0, 1.0f);
    dl->AddText(font, font_size,
                ImVec2(origin.x + pad_x, origin.y + pad_y),
                ImGui::GetColorU32(c.text), text);
    ImGui::Dummy(size);
}

void render_component(Component const& comp, float sc) {
    auto const& c = ui::colors();
    if (ui::fonts().strong) ImGui::PushFont(ui::fonts().strong);
    ImGui::TextUnformatted(comp.name);
    if (ui::fonts().strong) ImGui::PopFont();
    ImGui::PushStyleColor(ImGuiCol_Text, c.muted);
    ImGui::TextWrapped("%s", comp.role);
    ImGui::PopStyleColor();
    license_chip(comp.license);
    ImGui::Dummy(ImVec2(0, 12 * sc));
}

class CreditsPage : public Page {
public:
    std::string_view title() const override { return "Credits"; }

    void render(AppContext& /*ctx*/) override {
        auto const& c = ui::colors();
        const float sc = ui::scale();

        ui::page_header("Credits",
                        "The people and open-source code that ship inside Yume.");

        // ---- People ----
        if (ui::begin_auto_card("##credits_people")) {
            ui::section_label("Author and contributors");
            for (auto const& p : kPeople) {
                if (ui::fonts().strong) ImGui::PushFont(ui::fonts().strong);
                ImGui::TextUnformatted(p.name);
                if (ui::fonts().strong) ImGui::PopFont();
                ImGui::PushStyleColor(ImGuiCol_Text, c.accent);
                ImGui::TextUnformatted(p.title);
                ImGui::PopStyleColor();
                ImGui::PushStyleColor(ImGuiCol_Text, c.muted);
                ImGui::TextWrapped("%s", p.role);
                ImGui::PopStyleColor();
                ImGui::Dummy(ImVec2(0, 10 * sc));
            }
        }
        ui::end_card();
        ImGui::Dummy(ImVec2(0, 8 * sc));

        // ---- Components in three explicit scope groups ----
        for (auto const& group : kGroups) {
            // ImGui requires unique child IDs. Use the heading pointer as
            // a stable, unique discriminator without string allocation.
            char id[64];
            std::snprintf(id, sizeof(id), "##group_%p", (void const*)group.heading);
            if (ui::begin_auto_card(id)) {
                if (ui::fonts().section) ImGui::PushFont(ui::fonts().section);
                ImGui::TextUnformatted(group.heading);
                if (ui::fonts().section) ImGui::PopFont();
                ImGui::PushStyleColor(ImGuiCol_Text, c.muted);
                ImGui::TextWrapped("%s", group.blurb);
                ImGui::PopStyleColor();
                ImGui::Dummy(ImVec2(0, 12 * sc));

                for (std::size_t i = 0; i < group.count; ++i) {
                    render_component(group.items[i], sc);
                }
            }
            ui::end_card();
            ImGui::Dummy(ImVec2(0, 8 * sc));
        }
    }
};

}  // namespace

std::unique_ptr<Page> make_credits_page() {
    return std::make_unique<CreditsPage>();
}

}  // namespace yume::gui
