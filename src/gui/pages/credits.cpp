/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
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
    {"Codex",
     "Primary AI engineering partner",
     "Architecture, implementation, security hardening, testing, and"
     " documentation across Yume, BaseFWX, desktop, and Android."},
    {"Claude",
     "Supporting AI contributor",
     "Selected code reviews, refactors, and bug-fix contributions."},
};

constexpr Component kComponentsAll[] = {
    {"BaseFWX",
     "Key-wiping buffers, Argon2id/PBKDF2/HKDF, AEAD, X25519 and ML-KEM wrappers, and the .yss share container.",
     "LGPL-3.0-or-later"},
    {"liboqs (Open Quantum Safe)",
     "ML-KEM implementation: linked directly for key generation, reached through BaseFWX for encapsulation.",
     "MIT"},
    {"OpenSSL",
     "TLS 1.3, X.509, classical primitives, and the ML-DSA-87 signature provider.",
     "Apache-2.0"},
    {"Yume OpenSSL patch overlay",
     "Downstream patches for the Chrome-shaped TLS backend.",
     "AGPL-3.0-or-later"},
};

// Compiled into every desktop binary (CLI + GUI). Not present on Android,
// which uses JVM/Conscrypt equivalents.
constexpr Component kComponentsDesktopCore[] = {
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

struct Quote {
    char const* label;   // null = stack under the previous entry's label
    char const* text;
};

// Mirrors the Android Credits screen's "Recognition" + "From F1xGOD"
// block. Both quotes are authored content and don't get translated by
// the desktop GUI (the desktop is English-only today; Android handles
// i18n through AppStrings).
constexpr Quote kQuotes[] = {
    {"Recognition",
     "\"Credit is only fair when everyone has their place, and AI"
     " deserves to be recognized too.\""},
    {nullptr,
     "\"Judge the code, not the coder.\""},
    {"From F1xGOD",
     "\"Building on open source is one of the most empowering"
     " experiences in software development. You do not have to wait"
     " for someone else to fix an issue or add a feature — you can"
     " build the solution yourself.\""},
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

        // ---- Quotes (mirrors Android's CreditsScreen bottom card) ----
        if (ui::begin_auto_card("##credits_quotes")) {
            for (std::size_t i = 0; i < std::size(kQuotes); ++i) {
                auto const& q = kQuotes[i];

                if (q.label != nullptr) {
                    // New label starts a new logical group. Add a bit of
                    // breathing room above it when it isn't the first row.
                    if (i > 0) ImGui::Dummy(ImVec2(0, 6 * sc));

                    if (ui::fonts().small) ImGui::PushFont(ui::fonts().small);
                    ImGui::PushStyleColor(ImGuiCol_Text, c.muted);
                    ImGui::TextUnformatted(q.label);
                    ImGui::PopStyleColor();
                    if (ui::fonts().small) ImGui::PopFont();

                    ImGui::Dummy(ImVec2(0, 4 * sc));
                } else {
                    // Continuation quote under the previous label — small
                    // gap so it reads as the next bullet, not a new section.
                    ImGui::Dummy(ImVec2(0, 4 * sc));
                }

                ImFont* quote_font = ui::fonts().body_italic
                                         ? ui::fonts().body_italic
                                         : ui::fonts().body;
                if (quote_font) ImGui::PushFont(quote_font);
                ImGui::TextWrapped("%s", q.text);
                if (quote_font) ImGui::PopFont();
            }
        }
        ui::end_card();
        ImGui::Dummy(ImVec2(0, 8 * sc));
    }
};

}  // namespace

std::unique_ptr<Page> make_credits_page() {
    return std::make_unique<CreditsPage>();
}

}  // namespace yume::gui
