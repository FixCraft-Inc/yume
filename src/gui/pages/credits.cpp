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

// Anything that ships with every Yume implementation gets this scope.
// Anything that only ships with this binary gets the GUI-only scope.
constexpr char const* kScopeAll = "Used in every implementation of Yume.";
constexpr char const* kScopeGui = "Used only in the GUI implementation of Yume.";

struct Person {
    char const* name;
    char const* title;
    char const* role;
};

struct Component {
    char const* name;
    char const* scope;
    char const* role;
    char const* license;
};

constexpr Person kPeople[] = {
    {"F1xGOD",
     "Founder & CEO, FixCraft, Inc.",
     "Author. Lead developer and designer."},
    {"ChatGPT / Codex",
     "#1 Best Employee of the Year",
     "Debug support and fast implementation help for the author."},
};

// Order: core libraries (used in every implementation) first, then
// GUI-only ones. Within each group, alphabetical.
constexpr Component kComponents[] = {
    {"BaseFWX", kScopeAll,
     "The core Yume crypto engine - outer auth, inner post-quantum tunnel, key formats.",
     "GPL-3.0"},
    {"liboqs (Open Quantum Safe)", kScopeAll,
     "Post-quantum primitives (ML-KEM, ML-DSA) consumed through BaseFWX.",
     "MIT"},
    {"Boost (ASIO, system)", kScopeAll,
     "Network IO and the async runtime used by the relay and client.",
     "Boost Software License 1.0"},
    {"OpenSSL", kScopeAll,
     "TLS transport, X.509, and the classical crypto primitives.",
     "Apache-2.0"},
    {"nlohmann/json", kScopeAll,
     "JSON parsing and serialization for configs and protocol payloads.",
     "MIT"},
    {"spdlog", kScopeAll,
     "Structured logging.",
     "MIT"},
    {"zstd", kScopeAll,
     "Optional inner-frame compression.",
     "BSD-3-Clause"},

    {"Dear ImGui", kScopeGui,
     "Immediate-mode UI framework that draws every panel in this app.",
     "MIT"},
    {"GLFW", kScopeGui,
     "Window, OpenGL context, and input on Linux / Windows / macOS.",
     "zlib"},
    {"ImPlot", kScopeGui,
     "Plotting library (kept available for future charts).",
     "MIT"},
    {"FreeType", kScopeGui,
     "Font rasterisation used for the UI text.",
     "FTL or GPLv2"},
    {"NanoSVG", kScopeGui,
     "Rasterises the app icon SVG to multi-size window icons.",
     "zlib"},
    {"stb_image_write", kScopeGui,
     "PNG export of the rasterised icon at first launch.",
     "Public domain / MIT"},
    {"libayatana-appindicator", kScopeGui,
     "Linux system tray indicator (StatusNotifierItem bridge).",
     "LGPL-3.0"},
};

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
            ui::section_label("Author");
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
                ImGui::Dummy(ImVec2(0, 8 * sc));
            }
        }
        ui::end_card();

        ImGui::Dummy(ImVec2(0, 8 * sc));

        // ---- Components ----
        if (ui::begin_auto_card("##credits_components")) {
            ui::section_label("Open-source components");
            ImGui::PushStyleColor(ImGuiCol_Text, c.muted);
            ImGui::TextWrapped(
                "Third-party code Yume builds on, with licences. "
                "Each entry says where it actually runs.");
            ImGui::PopStyleColor();
            ImGui::Dummy(ImVec2(0, 8 * sc));

            for (auto const& comp : kComponents) {
                if (ui::fonts().strong) ImGui::PushFont(ui::fonts().strong);
                ImGui::TextUnformatted(comp.name);
                if (ui::fonts().strong) ImGui::PopFont();

                ImGui::PushStyleColor(ImGuiCol_Text, c.accent);
                ImGui::TextUnformatted(comp.scope);
                ImGui::PopStyleColor();

                ImGui::PushStyleColor(ImGuiCol_Text, c.muted);
                ImGui::TextWrapped("%s", comp.role);
                ImGui::PopStyleColor();

                ui::status_pill(comp.license, c.outline);
                ImGui::Dummy(ImVec2(0, 10 * sc));
            }
        }
        ui::end_card();
    }
};

}  // namespace

std::unique_ptr<Page> make_credits_page() {
    return std::make_unique<CreditsPage>();
}

}  // namespace yume::gui
