/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "pages/page.hpp"

#include <imgui.h>

#include "facade/config/config_io.hpp"
#include "facade/config/gui_preferences.hpp"
#include "ui/design.hpp"

namespace yume::gui {

namespace {

class SettingsPage : public Page {
public:
    std::string_view title() const override { return "Settings"; }

    void render(AppContext& ctx) override {
        auto const& p = ui::colors();

        ui::section_label("Appearance");
        bool dark = ctx.dark_mode;
        if (ui::checkbox("Use dark theme", &dark)) {
            ctx.dark_mode = dark;
            ui::apply_style(ui::scale(), dark);
            facade::config_io::GuiPreferences prefs =
                facade::config_io::load_gui_preferences();
            prefs.dark_mode = dark;
            facade::config_io::save_gui_preferences(prefs);
        }

        ui::section_label("Window");
        bool minimize = ctx.minimize_to_tray_on_close;
        if (!ctx.tray_available) ImGui::BeginDisabled();
        if (ui::checkbox("Minimize to tray on close", &minimize)) {
            ctx.minimize_to_tray_on_close = minimize;
            facade::config_io::GuiPreferences prefs =
                facade::config_io::load_gui_preferences();
            prefs.minimize_to_tray_on_close = minimize;
            facade::config_io::save_gui_preferences(prefs);
        }
        if (!ctx.tray_available) {
            ImGui::EndDisabled();
            if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) {
                ImGui::SetTooltip("System tray is not available on this system.");
            }
            ImGui::TextColored(p.muted,
                               "System tray is not available on this build.");
        } else {
            ImGui::TextColored(p.muted,
                               "When enabled, closing the window hides Yume in the tray.");
        }

        ui::section_label("Data");
        ImGui::TextColored(p.muted, "Configs and keys live in:");
        ImGui::TextWrapped("%s",
                           facade::config_io::default_data_dir().string().c_str());
    }
};

}  // namespace

std::unique_ptr<Page> make_settings_page() {
    return std::make_unique<SettingsPage>();
}

}  // namespace yume::gui
