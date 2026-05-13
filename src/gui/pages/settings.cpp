/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "pages/page.hpp"

#include <imgui.h>

#include "facade/config_io.hpp"
#include "theme/theme.hpp"
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
            theme::apply_material3(dark ? theme::Mode::Dark : theme::Mode::Light);
            ui::apply_style(ui::scale(), dark);
            // Persist so the next launch opens in the same mode.
            facade::config_io::GuiPreferences prefs;
            prefs.dark_mode = dark;
            facade::config_io::save_gui_preferences(prefs);
        }

        ui::section_label("Window");
#if YUME_GUI_TRAY
        ImGui::TextColored(p.muted,
                           "System tray is available. Close minimises to tray.");
#else
        ImGui::TextColored(p.muted,
                           "System tray is not available on this build.");
#endif

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
