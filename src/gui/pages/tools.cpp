/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "pages/page.hpp"

#include <limits>
#include <vector>

#include <imgui.h>

#include "ui/design.hpp"

namespace yume::gui {

namespace {

class ToolsPage : public Page {
public:
    ToolsPage() {
        pages_.push_back(make_keys_page());
        pages_.push_back(make_logs_page());
        pages_.push_back(make_settings_page());
        pages_.push_back(make_directory_page());
        pages_.push_back(make_chat_page());
    }

    std::string_view title() const override { return "Tools"; }

    void on_show(AppContext& ctx) override {
        show_child(ctx);
    }

    void render(AppContext& ctx) override {
        ui::page_header("Tools", "Keys, logs, appearance, and relay features.");

        const float sc = ui::scale();
        ImGui::BeginChild("##tools_nav", ImVec2(190 * sc, 0), ImGuiChildFlags_None);
        for (std::size_t i = 0; i < pages_.size(); ++i) {
            std::string label(pages_[i]->title());
            if (ui::nav_item(label.c_str(), label.c_str(), active_ == i, ImVec2(-1, 42 * sc))) {
                if (active_ != i) {
                    if (shown_ < pages_.size()) pages_[shown_]->on_hide(ctx);
                    active_ = i;
                    show_child(ctx);
                }
            }
        }
        ImGui::EndChild();

        ImGui::SameLine();
        ImGui::BeginChild("##tools_content", ImVec2(0, 0), ImGuiChildFlags_None);
        if (active_ < pages_.size()) {
            pages_[active_]->render(ctx);
        }
        ImGui::EndChild();
    }

private:
    void show_child(AppContext& ctx) {
        if (active_ < pages_.size() && shown_ != active_) {
            pages_[active_]->on_show(ctx);
            shown_ = active_;
        }
    }

    std::vector<std::unique_ptr<Page>> pages_;
    std::size_t active_{0};
    std::size_t shown_{std::numeric_limits<std::size_t>::max()};
};

}  // namespace

std::unique_ptr<Page> make_tools_page() {
    return std::make_unique<ToolsPage>();
}

}  // namespace yume::gui
