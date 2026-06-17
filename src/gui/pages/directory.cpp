/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "pages/page.hpp"

#include <string>
#include <vector>

#include <imgui.h>

#include "facade/session/client_session.hpp"
#include "ui/design.hpp"

namespace yume::gui {

namespace {

class DirectoryPage : public Page {
public:
    std::string_view title() const override { return "Directory"; }

    void on_show(AppContext& ctx) override {
        refresh(ctx);
    }

    void render(AppContext& ctx) override {
        const float sc = ui::scale();
        auto const& c = ui::colors();
        if (!ctx.client || !ctx.client->running()) {
            ui::unavailable_panel("Directory unavailable",
                                  "Connect the client first to list relay endpoints.");
            return;
        }

        ui::page_header("Directory", "Endpoints visible on the connected relay.");
        if (ui::secondary_button("Refresh", ImVec2(120 * sc, 44 * sc))) {
            refresh(ctx);
        }
        if (!last_error_.empty()) {
            ImGui::SameLine(0.0f, 12 * sc);
            ui::message_text(c.error, "%s", last_error_.c_str());
        }
        ImGui::Dummy(ImVec2(0, 8 * sc));

        if (ui::begin_data_table("##directory", 6)) {
            ui::data_table_headers({"Name", "Endpoint ID", "Kind",
                                    "Relay", "Platform", "Capabilities"});
            for (auto const& entry : entries_) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(entry.display_name.empty() ? "—" : entry.display_name.c_str());
                ImGui::TableNextColumn();
                if (ui::fonts().mono) ImGui::PushFont(ui::fonts().mono);
                ImGui::TextUnformatted(entry.endpoint_id.c_str());
                if (ui::fonts().mono) ImGui::PopFont();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(entry.endpoint_kind.c_str());
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(entry.relay_mode.c_str());
                ImGui::TableNextColumn();
                std::string platform = entry.client_platform;
                if (!entry.client_variant.empty()) {
                    platform += platform.empty() ? entry.client_variant : "/" + entry.client_variant;
                }
                ImGui::TextUnformatted(platform.empty() ? "—" : platform.c_str());
                ImGui::TableNextColumn();
                std::string caps;
                if (entry.allow_chat) caps += "chat";
                if (entry.allow_file) caps += caps.empty() ? "file" : ", file";
                if (entry.allow_bytes) caps += caps.empty() ? "bytes" : ", bytes";
                ImGui::TextUnformatted(caps.empty() ? "—" : caps.c_str());
            }
            ui::end_data_table();
        }
    }

private:
    void refresh(AppContext& ctx) {
        last_error_.clear();
        entries_.clear();
        if (!ctx.client || !ctx.client->running()) return;
        entries_ = ctx.client->directory(&last_error_);
    }

    std::vector<facade::ClientSession::DirectoryEntry> entries_;
    std::string last_error_;
};

}  // namespace

std::unique_ptr<Page> make_directory_page() {
    return std::make_unique<DirectoryPage>();
}

}  // namespace yume::gui
