/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "pages/page.hpp"

#include <cstring>
#include <ctime>

#include <imgui.h>

#include "facade/log_sink.hpp"
#include "theme/theme.hpp"
#include "ui/design.hpp"

namespace yume::gui {

namespace {

ImVec4 level_color(facade::LogLevel l, theme::Palette const& p) {
    switch (l) {
        case facade::LogLevel::Error:
        case facade::LogLevel::Critical: return p.error;
        case facade::LogLevel::Warn:     return p.warning;
        case facade::LogLevel::Info:     return p.on_surface;
        case facade::LogLevel::Debug:
        case facade::LogLevel::Trace:    return p.on_surface_variant;
    }
    return p.on_surface;
}

bool matches(facade::LogEntry const& e, int level_filter, const char* text_filter) {
    if ((int)e.level < level_filter) return false;
    if (text_filter && text_filter[0]) {
        if (e.message.find(text_filter) == std::string::npos &&
            e.component.find(text_filter) == std::string::npos) {
            return false;
        }
    }
    return true;
}

class LogsPage : public Page {
public:
    std::string_view title() const override { return "Logs"; }

    void render(AppContext& /*ctx*/) override {
        auto const& p = theme::current_palette();
        ui::page_header("Logs", "Live runtime events and facade messages.");

        const char* levels[] = {"trace", "debug", "info", "warn", "error", "critical"};
        ImGui::SetNextItemWidth(140);
        ImGui::Combo("Min level", &level_filter_, levels, IM_ARRAYSIZE(levels));
        ImGui::SameLine();
        ImGui::SetNextItemWidth(-280);
        ImGui::InputTextWithHint("##filter", "filter text",
                                 text_filter_, sizeof(text_filter_));
        ImGui::SameLine();
        ui::checkbox("Live tail", &live_tail_);
        ImGui::SameLine();
        if (ImGui::Button("Clear")) {
            facade::LogSink::instance().clear();
        }

        ImGui::Separator();

        auto entries = facade::LogSink::instance().snapshot(2000);

        ImGui::BeginChild("##log_scroll", ImVec2(0, 0), ImGuiChildFlags_Border);
        if (ui::fonts().mono) ImGui::PushFont(ui::fonts().mono);
        if (ui::begin_data_table("##logs", 4,
                                  ImGuiTableFlags_Resizable |
                                  ImGuiTableFlags_ScrollY)) {
            ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 100);
            ImGui::TableSetupColumn("Level", ImGuiTableColumnFlags_WidthFixed, 70);
            ImGui::TableSetupColumn("Component", ImGuiTableColumnFlags_WidthFixed, 140);
            ImGui::TableSetupColumn("Message");
            ui::data_table_header_row();

            ImGuiListClipper clipper;
            // Build a filtered index first so the clipper sees stable rows.
            filtered_.clear();
            filtered_.reserve(entries.size());
            for (std::size_t i = 0; i < entries.size(); ++i) {
                if (matches(entries[i], level_filter_, text_filter_)) {
                    filtered_.push_back(i);
                }
            }
            clipper.Begin((int)filtered_.size());
            while (clipper.Step()) {
                for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                    auto const& e = entries[filtered_[(std::size_t)row]];
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    auto tt = std::chrono::system_clock::to_time_t(e.ts);
                    std::tm tm{};
#ifdef _WIN32
                    localtime_s(&tm, &tt);
#else
                    localtime_r(&tt, &tm);
#endif
                    char buf[32];
                    std::strftime(buf, sizeof(buf), "%H:%M:%S", &tm);
                    ImGui::TextUnformatted(buf);
                    ImGui::TableNextColumn();
                    ImGui::TextColored(level_color(e.level, p), "%s",
                                       facade::to_string(e.level));
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(e.component.c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextWrapped("%s", e.message.c_str());
                }
            }
            if (live_tail_) ImGui::SetScrollHereY(1.0f);
            ui::end_data_table();
        }
        if (ui::fonts().mono) ImGui::PopFont();
        ImGui::EndChild();
    }

private:
    int level_filter_{2};  // info
    char text_filter_[256]{};
    bool live_tail_{true};
    std::vector<std::size_t> filtered_;
};

}  // namespace

std::unique_ptr<Page> make_logs_page() {
    return std::make_unique<LogsPage>();
}

}  // namespace yume::gui
