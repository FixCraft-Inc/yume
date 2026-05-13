/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "pages/page.hpp"

#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include <imgui.h>
#include <implot.h>

#include "facade/client_session.hpp"
#include "facade/server_session.hpp"
#include "facade/traffic_meter.hpp"
#include "ui/design.hpp"

namespace yume::gui {

namespace {

std::string format_bytes(std::uint64_t b) {
    char buf[32];
    if (b < 1024) std::snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)b);
    else if (b < 1024ull * 1024) std::snprintf(buf, sizeof(buf), "%.1f KiB", b / 1024.0);
    else if (b < 1024ull * 1024 * 1024) std::snprintf(buf, sizeof(buf), "%.1f MiB", b / (1024.0 * 1024));
    else std::snprintf(buf, sizeof(buf), "%.2f GiB", b / (1024.0 * 1024 * 1024));
    return buf;
}

std::string format_rate(double bps) {
    char buf[32];
    if (bps < 1024) std::snprintf(buf, sizeof(buf), "%.0f B/s", bps);
    else if (bps < 1024 * 1024) std::snprintf(buf, sizeof(buf), "%.1f KiB/s", bps / 1024);
    else std::snprintf(buf, sizeof(buf), "%.2f MiB/s", bps / (1024 * 1024));
    return buf;
}

ImVec4 state_color(facade::ConnectionState s) {
    auto const& c = ui::colors();
    switch (s) {
        case facade::ConnectionState::Connected: return c.success;
        case facade::ConnectionState::Failed: return c.error;
        case facade::ConnectionState::Disconnected:
        case facade::ConnectionState::Idle: return c.muted;
        default: return c.warning;
    }
}

class DashboardPage : public Page {
public:
    std::string_view title() const override { return "Overview"; }

    void render(AppContext& ctx) override {
        auto const& c = ui::colors();
        const float sc = ui::scale();
        facade::ClientStatus client{};
        if (ctx.client) client = ctx.client->status();
        facade::ServerStatus server{};
        if (ctx.server) server = ctx.server->status();

        ui::page_header("Overview", "Connection and local daemon status.");

        if (ui::begin_card("##hero", ImVec2(0, 170 * sc))) {
            if (ImGui::BeginTable("##status_table", 2, ImGuiTableFlags_SizingStretchSame)) {
                ImGui::TableNextColumn();
                ui::section_label("Client");
                ui::status_pill(facade::display_label(client.state), state_color(client.state));
                ui::muted_text("%s", client.server_endpoint.empty() ? "No server configured" : client.server_endpoint.c_str());
                if (!client.message.empty()) ui::muted_text("%s", client.message.c_str());

                ImGui::TableNextColumn();
                ui::section_label("Local yumed");
                ui::status_pill(server.running ? "Running" : "Stopped",
                                server.running ? c.success : c.muted);
                ui::muted_text("%s", server.listen_endpoint.empty() ? "0.0.0.0:443" : server.listen_endpoint.c_str());
                if (!server.message.empty()) ui::muted_text("%s", server.message.c_str());
                ImGui::EndTable();
            }
        }
        ui::end_card();

        ImGui::Dummy(ImVec2(0, 8 * sc));

        const float actions_h = last_error_.empty() ? 160 * sc : 204 * sc;
        if (ui::begin_card("##actions", ImVec2(0, actions_h))) {
            const bool server_running = ctx.server && ctx.server->running();
            if (server_running) {
                if (ui::primary_button("Stop local server", ImVec2(190 * sc, 48 * sc))) {
                    ctx.server->stop();
                }
            } else {
                if (ui::primary_button("Start local server", ImVec2(190 * sc, 48 * sc)) && ctx.server) {
                    std::string err;
                    if (!ctx.server->start(&err)) {
                        last_error_ = err.empty() ? "server start failed" : err;
                    } else {
                        last_error_.clear();
                    }
                }
            }
            ImGui::SameLine(0.0f, 14 * sc);
            const bool client_running = ctx.client && ctx.client->running();
            ImGui::BeginDisabled(!ctx.client);
            if (client_running) {
                if (ui::secondary_button("Disconnect client", ImVec2(190 * sc, 48 * sc))) {
                    ctx.client->stop();
                    last_error_.clear();
                }
            } else {
                if (ui::secondary_button("Connect client", ImVec2(170 * sc, 48 * sc))) {
                    std::string err;
                    if (!ctx.client->start(&err)) {
                        last_error_ = err.empty() ? "client start failed" : err;
                    } else {
                        last_error_.clear();
                    }
                }
            }
            ImGui::EndDisabled();
            ImGui::Dummy(ImVec2(0, 2 * sc));
            ui::muted_text("Client runs in the background through local IPC.");
            if (!last_error_.empty()) {
                ui::message_text(c.error, "%s", last_error_.c_str());
            }
        }
        ui::end_card();

        ImGui::Dummy(ImVec2(0, 8 * sc));
        float traffic_h = ImGui::GetContentRegionAvail().y;
        traffic_h = traffic_h < 360 * sc ? 360 * sc : traffic_h;
        if (ui::begin_card("##traffic", ImVec2(0, traffic_h))) {
            ui::section_label("Traffic");
            if (ImGui::BeginTable("##stats", 3, ImGuiTableFlags_SizingStretchSame)) {
                ImGui::TableNextColumn();
                ui::muted_text("TX");
                if (ui::fonts().strong) ImGui::PushFont(ui::fonts().strong);
                ImGui::TextUnformatted(format_bytes(client.bytes_sent).c_str());
                if (ui::fonts().strong) ImGui::PopFont();
                ImGui::SameLine(0.0f, 8 * sc);
                ImGui::TextColored(c.muted, "%s", format_rate(client.tx_rate_bps).c_str());

                ImGui::TableNextColumn();
                ui::muted_text("RX");
                if (ui::fonts().strong) ImGui::PushFont(ui::fonts().strong);
                ImGui::TextUnformatted(format_bytes(client.bytes_received).c_str());
                if (ui::fonts().strong) ImGui::PopFont();
                ImGui::SameLine(0.0f, 8 * sc);
                ImGui::TextColored(c.muted, "%s", format_rate(client.rx_rate_bps).c_str());

                ImGui::TableNextColumn();
                ui::muted_text("Profile / Inner");
                if (ui::fonts().strong) ImGui::PushFont(ui::fonts().strong);
                ImGui::TextWrapped("%s / %s", client.profile.c_str(),
                                   client.inner_mode.empty() ? "off" : client.inner_mode.c_str());
                if (ui::fonts().strong) ImGui::PopFont();
                ImGui::EndTable();
            }
            ImGui::Dummy(ImVec2(0, 6 * sc));

            float plot_h = traffic_h - 190 * sc;
            if (plot_h < 160 * sc) plot_h = 160 * sc;

            // Plot when we have samples; otherwise show a centred note
            // explaining why. The yume runtime doesn't yet expose byte
            // counters over IPC — they'll start showing up automatically
            // once the runtime gains a stats op.
            bool have_samples = false;
            std::vector<double> xs, tx, rx;
            if (ctx.client) {
                auto samples = ctx.client->traffic().history();
                if (!samples.empty()) {
                    have_samples = true;
                    const auto t0 = samples.front().t;
                    xs.reserve(samples.size());
                    tx.reserve(samples.size());
                    rx.reserve(samples.size());
                    for (auto const& s : samples) {
                        xs.push_back(std::chrono::duration<double>(s.t - t0).count());
                        tx.push_back(s.tx_bps);
                        rx.push_back(s.rx_bps);
                    }
                }
            }

            if (have_samples) {
                if (ImPlot::BeginPlot("##traffic_plot", ImVec2(-1, plot_h),
                                      ImPlotFlags_NoLegend | ImPlotFlags_NoBoxSelect)) {
                    ImPlot::SetupAxis(ImAxis_X1, "s",
                                      ImPlotAxisFlags_NoLabel | ImPlotAxisFlags_NoTickLabels);
                    ImPlot::SetupAxis(ImAxis_Y1, "B/s", ImPlotAxisFlags_AutoFit);
                    ImPlot::PlotLine("tx", xs.data(), tx.data(), (int)xs.size());
                    ImPlot::PlotLine("rx", xs.data(), rx.data(), (int)xs.size());
                    ImPlot::EndPlot();
                }
            } else {
                ImGui::PushStyleColor(ImGuiCol_ChildBg,
                                      ImVec4(c.surface_high.x, c.surface_high.y,
                                             c.surface_high.z, 0.35f));
                ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 12 * sc);
                ImGui::BeginChild("##traffic_placeholder", ImVec2(-1, plot_h),
                                  ImGuiChildFlags_AlwaysUseWindowPadding,
                                  ImGuiWindowFlags_NoScrollbar);
                const float pad = (plot_h - 56 * sc) * 0.5f;
                if (pad > 0) ImGui::Dummy(ImVec2(0, pad));
                ImGui::PushStyleColor(ImGuiCol_Text, c.muted);
                const char* msg = "Live traffic graph arrives in a follow-up release.";
                ImVec2 ts = ImGui::CalcTextSize(msg);
                ImGui::SetCursorPosX((ImGui::GetWindowSize().x - ts.x) * 0.5f);
                ImGui::TextUnformatted(msg);
                const char* sub = "Connect and route traffic through SOCKS to verify the proxy works.";
                ts = ImGui::CalcTextSize(sub);
                ImGui::SetCursorPosX((ImGui::GetWindowSize().x - ts.x) * 0.5f);
                ImGui::TextUnformatted(sub);
                ImGui::PopStyleColor();
                ImGui::EndChild();
                ImGui::PopStyleVar();
                ImGui::PopStyleColor();
            }
        }
        ui::end_card();
    }

private:
    std::string last_error_;
};

}  // namespace

std::unique_ptr<Page> make_dashboard_page() {
    return std::make_unique<DashboardPage>();
}

}  // namespace yume::gui
