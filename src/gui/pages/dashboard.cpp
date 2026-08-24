/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "pages/page.hpp"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <string>
#include <vector>

#include <imgui.h>

#include "facade/session/client_session.hpp"
#include "facade/session/server_session.hpp"
#include "facade/metrics/traffic_meter.hpp"
#include "ui/design.hpp"

namespace yume::gui {

namespace {

struct TrafficWindowOpt {
    char const* label;
    int seconds;
};
constexpr TrafficWindowOpt kTrafficWindows[] = {
    {"15s", 15}, {"60s", 60}, {"5m", 300}, {"15m", 900},
};
constexpr int kDefaultWindowIdx = 1;  // 60s

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

        if (ui::begin_auto_card("##hero")) {
            if (ImGui::BeginTable("##status_table", 2, ImGuiTableFlags_SizingStretchSame)) {
                ImGui::TableNextColumn();
                ui::section_label("Client");
                ui::status_pill(facade::display_label(client.state), state_color(client.state));
                ui::muted_text("%s", client.server_endpoint.empty() ? "No server configured" : client.server_endpoint.c_str());
                if (!client.message.empty()) ui::muted_text("%s", client.message.c_str());
                if (!client.server_tls_fingerprint_sha256.empty()) {
                    ui::muted_text("TLS leaf: %.16s...",
                                   client.server_tls_fingerprint_sha256.c_str());
                }
                if (client.state == facade::ConnectionState::Connected) {
                    ui::muted_text("Packet ABI: %s",
                                   client.packet_bulk_supported
                                       ? "packet_bulk_v1 ready"
                                       : "not advertised");
                    if (!client.server_capabilities.empty()) {
                        std::string caps;
                        for (auto const& capability : client.server_capabilities) {
                            if (!caps.empty()) caps += ", ";
                            caps += capability;
                        }
                        ui::muted_text("Capabilities: %s", caps.c_str());
                    }
                }

                ImGui::TableNextColumn();
                ui::section_label("Local yumed");
                ui::status_pill(server.running ? "Running" : "Stopped",
                                server.running ? c.success : c.muted);
                ui::muted_text("%s", server.listen_endpoint.empty() ? "0.0.0.0:443" : server.listen_endpoint.c_str());
                if (!server.message.empty()) {
                    // Display the message in error red when the server
                    // isn't running so failures (privileged port, port
                    // in use, missing certs) don't disappear into the
                    // muted grey under "Stopped".
                    if (!server.running) {
                        ui::message_text(c.error, "%s", server.message.c_str());
                    } else {
                        ui::muted_text("%s", server.message.c_str());
                    }
                }
                ImGui::EndTable();
            }
        }
        ui::end_card();

        ImGui::Dummy(ImVec2(0, 8 * sc));

        if (ui::begin_auto_card("##actions")) {
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
            ui::muted_text("Client runs in-process in the background.");
            if (!last_error_.empty()) {
                ui::message_text(c.error, "%s", last_error_.c_str());
            }
        }
        ui::end_card();

        // Per-side traffic card. Only show the ones whose runtime is
        // running, so the dashboard stays uncluttered when only one
        // half of the app is active.
        const bool client_running = ctx.client && ctx.client->running();
        const bool server_running = ctx.server && ctx.server->running();

        if (client_running) {
            ImGui::Dummy(ImVec2(0, 8 * sc));
            render_traffic_card(
                "##traffic_client",
                "Live traffic",
                client.bytes_sent, client.bytes_received,
                client.tx_rate_bps, client.rx_rate_bps,
                ctx.client ? &ctx.client->traffic() : nullptr,
                /*show_profile_meta=*/true, client, sc,
                window_idx_client_);
        }
        if (server_running) {
            ImGui::Dummy(ImVec2(0, 8 * sc));
            render_traffic_card(
                "##traffic_server",
                "Server traffic",
                server.bytes_out, server.bytes_in,
                0.0, 0.0,
                ctx.server ? &ctx.server->traffic() : nullptr,
                /*show_profile_meta=*/false, client, sc,
                window_idx_server_);
        }
        if (!client_running && !server_running) {
            ImGui::Dummy(ImVec2(0, 8 * sc));
            if (ui::begin_auto_card("##traffic_idle")) {
                ImGui::PushStyleColor(ImGuiCol_Text, c.muted);
                const char* msg = "Start the client or server to see live traffic.";
                ImVec2 ts = ImGui::CalcTextSize(msg);
                ImGui::SetCursorPosX((ImGui::GetWindowSize().x - ts.x) * 0.5f);
                ImGui::Dummy(ImVec2(0, 36 * sc));
                ImGui::SetCursorPosX((ImGui::GetWindowSize().x - ts.x) * 0.5f);
                ImGui::TextUnformatted(msg);
                ImGui::Dummy(ImVec2(0, 36 * sc));
                ImGui::PopStyleColor();
            }
            ui::end_card();
        }
    }

    void render_traffic_card(char const* id,
                             char const* title,
                             std::uint64_t bytes_sent,
                             std::uint64_t bytes_received,
                             double tx_rate_bps,
                             double rx_rate_bps,
                             facade::TrafficMeter const* meter,
                             bool show_profile_meta,
                             facade::ClientStatus const& client,
                             float sc,
                             int& window_idx) {
        auto const& c = ui::colors();
        // Auto-sizing card: it grows to fit the title row, plot, and stats
        // row. A fixed height was the source of the inner scrollbar.
        if (!ui::begin_auto_card(id)) { ui::end_card(); return; }

        // Compact picker: each segment hugs its label, ~56px each. Avoids
        // a 384px selector that overflows narrow card widths.
        const float seg_min   = 56.0f * sc;
        const float seg_total = seg_min * 4.0f;

        // Header row: title left, picker right. We don't BeginGroup the
        // title — we render it inline so SameLine + SetCursorPosX places
        // the picker at the card's right edge on the same line.
        if (ui::fonts().section) ImGui::PushFont(ui::fonts().section);
        ImGui::TextUnformatted(title);
        if (ui::fonts().section) ImGui::PopFont();

        ImGui::SameLine();
        const float right_edge = ImGui::GetContentRegionMax().x;
        const float picker_x   = std::max(ImGui::GetCursorPosX(),
                                          right_edge - seg_total);
        ImGui::SetCursorPosX(picker_x);
        {
            char const* labels[4];
            for (int i = 0; i < 4; ++i) labels[i] = kTrafficWindows[i].label;
            int new_idx = ui::segmented_control(
                (std::string(id) + "_win").c_str(), labels, 4, window_idx,
                seg_total);
            if (new_idx != window_idx) window_idx = new_idx;
        }
        ImGui::Dummy(ImVec2(0, 8 * sc));

        // Filter samples by the selected window.
        const int window_s = kTrafficWindows[window_idx].seconds;
        std::vector<facade::TrafficMeter::Sample> samples;
        if (meter) {
            auto all = meter->history();
            if ((int)all.size() > window_s) {
                samples.assign(all.end() - window_s, all.end());
            } else {
                samples = std::move(all);
            }
        }

        // Plot region — fixed height; the card auto-sizes around it.
        const float plot_h = 180.0f * sc;
        const ImVec2 plot_origin = ImGui::GetCursorScreenPos();
        const float plot_w = ImGui::GetContentRegionAvail().x;
        ImDrawList* dl = ImGui::GetWindowDrawList();
        dl->AddRectFilled(plot_origin,
                          ImVec2(plot_origin.x + plot_w, plot_origin.y + plot_h),
                          ImGui::GetColorU32(c.surface_high), 12.0f * sc);

        if (samples.size() >= 2) {
            draw_sparkline(dl, plot_origin, plot_w, plot_h, samples, c.accent, c.success);
        } else {
            char const* msg = (client.state == facade::ConnectionState::Connected)
                                  ? "Collecting samples..."
                                  : "Connect to start measuring traffic";
            ImVec2 ts = ImGui::CalcTextSize(msg);
            ImVec2 p(plot_origin.x + (plot_w - ts.x) * 0.5f,
                     plot_origin.y + (plot_h - ts.y) * 0.5f);
            dl->AddText(p, ImGui::GetColorU32(c.muted), msg);
        }
        ImGui::Dummy(ImVec2(0, plot_h));
        ImGui::Dummy(ImVec2(0, 8 * sc));

        // Bottom stats row: dot + arrow + rate + total, like Android.
        render_rate_stat("UP", c.accent, tx_rate_bps, bytes_sent, sc);
        ImGui::SameLine(0.0f, 24 * sc);
        render_rate_stat("DN", c.success, rx_rate_bps, bytes_received, sc);
        if (show_profile_meta && !client.profile.empty()) {
            ImGui::SameLine(0.0f, 24 * sc);
            ImGui::TextColored(c.muted, "%s / %s",
                               client.profile.c_str(),
                               client.security_mode.empty() ? "unknown" : client.security_mode.c_str());
        }
        ui::end_card();
    }

    static void render_rate_stat(char const* arrow,
                                 ImVec4 color,
                                 double rate,
                                 std::uint64_t total,
                                 float sc) {
        auto const& c = ui::colors();
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec2 p = ImGui::GetCursorScreenPos();
        const float r = 5.0f * sc;
        dl->AddCircleFilled(ImVec2(p.x + r, p.y + ImGui::GetTextLineHeight() * 0.5f),
                            r, ImGui::GetColorU32(color));
        ImGui::Dummy(ImVec2(r * 2 + 6 * sc, ImGui::GetTextLineHeight()));
        ImGui::SameLine(0.0f, 0.0f);
        if (ui::fonts().strong) ImGui::PushFont(ui::fonts().strong);
        ImGui::TextColored(color, "%s", arrow);
        if (ui::fonts().strong) ImGui::PopFont();
        ImGui::SameLine(0.0f, 4 * sc);
        ImGui::TextUnformatted(format_rate(rate).c_str());
        ImGui::SameLine(0.0f, 6 * sc);
        ImGui::TextColored(c.muted, "· %s", format_bytes(total).c_str());
    }

    // Cubic-smoothed dual-series sparkline drawn directly into the
    // window drawlist. Upload (top series) uses the accent colour;
    // download uses the success colour. Each series gets a soft
    // gradient fill below the line.
    static void draw_sparkline(ImDrawList* dl,
                               ImVec2 origin,
                               float w,
                               float h,
                               std::vector<facade::TrafficMeter::Sample> const& s,
                               ImVec4 up_col,
                               ImVec4 dn_col) {
        const int n = (int)s.size();
        double peak = 1024.0;
        for (auto const& sample : s) {
            if (sample.tx_bps > peak) peak = sample.tx_bps;
            if (sample.rx_bps > peak) peak = sample.rx_bps;
        }
        const float inner_pad = 8.0f;
        const float pw = w - inner_pad * 2;
        const float ph = h - inner_pad * 2;
        const float x_step = pw / float(n - 1);

        auto plot_series = [&](auto rate_of, ImVec4 line_col) {
            // Build N polyline points at the sample positions; the line
            // already looks smooth at 1Hz cadence, so the explicit
            // cubic from the Android side isn't necessary here.
            std::vector<ImVec2> pts;
            pts.reserve(n);
            for (int i = 0; i < n; ++i) {
                double r = rate_of(s[i]);
                float y_norm = float(std::clamp(r / peak, 0.0, 1.0));
                pts.emplace_back(origin.x + inner_pad + i * x_step,
                                 origin.y + inner_pad + (1.0f - y_norm) * ph);
            }
            // Soft fill underneath. We emit a quad per segment so the
            // gradient can fade vertically without leaning on a render
            // pipeline feature ImDrawList doesn't expose.
            ImVec4 fill_top = line_col;
            fill_top.w = 0.28f;
            ImVec4 fill_bot = line_col;
            fill_bot.w = 0.0f;
            ImU32 ft = ImGui::GetColorU32(fill_top);
            ImU32 fb = ImGui::GetColorU32(fill_bot);
            const float floor_y = origin.y + inner_pad + ph;
            for (int i = 0; i + 1 < (int)pts.size(); ++i) {
                ImVec2 a = pts[i];
                ImVec2 b = pts[i + 1];
                ImVec2 a_floor(a.x, floor_y);
                ImVec2 b_floor(b.x, floor_y);
                dl->AddRectFilledMultiColor(a, ImVec2(b.x, a.y), ft, ft, ft, ft);
                // The actual filled trapezoid:
                dl->AddTriangleFilled(a, b, b_floor, ft);
                dl->AddTriangleFilled(a, b_floor, a_floor, ft);
                (void)fb;
            }
            dl->AddPolyline(pts.data(), (int)pts.size(),
                            ImGui::GetColorU32(line_col), 0, 2.5f);
        };

        plot_series([](auto const& s) { return s.tx_bps; }, up_col);
        plot_series([](auto const& s) { return s.rx_bps; }, dn_col);
    }

private:
    std::string last_error_;
    int window_idx_client_{kDefaultWindowIdx};
    int window_idx_server_{kDefaultWindowIdx};
};

}  // namespace

std::unique_ptr<Page> make_dashboard_page() {
    return std::make_unique<DashboardPage>();
}

}  // namespace yume::gui
