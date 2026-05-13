/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "pages/page.hpp"

#include <cstdint>
#include <cstring>
#include <string>

#include <imgui.h>

#include "facade/config_io.hpp"
#include "facade/server_session.hpp"
#include "ui/design.hpp"

namespace yume::gui {

namespace {

void text_input(const char* label, std::string& value, const char* hint = nullptr) {
    char buf[512];
    std::strncpy(buf, value.c_str(), sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    ImGui::PushID(label);
    ui::field_label(label);
    ImGui::SetNextItemWidth(ui::form_width());
    if (hint) ImGui::InputTextWithHint("##value", hint, buf, sizeof(buf));
    else ImGui::InputText("##value", buf, sizeof(buf));
    value = buf;
    ImGui::PopID();
}

void int_input(const char* label, int& value) {
    ImGui::PushID(label);
    ui::field_label(label);
    ImGui::SetNextItemWidth(ui::form_width());
    ImGui::InputInt("##value", &value, 0, 0);
    ImGui::PopID();
}

void muted_inline_centered(char const* text, float row_y, float row_h) {
    if (ui::fonts().body) ImGui::PushFont(ui::fonts().body);
    const float text_h = ImGui::GetTextLineHeight();
    ImGui::SetCursorPosY(row_y + (row_h - text_h) * 0.5f);
    ImGui::PushStyleColor(ImGuiCol_Text, ui::colors().muted);
    ImGui::TextUnformatted(text);
    ImGui::PopStyleColor();
    if (ui::fonts().body) ImGui::PopFont();

    const float next_y = row_y + row_h + ImGui::GetStyle().ItemSpacing.y;
    if (ImGui::GetCursorPosY() < next_y) ImGui::SetCursorPosY(next_y);
}

class ServerPage : public Page {
public:
    std::string_view title() const override { return "Server"; }

    void on_show(AppContext& ctx) override {
        if (ctx.server && !loaded_) {
            cfg_ = ctx.server->config();
            loaded_ = true;
        }
    }

    void render(AppContext& ctx) override {
        auto const& c = ui::colors();
        const float sc = ui::scale();
        const bool running = ctx.server && ctx.server->running();
        const facade::ServerStatus status = ctx.server ? ctx.server->status() : facade::ServerStatus{};

        ui::page_header("Server", "Run and monitor a local yumed instance from the desktop.");

        if (ui::begin_auto_card("##server_status")) {
            ui::section_label("Local daemon");
            const float status_y = ImGui::GetCursorPosY();
            ImVec2 status_size = ui::status_pill(running ? "Running" : "Stopped",
                                                 running ? c.success : c.muted);
            ImGui::SameLine(0.0f, 18 * sc);
            muted_inline_centered(status.listen_endpoint.empty() ? "0.0.0.0:443" : status.listen_endpoint.c_str(),
                                  status_y,
                                  status_size.y);
            if (!status.ipc_path.empty()) ui::muted_text("IPC: %s", status.ipc_path.c_str());
            if (!status.message.empty()) ui::muted_text("%s", status.message.c_str());
        }
        ui::end_card();

        ImGui::Dummy(ImVec2(0, 8 * sc));
        if (ui::begin_auto_card("##server_config")) {
            ui::section_label("Configuration");
            ImGui::BeginDisabled(running);
            if (ImGui::BeginTable("##listener_cols", 2, ImGuiTableFlags_SizingStretchProp)) {
                ImGui::TableSetupColumn("Port", ImGuiTableColumnFlags_WidthStretch, 0.35f);
                ImGui::TableSetupColumn("Threads", ImGuiTableColumnFlags_WidthStretch, 0.65f);
                ImGui::TableNextColumn();
                int_input("Listen port", cfg_.listen_port);
                ImGui::TableNextColumn();
                int_input("Worker threads (0 = auto)", cfg_.threads);
                ImGui::EndTable();
            }
            text_input("Certificate (PEM)", cfg_.tls_cert);
            text_input("Private key (PEM)", cfg_.tls_key);
            text_input("Authorized keys", cfg_.auth_keys);
            text_input("Server name", cfg_.server_name);

            advanced_open_ = ui::disclosure_header("Advanced server settings", advanced_open_);
            if (advanced_open_) {
                ImGui::Dummy(ImVec2(0, 6 * sc));
                text_input("Auth metadata JSON", cfg_.auth_keys_meta);
                text_input("DNS resolver", cfg_.dns_server, "1.1.1.1");
                if (ImGui::BeginTable("##server_features", 4, ImGuiTableFlags_SizingStretchSame)) {
                    ImGui::TableNextColumn();
                    ui::checkbox("Relay", &cfg_.relay_enable);
                    ImGui::TableNextColumn();
                    ui::checkbox("Directory", &cfg_.directory_enable);
                    ImGui::TableNextColumn();
                    ui::checkbox("IPC", &cfg_.ipc_enable);
                    ImGui::TableNextColumn();
                    ui::checkbox("Anonym", &cfg_.anonym);
                    ImGui::EndTable();
                }
                text_input("IPC path", cfg_.ipc_path, "auto");

                if (cfg_.anonym) {
                    const char* proof_modes[] = {"auto", "local", "fixcraft"};
                    int proof_idx = 0;
                    for (int i = 0; i < 3; ++i) {
                        if (cfg_.anonym_proof_mode == proof_modes[i]) {
                            proof_idx = i;
                            break;
                        }
                    }
                    ui::field_label("Anonym proof mode");
                    ImGui::SetNextItemWidth(ui::form_width(320));
                    if (ImGui::Combo("##anonym_proof_mode", &proof_idx, proof_modes, 3)) {
                        cfg_.anonym_proof_mode = proof_modes[proof_idx];
                    }
                    text_input("Anonym API", cfg_.anonym_api, "optional");
                    text_input("Anonym token", cfg_.anonym_token, "optional");
                    text_input("Anonym CA key", cfg_.anonym_ca_key, "optional local signer key");
                    text_input("Anonym CA cert", cfg_.anonym_ca_cert, "optional local signer cert");
                    text_input("Anonym sub-CA key", cfg_.anonym_sub_key, "optional delegated signer key");
                    text_input("Anonym sub-CA cert", cfg_.anonym_sub_cert, "optional delegated signer cert");
                }

                ImGui::Separator();
                if (ImGui::BeginTable("##inner_flags", 4, ImGuiTableFlags_SizingStretchSame)) {
                    ImGui::TableNextColumn();
                    ui::checkbox("Inner crypto", &cfg_.inner_crypto);
                    ImGui::TableNextColumn();
                    ui::checkbox("Heavy", &cfg_.inner_heavy);
                    ImGui::TableNextColumn();
                    ui::checkbox("Dual", &cfg_.inner_dual);
                    ImGui::TableNextColumn();
                    ui::checkbox("Required", &cfg_.inner_required);
                    ImGui::EndTable();
                }
                ui::checkbox("Hop keys", &cfg_.inner_hop);
                int hop = (int)cfg_.hop_interval_ms;
                int_input("Hop interval (ms)", hop);
                {
                    cfg_.hop_interval_ms = hop < 0 ? 0u : (std::uint32_t)hop;
                }
            }
            ImGui::EndDisabled();

            auto report = facade::config_io::validate(cfg_);
            if (!report.errors.empty() || !report.warnings.empty()) {
                ImGui::Separator();
                for (auto const& e : report.errors) {
                    ImGui::TextColored(c.error, "- %s", e.c_str());
                }
                for (auto const& w : report.warnings) {
                    ImGui::TextColored(c.warning, "- %s", w.c_str());
                }
            }

            ImGui::Separator();
            if (!running) {
                ImGui::BeginDisabled(!report.ok());
                if (ui::primary_button("Start yumed", ImVec2(150 * sc, 48 * sc)) && ctx.server) {
                    ctx.server->set_config(cfg_);
                    std::string err;
                    if (!ctx.server->start(&err)) {
                        last_message_ = err.empty() ? "server start failed" : err;
                        last_error_ = true;
                    } else {
                        last_message_ = "Server started.";
                        last_error_ = false;
                    }
                }
                ImGui::EndDisabled();
            } else {
                if (ui::primary_button("Stop yumed", ImVec2(150 * sc, 48 * sc)) && ctx.server) {
                    ctx.server->stop();
                    last_message_ = "Server stopped.";
                    last_error_ = false;
                }
            }
            ImGui::SameLine();
            ImGui::BeginDisabled(running);
            if (ui::secondary_button("Save config", ImVec2(150 * sc, 48 * sc))) {
                std::string err;
                if (facade::config_io::save_server(
                        cfg_, facade::config_io::default_server_config_path(), &err)) {
                    if (ctx.server) ctx.server->set_config(cfg_);
                    last_message_ = "Saved.";
                    last_error_ = false;
                } else {
                    last_message_ = "Save failed: " + err;
                    last_error_ = true;
                }
            }
            ImGui::EndDisabled();

            if (!last_message_.empty()) {
                ImGui::Dummy(ImVec2(0, 2 * sc));
                ui::message_text(last_error_ ? c.error : c.success, "%s", last_message_.c_str());
            }

            if (ctx.server) {
                auto sessions = ctx.server->list_sessions();
                if (running || !sessions.empty()) {
                    ImGui::Dummy(ImVec2(0, 10 * sc));
                    ui::section_label("Sessions");
                    if (sessions.empty()) {
                        ui::muted_text("No active client sessions.");
                    } else if (ui::begin_data_table("##sessions", 4)) {
                        ui::data_table_headers({"Endpoint", "Name", "State", "Traffic"});
                        for (auto const& s : sessions) {
                            ImGui::TableNextRow();
                            ImGui::TableNextColumn(); ImGui::TextUnformatted(s.endpoint_id.c_str());
                            ImGui::TableNextColumn(); ImGui::TextUnformatted(s.display_name.c_str());
                            ImGui::TableNextColumn();
                            ui::status_pill(s.authenticated ? "Online" : "Pending",
                                            s.authenticated ? c.success : c.warning);
                            ImGui::TableNextColumn();
                            ImGui::Text("%llu / %llu",
                                        (unsigned long long)s.bytes_in,
                                        (unsigned long long)s.bytes_out);
                        }
                        ui::end_data_table();
                    }
                }
            }
        }
        ui::end_card();
    }

private:
    server::ServerConfig cfg_{};
    bool loaded_{false};
    bool advanced_open_{false};
    std::string last_message_;
    bool last_error_{false};
};

}  // namespace

std::unique_ptr<Page> make_server_page() {
    return std::make_unique<ServerPage>();
}

}  // namespace yume::gui
