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

#include "facade/client_session.hpp"
#include "facade/config_io.hpp"
#include "facade/secure_materials.hpp"
#include "ui/design.hpp"

namespace yume::gui {

namespace {

namespace sm = facade::secure_materials;

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

class ConnectPage : public Page {
public:
    std::string_view title() const override { return "Client"; }

    void on_show(AppContext& ctx) override {
        if (ctx.client && (!loaded_ || !ctx.client->running())) {
            cfg_ = ctx.client->config();
            loaded_ = true;
        }
    }

    void render(AppContext& ctx) override {
        auto const& c = ui::colors();
        const float sc = ui::scale();

        ui::page_header("Client",
                        "Choose a server, select trust material, and connect through local IPC.");

        if (ui::begin_auto_card("##connect_essential")) {
            ui::section_label("Profile");
            if (ImGui::BeginTable("##profile_cols", 2, ImGuiTableFlags_SizingStretchProp)) {
                ImGui::TableSetupColumn("Host", ImGuiTableColumnFlags_WidthStretch, 0.72f);
                ImGui::TableSetupColumn("Port", ImGuiTableColumnFlags_WidthStretch, 0.28f);
                ImGui::TableNextColumn();
                text_input("Server host", cfg_.server, "vpn.example.com");
                ImGui::TableNextColumn();
                int_input("Port", cfg_.port);
                ImGui::EndTable();
            }
            text_input("Display name", cfg_.preferred_name, "optional");

            ImGui::Dummy(ImVec2(0, 8 * sc));
            ui::section_label("Trust material");
            std::string ca_name = "Built-in CA";
            std::string key_name = cfg_.identity.empty() ? "Not selected" : cfg_.identity;
            if (auto ca = sm::get(cfg_.anonym_ca_material_id.empty()
                                      ? sm::kDefaultAnonymCaId
                                      : cfg_.anonym_ca_material_id)) {
                ca_name = ca->display_name;
            }
            if (!cfg_.auth_key_material_id.empty()) {
                if (auto key = sm::get(cfg_.auth_key_material_id)) {
                    key_name = key->display_name;
                }
            }
            ui::muted_text("Anonym CA: %s", ca_name.c_str());
            ui::muted_text("Auth key: %s", key_name.c_str());
            ui::muted_text("Use Security to import or switch saved CAs and auth keys.");
        }
        ui::end_card();

        ImGui::Dummy(ImVec2(0, 8 * sc));
        if (ui::begin_auto_card("##connect_security")) {
            ui::section_label("Connection");
            if (ImGui::BeginTable("##security_toggles", 3, ImGuiTableFlags_SizingStretchSame)) {
                ImGui::TableNextColumn();
                ui::checkbox("Inner crypto", &cfg_.inner_crypto);
                ImGui::TableNextColumn();
                ui::checkbox("Heavy KDF", &cfg_.inner_heavy);
                ImGui::TableNextColumn();
                ui::checkbox("Key hopping", &cfg_.inner_hop);
                ImGui::EndTable();
            }

            ImGui::Dummy(ImVec2(0, 12 * sc));
            ui::section_label("Anonymity proof");
            ui::field_label("Server anonym mode");
            const char* anonym_modes[] = {"Optional", "Required"};
            int anonym_idx = cfg_.require_anonym ? 1 : 0;
            ImGui::SetNextItemWidth(ui::form_width(320));
            if (ImGui::Combo("##anonym_mode", &anonym_idx, anonym_modes, 2)) {
                cfg_.require_anonym = anonym_idx == 1;
            }
            ui::muted_text(
                "Optional allows monitored servers after warning acceptance. Required refuses servers that do not prove anonym mode.");
            int_input("SOCKS5 port (0 = auto)", cfg_.socks_port);

            ImGui::Dummy(ImVec2(0, 8 * sc));
            advanced_open_ = ui::disclosure_header("TLS trust and advanced transport",
                                                   advanced_open_);
            if (advanced_open_) {
                text_input("Anonym public key override",
                           cfg_.anonym_pubkey,
                           "optional PEM; built-in key is default");
                text_input("TLS CA cert",
                           cfg_.tls_ca_cert,
                           "optional custom TLS CA");
                text_input("TLS pin SHA-256", cfg_.tls_pin_sha256, "optional certificate pin");
                int hop = (int)cfg_.hop_interval_ms;
                int_input("Hop interval (ms)", hop);
                {
                    cfg_.hop_interval_ms = hop < 0 ? 0u : (std::uint32_t)hop;
                }
                text_input("PQ public key", cfg_.pq_public_key);
                ui::checkbox("TLS stealth", &cfg_.tls_stealth_enabled);
                const char* profiles[] = {"chrome", "firefox", "safari"};
                int prof_idx = 0;
                for (int i = 0; i < 3; ++i) {
                    if (cfg_.tls_stealth_profile == profiles[i]) { prof_idx = i; break; }
                }
                ui::field_label("TLS profile");
                ImGui::SetNextItemWidth(ui::form_width(320));
                if (ImGui::Combo("##tls_profile", &prof_idx, profiles, 3)) {
                    cfg_.tls_stealth_profile = profiles[prof_idx];
                }
                ui::checkbox("Rotate profile", &cfg_.tls_stealth_rotate);
                int_input("IO threads (0 = auto)", cfg_.io_threads);

                const char* relay_modes[] = {"untrusted", "trusted", "operator"};
                int rm_idx = 0;
                for (int i = 0; i < 3; ++i) {
                    if (cfg_.relay_mode == relay_modes[i]) { rm_idx = i; break; }
                }
                ui::field_label("Relay mode");
                ImGui::SetNextItemWidth(ui::form_width(320));
                if (ImGui::Combo("##relay_mode", &rm_idx, relay_modes, 3)) {
                    cfg_.relay_mode = relay_modes[rm_idx];
                }
                if (ImGui::BeginTable("##relay_flags", 3, ImGuiTableFlags_SizingStretchSame)) {
                    ImGui::TableNextColumn();
                    ui::checkbox("Allow chat", &cfg_.allow_chat);
                    ImGui::TableNextColumn();
                    ui::checkbox("Allow file", &cfg_.allow_file);
                    ImGui::TableNextColumn();
                    ui::checkbox("Allow bytes", &cfg_.allow_bytes);
                    ImGui::EndTable();
                }
            }

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
            const bool can_save = report.ok();
            ImGui::BeginDisabled(!can_save);
            if (ui::primary_button("Save profile", ImVec2(150 * sc, 48 * sc))) {
                std::string err;
                if (facade::config_io::save_client(
                        cfg_, facade::config_io::default_client_config_path(), &err)) {
                    if (ctx.client) ctx.client->set_config(cfg_);
                    last_message_ = "Saved.";
                    last_error_ = false;
                } else {
                    last_message_ = "Save failed: " + err;
                    last_error_ = true;
                }
            }
            ImGui::EndDisabled();
            ImGui::SameLine();
            const bool running = ctx.client && ctx.client->running();
            ImGui::BeginDisabled(!ctx.client || (!running && !can_save));
            if (running) {
                if (ui::secondary_button("Disconnect", ImVec2(150 * sc, 48 * sc))) {
                    ctx.client->stop();
                    last_message_ = "Disconnected.";
                    last_error_ = false;
                }
            } else {
                if (ui::secondary_button("Connect", ImVec2(132 * sc, 48 * sc))) {
                    std::string err;
                    if (ctx.client) {
                        ctx.client->set_config(cfg_);
                        if (ctx.client->start(&err)) {
                            last_message_ = "Client starting.";
                            last_error_ = false;
                        } else {
                            last_message_ = err.empty() ? "Connect failed." : err;
                            last_error_ = true;
                        }
                    }
                }
            }
            ImGui::EndDisabled();
            ImGui::Dummy(ImVec2(0, 2 * sc));
            ui::muted_text("The GUI runs yume in the background and attaches through local IPC.");
            if (!last_message_.empty()) {
                ui::message_text(last_error_ ? c.error : c.success, "%s", last_message_.c_str());
            }
        }
        ui::end_card();
    }

private:
    client::ClientConfig cfg_{};
    bool loaded_{false};
    bool advanced_open_{false};
    std::string last_message_;
    bool last_error_{false};
};

}  // namespace

std::unique_ptr<Page> make_connect_page() {
    return std::make_unique<ConnectPage>();
}

}  // namespace yume::gui
