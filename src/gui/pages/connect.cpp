/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "pages/page.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

#include <imgui.h>

#include "client/transfer/share_file.hpp"
#include "core/security/secure_erase.hpp"
#include "core/stealth/http_profile.hpp"
#include "facade/session/client_session.hpp"
#include "facade/config/config_io.hpp"
#include "facade/config/profiles.hpp"
#include "facade/security/secure_materials.hpp"
#include "platform/file_dialog.hpp"
#include "ui/design.hpp"

#include <filesystem>
namespace yume::gui {

namespace {

namespace sm = facade::secure_materials;

void wipe_buffer(char* buffer, std::size_t size) noexcept {
    volatile char* cursor = buffer;
    for (std::size_t index = 0; index < size; ++index) {
        cursor[index] = 0;
    }
}

class SensitiveStringGuard {
public:
    explicit SensitiveStringGuard(std::string& value) noexcept : value_(value) {}
    ~SensitiveStringGuard() { security::secure_erase(value_); }

    SensitiveStringGuard(const SensitiveStringGuard&) = delete;
    SensitiveStringGuard& operator=(const SensitiveStringGuard&) = delete;

private:
    std::string& value_;
};

// width=0 means "take the full content region". Pass an explicit width
// when these helpers are placed side-by-side (e.g. host + port) so the
// inputs don't overflow their slice of the row.
void text_input(const char* label, std::string& value, const char* hint = nullptr,
                float width = 0.0f) {
    char buf[512];
    std::strncpy(buf, value.c_str(), sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    ImGui::PushID(label);
    ui::field_label(label);
    ImGui::SetNextItemWidth(width > 0.0f ? width : ui::form_width());
    if (hint) ImGui::InputTextWithHint("##value", hint, buf, sizeof(buf));
    else ImGui::InputText("##value", buf, sizeof(buf));
    value = buf;
    ImGui::PopID();
}

void int_input(const char* label, int& value, float width = 0.0f) {
    ImGui::PushID(label);
    ui::field_label(label);
    ImGui::SetNextItemWidth(width > 0.0f ? width : ui::form_width());
    ImGui::InputInt("##value", &value, 0, 0);
    ImGui::PopID();
}

ImVec4 state_color(facade::ConnectionState s) {
    auto const& c = ui::colors();
    switch (s) {
        case facade::ConnectionState::Connected: return c.success;
        case facade::ConnectionState::Failed:    return c.error;
        case facade::ConnectionState::Disconnected:
        case facade::ConnectionState::Idle:      return c.muted;
        default:                                 return c.warning;
    }
}

class ConnectPage : public Page {
public:
    ~ConnectPage() override {
        clear_export_sensitive();
        clear_import_sensitive();
    }

    std::string_view title() const override { return "Connection"; }

    void on_show(AppContext& ctx) override {
        refresh_profiles();
        if (ctx.client && (!loaded_ || !ctx.client->running())) {
            cfg_ = ctx.client->config();
            loaded_ = true;
        }
    }

    void on_hide(AppContext&) override {
        clear_export_sensitive();
        clear_import_sensitive();
    }

    void render(AppContext& ctx) override {
        auto const& c = ui::colors();
        const float sc = ui::scale();

        ui::page_header("Connection",
                        "Pick a saved server profile, choose trust material, then connect.");

        // Live state and the Connect/Disconnect control lead the page. They
        // used to sit at the bottom of a long form, which put the page's
        // primary verb below the fold at the default window size.
        render_connection_header(ctx, c, sc);
        ImGui::Dummy(ImVec2(0, 6 * sc));

        render_profile_card(ctx);
        ImGui::Dummy(ImVec2(0, 6 * sc));

        if (ui::begin_auto_card("##connect_essential")) {
            ui::section_label("Server");
            // Host + Port live on one row. ImGui tables don't reliably
            // respect SetNextItemWidth-overrides inside their cells, so
            // we lay it out manually: a wide host group, then SameLine,
            // then a fixed-width port group. Reserve enough room for the
            // port label and a 5-digit value.
            const float row_avail = ImGui::GetContentRegionAvail().x;
            const float port_w    = 110.0f * sc;
            const float gap       = 12.0f * sc;
            const float host_w    = std::max(120.0f * sc, row_avail - port_w - gap);
            ImGui::BeginGroup();
            text_input("Server host", cfg_.server, "vpn.example.com", host_w);
            ImGui::EndGroup();
            ImGui::SameLine(0, gap);
            ImGui::BeginGroup();
            int_input("Port", cfg_.port, port_w);
            ImGui::EndGroup();
            text_input("Display name", cfg_.preferred_name, "optional");

            ImGui::Dummy(ImVec2(0, 6 * sc));
            std::string ca_name = "Not selected";
            std::string key_name = cfg_.identity.empty() ? "Not selected" : cfg_.identity;
            if (!cfg_.anonym_ca_material_id.empty()) {
                if (auto ca = sm::get(cfg_.anonym_ca_material_id)) {
                    ca_name = ca->display_name;
                }
            } else if (!cfg_.anonym_ca_cert.empty()) {
                ca_name = cfg_.anonym_ca_cert;
            }
            if (!cfg_.auth_key_material_id.empty()) {
                if (auto key = sm::get(cfg_.auth_key_material_id)) {
                    key_name = key->display_name;
                }
            }
            ui::section_label_help(
                "Trust material",
                "Import or switch saved operator CAs and auth keys on the "
                "Security page.");
            ui::muted_text("Operator CA: %s", ca_name.c_str());
            ui::muted_text("Auth key: %s", key_name.c_str());
        }
        ui::end_card();

        ImGui::Dummy(ImVec2(0, 6 * sc));
        if (ui::begin_auto_card("##connect_security")) {
            // Not a choice: dev6 pins these. State them, do not offer them.
            cfg_.inner_crypto = true;
            cfg_.pq_public_key.clear();
            ui::section_label_help(
                "Transport security",
                "Fixed by the protocol, not configurable. Every session uses "
                "ML-KEM-1024 + X25519 + PSK with directional ratchets inside "
                "the HTTP/2 carrier.");
            ImGui::Dummy(ImVec2(0, 4 * sc));
            ui::status_pill("ML-KEM-1024 / X25519 / PSK", c.success);
            ImGui::SameLine(0.0f, 6 * sc);
            ui::status_pill("Directional ratchet", c.success);

            ImGui::Dummy(ImVec2(0, 8 * sc));
            ui::section_label("Operator identity proof");
            ui::field_label_help(
                "Operator verification policy",
                "Proves the server is authorized by the selected operator CA. "
                "It does not prove the operator cannot inspect or log "
                "traffic.");
            const char* anonym_modes[] = {"Required", "Allow monitored server"};
            int anonym_idx = (!cfg_.require_anonym && cfg_.accept_monitoring) ? 1 : 0;
            (void)ui::combo("##anonym_mode", &anonym_idx, anonym_modes, 2, 320.f);
            cfg_.require_anonym = anonym_idx == 0;
            cfg_.accept_monitoring = anonym_idx == 1;
            int_input("SOCKS5 port (0 = auto)", cfg_.socks_port);

            ImGui::Dummy(ImVec2(0, 8 * sc));
            advanced_open_ = ui::disclosure_header("TLS trust and advanced transport",
                                                   advanced_open_);
            if (advanced_open_) {
                // Trust material is selected on the Security page, not
                // pasted inline. Show what's currently selected.
                auto material_label = [](std::string const& id, char const* dflt) {
                    if (id.empty()) return std::string(dflt);
                    if (auto m = sm::get(id)) return m->display_name;
                    return std::string("unknown (id=") + id + ")";
                };
                ui::muted_text("External proof key: %s",
                               material_label(cfg_.anonym_pubkey_material_id,
                                              "embedded FixCraft key").c_str());
                ui::muted_text("TLS CA: %s",
                               material_label(cfg_.tls_ca_material_id,
                                              "system trust store").c_str());
                ui::muted_text("Use Security to import or change either.");
                text_input("Admission secret file", cfg_.obfs_secret_file,
                           "required 32-byte hex secret file");
                text_input("Inner PSK file", cfg_.inner_psk_file,
                           "required 32-byte hex PSK file");
                text_input("TLS pin SHA-256", cfg_.tls_pin_sha256, "optional certificate pin");
                cfg_.tls_stealth_enabled = true;
                const auto transport_profiles =
                    yume::http_profile::transport_client_names();
                ui::field_label("Transport profile");
                if (ImGui::BeginCombo("##transport_profile",
                                      cfg_.tls_stealth_profile.c_str())) {
                    for (const auto& profile : transport_profiles) {
                        const bool selected = cfg_.tls_stealth_profile == profile;
                        if (ImGui::Selectable(profile.c_str(), selected)) {
                            cfg_.tls_stealth_profile = profile;
                        }
                        if (selected) ImGui::SetItemDefaultFocus();
                    }
                    ImGui::EndCombo();
                }
                ui::muted_text(
                    "The transport-v2 runtime exposes one complete Chrome 151 "
                    "+ Node 24 identity.");
                int_input("IO threads (0 = auto)", cfg_.io_threads);

                const char* relay_modes[] = {"untrusted", "trusted", "operator"};
                int rm_idx = 0;
                for (int i = 0; i < 3; ++i) {
                    if (cfg_.relay_mode == relay_modes[i]) { rm_idx = i; break; }
                }
                ui::field_label("Relay mode");
                if (ui::combo("##relay_mode", &rm_idx, relay_modes, 3, 320.f)) {
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
                text_input("TLS server name override (SNI)", cfg_.tls_server_name,
                           "optional — blank uses server host");
                ui::checkbox("Headless service streams", &cfg_.service_streams_only);
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
            ImGui::BeginDisabled(!report.ok());
            if (ui::secondary_button("Save profile", ImVec2(126 * sc, 30 * sc))) {
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
        }
        ui::end_card();
    }

private:
    // Live connection state plus the page's primary verb, in one row.
    void render_connection_header(AppContext& ctx, ui::Colors const& c, float sc) {
        facade::ClientStatus st{};
        if (ctx.client) st = ctx.client->status();
        const bool running = ctx.client && ctx.client->running();
        // stop() returns before teardown finishes, so there is a window where
        // running() is already false but start() is still refused. Offering
        // Connect during it produces an error the user did nothing to cause.
        const bool busy = ctx.client && ctx.client->busy();
        auto const report = facade::config_io::validate(cfg_);

        if (ui::begin_auto_card("##connection_header")) {
            const float btn_w = 132 * sc;
            const float btn_h = 34 * sc;

            ImGui::BeginGroup();
            ui::status_pill(facade::display_label(st.state), state_color(st.state));
            ImGui::SameLine(0.0f, 10 * sc);
            ui::muted_text("%s", st.server_endpoint.empty()
                                     ? "No server configured"
                                     : st.server_endpoint.c_str());
            ImGui::EndGroup();

            ImGui::SameLine();
            const float shift = ImGui::GetContentRegionAvail().x - btn_w;
            if (shift > 0.0f) ImGui::Dummy(ImVec2(shift, 1));
            ImGui::SameLine(0.0f, 0.0f);

            ImGui::BeginDisabled(!ctx.client ||
                                 (!running && (busy || !report.ok())));
            if (running) {
                if (ui::secondary_button("Disconnect", ImVec2(btn_w, btn_h))) {
                    ctx.client->stop();
                    last_message_ = "Disconnected.";
                    last_error_ = false;
                }
            } else {
                if (ui::primary_button(busy ? "Disconnecting..." : "Connect",
                                       ImVec2(btn_w, btn_h))) {
                    std::string err;
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
            ImGui::EndDisabled();

            // When connected, the facade's own posture reporting is the
            // truth about this session -- not anything the form says.
            if (running && st.state == facade::ConnectionState::Connected) {
                ImGui::Dummy(ImVec2(0, 6 * sc));
                ui::muted_text("%s \xC2\xB7 %s \xC2\xB7 rekey window %u",
                               st.effective_protection.c_str(),
                               st.tls_backend.empty() ? "openssl"
                                                      : st.tls_backend.c_str(),
                               static_cast<unsigned>(st.rekey_window));
            }
            if (!st.message.empty()) {
                ImGui::Dummy(ImVec2(0, 4 * sc));
                ui::muted_text("%s", st.message.c_str());
            }
            if (!last_message_.empty()) {
                ImGui::Dummy(ImVec2(0, 4 * sc));
                ui::message_text(last_error_ ? c.error : c.success, "%s",
                                 last_message_.c_str());
            }
            if (!running && !report.ok()) {
                ImGui::Dummy(ImVec2(0, 4 * sc));
                for (auto const& e : report.errors) {
                    ImGui::TextColored(c.error, "\xE2\x80\xA2 %s", e.c_str());
                }
            }
        }
        ui::end_card();
    }

    void render_profile_card(AppContext& ctx) {
        const float sc = ui::scale();
        if (!ui::begin_auto_card("##connect_profile")) { ui::end_card(); return; }

        ui::section_label("Profile");
        std::vector<char const*> labels;
        labels.reserve(profiles_.size() + 1);
        labels.push_back("(unsaved)");
        for (auto const& p : profiles_) labels.push_back(p.display_name.c_str());

        int chosen = 0;
        for (std::size_t i = 0; i < profiles_.size(); ++i) {
            if (profiles_[i].id == active_id_) { chosen = static_cast<int>(i) + 1; break; }
        }
        if (ui::combo("##profile_pick", &chosen, labels.data(),
                      static_cast<int>(labels.size()), 280.f)) {
            if (chosen == 0) {
                active_id_.clear();
                facade::profiles::set_active("");
            } else {
                auto const& p = profiles_[chosen - 1];
                active_id_ = p.id;
                facade::profiles::set_active(p.id);
                if (auto loaded = facade::profiles::load(p.id)) {
                    cfg_ = *loaded;
                    if (ctx.client) ctx.client->set_config(cfg_);
                    last_message_ = "Switched to '" + p.display_name + "'.";
                    last_error_ = false;
                }
            }
        }

        ImGui::SameLine(0.0f, 10 * sc);
        if (ui::secondary_button("Save as", ImVec2(120 * sc, 40 * sc))) {
            new_name_[0] = 0;
            ImGui::OpenPopup("##save_profile");
        }
        ImGui::SameLine(0.0f, 6 * sc);
        ImGui::BeginDisabled(active_id_.empty());
        if (ui::quiet_button("Delete", ImVec2(100 * sc, 40 * sc))) {
            std::string err;
            if (facade::profiles::remove(active_id_, &err)) {
                last_message_ = "Profile deleted.";
                last_error_ = false;
                active_id_.clear();
            } else {
                last_message_ = "Delete failed: " + err;
                last_error_ = true;
            }
            refresh_profiles();
        }
        ImGui::EndDisabled();

        // Export / Import — backup the current profile to a password-
        // encrypted .yss ("yume secure store") file and restore it on
        // another device. The on-wire magic is what gates decoding,
        // so the file extension is decoration — any name works.
        ImGui::SameLine(0.0f, 10 * sc);
        ImGui::BeginDisabled(cfg_.server.empty() || cfg_.identity.empty());
        if (ui::quiet_button("Export...", ImVec2(96 * sc, 40 * sc))) {
            clear_export_sensitive();
            export_status_.clear();
            ImGui::OpenPopup("##share_export");
        }
        ImGui::EndDisabled();
        ImGui::SameLine(0.0f, 6 * sc);
        if (ui::quiet_button("Import...", ImVec2(96 * sc, 40 * sc))) {
            clear_import_sensitive();
            import_path_.clear();
            import_status_.clear();
            ImGui::OpenPopup("##share_import");
        }

        render_export_modal(ctx);
        render_import_modal(ctx);

        if (!active_id_.empty()) {
            ImGui::SameLine(0.0f, 6 * sc);
            if (ui::quiet_button("Save", ImVec2(96 * sc, 40 * sc))) {
                std::string display = active_id_;
                for (auto const& p : profiles_) {
                    if (p.id == active_id_) { display = p.display_name; break; }
                }
                std::string err;
                if (facade::profiles::save(active_id_, display, cfg_, &err)) {
                    last_message_ = "Profile saved.";
                    last_error_ = false;
                } else {
                    last_message_ = "Save failed: " + err;
                    last_error_ = true;
                }
                refresh_profiles();
            }
        }

        if (ImGui::BeginPopup("##save_profile")) {
            ui::field_label("Profile name");
            ImGui::SetNextItemWidth(280 * sc);
            ImGui::InputText("##new_profile_name", new_name_, sizeof(new_name_));
            ImGui::Dummy(ImVec2(0, 4 * sc));
            ImGui::BeginDisabled(new_name_[0] == 0);
            if (ui::primary_button("Create",
                                   ImVec2(ui::button_width("Create", 120), 38 * sc))) {
                std::string err;
                auto created = facade::profiles::create(new_name_, cfg_, &err);
                if (created) {
                    active_id_ = *created;
                    facade::profiles::set_active(*created);
                    last_message_ = "Profile created.";
                    last_error_ = false;
                    refresh_profiles();
                    ImGui::CloseCurrentPopup();
                } else {
                    last_message_ = "Create failed: " + err;
                    last_error_ = true;
                }
            }
            ImGui::EndDisabled();
            ImGui::SameLine(0.0f, 8 * sc);
            if (ui::secondary_button("Cancel",
                                     ImVec2(ui::button_width("Cancel", 100), 38 * sc))) {
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }
        ui::end_card();
    }

    void refresh_profiles() {
        profiles_ = facade::profiles::list();
        active_id_ = facade::profiles::active_id();
    }

    void render_export_modal(AppContext& ctx) {
        (void)ctx;
        const float sc = ui::scale();
        if (!ImGui::BeginPopupModal("##share_export", nullptr,
                                    ImGuiWindowFlags_AlwaysAutoResize)) return;
        ImGui::TextUnformatted("Export this profile to a .yss file");
        ImGui::Dummy(ImVec2(0, 4 * sc));
        ImGui::TextWrapped(
            "Encrypts the server connection info, your auth private key, "
            "the operator CA cert, PQ public key, and the obfs secret into "
            "one password-protected file. Anyone with the file AND the "
            "password becomes you on this server — pick a strong password.");
        ImGui::Dummy(ImVec2(0, 6 * sc));
        ui::field_label("Password (12+ chars)");
        ImGui::SetNextItemWidth(320 * sc);
        ImGui::InputText("##share_pwd1", export_pwd_, sizeof(export_pwd_),
                         ImGuiInputTextFlags_Password);
        ui::field_label("Confirm");
        ImGui::SetNextItemWidth(320 * sc);
        ImGui::InputText("##share_pwd2", export_pwd2_, sizeof(export_pwd2_),
                         ImGuiInputTextFlags_Password);
        if (!export_status_.empty()) {
            ImGui::Dummy(ImVec2(0, 4 * sc));
            ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.6f, 1.0f), "%s",
                               export_status_.c_str());
        }
        ImGui::Dummy(ImVec2(0, 6 * sc));
        bool can = std::strlen(export_pwd_) >= yume::share::kPasswordMin &&
                   std::strcmp(export_pwd_, export_pwd2_) == 0;
        ImGui::BeginDisabled(!can);
        if (ui::primary_button("Choose destination & export",
                               ImVec2(280 * sc, 38 * sc))) {
            std::string err;
            auto dest = platform::save_file_dialog(
                "Save yume secure store (.yss)",
                cfg_.server.empty() ? std::string("yume-backup.yss")
                                    : (cfg_.server + ".yss"),
                &err);
            if (!dest) {
                export_status_ = err.empty() ? std::string("cancelled") : err;
                clear_export_sensitive();
            } else {
                std::string werr;
                if (do_export(dest->string(), export_pwd_, &werr)) {
                    last_message_ = "Exported to " + dest->string();
                    last_error_ = false;
                    // Wipe password buffers so a screenshot of the next
                    // popup doesn't expose them.
                    clear_export_sensitive();
                    ImGui::CloseCurrentPopup();
                } else {
                    export_status_ = werr;
                    clear_export_sensitive();
                }
            }
        }
        ImGui::EndDisabled();
        ImGui::SameLine(0.0f, 8 * sc);
        if (ui::secondary_button("Cancel", ImVec2(100 * sc, 38 * sc))) {
            clear_export_sensitive();
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    void render_import_modal(AppContext& ctx) {
        (void)ctx;
        const float sc = ui::scale();
        if (!ImGui::BeginPopupModal("##share_import", nullptr,
                                    ImGuiWindowFlags_AlwaysAutoResize)) return;
        ImGui::TextUnformatted("Import a .yss file");
        ImGui::Dummy(ImVec2(0, 4 * sc));
        if (import_path_.empty()) {
            ImGui::TextWrapped("Pick a .yss file someone shared with you, or that you "
                               "exported on another device.");
            ImGui::Dummy(ImVec2(0, 6 * sc));
            if (ui::primary_button("Choose file...", ImVec2(180 * sc, 38 * sc))) {
                std::string err;
                auto src = platform::open_file_dialog("Open yume share file", &err);
                if (src) {
                    clear_import_sensitive();
                    import_path_ = src->string();
                    import_status_.clear();
                } else {
                    clear_import_sensitive();
                    import_status_ = err.empty() ? std::string("cancelled") : err;
                }
            }
        } else {
            ImGui::Text("File: %s", import_path_.c_str());
            ImGui::Dummy(ImVec2(0, 6 * sc));
            ui::field_label("Password");
            ImGui::SetNextItemWidth(320 * sc);
            ImGui::InputText("##share_import_pwd", import_pwd_, sizeof(import_pwd_),
                             ImGuiInputTextFlags_Password);
            ImGui::Dummy(ImVec2(0, 4 * sc));
            ImGui::BeginDisabled(import_pwd_[0] == 0);
            if (ui::primary_button("Decrypt & preview",
                                   ImVec2(200 * sc, 38 * sc))) {
                std::string err;
                if (do_decrypt_preview(&err)) {
                    import_status_.clear();
                } else {
                    import_status_ = err;
                }
            }
            ImGui::EndDisabled();
            if (import_summary_) {
                const auto& b = *import_summary_;
                ImGui::Dummy(ImVec2(0, 6 * sc));
                ImGui::TextUnformatted("─── Bundle contents ───");
                if (!b.label.empty())  ImGui::Text("Label:       %s", b.label.c_str());
                ImGui::Text("Server:      %s:%d", b.server_host.c_str(), b.server_port);
                ImGui::Text("Auth key:    %s", b.auth_private_key_pem.empty() ? "(none)" : "PRESENT");
                ImGui::Text("Operator CA: %s", b.anonym_ca_cert_pem.empty() ? "(none)" : "PRESENT");
                ImGui::Text("PQ pubkey:   %s", b.pq_public_key_pem.empty() ? "(none)" : "PRESENT");
                ImGui::Text("Obfs secret: %s", b.obfs_secret.empty() ? "(none)" : "PRESENT");
                ImGui::Text("Inner:       %s",
                    b.inner_crypto ? "on" : "off");
                ImGui::Dummy(ImVec2(0, 6 * sc));
                if (ui::primary_button("Apply: write to ~/.yume/imported/",
                                       ImVec2(300 * sc, 38 * sc))) {
                    std::string err;
                    if (do_apply_preview(&err)) {
                        clear_import_sensitive();
                        ImGui::CloseCurrentPopup();
                    } else {
                        import_status_ = err;
                        clear_import_sensitive();
                    }
                }
            }
        }
        if (!import_status_.empty()) {
            ImGui::Dummy(ImVec2(0, 4 * sc));
            ImGui::TextColored(ImVec4(1.0f, 0.6f, 0.6f, 1.0f), "%s",
                               import_status_.c_str());
        }
        ImGui::Dummy(ImVec2(0, 6 * sc));
        if (ui::secondary_button("Close", ImVec2(100 * sc, 38 * sc))) {
            clear_import_sensitive();
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    bool do_export(const std::string& dest, std::string password, std::string* err) {
        SensitiveStringGuard password_guard(password);
        yume::share::BackupInputs in;
        in.label = cfg_.server + (cfg_.port > 0 ? ":" + std::to_string(cfg_.port) : std::string());
        in.created_by = std::string("yume-gui");
        in.server_host = cfg_.server;
        in.server_port = cfg_.port > 0 ? cfg_.port : 443;
        in.identity_path = cfg_.identity;
        in.anonym_ca_cert_path = cfg_.anonym_ca_cert;
        in.tls_ca_cert_path = cfg_.tls_ca_cert;
        in.pq_public_key_path = cfg_.pq_public_key;
        in.obfuscation = cfg_.obfuscation;
        in.obfs_secret_path = cfg_.obfs_secret_file;
        in.inner_psk_path = cfg_.inner_psk_file;
        in.obfs_pad_multiple = cfg_.obfs_pad_multiple;
        in.obfs_jitter_ms = cfg_.obfs_jitter_ms;
        in.tls_pin_sha256 = cfg_.tls_pin_sha256;
        in.tls_stealth_profile = cfg_.tls_stealth_profile;
        in.tls_server_name = cfg_.tls_server_name;
        in.anonym_pubkey = cfg_.anonym_pubkey;
        in.inner_crypto = cfg_.inner_crypto;
        in.tunnel_count = static_cast<std::uint8_t>(
            std::clamp(cfg_.tunnel_count, 1, 16));
        in.require_operator_identity = cfg_.require_anonym;
        in.allow_udp = cfg_.allow_udp;
        in.allow_local_ip = cfg_.allow_local_ip;

        yume::share::ShareBundle bundle;
        if (!yume::share::build_backup_bundle(in, &bundle, err)) return false;
        auto bytes = yume::share::encode_share(bundle, password, err);
        if (bytes.empty()) return false;

        return yume::share::write_share_file_exclusive(dest, bytes, err);
    }

    bool do_decrypt_preview(std::string* err) {
        import_summary_.reset();
        std::vector<std::uint8_t> blob;
        if (!yume::share::read_share_file(import_path_, &blob, err)) {
            wipe_buffer(import_pwd_, sizeof(import_pwd_));
            return false;
        }
        std::string password(import_pwd_);
        SensitiveStringGuard password_guard(password);
        wipe_buffer(import_pwd_, sizeof(import_pwd_));
        auto bundle_opt = yume::share::decode_share(blob, password, err);
        if (!bundle_opt) return false;
        import_summary_ = std::move(*bundle_opt);
        return true;
    }

    bool do_apply_preview(std::string* err) {
        if (!import_summary_) { if (err) *err = "no bundle decrypted yet"; return false; }
        yume::share::ApplyResult applied;
        if (!yume::share::apply_imported_bundle(*import_summary_, &applied, err)) return false;
        last_message_ = "Imported to " + applied.target_dir +
                        " — connect with: yume --config " + applied.config_path;
        last_error_ = false;
        return true;
    }

    void clear_export_sensitive() noexcept {
        wipe_buffer(export_pwd_, sizeof(export_pwd_));
        wipe_buffer(export_pwd2_, sizeof(export_pwd2_));
    }

    void clear_import_sensitive() noexcept {
        wipe_buffer(import_pwd_, sizeof(import_pwd_));
        import_summary_.reset();
    }

    client::ClientConfig cfg_{};
    std::vector<facade::profiles::ProfileSummary> profiles_;
    std::string active_id_;
    char new_name_[160]{};
    bool loaded_{false};
    bool advanced_open_{false};
    std::string last_message_;
    bool last_error_{false};

    // Share-file dialog state
    char export_pwd_[160]{};
    char export_pwd2_[160]{};
    std::string export_status_;
    char import_pwd_[160]{};
    std::string import_path_;
    std::string import_status_;
    std::optional<yume::share::ShareBundle> import_summary_;
};

}  // namespace

std::unique_ptr<Page> make_connect_page() {
    return std::make_unique<ConnectPage>();
}

}  // namespace yume::gui
