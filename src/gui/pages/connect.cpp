/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "pages/page.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>

#include <imgui.h>

#include "client/share_file.hpp"
#include "facade/client_session.hpp"
#include "facade/config_io.hpp"
#include "facade/profiles.hpp"
#include "facade/secure_materials.hpp"
#include "platform/file_dialog.hpp"
#include "ui/design.hpp"

#include <filesystem>
#include <fstream>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace yume::gui {

namespace {

namespace sm = facade::secure_materials;

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

class ConnectPage : public Page {
public:
    std::string_view title() const override { return "Client"; }

    void on_show(AppContext& ctx) override {
        refresh_profiles();
        if (ctx.client && (!loaded_ || !ctx.client->running())) {
            cfg_ = ctx.client->config();
            loaded_ = true;
        }
    }

    void render(AppContext& ctx) override {
        auto const& c = ui::colors();
        const float sc = ui::scale();

        ui::page_header("Client",
                        "Pick a saved server profile, choose trust material, then connect.");

        render_profile_card(ctx);
        ImGui::Dummy(ImVec2(0, 8 * sc));

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
            if (ui::combo("##anonym_mode", &anonym_idx, anonym_modes, 2, 320.f)) {
                cfg_.require_anonym = anonym_idx == 1;
            }
            ui::muted_text(
                "Optional allows monitored servers after warning acceptance. Required refuses servers that do not prove anonym mode.");
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
                ui::muted_text("Anonym public key: %s",
                               material_label(cfg_.anonym_pubkey_material_id,
                                              "embedded default").c_str());
                ui::muted_text("TLS CA: %s",
                               material_label(cfg_.tls_ca_material_id,
                                              "system trust store").c_str());
                ui::muted_text("Use Security to import or change either.");
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
                if (ui::combo("##tls_profile", &prof_idx, profiles, 3, 320.f)) {
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
        if (ui::quiet_button("Export…", ImVec2(96 * sc, 40 * sc))) {
            export_pwd_[0] = 0;
            export_pwd2_[0] = 0;
            export_status_.clear();
            ImGui::OpenPopup("##share_export");
        }
        ImGui::EndDisabled();
        ImGui::SameLine(0.0f, 6 * sc);
        if (ui::quiet_button("Import…", ImVec2(96 * sc, 40 * sc))) {
            import_pwd_[0] = 0;
            import_path_.clear();
            import_status_.clear();
            import_summary_ = std::nullopt;
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
            "the anonym CA cert, PQ public key, and the obfs secret into "
            "one password-protected file. Anyone with the file AND the "
            "password becomes you on this server — pick a strong password.");
        ImGui::Dummy(ImVec2(0, 6 * sc));
        ui::field_label("Password (8+ chars)");
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
        bool can = std::strlen(export_pwd_) >= 8 &&
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
            } else {
                std::string werr;
                if (do_export(dest->string(), export_pwd_, &werr)) {
                    last_message_ = "Exported to " + dest->string();
                    last_error_ = false;
                    // Wipe password buffers so a screenshot of the next
                    // popup doesn't expose them.
                    std::memset(export_pwd_, 0, sizeof(export_pwd_));
                    std::memset(export_pwd2_, 0, sizeof(export_pwd2_));
                    ImGui::CloseCurrentPopup();
                } else {
                    export_status_ = werr;
                }
            }
        }
        ImGui::EndDisabled();
        ImGui::SameLine(0.0f, 8 * sc);
        if (ui::secondary_button("Cancel", ImVec2(100 * sc, 38 * sc))) {
            std::memset(export_pwd_, 0, sizeof(export_pwd_));
            std::memset(export_pwd2_, 0, sizeof(export_pwd2_));
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
            if (ui::primary_button("Choose file…", ImVec2(180 * sc, 38 * sc))) {
                std::string err;
                auto src = platform::open_file_dialog("Open yume share file", &err);
                if (src) {
                    import_path_ = src->string();
                    import_status_.clear();
                    import_summary_ = std::nullopt;
                } else {
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
                ImGui::Text("Anonym CA:   %s", b.anonym_ca_cert_pem.empty() ? "(none)" : "PRESENT");
                ImGui::Text("PQ pubkey:   %s", b.pq_public_key_pem.empty() ? "(none)" : "PRESENT");
                ImGui::Text("Obfs secret: %s", b.obfs_secret.empty() ? "(none)" : "PRESENT");
                ImGui::Text("Inner:       %s; hop=%s",
                    b.inner_crypto ? (b.inner_heavy ? "heavy" : "light") : "off",
                    b.inner_hop ? "on" : "off");
                ImGui::Dummy(ImVec2(0, 6 * sc));
                if (ui::primary_button("Apply: write to ~/.yume/imported/",
                                       ImVec2(300 * sc, 38 * sc))) {
                    std::string err;
                    if (do_apply_preview(&err)) {
                        std::memset(import_pwd_, 0, sizeof(import_pwd_));
                        ImGui::CloseCurrentPopup();
                    } else {
                        import_status_ = err;
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
            std::memset(import_pwd_, 0, sizeof(import_pwd_));
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }

    bool do_export(const std::string& dest, const std::string& password, std::string* err) {
        yume::share::BackupInputs in;
        in.label = cfg_.server + (cfg_.port > 0 ? ":" + std::to_string(cfg_.port) : std::string());
        in.created_by = std::string("yume-gui");
        in.server_host = cfg_.server;
        in.server_port = cfg_.port > 0 ? cfg_.port : 443;
        in.identity_path = cfg_.identity;
        in.anonym_ca_cert_path = cfg_.anonym_ca_cert;
        in.pq_public_key_path = cfg_.pq_public_key;
        in.obfuscation = cfg_.obfuscation;
        in.obfs_secret = cfg_.obfs_secret;
        in.obfs_pad_multiple = cfg_.obfs_pad_multiple;
        in.obfs_jitter_ms = cfg_.obfs_jitter_ms;
        in.tls_pin_sha256 = cfg_.tls_pin_sha256;
        in.tls_stealth_profile = cfg_.tls_stealth_profile;
        in.anonym_pubkey = cfg_.anonym_pubkey;
        in.inner_crypto = cfg_.inner_crypto;
        in.inner_heavy = cfg_.inner_heavy;
        in.inner_hop = cfg_.inner_hop;
        in.hop_interval_ms = cfg_.hop_interval_ms;
        in.allow_udp = cfg_.allow_udp;
        in.allow_local_ip = cfg_.allow_local_ip;

        yume::share::ShareBundle bundle;
        if (!yume::share::build_backup_bundle(in, &bundle, err)) return false;
        auto bytes = yume::share::encode_share(bundle, password, err);
        if (bytes.empty()) return false;

#ifndef _WIN32
        const mode_t prior = ::umask(0077);
#endif
        std::ofstream f(dest, std::ios::binary | std::ios::trunc);
#ifndef _WIN32
        ::umask(prior);
#endif
        if (!f) { if (err) *err = "cannot write " + dest; return false; }
        f.write(reinterpret_cast<const char*>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
        if (!f) { if (err) *err = "write failed: " + dest; return false; }
        f.close();
#ifndef _WIN32
        (void)::chmod(dest.c_str(), 0600);
#endif
        return true;
    }

    bool do_decrypt_preview(std::string* err) {
        std::ifstream f(import_path_, std::ios::binary);
        if (!f) { if (err) *err = "cannot open " + import_path_; return false; }
        std::vector<std::uint8_t> blob((std::istreambuf_iterator<char>(f)),
                                        std::istreambuf_iterator<char>());
        auto bundle_opt = yume::share::decode_share(blob, import_pwd_, err);
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
