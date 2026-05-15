/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 *
 * Server page.
 *
 * Consumer-facing layout: status pill, three plain-English setup
 * cards (Listening / Certificates / Allowed users), an Advanced
 * disclosure that hides everything CLI-flavoured, and a Start/Stop
 * action row. File-system paths are reached through "Browse..."
 * file pickers rather than free-text fields. Auth keys are managed
 * as a list of users (alias + fingerprint + revoke button) backed
 * by facade::keys, not as a raw path to an authorized_keys file.
 */

#include "pages/page.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include <imgui.h>

#include "facade/config_io.hpp"
#include "facade/keys.hpp"
#include "facade/log_sink.hpp"
#include "facade/server_session.hpp"
#include "platform/file_dialog.hpp"
#include "ui/design.hpp"

namespace yume::gui {

namespace {

// Local convenience for the two free-text inputs we still expose
// (port number, server display name in advanced). Everything else
// goes through a file picker or a checkbox.
void text_input(const char* label, std::string& value, const char* hint = nullptr) {
    char buf[512];
    std::strncpy(buf, value.c_str(), sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    ImGui::PushID(label);
    ui::field_label(label);
    ImGui::SetNextItemWidth(ui::form_width());
    if (hint) ImGui::InputTextWithHint("##value", hint, buf, sizeof(buf));
    else      ImGui::InputText("##value", buf, sizeof(buf));
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

// A path + Browse button. Renders the current value (or a friendly
// placeholder), then a tight button to pop a native file dialog and
// replace the value. Returns true if the value changed this frame.
bool file_picker(char const* label,
                 char const* dialog_title,
                 std::string& value,
                 char const* empty_hint,
                 char const* help_text = nullptr) {
    bool changed = false;
    auto const& c = ui::colors();
    const float sc = ui::scale();

    ImGui::PushID(label);
    ui::field_label(label);

    // Layout: path display takes most of the row, button on the right.
    const float row_avail   = ImGui::GetContentRegionAvail().x;
    const float button_w    = 110.0f * sc;
    const float gap         = 10.0f * sc;
    const float path_w      = std::max(120.0f * sc, row_avail - button_w - gap);

    ImGui::PushStyleColor(ImGuiCol_Text,
                          value.empty() ? c.muted : c.text);
    ImGui::BeginGroup();
    ImGui::SetNextItemWidth(path_w);
    char buf[1024];
    std::strncpy(buf, value.empty() ? empty_hint : value.c_str(),
                 sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = 0;
    // Read-only display via InputText with ReadOnly flag - users edit
    // by picking, not typing, but copy-paste from the box still works.
    ImGui::InputText("##path", buf, sizeof(buf),
                     ImGuiInputTextFlags_ReadOnly);
    ImGui::EndGroup();
    ImGui::PopStyleColor();

    ImGui::SameLine(0, gap);
    if (ui::secondary_button("Browse...", ImVec2(button_w, 0))) {
        std::string err;
        if (auto picked = platform::open_file_dialog(dialog_title, &err)) {
            value = picked->string();
            changed = true;
        }
    }

    if (help_text && *help_text) {
        ImGui::PushStyleColor(ImGuiCol_Text, c.muted);
        ImGui::TextWrapped("%s", help_text);
        ImGui::PopStyleColor();
    }
    ImGui::PopID();
    return changed;
}

// Resolve "~/.yume/authorized_keys" - or the user's chosen path -
// for both the listing and the append/remove ops.
std::filesystem::path default_auth_keys_path() {
    return facade::config_io::default_data_dir() / "authorized_keys";
}
std::filesystem::path default_auth_meta_path() {
    return facade::config_io::default_data_dir() / "authorized_keys.meta.json";
}

std::filesystem::path resolved_auth_keys(server::ServerConfig const& cfg) {
    return cfg.auth_keys.empty() ? default_auth_keys_path()
                                 : std::filesystem::path(cfg.auth_keys);
}
std::filesystem::path resolved_auth_meta(server::ServerConfig const& cfg) {
    return cfg.auth_keys_meta.empty() ? default_auth_meta_path()
                                      : std::filesystem::path(cfg.auth_keys_meta);
}

void push_log(facade::LogLevel level, std::string msg) {
    facade::LogEntry e;
    e.ts = std::chrono::system_clock::now();
    e.level = level;
    e.component = "gui.server";
    e.message = std::move(msg);
    facade::LogSink::instance().push(std::move(e));
}

class ServerPage : public Page {
public:
    std::string_view title() const override { return "Server"; }

    void on_show(AppContext& ctx) override {
        if (ctx.server && !loaded_) {
            cfg_ = ctx.server->config();
            loaded_ = true;
        }
        refresh_auth_keys();
    }

    void render(AppContext& ctx) override {
        auto const& c = ui::colors();
        const float sc = ui::scale();
        const bool running = ctx.server && ctx.server->running();
        const facade::ServerStatus st = ctx.server ? ctx.server->status()
                                                   : facade::ServerStatus{};

        ui::page_header("Server",
                        "Host your own Yume server so other people can connect to you.");

        render_status_card(c, sc, running, st);
        ImGui::Dummy(ImVec2(0, 8 * sc));

        render_listening_card(running, sc);
        ImGui::Dummy(ImVec2(0, 8 * sc));

        render_certificates_card(running, c, sc);
        ImGui::Dummy(ImVec2(0, 8 * sc));

        render_users_card(running, c, sc);
        ImGui::Dummy(ImVec2(0, 8 * sc));

        render_advanced_card(running, c, sc);
        ImGui::Dummy(ImVec2(0, 8 * sc));

        render_actions(ctx, running, c, sc);
        if (running) {
            ImGui::Dummy(ImVec2(0, 8 * sc));
            render_sessions(ctx, c, sc);
        }
    }

private:
    void render_status_card(ui::Colors const& c, float sc,
                            bool running, facade::ServerStatus const& st) {
        if (ui::begin_auto_card("##server_status")) {
            ui::section_label("Status");
            ui::status_pill(running ? "Running" : "Stopped",
                            running ? c.success : c.muted);
            ImGui::SameLine(0.0f, 16 * sc);
            ui::muted_text("%s",
                st.listen_endpoint.empty()
                    ? "Not yet listening"
                    : (std::string("Listening on ") + st.listen_endpoint).c_str());

            if (!st.message.empty()) {
                if (!running) {
                    // Red error text when the server isn't running and
                    // there's a message - port-bind permission denied,
                    // missing cert, etc.
                    ui::message_text(c.error, "%s", st.message.c_str());
                } else {
                    ui::muted_text("%s", st.message.c_str());
                }
            }
            if (running) {
                ui::muted_text("Connected users: %zu", st.active_sessions);
                ui::muted_text("Traffic in:  %llu bytes",
                               static_cast<unsigned long long>(st.bytes_in));
                ui::muted_text("Traffic out: %llu bytes",
                               static_cast<unsigned long long>(st.bytes_out));
            }
        }
        ui::end_card();
    }

    void render_listening_card(bool running, float sc) {
        if (ui::begin_auto_card("##listening")) {
            ui::section_label("Listening");
            ImGui::BeginDisabled(running);
            int_input("Port", cfg_.listen_port);
            ImGui::PushStyleColor(ImGuiCol_Text, ui::colors().muted);
            ImGui::TextWrapped(
                "The TCP port your server listens on. "
                "Ports below 1024 (like the default 443) require root or "
                "the cap_net_bind_service capability on Linux. "
                "8443 is a popular safe choice.");
            ImGui::PopStyleColor();
            ImGui::EndDisabled();
        }
        ui::end_card();
        (void)sc;
    }

    void render_certificates_card(bool running, ui::Colors const& c, float sc) {
        if (ui::begin_auto_card("##certs")) {
            ui::section_label("TLS certificate");
            ImGui::BeginDisabled(running);
            file_picker("Certificate file",
                        "Pick TLS certificate (.pem / .crt)",
                        cfg_.tls_cert,
                        "(no certificate selected)",
                        "Your server's TLS certificate. "
                        "Drop in a real Let's Encrypt-issued PEM for "
                        "public servers, or a self-signed one for friends-only.");
            ImGui::Dummy(ImVec2(0, 6 * sc));
            file_picker("Private key file",
                        "Pick TLS private key (.pem / .key)",
                        cfg_.tls_key,
                        "(no private key selected)",
                        "The private key that matches the certificate above. "
                        "Anyone with this file can impersonate your server - "
                        "store it safely.");
            ImGui::EndDisabled();
            if (cfg_.tls_cert.empty() || cfg_.tls_key.empty()) {
                ImGui::Dummy(ImVec2(0, 4 * sc));
                ImGui::PushStyleColor(ImGuiCol_Text, c.warning);
                ImGui::TextWrapped(
                    "Pick a certificate and key before starting the server.");
                ImGui::PopStyleColor();
            }
        }
        ui::end_card();
    }

    void render_users_card(bool running, ui::Colors const& c, float sc) {
        if (ui::begin_auto_card("##users")) {
            ui::section_label("Allowed users");
            ImGui::PushStyleColor(ImGuiCol_Text, c.muted);
            ImGui::TextWrapped(
                "Anyone connecting needs their public key listed here. "
                "Share their public key file with them out-of-band; they "
                "keep the matching private key on their own device.");
            ImGui::PopStyleColor();
            ImGui::Dummy(ImVec2(0, 6 * sc));

            if (auth_keys_.empty()) {
                ui::muted_text("No users authorized yet.");
            } else {
                if (ui::begin_data_table("##users_table", 3)) {
                    ui::data_table_headers({"Name", "Fingerprint", ""});
                    int row_idx = 0;
                    std::string revoke_fp;
                    for (auto const& k : auth_keys_) {
                        ImGui::TableNextRow();
                        ImGui::PushID(row_idx++);
                        ImGui::TableNextColumn();
                        ImGui::TextUnformatted(k.alias.empty() ? "(unnamed)"
                                                              : k.alias.c_str());
                        ImGui::TableNextColumn();
                        std::string short_fp = k.fingerprint.substr(
                            0, std::min<std::size_t>(k.fingerprint.size(), 16));
                        if (!k.fingerprint.empty() && k.fingerprint.size() > 16) short_fp += "...";
                        ImGui::TextUnformatted(short_fp.c_str());
                        ImGui::TableNextColumn();
                        if (ui::danger_button("Revoke",
                                              ImVec2(90 * sc, 32 * sc))) {
                            revoke_fp = k.fingerprint;
                        }
                        ImGui::PopID();
                    }
                    ui::end_data_table();
                    if (!revoke_fp.empty()) revoke(revoke_fp);
                }
            }

            ImGui::Dummy(ImVec2(0, 6 * sc));
            // Auto-width: pass 0 on the x dimension so ImGui sizes each
            // button to its label + frame padding. The hardcoded
            // 200*sc width clipped both labels on Windows where Segoe
            // UI metrics differ from Linux's URW Gothic.
            if (ui::primary_button("Add from public-key file...",
                                   ImVec2(0, 40 * sc))) {
                add_from_file();
            }
            ImGui::SameLine();
            if (ui::secondary_button("Generate new user keypair...",
                                     ImVec2(0, 40 * sc))) {
                generate_new_user();
            }

            if (!users_message_.empty()) {
                ImGui::Dummy(ImVec2(0, 4 * sc));
                ui::message_text(
                    users_message_error_ ? c.error : c.success,
                    "%s", users_message_.c_str());
            }
        }
        ui::end_card();
    }

    void render_advanced_card(bool running, ui::Colors const& c, float sc) {
        advanced_open_ = ui::disclosure_header("Advanced", advanced_open_);
        if (!advanced_open_) return;
        if (ui::begin_auto_card("##server_advanced")) {
            ImGui::BeginDisabled(running);
            ui::section_label("Identity & resolver");
            text_input("Server display name", cfg_.server_name);
            text_input("DNS resolver IP", cfg_.dns_server, "1.1.1.1");
            int_input("Worker threads (0 = auto)", cfg_.threads);

            ImGui::Dummy(ImVec2(0, 8 * sc));
            ui::section_label("Features");
            if (ImGui::BeginTable("##server_features", 3,
                                  ImGuiTableFlags_SizingStretchSame)) {
                ImGui::TableNextColumn();
                ui::checkbox("Allow relays", &cfg_.relay_enable);
                ImGui::TableNextColumn();
                ui::checkbox("Directory listing", &cfg_.directory_enable);
                ImGui::TableNextColumn();
                ui::checkbox("Anonym proof", &cfg_.anonym);
                ImGui::EndTable();
            }

            if (cfg_.anonym) {
                ImGui::Dummy(ImVec2(0, 6 * sc));
                ui::section_label("Anonym proof");
                ImGui::PushStyleColor(ImGuiCol_Text, c.muted);
                ImGui::TextWrapped(
                    "Cryptographically proves to clients that your server "
                    "does not log them. Requires a sub-CA cert/key issued "
                    "by FixCraft or a local trust anchor.");
                ImGui::PopStyleColor();
                ImGui::Dummy(ImVec2(0, 4 * sc));

                const char* proof_modes[] = {"auto", "local", "fixcraft"};
                int proof_idx = 0;
                for (int i = 0; i < 3; ++i) {
                    if (cfg_.anonym_proof_mode == proof_modes[i]) {
                        proof_idx = i; break;
                    }
                }
                ui::field_label("Proof mode");
                if (ui::combo("##anonym_proof_mode", &proof_idx,
                              proof_modes, 3, 320.f)) {
                    cfg_.anonym_proof_mode = proof_modes[proof_idx];
                }
                file_picker("Anonym sub-CA certificate",
                            "Pick Anonym sub-CA cert",
                            cfg_.anonym_sub_cert,
                            "(none - using FixCraft API only)",
                            nullptr);
                file_picker("Anonym sub-CA private key",
                            "Pick Anonym sub-CA key",
                            cfg_.anonym_sub_key,
                            "(none)", nullptr);
                file_picker("Anonym CA certificate (trust anchor)",
                            "Pick Anonym CA cert",
                            cfg_.anonym_ca_cert,
                            "(default embedded CA)", nullptr);
            }

            ImGui::Dummy(ImVec2(0, 8 * sc));
            ui::section_label("Inner post-quantum crypto");
            ImGui::PushStyleColor(ImGuiCol_Text, c.muted);
            ImGui::TextWrapped(
                "Adds an extra cipher layer on top of TLS. Heavy + Both "
                "is the recommended default; turn off only if you need "
                "to debug.");
            ImGui::PopStyleColor();
            ImGui::Dummy(ImVec2(0, 4 * sc));

            ui::checkbox("Enable inner crypto", &cfg_.inner_crypto);

            // Everything under here only matters if inner crypto is on.
            // Disable the controls (greyed) rather than hide them so the
            // user can see what they'd be setting if they re-enabled.
            ImGui::BeginDisabled(!cfg_.inner_crypto);
            ImGui::Dummy(ImVec2(0, 4 * sc));

            // Heavy / Dual were two booleans on disk but a single mode
            // in protocol terms. Collapse to one segmented selector and
            // map back to the two flags here so the underlying config
            // file format stays compatible with the CLI.
            //   Light = HKDF only        → heavy=false, dual=false
            //   Heavy = Argon2 only      → heavy=true,  dual=false
            //   Both  = advertise both,  → heavy=true,  dual=true
            //           client picks
            ui::field_label("Strength");
            int mode = 0;  // 0=Light, 1=Heavy, 2=Both
            if (cfg_.inner_heavy && cfg_.inner_dual) mode = 2;
            else if (cfg_.inner_heavy)               mode = 1;
            else                                     mode = 0;
            char const* mode_labels[] = {"Light", "Heavy", "Both"};
            int new_mode = ui::segmented_control(
                "##inner_mode", mode_labels, 3, mode, 280.0f * sc);
            if (new_mode != mode) {
                switch (new_mode) {
                    case 0: cfg_.inner_heavy = false; cfg_.inner_dual = false; break;
                    case 1: cfg_.inner_heavy = true;  cfg_.inner_dual = false; break;
                    case 2: cfg_.inner_heavy = true;  cfg_.inner_dual = true;  break;
                }
            }
            ImGui::PushStyleColor(ImGuiCol_Text, c.muted);
            ImGui::TextWrapped(
                "Light is fast (HKDF). Heavy is slow but stronger (Argon2). "
                "Both advertises Heavy+Light and lets each client pick.");
            ImGui::PopStyleColor();

            ImGui::Dummy(ImVec2(0, 4 * sc));
            ui::checkbox("Require inner crypto (refuse clients without it)",
                         &cfg_.inner_required);

            ImGui::Dummy(ImVec2(0, 4 * sc));
            ui::checkbox("Rotate inner keys mid-session", &cfg_.inner_hop);
            ImGui::BeginDisabled(!cfg_.inner_hop);
            int hop = static_cast<int>(cfg_.hop_interval_ms);
            int_input("Rotation interval (ms)", hop);
            cfg_.hop_interval_ms = hop < 0 ? 0u : static_cast<std::uint32_t>(hop);
            ImGui::EndDisabled();

            ImGui::EndDisabled();  // closes !cfg_.inner_crypto disabled

            ImGui::Dummy(ImVec2(0, 8 * sc));
            ui::section_label("External CLI control");
            ImGui::PushStyleColor(ImGuiCol_Text, c.muted);
            ImGui::TextWrapped(
                "Lets a separate `yume` command-line tool attach to this "
                "server for power-user automation. Leave off unless you "
                "specifically need it - the GUI itself doesn't use it.");
            ImGui::PopStyleColor();
            ImGui::Dummy(ImVec2(0, 4 * sc));
            ui::checkbox("Allow external CLI to attach", &cfg_.ipc_enable);
            // The path is just plumbing - we pick a sensible default
            // under XDG_RUNTIME_DIR ourselves; users never need to see
            // or edit it. cfg_.ipc_path is left as-is (empty means auto).

            ImGui::EndDisabled();
        }
        ui::end_card();
    }

    void render_actions(AppContext& ctx, bool running,
                        ui::Colors const& c, float sc) {
        if (ui::begin_auto_card("##server_actions")) {
            auto report = facade::config_io::validate(cfg_);
            for (auto const& e : report.errors)   ImGui::TextColored(c.error,   "- %s", e.c_str());
            for (auto const& w : report.warnings) ImGui::TextColored(c.warning, "- %s", w.c_str());
            if (!report.errors.empty()) ImGui::Dummy(ImVec2(0, 4 * sc));

            const ImVec2 btn(190 * sc, 48 * sc);
            if (!running) {
                ImGui::BeginDisabled(!report.ok() || !ctx.server);
                if (ui::primary_button("Start server", btn)) {
                    ctx.server->set_config(cfg_);
                    facade::config_io::save_server(
                        cfg_, facade::config_io::default_server_config_path(),
                        nullptr);
                    std::string err;
                    if (!ctx.server->start(&err)) {
                        last_message_ = err.empty() ? "Couldn't start the server."
                                                    : err;
                        last_error_ = true;
                    } else {
                        last_message_.clear();
                    }
                }
                ImGui::EndDisabled();
            } else {
                if (ui::secondary_button("Stop server", btn) && ctx.server) {
                    ctx.server->stop();
                    last_message_.clear();
                }
            }
            if (!last_message_.empty()) {
                ImGui::Dummy(ImVec2(0, 4 * sc));
                ui::message_text(last_error_ ? c.error : c.success,
                                 "%s", last_message_.c_str());
            }
        }
        ui::end_card();
    }

    void render_sessions(AppContext& ctx, ui::Colors const& c, float sc) {
        if (!ctx.server) return;
        auto sessions = ctx.server->list_sessions();
        if (sessions.empty()) return;
        if (ui::begin_auto_card("##sessions_card")) {
            ui::section_label("Connected users");
            if (ui::begin_data_table("##sessions", 4)) {
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
                                static_cast<unsigned long long>(s.bytes_in),
                                static_cast<unsigned long long>(s.bytes_out));
                }
                ui::end_data_table();
            }
        }
        ui::end_card();
        (void)sc;
    }

    // ---- Auth-keys management ---------------------------------------

    void refresh_auth_keys() {
        try {
            auth_keys_ = facade::keys::list_authorized(
                resolved_auth_keys(cfg_), resolved_auth_meta(cfg_));
        } catch (...) {
            auth_keys_.clear();
        }
    }

    void revoke(std::string const& fingerprint) {
        std::string err;
        if (facade::keys::remove_authorized(
                resolved_auth_keys(cfg_), resolved_auth_meta(cfg_),
                fingerprint, &err)) {
            users_message_ = "Revoked.";
            users_message_error_ = false;
            push_log(facade::LogLevel::Info,
                     "revoked authorized key " + fingerprint);
        } else {
            users_message_ = err.empty() ? "Couldn't revoke." : err;
            users_message_error_ = true;
        }
        refresh_auth_keys();
    }

    void add_from_file() {
        std::string err;
        auto picked = platform::open_file_dialog(
            "Pick the user's public-key file (.pub / .pem)", &err);
        if (!picked) return;
        std::ifstream f(*picked);
        if (!f) {
            users_message_ = "Couldn't open that file.";
            users_message_error_ = true;
            return;
        }
        std::string pem((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
        facade::keys::AuthorizedKeyEntry meta;
        meta.alias = picked->stem().string();
        if (facade::keys::append_authorized(
                resolved_auth_keys(cfg_), resolved_auth_meta(cfg_),
                pem, meta, &err)) {
            users_message_ = std::string("Added user: ") + meta.alias;
            users_message_error_ = false;
            push_log(facade::LogLevel::Info,
                     "added authorized key for " + meta.alias);
        } else {
            users_message_ = err.empty() ? "Couldn't add that key." : err;
            users_message_error_ = true;
        }
        refresh_auth_keys();
    }

    void generate_new_user() {
        // Place the keypair under the same data dir as the config so the
        // .pub file is right next to authorized_keys. The .key file is
        // what the user hands to whoever they're authorizing.
        auto data_dir = facade::config_io::default_data_dir();
        std::error_code ec;
        std::filesystem::create_directories(data_dir, ec);

        // Auto-generate an alias from the current time. Users can rename
        // later via the meta file; we don't expose a rename UI yet.
        char alias[64];
        auto now = std::chrono::system_clock::now().time_since_epoch();
        auto ms  = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
        std::snprintf(alias, sizeof(alias), "user-%lld",
                      static_cast<long long>(ms));

        std::string err;
        auto kp = facade::keys::generate_ed25519(data_dir, alias, &err);
        if (!kp) {
            users_message_ = err.empty() ? "Key generation failed." : err;
            users_message_error_ = true;
            return;
        }
        // Read back the public PEM and authorize it.
        std::ifstream f(kp->public_path);
        if (!f) {
            users_message_ = "Generated keypair but couldn't read the public file.";
            users_message_error_ = true;
            return;
        }
        std::string pem((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
        facade::keys::AuthorizedKeyEntry meta;
        meta.alias = alias;
        if (facade::keys::append_authorized(
                resolved_auth_keys(cfg_), resolved_auth_meta(cfg_),
                pem, meta, &err)) {
            users_message_ = std::string("Created ") + alias + ". Share "
                           + kp->private_path.string()
                           + " (the .key file) with them; keep the .pub for yourself.";
            users_message_error_ = false;
            push_log(facade::LogLevel::Info,
                     "generated and authorized keypair for " + std::string(alias));
        } else {
            users_message_ = err.empty() ? "Couldn't authorize the new key."
                                         : err;
            users_message_error_ = true;
        }
        refresh_auth_keys();
    }

    server::ServerConfig                       cfg_{};
    bool                                       loaded_{false};
    bool                                       advanced_open_{false};
    std::string                                last_message_;
    bool                                       last_error_{false};

    std::vector<facade::keys::AuthorizedKeyEntry> auth_keys_;
    std::string                                users_message_;
    bool                                       users_message_error_{false};
};

}  // namespace

std::unique_ptr<Page> make_server_page() {
    return std::make_unique<ServerPage>();
}

}  // namespace yume::gui
