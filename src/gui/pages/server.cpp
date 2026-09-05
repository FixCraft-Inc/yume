/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
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
#include <limits>
#include <string>
#include <unordered_map>
#include <vector>

#include <imgui.h>

#include "facade/config/config_io.hpp"
#include "facade/keys/keys.hpp"
#include "facade/logging/log_sink.hpp"
#include "facade/session/server_session.hpp"
#include "core/app_codec/builtin/monero_rpc.hpp"
#include "core/app_codec/codec.hpp"
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

void u32_input(const char* label, std::uint32_t& value, bool allow_zero = true) {
    int editable = static_cast<int>(std::min<std::uint32_t>(
        value, static_cast<std::uint32_t>(std::numeric_limits<int>::max())));
    int_input(label, editable);
    const int minimum = allow_zero ? 0 : 1;
    value = static_cast<std::uint32_t>(std::max(editable, minimum));
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
    // Explanation rides on a hover marker rather than a paragraph under the
    // control; a column of file pickers each trailed by three wrapped lines
    // was most of what made this page unreadable.
    if (help_text && *help_text) {
        ui::field_label_help(label, help_text);
    } else {
        ui::field_label(label);
    }

    // Layout: path display takes most of the row, button on the right.
    const float row_avail   = ImGui::GetContentRegionAvail().x;
    const float button_w    = 84.0f * sc;
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
std::filesystem::path resolved_admin_keys(server::ServerConfig const& cfg) {
    return std::filesystem::path(cfg.admin_keys);
}

std::string format_byte_count(std::uint64_t b) {
    char buf[32];
    if (b < 1024ull) {
        std::snprintf(buf, sizeof(buf), "%llu B",
                      static_cast<unsigned long long>(b));
    } else if (b < 1024ull * 1024) {
        std::snprintf(buf, sizeof(buf), "%.1f KiB", b / 1024.0);
    } else if (b < 1024ull * 1024 * 1024) {
        std::snprintf(buf, sizeof(buf), "%.1f MiB", b / (1024.0 * 1024));
    } else {
        std::snprintf(buf, sizeof(buf), "%.2f GiB", b / (1024.0 * 1024 * 1024));
    }
    return buf;
}

void push_log(facade::LogLevel level, std::string msg) {
    facade::LogSink::instance().push(level, "gui.server", std::move(msg));
}

class ServerPage : public Page {
public:
    std::string_view title() const override { return "Configuration"; }

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

        // Status and the Start/Stop control are one card at the top. The
        // action used to sit below six configuration cards, which put the
        // page's primary verb off-screen at the default window size.
        render_status_card(ctx, c, sc, running, st);
        ImGui::Dummy(ImVec2(0, 6 * sc));

        if (running) {
            render_sessions(ctx, c, sc);
            ImGui::Dummy(ImVec2(0, 6 * sc));
        }

        render_listening_card(running, sc);
        ImGui::Dummy(ImVec2(0, 6 * sc));

        render_certificates_card(running, c, sc);
        ImGui::Dummy(ImVec2(0, 6 * sc));

        render_transport_security_card(running, c, sc);
        ImGui::Dummy(ImVec2(0, 6 * sc));

        render_users_card(running, c, sc);
        ImGui::Dummy(ImVec2(0, 6 * sc));

        render_advanced_card(running, c, sc);
    }

private:
    // Status + primary action in one header card: state pill and endpoint on
    // the left, Start/Stop on the right, live counters underneath. Blocking
    // errors are listed here too, next to the button they block.
    void render_status_card(AppContext& ctx, ui::Colors const& c, float sc,
                            bool running, facade::ServerStatus const& st) {
        auto const report = facade::config_io::validate(cfg_);
        if (ui::begin_auto_card("##server_status")) {
            const float btn_w = 132 * sc;
            const float btn_h = 34 * sc;

            ImGui::BeginGroup();
            ui::status_pill(running ? "Running" : "Stopped",
                            running ? c.success : c.muted);
            ImGui::SameLine(0.0f, 10 * sc);
            ui::muted_text("%s",
                st.listen_endpoint.empty()
                    ? "Not yet listening"
                    : (std::string("Listening on ") + st.listen_endpoint).c_str());
            ImGui::EndGroup();

            // Right-align the action on the same row as the status pill.
            ImGui::SameLine();
            const float shift =
                ImGui::GetContentRegionAvail().x - btn_w;
            if (shift > 0.0f) ImGui::Dummy(ImVec2(shift, 1));
            ImGui::SameLine(0.0f, 0.0f);
            render_start_stop(ctx, running, report, ImVec2(btn_w, btn_h));

            if (running) {
                ImGui::Dummy(ImVec2(0, 6 * sc));
                ui::muted_text("%zu connected  \xC2\xB7  %s in  \xC2\xB7  %s out",
                               st.active_sessions,
                               format_byte_count(st.bytes_in).c_str(),
                               format_byte_count(st.bytes_out).c_str());
            }
            if (!st.message.empty()) {
                ImGui::Dummy(ImVec2(0, 4 * sc));
                if (!running) {
                    ui::message_text(c.error, "%s", st.message.c_str());
                } else {
                    ui::muted_text("%s", st.message.c_str());
                }
            }
            if (!last_message_.empty()) {
                ImGui::Dummy(ImVec2(0, 4 * sc));
                ui::message_text(last_error_ ? c.error : c.success,
                                 "%s", last_message_.c_str());
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

    void render_start_stop(AppContext& ctx, bool running,
                           facade::config_io::ValidationReport const& report,
                           ImVec2 size) {
        if (running) {
            if (ui::secondary_button("Stop server", size) && ctx.server) {
                ctx.server->stop();
                last_message_.clear();
            }
            return;
        }
        // Teardown outlives running(); offering Start during it would only
        // produce a "still stopping" refusal.
        const bool busy = ctx.server && ctx.server->busy();
        ImGui::BeginDisabled(!report.ok() || !ctx.server || busy);
        if (ui::primary_button(busy ? "Stopping..." : "Start server", size)) {
            ctx.server->set_config(cfg_);
            facade::config_io::save_server(
                cfg_, facade::config_io::default_server_config_path(), nullptr);
            std::string err;
            if (!ctx.server->start(&err)) {
                last_message_ = err.empty() ? "Couldn't start the server." : err;
                last_error_ = true;
            } else {
                last_message_.clear();
                last_error_ = false;
            }
        }
        ImGui::EndDisabled();
    }

    void render_listening_card(bool running, float sc) {
        if (ui::begin_auto_card("##listening")) {
            ui::section_label("Listening");
            ImGui::BeginDisabled(running);
            ImGui::PushID("Port");
            ui::field_label_help(
                "Port",
                "The TCP port your server listens on. Ports below 1024 "
                "(including the default 443) need root or the "
                "cap_net_bind_service capability on Linux. 8443 avoids that.");
            ImGui::SetNextItemWidth(ui::form_width(220));
            ImGui::InputInt("##value", &cfg_.listen_port, 0, 0);
            ImGui::PopID();
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
                        "Your server's TLS certificate. A real Let's "
                        "Encrypt-issued PEM for public servers, or a "
                        "self-signed one for friends-only.");
            ImGui::Dummy(ImVec2(0, 4 * sc));
            file_picker("Private key file",
                        "Pick TLS private key (.pem / .key)",
                        cfg_.tls_key,
                        "(no private key selected)",
                        "The private key matching the certificate above. "
                        "Anyone holding this file can impersonate your "
                        "server.");
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

    // The protocol fixes the encryption suite. This card supplies its keys
    // and the cover source required by prepare_v2_security_config().
    void render_transport_security_card(bool running, ui::Colors const& c, float sc) {
        if (ui::begin_auto_card("##transport_security")) {
            ui::section_label_help(
                "Transport security",
                "Fixed by the protocol, not configurable. Every session uses "
                "composite Ed25519 + ML-DSA-87 authentication and an "
                "ML-KEM-1024/X25519/PSK directional ratchet inside the HTTP/2 "
                "carrier.");
            ImGui::Dummy(ImVec2(0, 4 * sc));

            ui::status_pill("Composite AUTH v2", c.success);
            ImGui::SameLine(0.0f, 6 * sc);
            ui::status_pill("Hybrid ratchet", c.success);
            ImGui::SameLine(0.0f, 6 * sc);
            ui::status_pill("H2 carrier", c.success);

            ImGui::Dummy(ImVec2(0, 8 * sc));
            ImGui::BeginDisabled(running);
            file_picker("Admission secret file",
                        "Pick the 32-byte admission secret",
                        cfg_.obfs_secret_file,
                        "(required)",
                        "Shared out-of-band with every client. The server "
                        "refuses to start without it.");
            ImGui::Dummy(ImVec2(0, 4 * sc));
            file_picker("Inner PSK file",
                        "Pick the 32-byte inner pre-shared key",
                        cfg_.inner_psk_file,
                        "(required)",
                        "Seeds the inner ratchet alongside the hybrid KEM. "
                        "Also required at startup.");
            ImGui::Dummy(ImVec2(0, 4 * sc));
            ImGui::PushID("cover_backend");
            ui::field_label_help(
                "Cover backend",
                "A real local HTTP server that answers unauthenticated "
                "requests, so the port looks like an ordinary web host. "
                "Health-checked at startup; must be a loopback literal.");
            ImGui::SetNextItemWidth(ui::form_width());
            {
                char buf[512];
                std::strncpy(buf, cfg_.real_backend.c_str(), sizeof(buf) - 1);
                buf[sizeof(buf) - 1] = 0;
                ImGui::InputTextWithHint("##value", "loopback://127.0.0.1:8080",
                                         buf, sizeof(buf));
                cfg_.real_backend = buf;
            }
            ImGui::PopID();
            ImGui::Dummy(ImVec2(0, 4 * sc));
            file_picker("Cover index page",
                        "Pick the HTML page the HTTP/2 decoy serves",
                        cfg_.real_index_path,
                        "(required)",
                        "Ordinary HTTP/1.1 and HTTP/2 GET/HEAD reach the backend. "
                        "Separate probe paths need a cover page. There is no "
                        "built-in default: a page compiled into the daemon "
                        "would be identical on every YUME server and would "
                        "identify this one. A captured upstream response or a "
                        "static cover root satisfies the same requirement.");
            ImGui::EndDisabled();
        }
        ui::end_card();
    }

    // `running` is unused here on purpose, and kept for symmetry with the five
    // sibling render_*_card functions. Authorized keys are the one setting that
    // stays editable while the server is up — the daemon reloads them live
    // (yume_server_reload_auth) — so unlike the listening/certificate/advanced
    // cards there is nothing here to disable.
    void render_users_card([[maybe_unused]] bool running, ui::Colors const& c, float sc) {
        if (ui::begin_auto_card("##users")) {
            ui::section_label_help(
                "Allowed users",
                "Anyone connecting needs their public key listed here. They "
                "send you their public key file out-of-band and keep the "
                "matching private key on their own device.");
            ImGui::Dummy(ImVec2(0, 4 * sc));

            if (auth_keys_.empty()) {
                ui::muted_text("No users authorized yet.");
            } else {
                if (ui::begin_data_table("##users_table", 3)) {
                    ui::data_table_headers({"Name", "Fingerprint", ""});
                    int row_idx = 0;
                    std::string revoke_fp;
                    std::string rename_fp;
                    std::string rename_alias;
                    for (auto const& k : auth_keys_) {
                        ImGui::TableNextRow();
                        ImGui::PushID(row_idx++);
                        ImGui::TableNextColumn();
                        char alias_buf[128]{};
                        auto alias_it = alias_edits_.find(k.fingerprint);
                        if (alias_it != alias_edits_.end()) {
                            std::strncpy(alias_buf, alias_it->second.c_str(), sizeof(alias_buf) - 1);
                        } else {
                            std::strncpy(alias_buf, k.alias.c_str(), sizeof(alias_buf) - 1);
                        }
                        ImGui::SetNextItemWidth(160 * sc);
                        if (ImGui::InputText("##alias", alias_buf, sizeof(alias_buf))) {
                            alias_edits_[k.fingerprint] = alias_buf;
                        }
                        if (ImGui::IsItemDeactivatedAfterEdit()) {
                            rename_fp = k.fingerprint;
                            rename_alias = alias_buf;
                        }
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
                    if (!rename_fp.empty()) rename_user(rename_fp, rename_alias);
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

    void render_advanced_card(bool running, [[maybe_unused]] ui::Colors const& c,
                              float sc) {
        advanced_open_ = ui::disclosure_header("Advanced", advanced_open_);
        if (!advanced_open_) return;
        if (ui::begin_auto_card("##server_advanced")) {
            ImGui::BeginDisabled(running);
            ui::section_label("Identity & resolver");
            text_input("Server display name", cfg_.server_name);
            text_input("DNS resolver IP", cfg_.dns_server, "1.1.1.1");
            text_input("Outbound SOCKS5 proxy", cfg_.outbound_proxy_url,
                       "socks5://127.0.0.1:9050");
            ui::section_label("Capacity & fair use");
            int_input("Worker threads (0 = auto)", cfg_.threads);
            u32_input("Maximum live sessions (0 = unlimited)", cfg_.max_sessions);
            u32_input("Default sessions per bulk key",
                      cfg_.bulk_key_max_sessions, false);
            u32_input("Server egress cap (Mbit/s, 0 = unlimited)",
                      cfg_.egress_mbps);
            u32_input("Accepted connections per second (0 = unlimited)",
                      cfg_.accept_rate_limit);

            ImGui::Dummy(ImVec2(0, 8 * sc));
            ui::section_label("Features");
            if (ImGui::BeginTable("##server_features", 3,
                                  ImGuiTableFlags_SizingStretchSame)) {
                ImGui::TableNextColumn();
                ui::checkbox("Allow relays", &cfg_.relay_enable);
                ImGui::TableNextColumn();
                ui::checkbox("Directory listing", &cfg_.directory_enable);
                ImGui::TableNextColumn();
                ImGui::BeginDisabled(!cfg_.anonym);
                ui::checkbox("Operator identity proof (yumed only)", &cfg_.anonym);
                ImGui::EndDisabled();
                ImGui::EndTable();
            }
            ui::checkbox("Federation", &cfg_.federation_enable);

            if (cfg_.federation_enable) {
                ImGui::Dummy(ImVec2(0, 6 * sc));
                ui::section_label("Federation");
                file_picker("Federation AUTH key",
                            "Pick federation composite identity PEM",
                            cfg_.federation_identity,
                            "(required)", nullptr);
                file_picker("Federation peer CA",
                            "Pick federation peer CA",
                            cfg_.federation_operator_ca,
                            "(required)", nullptr);
                std::string peer_json = cfg_.federation_peers.empty()
                    ? std::string{}
                    : cfg_.federation_peers.front();
                text_input("Federation peer JSON", peer_json,
                           "{\"id\":\"peer-b\",\"url\":\"yume://host:443\","
                           "\"psk_file\":\"...\",\"carrier_secret_file\":\"...\"}");
                if (peer_json.empty()) {
                    cfg_.federation_peers.clear();
                } else if (cfg_.federation_peers.empty()) {
                    cfg_.federation_peers.push_back(peer_json);
                } else {
                    cfg_.federation_peers.front() = peer_json;
                }
            }

            if (cfg_.anonym) {
                ImGui::BeginDisabled();
                ImGui::Dummy(ImVec2(0, 6 * sc));
                ui::section_label_help(
                    "Operator identity proof",
                    "Proves this server is authorized by the operator CA the "
                    "client selected. It does not prove the host cannot "
                    "inspect or log traffic.");
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
                file_picker("External proof API token",
                            "Pick owner-only external proof API token file",
                            cfg_.anonym_token_file,
                            "(none)", nullptr);
                file_picker("Delegated server certificate",
                            "Pick CA-signed delegated server certificate",
                            cfg_.anonym_sub_cert,
                            "(none - external proof service only)",
                            nullptr);
                file_picker("Delegated server private key",
                            "Pick delegated server key",
                            cfg_.anonym_sub_key,
                            "(none)", nullptr);
                file_picker("Operator CA certificate (trust anchor)",
                            "Pick operator CA cert",
                            cfg_.anonym_ca_cert,
                            "(none)", nullptr);
                ImGui::EndDisabled();
            }

            ImGui::Dummy(ImVec2(0, 8 * sc));
            codecs_open_ = ui::disclosure_header("App Codecs", codecs_open_);
            if (codecs_open_) {
                ui::muted_text(
                    "Parse local app protocols and relay typed envelopes over "
                    "Yume streams. Each key still needs its own permission.");
                ImGui::Dummy(ImVec2(0, 4 * sc));
                if (ui::checkbox("Enable Monero RPC codec", &cfg_.allow_monero_rpc_codec)) {
                    if (cfg_.allow_monero_rpc_codec) {
                        yume::app_codec::add_codec_unique(
                            &cfg_.allowed_codecs, yume::app_codec::builtin::kMoneroRpcCodecId);
                    } else {
                        auto& codecs = cfg_.allowed_codecs;
                        codecs.erase(
                            std::remove_if(codecs.begin(), codecs.end(),
                                           [](std::string const& id) {
                                               return yume::app_codec::canonical_codec_id(id) ==
                                                      std::string(
                                                          yume::app_codec::builtin::kMoneroRpcCodecId);
                                           }),
                            codecs.end());
                    }
                }
                ImGui::BeginDisabled(!cfg_.allow_monero_rpc_codec);
                text_input("Monero RPC backend host", cfg_.monero_rpc_backend_host,
                           "127.0.0.1");
                int backend_port = cfg_.monero_rpc_backend_port;
                int_input("Monero RPC backend port", backend_port);
                cfg_.monero_rpc_backend_port = backend_port;
                ImGui::EndDisabled();
            }

            ImGui::Dummy(ImVec2(0, 8 * sc));
            ui::section_label_help(
                "External CLI control",
                "Lets a separate `yume` command-line tool attach to this "
                "server for automation. Leave off unless you need it - the "
                "GUI itself does not use it.");
            ImGui::Dummy(ImVec2(0, 4 * sc));
            ui::checkbox("Allow external CLI to attach", &cfg_.ipc_enable);
            // The path is just plumbing - we pick a sensible default
            // under XDG_RUNTIME_DIR ourselves; users never need to see
            // or edit it. cfg_.ipc_path is left as-is (empty means auto).

            ImGui::EndDisabled();
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
                ui::data_table_headers(
                    {"Endpoint", "Name", "State", "Client"});
                for (auto const& s : sessions) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(s.endpoint_id.c_str());
                    ImGui::TableNextColumn(); ImGui::TextUnformatted(s.display_name.c_str());
                    ImGui::TableNextColumn();
                    const char* session_state = !s.authenticated
                        ? "pending"
                        : (s.state.empty() ? "online" : s.state.c_str());
                    ui::status_pill(session_state,
                                    s.authenticated ? c.success : c.warning);
                    ImGui::TableNextColumn();
                    const char* client_platform = s.client_platform.empty()
                        ? "unknown" : s.client_platform.c_str();
                    ImGui::Text("%s%s%s", client_platform,
                                s.client_version.empty() ? "" : " ",
                                s.client_version.c_str());
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

    void rename_user(std::string const& fingerprint, std::string const& alias) {
        facade::keys::AuthorizedKeyEntry patch;
        patch.alias = alias;
        std::string err;
        if (facade::keys::update_authorized(
                resolved_auth_keys(cfg_), resolved_auth_meta(cfg_),
                fingerprint, patch, &err)) {
            users_message_ = "Renamed user.";
            users_message_error_ = false;
            alias_edits_.erase(fingerprint);
        } else {
            users_message_ = err.empty() ? "Couldn't rename user." : err;
            users_message_error_ = true;
        }
        refresh_auth_keys();
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
                resolved_admin_keys(cfg_),
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
        auto kp = facade::keys::generate_identity(data_dir, alias, &err);
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
                resolved_admin_keys(cfg_),
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
    bool                                       codecs_open_{false};
    std::string                                last_message_;
    bool                                       last_error_{false};

    std::vector<facade::keys::AuthorizedKeyEntry> auth_keys_;
    std::unordered_map<std::string, std::string> alias_edits_;
    std::string                                users_message_;
    bool                                       users_message_error_{false};
};

}  // namespace

std::unique_ptr<Page> make_server_page() {
    return std::make_unique<ServerPage>();
}

}  // namespace yume::gui
