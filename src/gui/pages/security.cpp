/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "pages/page.hpp"

#include <cstring>
#include <string>
#include <vector>

#include <imgui.h>

#include "facade/client_session.hpp"
#include "facade/config_io.hpp"
#include "facade/log_sink.hpp"
#include "facade/secure_materials.hpp"
#include "platform/file_dialog.hpp"
#include "ui/design.hpp"

namespace yume::gui {

namespace {

namespace sm = facade::secure_materials;

class SecurityPage : public Page {
public:
    std::string_view title() const override { return "Security"; }

    void on_show(AppContext& ctx) override {
        refresh(ctx);
    }

    void render(AppContext& ctx) override {
        auto const& c = ui::colors();
        const float sc = ui::scale();
        cfg_ = ctx.client ? ctx.client->config() : client::ClientConfig{};

        ui::page_header("Security", "Trusted anonym CAs and client auth keys.");

        if (ui::begin_auto_card("##security_summary")) {
            ui::section_label("Selected client material");
            ui::muted_text("Anonym CA");
            if (ui::fonts().strong) ImGui::PushFont(ui::fonts().strong);
            ImGui::TextWrapped("%s", selected_ca_name().c_str());
            if (ui::fonts().strong) ImGui::PopFont();
            ui::muted_text("Auth key");
            if (ui::fonts().strong) ImGui::PushFont(ui::fonts().strong);
            ImGui::TextWrapped("%s", selected_key_name().c_str());
            if (ui::fonts().strong) ImGui::PopFont();
            ui::muted_text("Built-in CA is ready by default. Imported auth keys are copied into your local Yume store.");
        }
        ui::end_card();

        ImGui::Dummy(ImVec2(0, 8 * sc));
        if (ui::begin_auto_card("##security_materials")) {
            static char const* const kTabs[] = {
                "Anonym CAs", "Auth keys", "TLS CAs", "Anonym pubkeys"
            };
            active_tab_ = ui::segmented_control(
                "##security_tabs", kTabs, 4, active_tab_);
            ImGui::Dummy(ImVec2(0, 14 * sc));
            switch (active_tab_) {
                case 0: render_material_tab(ctx, sm::MaterialType::AnonymCa); break;
                case 1: render_material_tab(ctx, sm::MaterialType::AuthKey); break;
                case 2: render_material_tab(ctx, sm::MaterialType::TlsCa); break;
                case 3: render_material_tab(ctx, sm::MaterialType::AnonymPubkey); break;
                default: break;
            }
            if (!last_message_.empty()) {
                ImGui::Dummy(ImVec2(0, 6 * sc));
                ui::message_text(last_error_ ? c.error : c.success, "%s", last_message_.c_str());
            }
        }
        ui::end_card();
    }

private:
    void refresh(AppContext& ctx) {
        std::string err;
        cas_ = sm::list(sm::MaterialType::AnonymCa, &err);
        keys_ = sm::list(sm::MaterialType::AuthKey, &err);
        tls_cas_ = sm::list(sm::MaterialType::TlsCa, &err);
        anon_pubkeys_ = sm::list(sm::MaterialType::AnonymPubkey, &err);
        if (ctx.client) cfg_ = ctx.client->config();
        if (!err.empty()) {
            last_message_ = err;
            last_error_ = true;
        }
    }

    std::string selected_ca_name() const {
        std::string id = cfg_.anonym_ca_material_id.empty()
            ? sm::kDefaultAnonymCaId
            : cfg_.anonym_ca_material_id;
        for (auto const& item : cas_) {
            if (item.id == id) return item.display_name;
        }
        return cfg_.anonym_ca_cert.empty() ? "Built-in CA" : cfg_.anonym_ca_cert;
    }

    std::string selected_key_name() const {
        for (auto const& item : keys_) {
            if (item.id == cfg_.auth_key_material_id) return item.display_name;
        }
        return cfg_.identity.empty() ? "Not selected" : cfg_.identity;
    }

    void select_material(AppContext& ctx, sm::MaterialSummary const& item) {
        if (!ctx.client) return;
        auto cfg = ctx.client->config();
        std::string err;
        switch (item.type) {
            case sm::MaterialType::AnonymCa:
                cfg.anonym_ca_material_id = item.id;
                cfg.anonym_ca_cert = item.path.string();
                break;
            case sm::MaterialType::AuthKey:
                cfg.auth_key_material_id = item.id;
                cfg.identity = item.path.string();
                break;
            case sm::MaterialType::AnonymPubkey:
                cfg.anonym_pubkey_material_id = item.id;
                cfg.anonym_pubkey = item.path.string();
                break;
            case sm::MaterialType::TlsCa:
                cfg.tls_ca_material_id = item.id;
                cfg.tls_ca_cert = item.path.string();
                break;
        }
        ctx.client->set_config(cfg);
        if (!facade::config_io::save_client(
                cfg, facade::config_io::default_client_config_path(), &err)) {
            last_message_ = "Selection saved in memory, but config save failed: " + err;
            last_error_ = true;
            log_event(facade::LogLevel::Warn,
                      "select " + std::string(sm::type_label(item.type)) +
                          " '" + item.display_name +
                          "' (id=" + item.id + ") — config save failed: " + err);
        } else {
            last_message_ = std::string(sm::type_label(item.type)) + " selected.";
            last_error_ = false;
            log_event(facade::LogLevel::Info,
                      "selected " + std::string(sm::type_label(item.type)) +
                          " '" + item.display_name +
                          "' (id=" + item.id + ")");
        }
        cfg_ = cfg;
        refresh(ctx);
    }

    void import_current(sm::MaterialType type, bool from_file, AppContext& ctx) {
        sm::MaterialSummary summary;
        std::string err;
        bool ok = from_file
            ? sm::import_file(type, import_name_, import_path_, &summary, &err)
            : sm::import_text(type, import_name_, import_text_, &summary, &err);
        if (!ok) {
            last_message_ = err.empty() ? "Import failed." : err;
            last_error_ = true;
            log_event(facade::LogLevel::Error,
                      std::string("import failed: ") + last_message_);
            return;
        }
        log_event(facade::LogLevel::Info,
                  "imported " + std::string(sm::type_label(type)) +
                      " '" + summary.display_name +
                      "' (id=" + summary.id +
                      ", path=" + summary.path.string() + ")");
        // Auto-select the freshly-imported material so the user doesn't
        // have to click Use as a second step. This is the actual fix for
        // "imported but yume fails to use it" — without it, a fresh
        // install would keep the old (often empty) identity active.
        select_material(ctx, summary);
        last_message_ = "Imported " + summary.display_name + " and set as active.";
        last_error_ = false;
        import_name_[0] = 0;
        import_path_[0] = 0;
        import_text_[0] = 0;
        refresh(ctx);
    }

    static void log_event(facade::LogLevel level, std::string message) {
        facade::LogEntry e;
        e.ts = std::chrono::system_clock::now();
        e.level = level;
        e.component = "gui.security";
        e.message = std::move(message);
        facade::LogSink::instance().push(std::move(e));
    }

    void choose_file(sm::MaterialType type) {
        std::string err;
        auto picked = platform::open_file_dialog(
            (std::string("Choose ") + sm::type_label(type)).c_str(),
            &err);
        if (!picked) {
            if (!err.empty() && err != "file selection cancelled") {
                last_message_ = err;
                last_error_ = true;
            }
            return;
        }
        auto text = picked->string();
        std::strncpy(import_path_, text.c_str(), sizeof(import_path_) - 1);
        import_path_[sizeof(import_path_) - 1] = 0;
        last_message_.clear();
        last_error_ = false;
    }

    void render_material_row(AppContext& ctx, sm::MaterialSummary const& item, bool selected) {
        auto const& c = ui::colors();
        const float sc = ui::scale();
        ImGui::PushID(item.id.c_str());
        ImGui::PushStyleColor(ImGuiCol_ChildBg, selected ? c.surface_high : c.surface);
        ImGui::PushStyleColor(ImGuiCol_Border, selected ? c.accent : c.outline);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 12 * sc);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18 * sc, 14 * sc));
        // Auto-resize Y so the row hugs its contents — the previous fixed
        // 88 px left a band of whitespace under the source label.
        ImGui::BeginChild("##material_row",
                          ImVec2(0, 0),
                          ImGuiChildFlags_Border |
                              ImGuiChildFlags_AlwaysUseWindowPadding |
                              ImGuiChildFlags_AutoResizeY,
                          ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
        if (ImGui::BeginTable("##material_row_cols", 3, ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("Main", ImGuiTableColumnFlags_WidthStretch, 0.46f);
            ImGui::TableSetupColumn("Meta", ImGuiTableColumnFlags_WidthStretch, 0.24f);
            ImGui::TableSetupColumn("Actions", ImGuiTableColumnFlags_WidthStretch, 0.30f);
            ImGui::TableNextColumn();
            if (ui::fonts().strong) ImGui::PushFont(ui::fonts().strong);
            ImGui::TextUnformatted(item.display_name.c_str());
            if (ui::fonts().strong) ImGui::PopFont();
            ui::muted_text("%s", item.source_label.c_str());

            ImGui::TableNextColumn();
            if (!item.fingerprint.empty()) {
                // Same font as the rest of the row, just muted. Mono made
                // the hex look like a different widget; small font made
                // it disappear.
                ImGui::PushStyleColor(ImGuiCol_Text, ui::colors().muted);
                ImGui::TextUnformatted(item.fingerprint.substr(0, 16).c_str());
                ImGui::PopStyleColor();
            }

            ImGui::TableNextColumn();
            ui::status_pill(selected ? "Selected" : "Ready",
                            selected ? c.success : c.muted);
            ImGui::Dummy(ImVec2(0, 6 * sc));
            // Stack the action buttons vertically and let each take the
            // full column width so neither clips at the right edge.
            if (!selected) {
                if (ui::secondary_button("Use", ImVec2(-1, 36 * sc))) {
                    select_material(ctx, item);
                }
            }
            if (!item.is_default) {
                if (!selected) ImGui::Dummy(ImVec2(0, 4 * sc));
                if (ui::danger_button("Delete", ImVec2(-1, 36 * sc))) {
                    std::string err;
                    if (sm::remove(item.id, &err)) {
                        last_message_ = "Deleted.";
                        last_error_ = false;
                        refresh(ctx);
                    } else {
                        last_message_ = err.empty() ? "Delete failed." : err;
                        last_error_ = true;
                    }
                }
            }
            ImGui::EndTable();
        }
        ImGui::EndChild();
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor(2);
        ImGui::PopID();
    }

    std::vector<sm::MaterialSummary>& items_for(sm::MaterialType type) {
        switch (type) {
            case sm::MaterialType::AnonymCa:     return cas_;
            case sm::MaterialType::AuthKey:      return keys_;
            case sm::MaterialType::TlsCa:        return tls_cas_;
            case sm::MaterialType::AnonymPubkey: return anon_pubkeys_;
        }
        return cas_;
    }

    bool is_selected(sm::MaterialSummary const& item) const {
        switch (item.type) {
            case sm::MaterialType::AnonymCa: {
                auto id = cfg_.anonym_ca_material_id.empty()
                    ? sm::kDefaultAnonymCaId : cfg_.anonym_ca_material_id;
                return id == item.id;
            }
            case sm::MaterialType::AuthKey:
                return cfg_.auth_key_material_id == item.id;
            case sm::MaterialType::AnonymPubkey:
                return cfg_.anonym_pubkey_material_id == item.id;
            case sm::MaterialType::TlsCa:
                return cfg_.tls_ca_material_id == item.id;
        }
        return false;
    }

    void render_material_tab(AppContext& ctx, sm::MaterialType type) {
        auto& items = items_for(type);
        const float sc = ui::scale();

        char const* section = "";
        char const* hint = "";
        char const* empty = "";
        char const* import_title = "";
        switch (type) {
            case sm::MaterialType::AnonymCa:
                section = "Trusted anonym certificates";
                hint = "Select the CA used to verify anonym proof. The embedded CA cannot be removed.";
                empty = "No trusted CAs are available.";
                import_title = "Import CA";
                break;
            case sm::MaterialType::AuthKey:
                section = "Client authentication keys";
                hint = "Select the private key used when the desktop client connects.";
                empty = "No auth keys imported yet.";
                import_title = "Import auth key";
                break;
            case sm::MaterialType::TlsCa:
                section = "Extra TLS roots";
                hint = "Pin a custom root CA for the outer TLS verify chain. Leave none selected to use the system trust store.";
                empty = "No extra TLS roots imported.";
                import_title = "Import TLS CA";
                break;
            case sm::MaterialType::AnonymPubkey:
                section = "Anonym signing public keys";
                hint = "Override the embedded anonym signing public key. Only needed for self-hosted anonym authorities.";
                empty = "No anonym public keys imported.";
                import_title = "Import anonym public key";
                break;
        }
        ui::section_label(section);
        ui::muted_text("%s", hint);

        if (items.empty()) {
            ui::muted_text("%s", empty);
        } else {
            for (auto const& item : items) {
                render_material_row(ctx, item, is_selected(item));
                ImGui::Dummy(ImVec2(0, 8 * sc));
            }
        }

        ImGui::Dummy(ImVec2(0, 12 * sc));
        ui::section_label(import_title);
        ui::field_label("Display name");
        ImGui::SetNextItemWidth(ui::form_width(420));
        ImGui::InputText("##material_name", import_name_, sizeof(import_name_));
        if (ui::secondary_button("Choose file", ImVec2(140 * sc, 44 * sc))) {
            choose_file(type);
        }
        ImGui::SameLine(0.0f, 12 * sc);
        ImGui::BeginDisabled(import_path_[0] == 0);
        if (ui::primary_button("Import selected", ImVec2(170 * sc, 44 * sc))) {
            import_current(type, true, ctx);
        }
        ImGui::EndDisabled();
        if (import_path_[0] == 0) {
            ui::muted_text("No file selected.");
        } else {
            ui::muted_text("Selected: %s", import_path_);
        }

        ui::field_label("Paste PEM");
        ImGui::InputTextMultiline("##material_pem",
                                  import_text_,
                                  sizeof(import_text_),
                                  ImVec2(-1, 180 * sc));
        if (ui::primary_button("Save pasted PEM", ImVec2(176 * sc, 46 * sc))) {
            import_current(type, false, ctx);
        }
    }

    client::ClientConfig cfg_{};
    std::vector<sm::MaterialSummary> cas_;
    std::vector<sm::MaterialSummary> keys_;
    std::vector<sm::MaterialSummary> tls_cas_;
    std::vector<sm::MaterialSummary> anon_pubkeys_;
    int active_tab_{0};
    char import_name_[160]{};
    char import_path_[512]{};
    char import_text_[8192]{};
    std::string last_message_;
    bool last_error_{false};
};

}  // namespace

std::unique_ptr<Page> make_security_page() {
    return std::make_unique<SecurityPage>();
}

}  // namespace yume::gui
