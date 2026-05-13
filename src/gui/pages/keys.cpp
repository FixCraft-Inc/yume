/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "pages/page.hpp"

#include <cstring>
#include <filesystem>

#include <imgui.h>

#include "facade/config_io.hpp"
#include "facade/keys.hpp"
#include "ui/design.hpp"

namespace yume::gui {

namespace {

class KeysPage : public Page {
public:
    std::string_view title() const override { return "Keys"; }

    void on_show(AppContext& /*ctx*/) override {
        // Defaults: keys live under <data dir>/keys
        if (keys_dir_[0] == 0) {
            const auto p = facade::config_io::default_data_dir() / "keys";
            std::strncpy(keys_dir_, p.string().c_str(), sizeof(keys_dir_) - 1);
        }
        if (auth_keys_path_[0] == 0) {
            const auto p = facade::config_io::default_data_dir() / "authorized_keys";
            std::strncpy(auth_keys_path_, p.string().c_str(),
                         sizeof(auth_keys_path_) - 1);
        }
        if (meta_path_[0] == 0) {
            const auto p = facade::config_io::default_data_dir() / "authorized_keys.meta.json";
            std::strncpy(meta_path_, p.string().c_str(), sizeof(meta_path_) - 1);
        }
    }

    void render(AppContext& /*ctx*/) override {
        auto const& c = ui::colors();
        const float sc = ui::scale();

        ui::page_header("Keys", "Generate server keys and manage authorized client public keys.");

        if (ui::begin_auto_card("##generate_keys")) {
            ui::section_label("Generate keys");
            ui::field_label("Keys directory");
            ImGui::SetNextItemWidth(ui::form_width());
            ImGui::InputText("##keys_dir", keys_dir_, sizeof(keys_dir_));
            ui::field_label("Base name");
            ImGui::SetNextItemWidth(ui::form_width());
            ImGui::InputText("##base_name", base_name_, sizeof(base_name_));

            const float button_h = 48 * sc;
            if (ui::primary_button("Generate identity key",
                                   ImVec2(ui::button_width("Generate identity key", 220), button_h))) {
                std::string err;
                auto kp = facade::keys::generate_ed25519(keys_dir_, base_name_, &err);
                last_message_ = kp ? ("Generated " + kp->fingerprint)
                                   : ("Failed: " + err);
                last_was_error_ = !kp.has_value();
            }
            ImGui::SameLine(0.0f, 10 * sc);
            if (ui::secondary_button("Generate PQ key",
                                     ImVec2(ui::button_width("Generate PQ key", 180), button_h))) {
                const auto priv = std::filesystem::path(keys_dir_) /
                                  (std::string(base_name_) + ".pq.key");
                const auto pub = std::filesystem::path(keys_dir_) /
                                 (std::string(base_name_) + ".pq.pub");
                std::string err;
                auto kp = facade::keys::generate_ml_kem_768(priv, pub, &err);
                last_message_ = kp ? ("Generated PQ keypair at " + priv.string())
                                   : ("Failed: " + err);
                last_was_error_ = !kp.has_value();
            }
            if (!last_message_.empty()) {
                ImGui::Dummy(ImVec2(0, 2 * sc));
                ui::message_text(last_was_error_ ? c.error : c.success,
                                 "%s", last_message_.c_str());
            }
        }
        ui::end_card();

        ImGui::Dummy(ImVec2(0, 8 * sc));
        if (ui::begin_auto_card("##authorized_keys")) {
            ui::section_label("Authorized keys");
            ui::field_label("authorized_keys");
            ImGui::SetNextItemWidth(ui::form_width());
            ImGui::InputText("##authorized_keys_path", auth_keys_path_, sizeof(auth_keys_path_));
            ui::field_label("metadata JSON");
            ImGui::SetNextItemWidth(ui::form_width());
            ImGui::InputText("##meta_path", meta_path_, sizeof(meta_path_));

            const float button_h = 44 * sc;
            if (ui::secondary_button("Refresh",
                                     ImVec2(ui::button_width("Refresh", 118), button_h))) {
                entries_ = facade::keys::list_authorized(auth_keys_path_, meta_path_);
            }
            ImGui::SameLine(0.0f, 10 * sc);
            if (ui::primary_button("Import public key",
                                   ImVec2(ui::button_width("Import public key", 196), button_h))) {
                ImGui::OpenPopup("Import authorized key");
            }

            if (ImGui::BeginPopup("Import authorized key")) {
                ImGui::TextWrapped("Paste the contents of an Ed25519 .pub file:");
                ImGui::InputTextMultiline("##pem", import_buf_, sizeof(import_buf_),
                                          ImVec2(480 * sc, 150 * sc));
                ui::field_label("Alias");
                ImGui::SetNextItemWidth(480 * sc);
                ImGui::InputText("##alias", import_alias_, sizeof(import_alias_));
                if (ui::primary_button("Add",
                                       ImVec2(ui::button_width("Add", 112), 42 * sc))) {
                    facade::keys::AuthorizedKeyEntry meta;
                    meta.alias = import_alias_;
                    std::string err;
                    const bool ok = facade::keys::append_authorized(
                        auth_keys_path_, meta_path_, import_buf_, meta, &err);
                    last_message_ = ok ? "Imported." : ("Failed: " + err);
                    last_was_error_ = !ok;
                    if (ok) {
                        entries_ = facade::keys::list_authorized(auth_keys_path_, meta_path_);
                        import_buf_[0] = 0;
                        import_alias_[0] = 0;
                    }
                    ImGui::CloseCurrentPopup();
                }
                ImGui::SameLine(0.0f, 10 * sc);
                if (ui::secondary_button("Cancel",
                                         ImVec2(ui::button_width("Cancel", 124), 42 * sc))) {
                    ImGui::CloseCurrentPopup();
                }
                ImGui::EndPopup();
            }

            ImGui::Dummy(ImVec2(0, 6 * sc));
            if (entries_.empty()) {
                ui::muted_text("No authorized public keys loaded.");
            } else if (ImGui::BeginTable("##keys_table", 4,
                                         ImGuiTableFlags_RowBg |
                                             ImGuiTableFlags_BordersInnerH |
                                             ImGuiTableFlags_Resizable)) {
                ImGui::TableSetupColumn("fingerprint");
                ImGui::TableSetupColumn("alias");
                ImGui::TableSetupColumn("algorithm");
                ImGui::TableSetupColumn("action");
                ImGui::TableHeadersRow();
                for (auto const& e : entries_) {
                    ImGui::TableNextRow();
                    ImGui::TableNextColumn();
                    // Show short fingerprint (first 16 chars) for readability.
                    ImGui::TextUnformatted(e.fingerprint.substr(0, 16).c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(e.alias.empty() ? "-" : e.alias.c_str());
                    ImGui::TableNextColumn();
                    ImGui::TextUnformatted(e.algorithm.c_str());
                    ImGui::TableNextColumn();
                    ImGui::PushID(e.fingerprint.c_str());
                    if (ui::quiet_button("Remove", ImVec2(ui::button_width("Remove", 104), 38 * sc))) {
                        std::string err;
                        if (facade::keys::remove_authorized(
                                auth_keys_path_, meta_path_, e.fingerprint, &err)) {
                            last_message_ = "Removed.";
                            last_was_error_ = false;
                            entries_ = facade::keys::list_authorized(auth_keys_path_, meta_path_);
                            ImGui::PopID();
                            break;
                        } else {
                            last_message_ = "Failed: " + err;
                            last_was_error_ = true;
                        }
                    }
                    ImGui::PopID();
                }
                ImGui::EndTable();
            }
        }
        ui::end_card();
    }

private:
    char keys_dir_[512]{};
    char base_name_[128] = {'i','d','_','e','d','2','5','5','1','9','\0'};
    char auth_keys_path_[512]{};
    char meta_path_[512]{};

    char import_buf_[4096]{};
    char import_alias_[128]{};

    std::vector<facade::keys::AuthorizedKeyEntry> entries_;
    std::string last_message_;
    bool last_was_error_{false};
};

}  // namespace

std::unique_ptr<Page> make_keys_page() {
    return std::make_unique<KeysPage>();
}

}  // namespace yume::gui
