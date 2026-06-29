/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "pages/page.hpp"

#include <cstring>
#include <string>

#include <imgui.h>

#include "facade/session/client_session.hpp"
#include "ui/design.hpp"

namespace yume::gui {

namespace {

class ChatPage : public Page {
public:
    std::string_view title() const override { return "Chat"; }

    void on_show(AppContext& ctx) override {
        if (ctx.pending_jump_arg.empty()) return;
        std::strncpy(peer_, ctx.pending_jump_arg.c_str(), sizeof(peer_) - 1);
        peer_[sizeof(peer_) - 1] = 0;
        if (ctx.client && ctx.client->running()) {
            std::string err;
            active_channel_ = ctx.client->open_chat(peer_, &err);
            last_error_ = err;
        }
    }

    void render(AppContext& ctx) override {
        auto const& p = ui::colors();
        const float left_w = 220.f;

        if (!ctx.client || !ctx.client->running()) {
            ui::unavailable_panel("Chat unavailable",
                                  "Connect the client first to open a relay chat.");
            return;
        }

        ui::page_header("Chat", "Open a chat by endpoint id or display name.");
        ImGui::SetNextItemWidth(340.f);
        ImGui::InputTextWithHint("##peer", "endpoint id or display name", peer_, sizeof(peer_));
        ImGui::SameLine();
        if (ui::secondary_button("Open", ImVec2(100, 0))) {
            std::string err;
            active_channel_ = ctx.client->open_chat(peer_, &err);
            last_error_ = err;
        }
        if (!last_error_.empty()) {
            ui::message_text(p.error, "%s", last_error_.c_str());
        }
        ImGui::Dummy(ImVec2(0, 8.f));

        ImGui::BeginChild("##channels", ImVec2(left_w, 0),
                          ImGuiChildFlags_Border);
        ImGui::TextColored(p.muted, "Channels");
        ImGui::Separator();
        ImGui::TextDisabled("%s", active_channel_.empty() ? "(no open channels)" : "active");
        ImGui::EndChild();

        ImGui::SameLine();

        ImGui::BeginChild("##chatlog", ImVec2(0, 0), ImGuiChildFlags_Border);
        if (active_channel_.empty()) {
            ImGui::TextColored(p.muted,
                               "Select a channel or open one from the Directory page.");
        } else {
            auto history = ctx.client->chat_history(active_channel_);
            for (auto const& msg : history) {
                ImGui::TextWrapped("<%s> %s",
                                   msg.from_endpoint_id.c_str(),
                                   msg.text.c_str());
            }
            ImGui::Separator();
            ImGui::SetNextItemWidth(-110);
            ImGui::InputText("##input", input_, sizeof(input_));
            ImGui::SameLine();
            if (ui::primary_button("Send", ImVec2(100, 0))) {
                std::string err;
                if (!ctx.client->send_chat(active_channel_, input_, &err)) {
                    last_error_ = err;
                } else {
                    input_[0] = 0;
                    last_error_.clear();
                }
            }
            if (!last_error_.empty()) {
                ImGui::TextColored(p.error, "%s", last_error_.c_str());
            }
        }
        ImGui::EndChild();
    }

private:
    std::string active_channel_;
    std::string last_error_;
    char peer_[256]{};
    char input_[1024]{};
};

}  // namespace

std::unique_ptr<Page> make_chat_page() {
    return std::make_unique<ChatPage>();
}

}  // namespace yume::gui
