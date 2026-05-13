/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <memory>
#include <string>
#include <string_view>

namespace yume::facade {
class ClientSession;
class ServerSession;
}

namespace yume::gui {

// Aggregated handle passed to every page each frame so pages don't need
// to know about the App class directly.
struct AppContext {
    yume::facade::ClientSession* client{nullptr};
    yume::facade::ServerSession* server{nullptr};
    bool dark_mode{true};
    // page-to-app actions
    bool request_quit{false};
    bool request_minimize_to_tray{false};
    bool jump_to_directory{false};
    bool jump_to_chat{false};
    std::string pending_jump_arg;
};

class Page {
public:
    virtual ~Page() = default;
    virtual std::string_view title() const = 0;
    virtual const char* icon() const { return ""; }
    virtual void render(AppContext& ctx) = 0;
    virtual void on_show(AppContext& /*ctx*/) {}
    virtual void on_hide(AppContext& /*ctx*/) {}
};

std::unique_ptr<Page> make_dashboard_page();
std::unique_ptr<Page> make_connect_page();
std::unique_ptr<Page> make_security_page();
std::unique_ptr<Page> make_server_page();
std::unique_ptr<Page> make_directory_page();
std::unique_ptr<Page> make_chat_page();
std::unique_ptr<Page> make_keys_page();
std::unique_ptr<Page> make_logs_page();
std::unique_ptr<Page> make_settings_page();
std::unique_ptr<Page> make_tools_page();
std::unique_ptr<Page> make_credits_page();

}  // namespace yume::gui
