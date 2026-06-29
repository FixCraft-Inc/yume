/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "pages/page.hpp"
#include "platform/tray.hpp"
#include "platform/window.hpp"

namespace yume::facade {
class ClientSession;
class ServerSession;
}

namespace yume::gui {

struct Options {
    bool headless{false};
    bool start_minimized{false};
    bool no_tray{false};
    std::string client_config_path;
    std::string server_config_path;
};

class App {
public:
    explicit App(Options opts);
    ~App();

    App(App const&) = delete;
    App& operator=(App const&) = delete;

    int run();

private:
    enum class Workspace {
        Client,
        Server,
    };

    enum class NavScope {
        Common,
        Client,
        Server,
    };

    struct NavPage {
        std::unique_ptr<Page> page;
        NavScope scope{NavScope::Common};
    };

    void load_configs();
    void install_imgui();
    void render_frame();
    void render_sidebar();
    void render_content();
    bool page_visible(std::size_t index) const;
    std::size_t first_page_for(NavScope scope) const;
    void select_page(std::size_t index);
    void set_workspace(Workspace workspace);
    std::size_t find_page_index(std::string_view title, NavScope scope) const;
    void handle_page_navigation(AppContext& ctx);

    Options opts_;
    std::unique_ptr<Window> window_;
    std::unique_ptr<yume::facade::ClientSession> client_;
    std::unique_ptr<yume::facade::ServerSession> server_;
    std::unique_ptr<Tray> tray_;
    std::vector<NavPage> pages_;
    Workspace workspace_{Workspace::Client};
    std::size_t active_page_{0};
    std::size_t last_client_page_{0};
    std::size_t last_server_page_{0};
    std::size_t shown_page_{static_cast<std::size_t>(-1)};
    bool tray_minimized_{false};
    bool dark_mode_{true};
    bool minimize_to_tray_on_close_{true};
    // Set true when the user explicitly chose "Quit Yume" from the tray
    // menu, so the GLFW close interceptor lets the close go through
    // instead of hiding to tray.
    bool quit_requested_{false};

    // Background-resolved IPv4 of the active server, used by the tray
    // menu's country line. We resolve on a worker so the frame loop
    // never blocks on getaddrinfo. The host string we last submitted a
    // resolve for is held under the same mutex.
    std::mutex resolve_mtx_;
    std::string resolved_host_;
    std::string resolved_ip_;
    std::atomic<bool> resolve_in_flight_{false};

    std::string pending_jump_arg_;

    void kick_off_resolve_if_needed(std::string const& host);
};

int run_headless(Options const& opts);

}  // namespace yume::gui
