/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "pages/page.hpp"
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

    Options opts_;
    std::unique_ptr<Window> window_;
    std::unique_ptr<yume::facade::ClientSession> client_;
    std::unique_ptr<yume::facade::ServerSession> server_;
    std::vector<NavPage> pages_;
    Workspace workspace_{Workspace::Client};
    std::size_t active_page_{0};
    std::size_t last_client_page_{0};
    std::size_t last_server_page_{0};
    std::size_t shown_page_{static_cast<std::size_t>(-1)};
    bool tray_minimized_{false};
    bool dark_mode_{true};
};

int run_headless(Options const& opts);

}  // namespace yume::gui
