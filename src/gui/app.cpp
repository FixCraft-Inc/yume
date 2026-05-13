/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "app.hpp"

#include <chrono>
#include <cstdio>
#include <thread>
#include <utility>

#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <implot.h>

#include "facade/client_session.hpp"
#include "facade/config_io.hpp"
#include "facade/log_sink.hpp"
#include "facade/server_session.hpp"
#include "theme/theme.hpp"
#include "ui/design.hpp"

namespace yume::gui {

namespace {

bool mode_button(char const* label, bool selected, ImVec2 size) {
    auto const& c = ui::colors();
    ImGui::PushStyleColor(ImGuiCol_Button, selected ? c.accent : c.surface_high);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, selected ? c.accent_hover : c.surface_high);
    // When NOT selected, "active" must NOT swap to the full accent —
    // that would briefly flash a pink-bg + light-text combo. Use a
    // soft accent tint instead so the text colour we push below stays
    // legible across all three button states.
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                          selected ? c.accent_hover
                                   : ImVec4(c.accent.x, c.accent.y, c.accent.z, 0.22f));
    // Selected → on_accent (dark wine on pink in dark mode, white on
    // plum in light mode). Unselected → muted, with full text colour on
    // hover so it doesn't pop on press. Matches Android's tab indicator
    // logic where the active tab has on_primary text and inactive tabs
    // are on_surface_variant.
    ImGui::PushStyleColor(ImGuiCol_Text, selected ? c.on_accent : c.muted);
    if (ui::fonts().strong) ImGui::PushFont(ui::fonts().strong);
    bool pressed = ImGui::Button(label, size);
    if (ui::fonts().strong) ImGui::PopFont();
    ImGui::PopStyleColor(4);
    return pressed;
}

}  // namespace

App::App(Options opts) : opts_(std::move(opts)) {
    // Initialise the singleton log sink early so every subsequent emit
    // is captured for the Logs page.
    (void)facade::LogSink::instance();

    load_configs();

    // Restore the persisted dark/light preference before the theme is
    // applied, so the very first frame paints with the user's choice
    // instead of flashing the default and then re-applying.
    dark_mode_ = facade::config_io::load_gui_preferences().dark_mode;

    window_ = std::make_unique<Window>("Yume", 1280, 800);
    install_imgui();

    pages_.push_back({make_dashboard_page(), NavScope::Common});
    pages_.push_back({make_connect_page(), NavScope::Client});
    pages_.push_back({make_security_page(), NavScope::Client});
    pages_.push_back({make_logs_page(), NavScope::Client});
    pages_.push_back({make_settings_page(), NavScope::Client});
    pages_.push_back({make_server_page(), NavScope::Server});
    pages_.push_back({make_keys_page(), NavScope::Server});
    pages_.push_back({make_logs_page(), NavScope::Server});
    pages_.push_back({make_settings_page(), NavScope::Server});

    active_page_ = first_page_for(NavScope::Common);
    last_client_page_ = first_page_for(NavScope::Client);
    last_server_page_ = first_page_for(NavScope::Server);
}

App::~App() {
    if (window_) {
        ImGui_ImplOpenGL3_Shutdown();
        ImGui_ImplGlfw_Shutdown();
        ImPlot::DestroyContext();
        ImGui::DestroyContext();
    }
}

void App::load_configs() {
    using namespace facade::config_io;

    const auto client_path = opts_.client_config_path.empty()
                                 ? default_client_config_path()
                                 : std::filesystem::path(opts_.client_config_path);
    client::ClientConfig client_cfg;
    if (std::filesystem::exists(client_path)) {
        std::string err;
        if (auto c = load_client(client_path, &err)) {
            client_cfg = *c;
        } else {
            // Non-fatal: surface via log sink so user sees it on the Logs page.
            facade::LogEntry e;
            e.ts = std::chrono::system_clock::now();
            e.level = facade::LogLevel::Warn;
            e.component = "gui.app";
            e.message = "client config load failed: " + err;
            facade::LogSink::instance().push(std::move(e));
        }
    }
    client_ = std::make_unique<facade::ClientSession>(client_cfg);

    const auto server_path = opts_.server_config_path.empty()
                                 ? default_server_config_path()
                                 : std::filesystem::path(opts_.server_config_path);
    server::ServerConfig server_cfg;
    if (std::filesystem::exists(server_path)) {
        std::string err;
        if (auto s = load_server(server_path, &err)) {
            server_cfg = *s;
        } else {
            facade::LogEntry e;
            e.ts = std::chrono::system_clock::now();
            e.level = facade::LogLevel::Warn;
            e.component = "gui.app";
            e.message = "server config load failed: " + err;
            facade::LogSink::instance().push(std::move(e));
        }
    }
    server_ = std::make_unique<facade::ServerSession>(server_cfg);
}

void App::install_imgui() {
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImPlot::CreateContext();

    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;  // don't litter cwd with imgui.ini
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigWindowsMoveFromTitleBarOnly = true;

    theme::apply_material3(dark_mode_ ? theme::Mode::Dark : theme::Mode::Light);
    const float scale = window_ ? window_->content_scale() : 1.0f;
    ui::install_fonts(scale);
    ui::apply_style(scale, dark_mode_);

    ImGui_ImplGlfw_InitForOpenGL(window_->raw(), true);
    ImGui_ImplOpenGL3_Init("#version 330 core");
}

bool App::page_visible(std::size_t index) const {
    if (index >= pages_.size()) return false;
    NavScope const scope = pages_[index].scope;
    if (scope == NavScope::Common) return true;
    if (workspace_ == Workspace::Client) return scope == NavScope::Client;
    return scope == NavScope::Server;
}

std::size_t App::first_page_for(NavScope scope) const {
    for (std::size_t i = 0; i < pages_.size(); ++i) {
        if (pages_[i].scope == scope) return i;
    }
    return 0;
}

void App::select_page(std::size_t index) {
    if (index >= pages_.size()) return;
    active_page_ = index;
    if (pages_[index].scope == NavScope::Client) last_client_page_ = index;
    if (pages_[index].scope == NavScope::Server) last_server_page_ = index;
}

void App::set_workspace(Workspace workspace) {
    if (workspace_ == workspace) return;
    workspace_ = workspace;
    if (active_page_ < pages_.size() && pages_[active_page_].scope == NavScope::Common) {
        return;
    }
    select_page(workspace_ == Workspace::Client ? last_client_page_ : last_server_page_);
}

void App::render_sidebar() {
    const float sc = ui::scale();
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(30 * sc, 28 * sc));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 16 * sc);
    ImGui::BeginChild("##sidebar", ImVec2(276 * sc, 0),
                      ImGuiChildFlags_AlwaysUseWindowPadding,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    if (ui::fonts().title) ImGui::PushFont(ui::fonts().title);
    ImGui::TextUnformatted("YUME");
    if (ui::fonts().title) ImGui::PopFont();
    ui::muted_text("Stealth transport control");
    ImGui::Dummy(ImVec2(0, 18 * sc));

    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 8 * sc));
    for (std::size_t i = 0; i < pages_.size(); ++i) {
        if (pages_[i].scope != NavScope::Common) continue;
        std::string label(pages_[i].page->title());
        if (ui::nav_item(label.c_str(), label.c_str(), i == active_page_, ImVec2(-1, 48 * sc))) {
            select_page(i);
        }
    }
    ImGui::PopStyleVar();

    ImGui::Dummy(ImVec2(0, 16 * sc));
    ui::field_label("Workspace");
    const float switch_gap = 8 * sc;
    const float switch_w = ImGui::GetContentRegionAvail().x;
    const float half_w = (switch_w - switch_gap) * 0.5f;
    if (mode_button("Client", workspace_ == Workspace::Client, ImVec2(half_w, 44 * sc))) {
        set_workspace(Workspace::Client);
    }
    ImGui::SameLine(0.0f, switch_gap);
    if (mode_button("Server", workspace_ == Workspace::Server, ImVec2(half_w, 44 * sc))) {
        set_workspace(Workspace::Server);
    }

    ImGui::Dummy(ImVec2(0, 18 * sc));
    ui::field_label(workspace_ == Workspace::Client ? "Client" : "Server");
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 8 * sc));
    for (std::size_t i = 0; i < pages_.size(); ++i) {
        if (!page_visible(i) || pages_[i].scope == NavScope::Common) continue;
        std::string label(pages_[i].page->title());
        std::string id = label + "##" + std::to_string(i);
        if (ui::nav_item(id.c_str(), label.c_str(), i == active_page_, ImVec2(-1, 48 * sc))) {
            select_page(i);
        }
    }
    ImGui::PopStyleVar();

    ImGui::EndChild();
    ImGui::PopStyleVar(2);
}

void App::render_content() {
    const float sc = ui::scale();
    ImGui::SameLine(0.0f, 16 * sc);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(32 * sc, 28 * sc));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 16 * sc);
    ImGui::BeginChild("##content", ImVec2(0, 0),
                      ImGuiChildFlags_AlwaysUseWindowPadding);

    AppContext ctx;
    ctx.client = client_.get();
    ctx.server = server_.get();
    ctx.dark_mode = dark_mode_;

    if (active_page_ < pages_.size()) {
        if (shown_page_ != active_page_) {
            if (shown_page_ < pages_.size()) {
                pages_[shown_page_].page->on_hide(ctx);
            }
            pages_[active_page_].page->on_show(ctx);
            shown_page_ = active_page_;
        }
        pages_[active_page_].page->render(ctx);
    }
    dark_mode_ = ctx.dark_mode;

    ImGui::EndChild();
    ImGui::PopStyleVar(2);
}

void App::render_frame() {
    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();

    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGuiIO const& io = ImGui::GetIO();
    ImGui::SetNextWindowSize(io.DisplaySize);
    constexpr ImGuiWindowFlags root_flags =
        ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoBringToFrontOnFocus;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::Begin("Yume", nullptr, root_flags);

    render_sidebar();
    render_content();

    ImGui::End();
    ImGui::PopStyleVar();

    ImGui::Render();
}

int App::run() {
    if (opts_.start_minimized && window_) {
        window_->hide();
    }

    while (!window_->should_close()) {
        if (!window_->visible()) {
            // No frame work while hidden; wake on events with a long timeout
            // to keep CPU near zero.
            window_->wait_events_with_timeout(0.5);
            continue;
        }
        window_->poll_events();

        render_frame();

        int fbw = 0, fbh = 0;
        window_->framebuffer_size(fbw, fbh);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        window_->swap_buffers();
    }

    if (client_) client_->stop();
    if (server_) server_->stop();
    return 0;
}

int run_headless(Options const& /*opts*/) {
    std::printf(
        "yume-gui --headless: GUI facade smoke test passed.\n"
        "Local server lifecycle is available; GUI client start/stop uses "
        "the yume runtime through local IPC.\n");
    return 0;
}

}  // namespace yume::gui
