/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "app.hpp"

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <thread>
#include <utility>

#define GLFW_INCLUDE_NONE
#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <implot.h>

#include "core/version.hpp"
#include "facade/session/client_session.hpp"
#include "facade/config/config_io.hpp"
#include "facade/logging/log_sink.hpp"
#include "facade/session/server_session.hpp"
#include "facade/model/status.hpp"
#include "geo/country_lookup.hpp"
#include "platform/file_dialog.hpp"
#include "ui/design.hpp"

#include <cstring>
#include <string_view>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <sys/socket.h>
#endif

namespace yume::gui {

namespace {

// Translate a facade::ConnectionState into the tray overlay's state.
// Idle/Disconnected map to Off so the tray icon stays clean when nothing
// is in flight; transient states (Resolving/Connecting/TlsHandshake/etc.)
// all map to Connecting so the user sees the amber dot until the
// connection either lands or fails.
TrayServiceState tray_from_client_state(facade::ConnectionState s) {
    using S = facade::ConnectionState;
    switch (s) {
        case S::Connected:    return TrayServiceState::Connected;
        case S::Failed:       return TrayServiceState::Error;
        case S::Idle:
        case S::Disconnected: return TrayServiceState::Off;
        // Resolving / Connecting / TlsHandshake / Authenticating /
        // Reconnecting all read as "Connecting" on the tray.
        default:              return TrayServiceState::Connecting;
    }
}

TrayServiceState tray_from_server(facade::ServerStatus const& s) {
    if (s.running) return TrayServiceState::Connected;
    // ServerStatus has no rich state machine yet; treat "not running"
    // as off. When we add lifecycle events from the runtime controller
    // we can surface Connecting/Error here.
    return TrayServiceState::Off;
}

// Split "host:port" into just the host. We don't validate; the country
// lookup will reject anything that doesn't parse as IPv4. Bracketed
// IPv6 stays bracketed and will simply fall through to no-match.
std::string host_part_of(std::string const& endpoint) {
    if (endpoint.empty()) return {};
    if (endpoint.front() == '[') {
        auto rb = endpoint.find(']');
        if (rb == std::string::npos) return endpoint;
        return endpoint.substr(1, rb - 1);
    }
    auto colon = endpoint.rfind(':');
    if (colon == std::string::npos) return endpoint;
    return endpoint.substr(0, colon);
}

std::string format_rate(double bps) {
    char buf[32];
    if (bps < 1024.0)              std::snprintf(buf, sizeof(buf), "%.0f B/s", bps);
    else if (bps < 1024.0 * 1024)  std::snprintf(buf, sizeof(buf), "%.1f KiB/s", bps / 1024.0);
    else if (bps < 1024.0 * 1024 * 1024)
                                   std::snprintf(buf, sizeof(buf), "%.2f MiB/s", bps / (1024.0 * 1024));
    else                           std::snprintf(buf, sizeof(buf), "%.2f GiB/s", bps / (1024.0 * 1024 * 1024));
    return buf;
}

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
    auto const gui_prefs = facade::config_io::load_gui_preferences();
    dark_mode_ = gui_prefs.dark_mode;
    minimize_to_tray_on_close_ = gui_prefs.minimize_to_tray_on_close;

    window_ = std::make_unique<Window>(
        std::string("Yume ") + yume::kVersion, 1280, 800);
    install_imgui();

    // System tray. Constructing it does the GTK init + appindicator
    // setup; if the system has no StatusNotifier host (e.g. raw Sway
    // without waybar) the tray reports available() == false and the
    // close-to-tray hook below falls back to plain quit semantics.
    if (!opts_.no_tray) {
        tray_ = std::make_unique<Tray>(
            std::string("Yume"),
            Tray::Callbacks{
                /*on_show_window=*/[this]() {
                    if (window_) {
                        window_->show();
                        glfwFocusWindow(window_->raw());
                    }
                },
                /*on_quit=*/[this]() {
                    quit_requested_ = true;
                    if (window_) {
                        glfwSetWindowShouldClose(window_->raw(), GLFW_TRUE);
                    }
                },
            });

        // Intercept the window close button so it hides to tray instead
        // of quitting. Only installed when the tray actually attached —
        // otherwise close behaves normally.
        if (tray_->available() && window_) {
            glfwSetWindowUserPointer(window_->raw(), this);
            glfwSetWindowCloseCallback(window_->raw(),
                [](GLFWwindow* w) {
                    auto* app = static_cast<App*>(glfwGetWindowUserPointer(w));
                    if (!app) return;
                    if (app->quit_requested_) return;  // let close proceed
                    if (!app->minimize_to_tray_on_close_) return;
                    // Cancel the close and hide instead.
                    glfwSetWindowShouldClose(w, GLFW_FALSE);
                    glfwHideWindow(w);
                });
        }
    }

    pages_.push_back({make_dashboard_page(), NavScope::Common});
    pages_.push_back({make_connect_page(), NavScope::Client});
    pages_.push_back({make_security_page(), NavScope::Client});
    pages_.push_back({make_directory_page(), NavScope::Client});
    pages_.push_back({make_chat_page(), NavScope::Client});
    pages_.push_back({make_logs_page(), NavScope::Client});
    pages_.push_back({make_settings_page(), NavScope::Client});
    pages_.push_back({make_credits_page(), NavScope::Client});
    pages_.push_back({make_server_page(), NavScope::Server});
    pages_.push_back({make_keys_page(), NavScope::Server});
    pages_.push_back({make_logs_page(), NavScope::Server});
    pages_.push_back({make_settings_page(), NavScope::Server});
    pages_.push_back({make_credits_page(), NavScope::Server});

    active_page_ = first_page_for(NavScope::Common);
    last_client_page_ = first_page_for(NavScope::Client);
    last_server_page_ = first_page_for(NavScope::Server);
}

void App::kick_off_resolve_if_needed(std::string const& host) {
    if (host.empty()) return;
    // Already-cached or in-flight for the same host? Bail.
    {
        std::lock_guard<std::mutex> g(resolve_mtx_);
        if (resolved_host_ == host && !resolved_ip_.empty()) return;
    }
    bool expected = false;
    if (!resolve_in_flight_.compare_exchange_strong(expected, true)) {
        return;  // someone else is already resolving
    }
    std::thread([this, host]() {
        std::string ip;
        addrinfo hints{};
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        if (getaddrinfo(host.c_str(), nullptr, &hints, &res) == 0 && res) {
            char buf[INET_ADDRSTRLEN] = {0};
            sockaddr_in* sa = reinterpret_cast<sockaddr_in*>(res->ai_addr);
            if (inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf))) {
                ip = buf;
            }
            freeaddrinfo(res);
        }
        {
            std::lock_guard<std::mutex> g(resolve_mtx_);
            resolved_host_ = host;
            resolved_ip_   = ip;
        }
        resolve_in_flight_.store(false);
    }).detach();
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
            facade::LogSink::instance().push(
                facade::LogLevel::Warn,
                "gui.app",
                "client config load failed: " + err);
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
            facade::LogSink::instance().push(
                facade::LogLevel::Warn,
                "gui.app",
                "server config load failed: " + err);
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

    const float scale = window_ ? window_->content_scale() : 1.0f;
    ui::install_fonts(scale);
    ui::apply_style(scale, dark_mode_);

    ImGui_ImplGlfw_InitForOpenGL(window_->raw(), true);
    ImGui_ImplOpenGL3_Init("#version 330 core");
    platform::set_dialog_parent_window(window_->raw());
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

std::size_t App::find_page_index(std::string_view title, NavScope scope) const {
    for (std::size_t i = 0; i < pages_.size(); ++i) {
        if (pages_[i].scope == scope && pages_[i].page->title() == title) {
            return i;
        }
    }
    return static_cast<std::size_t>(-1);
}

void App::handle_page_navigation(AppContext& ctx) {
    if (ctx.jump_to_directory) {
        ctx.jump_to_directory = false;
        auto idx = find_page_index("Directory", NavScope::Client);
        if (idx < pages_.size()) {
            set_workspace(Workspace::Client);
            select_page(idx);
        }
    }
    if (ctx.jump_to_chat) {
        ctx.jump_to_chat = false;
        if (!ctx.pending_jump_arg.empty()) {
            pending_jump_arg_ = std::move(ctx.pending_jump_arg);
        }
        auto idx = find_page_index("Chat", NavScope::Client);
        if (idx < pages_.size()) {
            set_workspace(Workspace::Client);
            select_page(idx);
        }
    }
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
    ctx.tray_available = tray_ && tray_->available();
    ctx.minimize_to_tray_on_close = minimize_to_tray_on_close_;
    if (!pending_jump_arg_.empty()) {
        ctx.pending_jump_arg = pending_jump_arg_;
        pending_jump_arg_.clear();
    }

    if (active_page_ < pages_.size()) {
        if (shown_page_ != active_page_) {
            if (shown_page_ < pages_.size()) {
                pages_[shown_page_].page->on_hide(ctx);
            }
            pages_[active_page_].page->on_show(ctx);
            shown_page_ = active_page_;
        }
        pages_[active_page_].page->render(ctx);
        handle_page_navigation(ctx);
    }
    dark_mode_ = ctx.dark_mode;
    minimize_to_tray_on_close_ = ctx.minimize_to_tray_on_close;

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

    auto update_tray_status = [this]() {
        if (!tray_ || !tray_->available()) return;
        TrayStatus st;
        facade::ClientStatus cs{};
        facade::ServerStatus ss{};
        if (client_) {
            cs = client_->status();
            st.client = tray_from_client_state(cs.state);
        }
        if (server_) {
            ss = server_->status();
            st.server = tray_from_server(ss);
        }
        tray_->set_status(st);

        TrayInfo info;
        if (client_) {
            info.client_state = facade::display_label(cs.state);
            if (!cs.server_endpoint.empty()) {
                info.client_server = cs.server_endpoint;
            }
            if (!cs.profile.empty() || !cs.inner_mode.empty()) {
                info.client_profile = (cs.profile.empty() ? "default" : cs.profile)
                                    + std::string(" / ")
                                    + (cs.inner_mode.empty() ? "off" : cs.inner_mode);
            }
            std::string host = host_part_of(cs.server_endpoint);
            kick_off_resolve_if_needed(host);
            std::string ip;
            {
                std::lock_guard<std::mutex> g(resolve_mtx_);
                if (resolved_host_ == host && !resolved_ip_.empty()) {
                    ip = resolved_ip_;
                }
            }
            // If the endpoint is already an IPv4 literal, use it directly.
            if (ip.empty()) {
                in_addr a{};
                if (!host.empty() && inet_pton(AF_INET, host.c_str(), &a) == 1) {
                    ip = host;
                }
            }
            if (!ip.empty()) {
                info.exit_ip = ip;
                if (auto match = geo::lookup_ipv4(ip)) {
                    info.exit_country = match->display_name;
                    if (!match->flag_emoji.empty()) {
                        info.exit_country = match->flag_emoji + " " + info.exit_country;
                    }
                }
            }
            if (cs.state == facade::ConnectionState::Connected) {
                info.client_rates = std::string("\xE2\x86\x91 ") + format_rate(cs.tx_rate_bps)
                                  + "   \xE2\x86\x93 " + format_rate(cs.rx_rate_bps);
            }
        }
        if (server_) {
            if (ss.running) {
                info.server_state = ss.listen_endpoint.empty()
                    ? std::string("Running")
                    : "Running on " + ss.listen_endpoint;
            } else {
                info.server_state = "Stopped";
            }
        }
        tray_->set_info(info);
    };

    while (!window_->should_close()) {
        // GTK side: drain pending events so the user's tray menu clicks
        // ("Show Yume" / "Quit Yume") fire on this thread. Tray's
        // pump_events is a cheap no-op when the tray isn't initialised.
        if (tray_) tray_->pump_events();

        if (!window_->visible()) {
            // Hidden state — short wait so tray click latency stays under
            // 100 ms while idle CPU stays near zero.
            window_->wait_events_with_timeout(0.1);
            update_tray_status();
            continue;
        }
        window_->poll_events();

        update_tray_status();
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

int run_headless(Options const& opts) {
    (void)facade::LogSink::instance();

    const auto client_path = opts.client_config_path.empty()
                                 ? facade::config_io::default_client_config_path()
                                 : std::filesystem::path(opts.client_config_path);
    client::ClientConfig client_cfg;
    if (std::filesystem::exists(client_path)) {
        std::string err;
        if (auto c = facade::config_io::load_client(client_path, &err)) {
            client_cfg = *c;
        } else {
            std::fprintf(stderr, "yume-gui --headless: client config: %s\n", err.c_str());
            return 1;
        }
    }

    const auto server_path = opts.server_config_path.empty()
                                 ? facade::config_io::default_server_config_path()
                                 : std::filesystem::path(opts.server_config_path);
    server::ServerConfig server_cfg;
    if (std::filesystem::exists(server_path)) {
        std::string err;
        if (auto s = facade::config_io::load_server(server_path, &err)) {
            server_cfg = *s;
        } else {
            std::fprintf(stderr, "yume-gui --headless: server config: %s\n", err.c_str());
            return 1;
        }
    }

    facade::ServerSession server(server_cfg);
    facade::ClientSession client(client_cfg);

    auto const server_report = facade::config_io::validate(server_cfg);
    if (server_report.ok()) {
        std::string err;
        if (server.start(&err)) {
            std::printf("yume-gui --headless: server start/stop OK\n");
            server.stop();
        } else {
            std::printf("yume-gui --headless: server start skipped (%s)\n",
                        err.empty() ? "unknown error" : err.c_str());
        }
    } else {
        std::printf("yume-gui --headless: server start skipped (config invalid)\n");
    }

    auto const client_report = facade::config_io::validate(client_cfg);
    if (client_report.ok()) {
        std::string err;
        if (client.start(&err)) {
            std::printf("yume-gui --headless: client start/stop OK\n");
            client.stop();
        } else {
            std::printf("yume-gui --headless: client start skipped (%s)\n",
                        err.empty() ? "unknown error" : err.c_str());
        }
    } else {
        std::printf("yume-gui --headless: client start skipped (config invalid)\n");
    }

    std::printf("yume-gui --headless: facade lifecycle smoke complete.\n");
    return 0;
}

}  // namespace yume::gui
