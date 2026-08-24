/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "app.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <filesystem>
#include <system_error>
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
#include "platform/png_writer.hpp"
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

#ifdef _WIN32
// Winsock is per-process and reference counted. The GUI's own resolver is the
// only code here that calls a socket API without going through Boost.Asio, so
// it initialises Winsock itself rather than depending on another subsystem
// having done it first.
std::mutex& winsock_mutex() {
    static std::mutex m;
    return m;
}
int& winsock_refs() {
    static int refs = 0;
    return refs;
}
void ensure_winsock() {
    std::lock_guard<std::mutex> g(winsock_mutex());
    if (winsock_refs()++ == 0) {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
            // Leave the count incremented: a failed start must not let the
            // next caller believe it holds an initialised stack.
            std::fprintf(stderr, "yume-gui: WSAStartup failed\n");
        }
    }
}
void release_winsock() {
    std::lock_guard<std::mutex> g(winsock_mutex());
    if (--winsock_refs() == 0) {
        WSACleanup();
    }
}
#else
inline void ensure_winsock() {}
inline void release_winsock() {}
#endif

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

    // Logs, Settings and Credits are workspace-agnostic. They used to be
    // instantiated once per workspace, which gave each of them two
    // independent copies of its own scroll position, filter and expansion
    // state; switching workspaces silently swapped which copy you were
    // looking at. They are Common now, so there is exactly one of each.
    pages_.push_back({make_dashboard_page(), NavScope::Common});
    pages_.push_back({make_connect_page(), NavScope::Client});
    pages_.push_back({make_security_page(), NavScope::Client});
    pages_.push_back({make_directory_page(), NavScope::Client});
    pages_.push_back({make_chat_page(), NavScope::Client});
    pages_.push_back({make_server_page(), NavScope::Server});
    pages_.push_back({make_keys_page(), NavScope::Server});
    pages_.push_back({make_logs_page(), NavScope::Common});
    pages_.push_back({make_settings_page(), NavScope::Common});
    pages_.push_back({make_credits_page(), NavScope::Common});

    active_page_ = first_page_for(NavScope::Common);
    last_client_page_ = first_page_for(NavScope::Client);
    last_server_page_ = first_page_for(NavScope::Server);

    if (!opts_.page.empty()) {
        bool found = false;
        for (std::size_t i = 0; i < pages_.size() && !found; ++i) {
            std::string_view const title = pages_[i].page->title();
            if (title.size() != opts_.page.size()) continue;
            found = std::equal(title.begin(), title.end(), opts_.page.begin(),
                               [](char a, char b) {
                                   return std::tolower(
                                              static_cast<unsigned char>(a)) ==
                                          std::tolower(
                                              static_cast<unsigned char>(b));
                               });
            if (found) {
                if (pages_[i].scope == NavScope::Server) {
                    set_workspace(Workspace::Server);
                } else if (pages_[i].scope == NavScope::Client) {
                    set_workspace(Workspace::Client);
                }
                select_page(i);
            }
        }
        if (!found) {
            std::fprintf(stderr, "yume-gui: no page named '%s'\n",
                         opts_.page.c_str());
        }
    }
}

void App::kick_off_resolve_if_needed(std::string const& host) {
    if (host.empty()) return;
    // Already-cached or in-flight for the same host? Bail.
    {
        std::lock_guard<std::mutex> g(resolve_->mtx);
        if (resolve_->host == host && !resolve_->ip.empty()) return;
    }
    bool expected = false;
    if (!resolve_in_flight_.compare_exchange_strong(expected, true)) {
        return;  // someone else is already resolving
    }
    // The previous worker has already published its result and cleared the
    // in-flight flag, so this join is on a thread that is about to exit.
    if (resolver_thread_.joinable()) {
        resolver_thread_.join();
    }
    {
        std::lock_guard<std::mutex> g(resolve_->mtx);
        resolve_->finished = false;
    }
    // Capture the shared state, never `this`: a detached worker must stay
    // safe after the App is gone.
    resolver_thread_ = std::thread([state = resolve_, host]() {
        // Winsock must be initialised before getaddrinfo, and this worker does
        // not go through Boost.Asio, so it cannot assume Asio's static
        // winsock_init has run. Reference-counted per process; the matching
        // WSACleanup happens below.
        ensure_winsock();
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
            std::lock_guard<std::mutex> g(state->mtx);
            state->host     = host;
            state->ip       = ip;
            state->finished = true;
        }
        state->done.notify_all();
        release_winsock();
    });
}

App::~App() {
    if (resolver_thread_.joinable()) {
        // getaddrinfo cannot be interrupted, so give a live lookup a short
        // grace period and then walk away from it. The worker owns its state
        // through the shared_ptr, so detaching leaks nothing that points at
        // this object and shutdown stays bounded under hostile DNS.
        bool settled = false;
        {
            std::unique_lock<std::mutex> lk(resolve_->mtx);
            settled = resolve_->done.wait_for(
                lk, std::chrono::milliseconds(250),
                [this]() { return resolve_->finished; });
        }
        if (settled) {
            resolver_thread_.join();
        } else {
            resolver_thread_.detach();
        }
    }
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
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(16 * sc, 16 * sc));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 10 * sc);
    ImGui::BeginChild("##sidebar", ImVec2(196 * sc, 0),
                      ImGuiChildFlags_AlwaysUseWindowPadding,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    if (ui::fonts().title) ImGui::PushFont(ui::fonts().title);
    ImGui::TextUnformatted("YUME");
    if (ui::fonts().title) ImGui::PopFont();
    if (ui::fonts().small) ImGui::PushFont(ui::fonts().small);
    ImGui::PushStyleColor(ImGuiCol_Text, ui::colors().muted);
    ImGui::TextUnformatted("Stealth transport");
    ImGui::PopStyleColor();
    if (ui::fonts().small) ImGui::PopFont();
    ImGui::Dummy(ImVec2(0, 12 * sc));

    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 3 * sc));
    for (std::size_t i = 0; i < pages_.size(); ++i) {
        if (pages_[i].scope != NavScope::Common) continue;
        std::string label(pages_[i].page->title());
        if (ui::nav_item(label.c_str(), label.c_str(), i == active_page_, ImVec2(-1, 34 * sc))) {
            select_page(i);
        }
    }
    ImGui::PopStyleVar();

    ImGui::Dummy(ImVec2(0, 14 * sc));
    ui::field_label("Workspace");
    const float switch_gap = 6 * sc;
    const float switch_w = ImGui::GetContentRegionAvail().x;
    const float half_w = (switch_w - switch_gap) * 0.5f;
    if (mode_button("Client", workspace_ == Workspace::Client, ImVec2(half_w, 30 * sc))) {
        set_workspace(Workspace::Client);
    }
    ImGui::SameLine(0.0f, switch_gap);
    if (mode_button("Server", workspace_ == Workspace::Server, ImVec2(half_w, 30 * sc))) {
        set_workspace(Workspace::Server);
    }

    ImGui::Dummy(ImVec2(0, 14 * sc));
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 3 * sc));
    for (std::size_t i = 0; i < pages_.size(); ++i) {
        if (!page_visible(i) || pages_[i].scope == NavScope::Common) continue;
        std::string label(pages_[i].page->title());
        std::string id = label + "##" + std::to_string(i);
        if (ui::nav_item(id.c_str(), label.c_str(), i == active_page_, ImVec2(-1, 34 * sc))) {
            select_page(i);
        }
    }
    ImGui::PopStyleVar();

    ImGui::EndChild();
    ImGui::PopStyleVar(2);
}

void App::render_content() {
    const float sc = ui::scale();
    ImGui::SameLine(0.0f, 10 * sc);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20 * sc, 16 * sc));
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 10 * sc);
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

namespace {

// glReadPixels is OpenGL 1.0, but this project deliberately carries no GL
// loader (the ImGui backend brings its own). Fetching the one entry point we
// need through GLFW keeps it that way.
using GlReadPixelsFn = void (*)(int, int, int, int, unsigned, unsigned, void*);
constexpr unsigned kGlRgba = 0x1908;
constexpr unsigned kGlUnsignedByte = 0x1401;

// ImGui sizes several of our containers from the previous frame's content, so
// a single frame captures a half-laid-out page. Five is comfortably past the
// point where auto-sized cards and the nav settle.
constexpr int kSettleFrames = 5;

bool write_framebuffer_png(Window& window, std::string const& path) {
    auto read_pixels =
        reinterpret_cast<GlReadPixelsFn>(glfwGetProcAddress("glReadPixels"));
    if (!read_pixels) {
        std::fprintf(stderr, "yume-gui: glReadPixels unavailable\n");
        return false;
    }
    int w = 0, h = 0;
    window.framebuffer_size(w, h);
    if (w <= 0 || h <= 0) {
        std::fprintf(stderr, "yume-gui: framebuffer has no size\n");
        return false;
    }

    std::vector<unsigned char> pixels(
        static_cast<std::size_t>(w) * static_cast<std::size_t>(h) * 4u);
    read_pixels(0, 0, w, h, kGlRgba, kGlUnsignedByte, pixels.data());

    // GL origin is bottom-left; PNG is top-left.
    const std::size_t stride = static_cast<std::size_t>(w) * 4u;
    std::vector<unsigned char> flipped(pixels.size());
    for (int row = 0; row < h; ++row) {
        std::memcpy(flipped.data() + static_cast<std::size_t>(row) * stride,
                    pixels.data() +
                        static_cast<std::size_t>(h - 1 - row) * stride,
                    stride);
    }

    if (!platform::write_png_rgba(path, w, h, flipped.data())) {
        std::fprintf(stderr, "yume-gui: could not write %s\n", path.c_str());
        return false;
    }
    std::printf("yume-gui: captured %s (%dx%d)\n", path.c_str(), w, h);
    return true;
}

// Filesystem-safe slug for a page title.
std::string slug_of(std::string_view title) {
    std::string out;
    out.reserve(title.size());
    for (char ch : title) {
        if (std::isalnum(static_cast<unsigned char>(ch))) {
            out.push_back(static_cast<char>(
                std::tolower(static_cast<unsigned char>(ch))));
        } else if (!out.empty() && out.back() != '-') {
            out.push_back('-');
        }
    }
    while (!out.empty() && out.back() == '-') out.pop_back();
    return out.empty() ? std::string("page") : out;
}

}  // namespace

bool App::run_capture() {
    if (!window_) return false;

    auto render_and_write = [this](std::string const& path) {
        for (int i = 0; i < kSettleFrames; ++i) {
            window_->poll_events();
            render_frame();
            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
            // Read before presenting. glReadPixels defaults to GL_BACK, and
            // swapping first would leave the back buffer holding the previous
            // frame rather than the one just drawn.
            if (i + 1 == kSettleFrames) break;
            window_->swap_buffers();
        }
        const bool ok = write_framebuffer_png(*window_, path);
        window_->swap_buffers();
        return ok;
    };

    bool ok = true;
    if (!opts_.capture_all_dir.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(opts_.capture_all_dir, ec);
        if (ec) {
            std::fprintf(stderr, "yume-gui: cannot create %s: %s\n",
                         opts_.capture_all_dir.c_str(), ec.message().c_str());
            return false;
        }
        int index = 0;
        for (auto const workspace : {Workspace::Client, Workspace::Server}) {
            set_workspace(workspace);
            char const* ws = workspace == Workspace::Client ? "client" : "server";
            for (std::size_t i = 0; i < pages_.size(); ++i) {
                // Common pages belong to no workspace in particular; capture
                // them once, on the client pass.
                if (pages_[i].scope == NavScope::Common &&
                    workspace != Workspace::Client) {
                    continue;
                }
                if (!page_visible(i)) continue;
                select_page(i);
                char stem[128];
                std::snprintf(stem, sizeof(stem), "%02d-%s-%s.png", index++, ws,
                              slug_of(pages_[i].page->title()).c_str());
                // Build through filesystem::path so the separator is right on
                // every platform rather than assuming '/'.
                const auto out =
                    std::filesystem::path(opts_.capture_all_dir) / stem;
                ok = render_and_write(out.string()) && ok;
            }
        }
    } else {
        ok = render_and_write(opts_.capture_path);
    }
    return ok;
}

int App::run() {
    if (!opts_.capture_path.empty() || !opts_.capture_all_dir.empty()) {
        const bool ok = run_capture();
        if (client_) client_->stop();
        if (server_) server_->stop();
        return ok ? 0 : 1;
    }
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
            if (!cs.profile.empty() || !cs.security_mode.empty()) {
                info.client_profile = (cs.profile.empty() ? "default" : cs.profile)
                                    + std::string(" / ")
                                    + (cs.security_mode.empty() ? "unknown" : cs.security_mode);
            }
            std::string host = host_part_of(cs.server_endpoint);
            kick_off_resolve_if_needed(host);
            std::string ip;
            {
                std::lock_guard<std::mutex> g(resolve_->mtx);
                if (resolve_->host == host && !resolve_->ip.empty()) {
                    ip = resolve_->ip;
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

namespace {

// Bounded wait budget for one client connect attempt. The client's own
// blocking phases are a 10-second connect plus a 12-second TLS handshake, so
// anything below ~25 s would time out a healthy connection on a slow path.
constexpr auto kConnectBudget = std::chrono::seconds(30);
// Stop is signal-then-teardown; a healthy session leaves Connected quickly.
constexpr auto kStopBudget = std::chrono::seconds(15);
constexpr auto kPollInterval = std::chrono::milliseconds(50);

void headless_note(char const* fmt, ...) {
    std::va_list args;
    va_start(args, fmt);
    std::fputs("yume-gui --headless: ", stdout);
    std::vfprintf(stdout, fmt, args);
    std::fputc('\n', stdout);
    va_end(args);
    std::fflush(stdout);
}

// A failing acceptance gate that prints only "it failed" is not usable. Drain
// the typed log stream the GUI already collects so the reason is in the same
// output as the verdict.
void headless_dump_log(std::size_t max_entries = 40) {
    auto const entries = facade::LogSink::instance().snapshot(max_entries);
    if (entries.empty()) return;
    std::fputs("yume-gui --headless: --- recent log ---\n", stderr);
    for (auto const& e : entries) {
        std::fprintf(stderr, "  [%s] %s: %s\n",
                     facade::to_string(e.level),
                     e.component.c_str(), e.message.c_str());
    }
}

void headless_fail(char const* fmt, ...) {
    std::va_list args;
    va_start(args, fmt);
    std::fputs("yume-gui --headless: FAIL: ", stderr);
    std::vfprintf(stderr, fmt, args);
    std::fputc('\n', stderr);
    va_end(args);
}

// Poll until the client reaches Connected. Failed/Disconnected are terminal
// negatives, not states to keep waiting through.
bool await_connected(facade::ClientSession& client, std::string* why) {
    const auto deadline = std::chrono::steady_clock::now() + kConnectBudget;
    bool observed_running = false;
    for (;;) {
        auto const st = client.status();
        observed_running = observed_running || client.running();
        switch (st.state) {
            case facade::ConnectionState::Connected:
                return true;
            case facade::ConnectionState::Failed:
                if (why) {
                    *why = st.message.empty() ? "connection failed" : st.message;
                }
                return false;
            case facade::ConnectionState::Disconnected:
            case facade::ConnectionState::Idle:
                // Terminal only once the runtime has actually been up at some
                // point. start() admits work asynchronously, so the first
                // polls legitimately read Idle with running() still false;
                // treating that as failure would fail a healthy connect.
                if (observed_running && !client.running()) {
                    if (why) {
                        *why = std::string("session ended in ") +
                               facade::display_label(st.state) +
                               (st.message.empty() ? "" : " (" + st.message + ")");
                    }
                    return false;
                }
                break;
            default:
                break;  // Resolving / Connecting / TlsHandshake / Authenticating
        }
        if (std::chrono::steady_clock::now() >= deadline) {
            if (why) {
                *why = std::string("timed out in state ") +
                       facade::display_label(st.state);
            }
            return false;
        }
        std::this_thread::sleep_for(kPollInterval);
    }
}

// Waits for full quiescence, not merely "not running". stop() returns before
// teardown completes, so a restart issued the moment running() goes false is
// refused with "client runtime is still stopping". busy() is the predicate
// start() actually admits on.
bool await_client_stopped(facade::ClientSession& client, std::string* why) {
    const auto deadline = std::chrono::steady_clock::now() + kStopBudget;
    while (client.busy()) {
        if (std::chrono::steady_clock::now() >= deadline) {
            if (why) {
                *why = client.running()
                           ? "client still running after stop()"
                           : "client teardown did not finish after stop()";
            }
            return false;
        }
        std::this_thread::sleep_for(kPollInterval);
    }
    auto const st = client.status();
    if (st.state == facade::ConnectionState::Connected) {
        if (why) *why = "client still reports Connected after stop()";
        return false;
    }
    return true;
}

bool await_server_running(facade::ServerSession& server, bool want,
                          std::string* why) {
    const auto deadline = std::chrono::steady_clock::now() + kStopBudget;
    for (;;) {
        // Stopping means fully torn down, for the same reason as the client:
        // otherwise a restart lands inside the teardown window.
        const bool settled = want ? server.running() : !server.busy();
        if (settled) return true;
        if (std::chrono::steady_clock::now() >= deadline) {
            if (why) {
                *why = want ? "server did not reach running"
                            : "server teardown did not finish after stop()";
            }
            return false;
        }
        std::this_thread::sleep_for(kPollInterval);
    }
}

// Load one config file. `explicit_path` distinguishes "the user named this
// file" (missing is an error) from "we probed the default location".
enum class LoadOutcome { Loaded, Absent, Invalid };

template <typename Cfg, typename Loader>
LoadOutcome load_headless_config(std::filesystem::path const& path,
                                 bool explicit_path,
                                 Loader&& loader,
                                 Cfg& out,
                                 char const* what) {
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) {
        if (explicit_path) {
            headless_fail("%s config not found: %s", what, path.string().c_str());
            return LoadOutcome::Invalid;
        }
        return LoadOutcome::Absent;
    }
    std::string err;
    if (auto loaded = loader(path, &err)) {
        out = *loaded;
        return LoadOutcome::Loaded;
    }
    headless_fail("%s config %s: %s", what, path.string().c_str(),
                  err.empty() ? "could not be parsed" : err.c_str());
    return LoadOutcome::Invalid;
}

// One full server lifecycle: start, observe running, stop, observe stopped.
bool exercise_server(server::ServerConfig const& cfg) {
    auto const report = facade::config_io::validate(cfg);
    for (auto const& w : report.warnings) {
        headless_note("server config warning: %s", w.c_str());
    }
    if (!report.ok()) {
        for (auto const& e : report.errors) {
            headless_fail("server config: %s", e.c_str());
        }
        return false;
    }

    facade::ServerSession server(cfg);
    std::string err;
    if (!server.start(&err)) {
        headless_fail("server start: %s",
                      err.empty() ? "start refused" : err.c_str());
        return false;
    }
    std::string why;
    if (!await_server_running(server, true, &why)) {
        headless_fail("server start: %s", why.c_str());
        return false;
    }
    headless_note("server started on %s",
                  server.status().listen_endpoint.c_str());

    server.stop();
    if (!await_server_running(server, false, &why)) {
        headless_fail("server stop: %s", why.c_str());
        return false;
    }
    headless_note("server stopped");
    return true;
}

// One full client lifecycle: connect, stop, reconnect, stop. The reconnect
// leg is what proves the session is genuinely restartable rather than
// one-shot, which is the case the old smoke never covered.
bool exercise_client(client::ClientConfig const& cfg) {
    auto const report = facade::config_io::validate(cfg);
    for (auto const& w : report.warnings) {
        headless_note("client config warning: %s", w.c_str());
    }
    if (!report.ok()) {
        for (auto const& e : report.errors) {
            headless_fail("client config: %s", e.c_str());
        }
        return false;
    }

    facade::ClientSession client(cfg);
    for (int attempt = 1; attempt <= 2; ++attempt) {
        char const* leg = attempt == 1 ? "connect" : "reconnect";
        std::string err;
        if (!client.start(&err)) {
            headless_fail("client %s: %s", leg,
                          err.empty() ? "start refused" : err.c_str());
            return false;
        }
        {
            auto const after = client.status();
            headless_note("client %s: start admitted (state=%s, busy=%d)", leg,
                          facade::display_label(after.state),
                          client.busy() ? 1 : 0);
        }
        std::string why;
        if (!await_connected(client, &why)) {
            headless_fail("client %s: %s", leg, why.c_str());
            client.stop();
            return false;
        }
        headless_note("client %s reached Connected (%s)", leg,
                      client.status().server_endpoint.c_str());

        client.stop();
        if (!await_client_stopped(client, &why)) {
            headless_fail("client %s stop: %s", leg, why.c_str());
            return false;
        }
        headless_note("client %s stop clean", leg);
    }
    return true;
}

}  // namespace

// Exit codes: 0 every exercised lifecycle passed; 1 a lifecycle failed;
// 2 nothing could be exercised (missing/unparseable configuration). A run
// that exercises nothing is never reported as success.
int run_headless(Options const& opts) {
    (void)facade::LogSink::instance();

    const bool client_explicit = !opts.client_config_path.empty();
    const auto client_path = client_explicit
                                 ? std::filesystem::path(opts.client_config_path)
                                 : facade::config_io::default_client_config_path();
    const bool server_explicit = !opts.server_config_path.empty();
    const auto server_path = server_explicit
                                 ? std::filesystem::path(opts.server_config_path)
                                 : facade::config_io::default_server_config_path();

    client::ClientConfig client_cfg;
    const auto client_load = load_headless_config(
        client_path, client_explicit,
        [](std::filesystem::path const& p, std::string* e) {
            return facade::config_io::load_client(p, e);
        },
        client_cfg, "client");

    server::ServerConfig server_cfg;
    const auto server_load = load_headless_config(
        server_path, server_explicit,
        [](std::filesystem::path const& p, std::string* e) {
            return facade::config_io::load_server(p, e);
        },
        server_cfg, "server");

    if (client_load == LoadOutcome::Invalid ||
        server_load == LoadOutcome::Invalid) {
        return 2;
    }
    if (client_load == LoadOutcome::Absent && server_load == LoadOutcome::Absent) {
        headless_fail(
            "no client or server configuration found; nothing to exercise "
            "(looked for %s and %s)",
            client_path.string().c_str(), server_path.string().c_str());
        return 2;
    }

    bool ok = true;
    // Server first: when both configs are present the client leg may well be
    // pointed at this very server.
    if (server_load == LoadOutcome::Loaded) {
        ok = exercise_server(server_cfg) && ok;
    }
    if (client_load == LoadOutcome::Loaded) {
        ok = exercise_client(client_cfg) && ok;
    }

    if (!ok) {
        headless_dump_log();
        headless_fail("lifecycle contract not met");
        return 1;
    }
    headless_note("all exercised lifecycles passed");
    return 0;
}

}  // namespace yume::gui
