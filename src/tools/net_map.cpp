/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// yume-net-map — ASCII visualization of the local yumed's federation
// topology. Connects to the local admin socket, reads runtime.status +
// federation.status, and prints a small fan / hex layout of the
// current node + its peers. Falls back to a flat table when the peer
// count gets too large for a useful drawing.
//
// Intentionally separate binary so it can be dropped onto a server
// without pulling in the rest of the yumed CLI surface, and so it
// can't accidentally mutate runtime state — it only reads.

#include "core/runtime/local_runtime.hpp"
#include "server/runtime/local_runtime.hpp"
#include "util.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace {

struct GlyphSet {
    const char* horiz;     // ─
    const char* vert;      // │
    const char* tl;        // ┌
    const char* tr;        // ┐
    const char* bl;        // └
    const char* br;        // ┘
    const char* top_tee;   // ┬
    const char* bot_tee;   // ┴
    const char* left_tee;  // ├
    const char* right_tee; // ┤
    const char* cross;     // ┼
};

constexpr GlyphSet kUnicodeGlyphs = {
    "─", "│", "┌", "┐", "└", "┘", "┬", "┴", "├", "┤", "┼",
};
constexpr GlyphSet kAsciiGlyphs = {
    "-", "|", "+", "+", "+", "+", "+", "+", "+", "+", "+",
};

struct Node {
    std::string id;
    std::string display;  // server_name if set, else id
    std::string addr;     // host:port hint, "local" for self
    int channels{0};
    std::string state;    // "self" / "ready" / "connecting" / "idle" / "error"
    std::string error;    // populated when state == "error"
    bool is_self{false};
};

struct Cli {
    std::string socket;
    bool ascii_only{false};
    bool json_out{false};
};

void print_usage() {
    std::cout <<
        "yume-net-map - ASCII visualization of a yumed cluster\n"
        "\n"
        "Usage:\n"
        "  yume-net-map [--socket <path>] [--ascii] [--json]\n"
        "\n"
        "Options:\n"
        "  --socket <path>    Yumed admin socket. Default: $YUME_IPC if set,\n"
        "                     otherwise auto-discover the local server.\n"
        "  --ascii            Use pure ASCII box chars (default: Unicode).\n"
        "  --json             Print the raw runtime+federation JSON instead\n"
        "                     of the diagram.\n"
        "  -h, --help         This message.\n"
        "\n"
        "Reads only. Never sends mutating ops to the daemon.\n";
}

bool parse_cli(int argc, char** argv, Cli& cli) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage();
            std::exit(0);
        }
        if (arg == "--ascii") {
            cli.ascii_only = true;
        } else if (arg == "--json") {
            cli.json_out = true;
        } else if (arg == "--socket" && i + 1 < argc) {
            cli.socket = argv[++i];
        } else {
            std::cerr << "yume-net-map: unknown argument: " << arg << "\n\n";
            print_usage();
            return false;
        }
    }
    if (cli.socket.empty()) {
        if (const char* env = std::getenv("YUME_IPC")) {
            cli.socket = env;
        }
    }
    return true;
}

// Discovers the first available local-server socket by trying the
// default path-conventions. Returns empty if none reachable.
std::string discover_socket() {
    // The server-side socket path is derived from the instance key, which
    // we don't know without reading the server's config. As a fallback,
    // scan the standard runtime dir for any socket whose role-prefix is
    // "server-".
    std::vector<std::filesystem::path> candidates;
    const char* xdg = std::getenv("XDG_RUNTIME_DIR");
    if (xdg && *xdg) {
        candidates.emplace_back(std::filesystem::path(xdg) / "yume");
    }
    candidates.emplace_back("/run/yume");
    candidates.emplace_back("/tmp/yume");
    for (const auto& dir : candidates) {
        std::error_code ec;
        if (!std::filesystem::is_directory(dir, ec)) continue;
        for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
            const auto name = entry.path().filename().string();
            if (name.rfind("server-", 0) != 0) continue;
            if (yume::server::LocalRuntime::available(entry.path().string())) {
                return entry.path().string();
            }
        }
    }
    return {};
}

// Fetches runtime.status + federation.status, normalises into Node list.
std::optional<std::vector<Node>> collect_topology(const std::string& socket_path,
                                                  std::string* error) {
    auto status = yume::server::LocalRuntime::request(
        socket_path, {{"op", "runtime.status"}, {"args", nlohmann::json::object()}},
        error, 5000);
    if (!error->empty() || !status.value("ok", false)) {
        if (error->empty()) {
            *error = status.value("error", "runtime.status failed");
        }
        return std::nullopt;
    }
    auto fed = yume::server::LocalRuntime::request(
        socket_path, {{"op", "federation.status"}, {"args", nlohmann::json::object()}},
        error, 5000);
    if (!error->empty() || !fed.value("ok", false)) {
        if (error->empty()) {
            *error = fed.value("error", "federation.status failed");
        }
        return std::nullopt;
    }

    std::vector<Node> nodes;
    Node self;
    self.is_self = true;
    self.id = status["result"].value("server_id", "");
    const std::string self_name = status["result"].value("server_name", "");
    self.display = self_name.empty() ? self.id : self_name;
    if (self.display.empty()) self.display = "(local)";
    const int port = status["result"].value("listen_port", 0);
    self.addr = port > 0 ? ("local:" + std::to_string(port)) : "local";
    self.channels = static_cast<int>(status["result"].value("endpoints", 0));
    self.state = "self";
    nodes.push_back(std::move(self));

    const bool fed_enabled = fed["result"].value("enabled", false);
    if (fed_enabled && fed["result"].contains("peer_status")) {
        for (const auto& peer : fed["result"]["peer_status"]) {
            Node n;
            n.id = peer.value("id", "?");
            n.display = n.id;
            n.channels = static_cast<int>(peer.value("channels_active", 0));
            n.state = peer.value("ready", false) ? "ready" : peer.value("state", "?");
            n.error = peer.value("last_error", "");
            if (!n.error.empty() && n.state != "ready") {
                n.state = "error";
            }
            nodes.push_back(std::move(n));
        }
    }
    return nodes;
}

// One renderable box: 4 lines × 14 cols, label/addr/state. The width is
// fixed so layout math stays simple; callers truncate long strings.
constexpr int kBoxW = 16;
constexpr int kBoxH = 5;

std::string trunc(const std::string& s, std::size_t max) {
    if (s.size() <= max) return s;
    if (max <= 1) return s.substr(0, max);
    return s.substr(0, max - 1) + "…";
}

std::vector<std::string> render_box(const Node& n, const GlyphSet& g, bool ascii) {
    // Top/bottom borders, padded label/addr/state inside.
    auto bar = [&](const char* l, const char* r) {
        std::string out = l;
        for (int i = 0; i < kBoxW - 2; ++i) out += g.horiz;
        out += r;
        return out;
    };
    auto row = [&](const std::string& body) {
        // Width = kBoxW - 2 (inner) but content can use multi-byte chars;
        // we trust callers passed ASCII-equivalent length via trunc().
        std::string padded = body;
        int slack = (kBoxW - 2) - static_cast<int>(body.size());
        if (slack > 0) padded += std::string(slack, ' ');
        else padded = body.substr(0, kBoxW - 2);
        return std::string(g.vert) + padded + g.vert;
    };

    std::vector<std::string> out;
    out.push_back(bar(g.tl, g.tr));
    std::string title = n.is_self ? ("* " + trunc(n.display, kBoxW - 4))
                                  : trunc(n.display, kBoxW - 2);
    out.push_back(row(title));
    out.push_back(row(trunc(n.addr, kBoxW - 2)));
    std::string state_line = n.is_self
        ? (std::to_string(n.channels) + " endpoints")
        : (std::to_string(n.channels) + " ch " + n.state);
    out.push_back(row(trunc(state_line, kBoxW - 2)));
    out.push_back(bar(g.bl, g.br));
    (void)ascii;
    return out;
}

// 2D character canvas with glyph-aware overwrite. Each cell stores a
// single Unicode glyph as a std::string (multi-byte safe).
class Canvas {
public:
    Canvas(int w, int h) : w_(w), h_(h), cells_(w * h, " ") {}

    void put(int x, int y, const std::string& glyph) {
        if (x < 0 || y < 0 || x >= w_ || y >= h_) return;
        cells_[y * w_ + x] = glyph;
    }

    void place_box(int x, int y, const std::vector<std::string>& lines) {
        for (std::size_t row = 0; row < lines.size(); ++row) {
            const std::string& s = lines[row];
            // Walk the UTF-8 string a code point at a time and put one
            // canvas cell per visible glyph.
            int col = 0;
            for (std::size_t i = 0; i < s.size();) {
                unsigned char b = static_cast<unsigned char>(s[i]);
                std::size_t n = 1;
                if ((b & 0xE0) == 0xC0) n = 2;
                else if ((b & 0xF0) == 0xE0) n = 3;
                else if ((b & 0xF8) == 0xF0) n = 4;
                if (i + n > s.size()) break;
                put(x + col, y + static_cast<int>(row), s.substr(i, n));
                i += n;
                ++col;
            }
        }
    }

    void draw_hline(int x1, int x2, int y, const std::string& glyph) {
        if (x1 > x2) std::swap(x1, x2);
        for (int x = x1; x <= x2; ++x) put(x, y, glyph);
    }

    void draw_vline(int x, int y1, int y2, const std::string& glyph) {
        if (y1 > y2) std::swap(y1, y2);
        for (int y = y1; y <= y2; ++y) put(x, y, glyph);
    }

    void print(std::ostream& out) const {
        for (int y = 0; y < h_; ++y) {
            for (int x = 0; x < w_; ++x) {
                out << cells_[y * w_ + x];
            }
            out << '\n';
        }
    }

private:
    int w_, h_;
    std::vector<std::string> cells_;
};

void render_diagram(const std::vector<Node>& nodes, bool ascii, std::ostream& out) {
    const GlyphSet& g = ascii ? kAsciiGlyphs : kUnicodeGlyphs;
    if (nodes.empty()) {
        out << "(no nodes)\n";
        return;
    }
    const Node& self = nodes[0];
    std::vector<Node> peers(nodes.begin() + 1, nodes.end());

    // Standalone self — just the box.
    if (peers.empty()) {
        auto box = render_box(self, g, ascii);
        for (const auto& line : box) out << line << '\n';
        out << "(federation disabled or no peers)\n";
        return;
    }

    // 7+ peers: table fallback. The drawing math gets ugly past 6
    // and the result isn't more useful than a sorted list.
    if (peers.size() > 6) {
        auto self_box = render_box(self, g, ascii);
        for (const auto& line : self_box) out << line << '\n';
        out << '\n';
        out << "Peers (" << peers.size() << "):\n";
        for (const auto& p : peers) {
            out << "  - " << p.display
                << "  " << p.channels << " ch"
                << "  state=" << p.state;
            if (!p.error.empty()) out << "  error=" << p.error;
            out << '\n';
        }
        return;
    }

    // 1-6 peers: spoke layout. Self at top, peers in a row below with
    // diagonal connectors. Total canvas width adapts to peer count.
    const int gap = 4;
    const int peer_count = static_cast<int>(peers.size());
    const int peer_strip_w = peer_count * kBoxW + (peer_count - 1) * gap;
    const int canvas_w = std::max(peer_strip_w, kBoxW) + 4;
    const int peer_strip_x0 = (canvas_w - peer_strip_w) / 2;
    const int self_x0 = (canvas_w - kBoxW) / 2;

    const int self_y = 0;
    const int connect_y = self_y + kBoxH;
    const int spoke_h = 2;
    const int peers_y = connect_y + spoke_h;
    const int canvas_h = peers_y + kBoxH;

    Canvas c(canvas_w, canvas_h);
    c.place_box(self_x0, self_y, render_box(self, g, ascii));

    // Drop one bot-tee on the self box's bottom border so the spoke
    // visibly originates from it.
    c.put(self_x0 + kBoxW / 2, self_y + kBoxH - 1, g.bot_tee);

    // Spoke from self midline down to a horizontal bar across the
    // peer strip, then down to each peer's top-center.
    const int self_mid_x = self_x0 + kBoxW / 2;
    c.draw_vline(self_mid_x, self_y + kBoxH, connect_y, g.vert);

    if (peer_count == 1) {
        // Direct vertical link to single peer.
        const int peer_x = peer_strip_x0;
        const int peer_mid = peer_x + kBoxW / 2;
        c.draw_vline(peer_mid, connect_y, peers_y - 1, g.vert);
        c.put(peer_mid, peers_y, g.top_tee);
        c.place_box(peer_x, peers_y, render_box(peers[0], g, ascii));
    } else {
        // Horizontal bus across the peer strip, with verticals down
        // into each peer's top border.
        const int left_mid = peer_strip_x0 + kBoxW / 2;
        const int right_mid = peer_strip_x0 + (peer_count - 1) * (kBoxW + gap) + kBoxW / 2;
        c.draw_hline(left_mid, right_mid, connect_y, g.horiz);
        // Connector glyphs at the ends and the self-spoke join.
        c.put(left_mid, connect_y, g.tl);
        c.put(right_mid, connect_y, g.tr);
        if (self_mid_x >= left_mid && self_mid_x <= right_mid) {
            c.put(self_mid_x, connect_y, g.top_tee);
        }
        for (int i = 0; i < peer_count; ++i) {
            const int px = peer_strip_x0 + i * (kBoxW + gap);
            const int pmid = px + kBoxW / 2;
            c.draw_vline(pmid, connect_y, peers_y - 1, g.vert);
            // Connector at the bus row: ┬ unless this column is also
            // an endpoint of the bus (then keep the corner).
            if (pmid != left_mid && pmid != right_mid && pmid != self_mid_x) {
                c.put(pmid, connect_y, g.top_tee);
            }
            c.put(pmid, peers_y, g.top_tee);  // joins the peer's top border
            c.place_box(px, peers_y, render_box(peers[i], g, ascii));
        }
    }
    c.print(out);
}

}  // namespace

int main(int argc, char** argv) {
    Cli cli;
    if (!parse_cli(argc, argv, cli)) {
        return 1;
    }

    if (cli.socket.empty()) {
        cli.socket = discover_socket();
    }
    if (cli.socket.empty()) {
        std::cerr << "yume-net-map: could not locate a yumed admin socket.\n"
                     "  Pass --socket <path> or set YUME_IPC=<path>.\n"
                     "  Default discovery: $XDG_RUNTIME_DIR/yume, /run/yume, /tmp/yume.\n";
        return 1;
    }
    if (!yume::server::LocalRuntime::available(cli.socket)) {
        std::cerr << "yume-net-map: socket not reachable: " << cli.socket << '\n';
        return 1;
    }

    std::string error;
    auto nodes_opt = collect_topology(cli.socket, &error);
    if (!nodes_opt) {
        std::cerr << "yume-net-map: " << error << '\n';
        return 1;
    }
    const auto& nodes = *nodes_opt;

    if (cli.json_out) {
        nlohmann::json out = nlohmann::json::array();
        for (const auto& n : nodes) {
            out.push_back({
                {"id", n.id},
                {"display", n.display},
                {"addr", n.addr},
                {"channels", n.channels},
                {"state", n.state},
                {"error", n.error},
                {"is_self", n.is_self},
            });
        }
        std::cout << out.dump(2) << '\n';
        return 0;
    }

    render_diagram(nodes, cli.ascii_only, std::cout);
    return 0;
}
