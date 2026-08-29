/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/federation/topology_render.hpp"

#include "server/federation/types.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <ostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yume::server {

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
    const char* cross;     // ┼
    // --ascii exists for terminals that cannot render box drawing, so the
    // truncation marker has to be 7-bit there too, not just the borders.
    const char* ellipsis;
};

constexpr GlyphSet kUnicodeGlyphs = {
    "─", "│", "┌", "┐", "└", "┘", "┬", "┴", "┼", "…"};
constexpr GlyphSet kAsciiGlyphs = {
    "-", "|", "+", "+", "+", "+", "+", "+", "+", "~"};

// One renderable box: 4 lines × 14 cols, label/addr/state. The width is
// fixed so layout math stays simple; callers truncate long strings.
constexpr int kBoxW = 16;
constexpr int kBoxH = 5;

// Box widths are measured in code points, never bytes. A peer's dial address
// or display name is arbitrary text, and cutting one mid-sequence would emit a
// broken UTF-8 byte into the terminal; the canvas below also places one cell
// per code point, so a byte-based width would misalign every box after it.
//
// Known limit: a code point is not a display column. East Asian wide
// characters and combining marks still render wider or narrower than the
// budget assumes, so a box holding them looks ragged. The layout stays
// structurally correct because every stage counts the same way; only the
// visual alignment of that one box suffers. Fixing it needs real character
// width data, which is not worth a table here.

std::size_t glyph_length(std::string_view text) {
    std::size_t glyphs = 0;
    for (const char byte : text) {
        // Count everything that is not a UTF-8 continuation byte.
        if ((static_cast<unsigned char>(byte) & 0xC0) != 0x80) ++glyphs;
    }
    return glyphs;
}

// Byte offset just past the first `glyphs` code points.
std::size_t glyph_prefix_bytes(std::string_view text, std::size_t glyphs) {
    std::size_t seen = 0;
    std::size_t offset = 0;
    while (offset < text.size()) {
        if ((static_cast<unsigned char>(text[offset]) & 0xC0) != 0x80) {
            if (seen == glyphs) return offset;
            ++seen;
        }
        ++offset;
    }
    return text.size();
}

// Truncates to `width` glyphs, spending the last one on an ellipsis so the
// reader can tell the value was cut.
std::string fit(std::string_view text, std::size_t width,
                const char* ellipsis) {
    if (glyph_length(text) <= width) return std::string(text);
    if (width == 0) return {};
    if (width == 1) return ellipsis;
    return std::string(text.substr(0, glyph_prefix_bytes(text, width - 1))) +
           ellipsis;
}

std::string string_field(const nlohmann::json& object,
                         std::string_view name,
                         std::string fallback = {}) {
    if (!object.is_object()) return fallback;
    const auto found = object.find(std::string(name));
    return found != object.end() && found->is_string()
        ? found->get<std::string>() : std::move(fallback);
}

bool bool_field(const nlohmann::json& object,
                std::string_view name,
                bool fallback = false) {
    if (!object.is_object()) return fallback;
    const auto found = object.find(std::string(name));
    return found != object.end() && found->is_boolean()
        ? found->get<bool>() : fallback;
}

std::size_t count_field(const nlohmann::json& object,
                        std::string_view name) {
    if (!object.is_object()) return 0;
    const auto found = object.find(std::string(name));
    if (found == object.end()) return 0;
    try {
        if (found->is_number_unsigned()) return found->get<std::size_t>();
        if (found->is_number_integer()) {
            const auto value = found->get<std::int64_t>();
            return value >= 0 ? static_cast<std::size_t>(value) : 0;
        }
    } catch (const nlohmann::json::exception&) {
    }
    return 0;
}

int port_field(const nlohmann::json& object,
               std::string_view name) {
    const std::size_t value = count_field(object, name);
    return value <= 65535U ? static_cast<int>(value) : 0;
}

std::vector<std::string> render_box(const TopologyBox& n,
                                    const GlyphSet& g) {
    constexpr std::size_t kInnerW = static_cast<std::size_t>(kBoxW) - 2U;
    auto bar = [&](const char* l, const char* r) {
        std::string out = l;
        for (std::size_t i = 0; i < kInnerW; ++i) out += g.horiz;
        out += r;
        return out;
    };
    auto row = [&](std::string_view body) {
        std::string padded = fit(body, kInnerW, g.ellipsis);
        padded.append(kInnerW - glyph_length(padded), ' ');
        return std::string(g.vert) + padded + g.vert;
    };

    std::vector<std::string> out;
    out.push_back(bar(g.tl, g.tr));
    out.push_back(row(n.is_self
        ? "* " + fit(n.display, kInnerW - 2U, g.ellipsis)
        : n.display));
    out.push_back(row(n.addr));
    out.push_back(row(n.is_self
        ? std::to_string(n.local_endpoint_count) + " endpoints"
        : std::to_string(n.active_channel_count) + " ch " + n.state));
    out.push_back(bar(g.bl, g.br));
    return out;
}

// 2D character canvas with glyph-aware overwrite. Each cell stores a
// single Unicode glyph as a std::string (multi-byte safe).
class Canvas {
public:
    Canvas(int w, int h)
        : w_(std::max(0, w)),
          h_(std::max(0, h)),
          cells_(static_cast<std::size_t>(w_) *
                     static_cast<std::size_t>(h_),
                 " ") {}

    void put(int x, int y, const std::string& glyph) {
        if (x < 0 || y < 0 || x >= w_ || y >= h_) return;
        cells_[index(x, y)] = glyph;
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
                out << cells_[index(x, y)];
            }
            out << '\n';
        }
    }

private:
    std::size_t index(int x, int y) const noexcept {
        return static_cast<std::size_t>(y) *
                   static_cast<std::size_t>(w_) +
               static_cast<std::size_t>(x);
    }

    int w_, h_;
    std::vector<std::string> cells_;
};

}  // namespace

void render_topology(const std::vector<TopologyBox>& nodes, bool ascii, std::ostream& out) {
    const GlyphSet& g = ascii ? kAsciiGlyphs : kUnicodeGlyphs;
    if (nodes.empty()) {
        out << "(no nodes)\n";
        return;
    }
    const TopologyBox& self = nodes[0];
    std::vector<TopologyBox> peers(nodes.begin() + 1, nodes.end());

    // Standalone self — just the box.
    if (peers.empty()) {
        auto box = render_box(self, g);
        for (const auto& line : box) out << line << '\n';
        out << "(federation disabled or no peers)\n";
        return;
    }

    // 7+ peers: table fallback. The drawing math gets ugly past 6
    // and the result isn't more useful than a sorted list.
    if (peers.size() > kMaxDrawnPeers) {
        auto self_box = render_box(self, g);
        for (const auto& line : self_box) out << line << '\n';
        out << '\n';
        out << "Peers (" << peers.size() << "):\n";
        for (const auto& p : peers) {
            out << "  - " << p.display
                << "  " << p.active_channel_count << " ch"
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
    c.place_box(self_x0, self_y, render_box(self, g));

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
        c.place_box(peer_x, peers_y, render_box(peers[0], g));
        c.put(peer_mid, peers_y, g.top_tee);
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
            // The self spoke arrives from above, so this is a bottom tee until
            // a peer spoke also leaves the same column below.
            c.put(self_mid_x, connect_y, g.bot_tee);
        }
        for (int i = 0; i < peer_count; ++i) {
            const int px = peer_strip_x0 + i * (kBoxW + gap);
            const int pmid = px + kBoxW / 2;
            // Start below the bus row: drawing through it would overwrite the
            // corner and join glyphs placed above with a plain vertical.
            c.draw_vline(pmid, connect_y + 1, peers_y - 1, g.vert);
            // Connector at the bus row: ┬ unless this column is also an
            // endpoint of the bus or the self spoke, whose glyphs already fit.
            if (pmid == self_mid_x) {
                c.put(pmid, connect_y, g.cross);
            } else if (pmid != left_mid && pmid != right_mid) {
                c.put(pmid, connect_y, g.top_tee);
            }
            c.place_box(
                px, peers_y,
                render_box(peers[static_cast<std::size_t>(i)], g));
            c.put(pmid, peers_y, g.top_tee);  // joins the peer's top border
        }
    }
    c.print(out);
}

std::vector<TopologyBox> topology_boxes(const nlohmann::json& topology) {
    std::vector<TopologyBox> boxes;

    const auto& self_json = topology.contains("self") && topology["self"].is_object()
        ? topology["self"] : nlohmann::json::object();
    TopologyBox self;
    self.is_self = true;
    self.id = string_field(self_json, "server_id");
    const std::string self_name = string_field(self_json, "server_name");
    self.display = self_name.empty() ? self.id : self_name;
    if (self.display.empty()) self.display = "(local)";
    const int port = port_field(self_json, "listen_port");
    self.addr = port > 0 ? ("local:" + std::to_string(port)) : "local";
    self.local_endpoint_count = count_field(self_json, "local_endpoints");
    self.state = "self";
    boxes.push_back(std::move(self));

    if (!topology.contains("nodes") || !topology["nodes"].is_array()) {
        return boxes;
    }
    for (const auto& peer : topology["nodes"]) {
        if (!peer.is_object()) continue;
        TopologyBox box;
        box.id = string_field(peer, "peer_id", "?");
        box.display = box.id;
        box.active_channel_count = count_field(peer, "channels_active");
        box.state = bool_field(peer, "ready")
            ? "ready" : string_field(peer, "state", "?");
        box.error = sanitize_federation_public_error(
            string_field(peer, "last_error"));
        if (!box.error.empty() && box.state != "ready") {
            box.state = "error";
        }
        // A configured peer reports where it is dialed; one whose entry failed
        // to parse has no configuration object and keeps an empty address.
        if (peer.contains("configuration") && peer["configuration"].is_object()) {
            const auto& configuration = peer["configuration"];
            const std::string host = string_field(configuration, "host");
            const int peer_port = port_field(configuration, "port");
            if (!host.empty() && peer_port > 0) {
                box.addr = format_federation_host_port(host, peer_port);
            }
        }
        boxes.push_back(std::move(box));
    }
    return boxes;
}

}  // namespace yume::server
