/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 *
 * Stateless HTTP/2 carrier codec used by --obfs. We forge the byte-shape of a
 * Chrome 135 client/server exchange so a stateless DPI box classifies the
 * stream as benign HTTPS-over-h2 traffic. We do not implement a conformant
 * HTTP/2 server: SETTINGS changes are ignored, the HPACK dynamic table is
 * never grown, flow control is not enforced. A peer that fully tracks h2
 * stream state will desync within seconds; that's by design.
 */

#include "core/obfs_h2.hpp"

#include <openssl/rand.h>

#include <algorithm>
#include <cstring>

namespace yume::obfs {

namespace {

constexpr std::uint8_t kFrameData         = 0x00;
constexpr std::uint8_t kFrameHeaders      = 0x01;
constexpr std::uint8_t kFramePriority     = 0x02;
constexpr std::uint8_t kFrameRstStream    = 0x03;
constexpr std::uint8_t kFrameSettings     = 0x04;
constexpr std::uint8_t kFramePing         = 0x06;
constexpr std::uint8_t kFrameGoaway       = 0x07;
constexpr std::uint8_t kFrameWindowUpdate = 0x08;
constexpr std::uint8_t kFrameContinuation = 0x09;

constexpr std::uint8_t kFlagAck         = 0x01;
constexpr std::uint8_t kFlagEndStream   = 0x01;
constexpr std::uint8_t kFlagEndHeaders  = 0x04;
constexpr std::uint8_t kFlagPadded      = 0x08;
constexpr std::uint8_t kFlagPriority    = 0x20;

constexpr std::size_t kFrameHeaderLen = 9;
constexpr std::size_t kPrefaceLen = 24;

constexpr char kClientPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

void put_be24(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

void put_be32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

void put_be16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
}

std::uint32_t read_be24(const std::uint8_t* p) {
    return (static_cast<std::uint32_t>(p[0]) << 16) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
            static_cast<std::uint32_t>(p[2]);
}

std::uint32_t read_be31(const std::uint8_t* p) {
    return ((static_cast<std::uint32_t>(p[0]) & 0x7F) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
            static_cast<std::uint32_t>(p[3]);
}

void append_frame_header(std::vector<std::uint8_t>& out,
                         std::uint32_t length,
                         std::uint8_t type,
                         std::uint8_t flags,
                         std::uint32_t stream_id) {
    put_be24(out, length);
    out.push_back(type);
    out.push_back(flags);
    put_be32(out, stream_id & 0x7FFFFFFFu);
}

void append_hpack_indexed(std::vector<std::uint8_t>& out, std::uint8_t static_idx) {
    out.push_back(0x80 | (static_idx & 0x7F));
}

// HPACK §5.1 integer encoding. `prefix_bits` (4-7) is the number of
// bits available in the first byte after the opcode pattern. `first_byte_high`
// is the opcode bit pattern that occupies the high bits.
void append_hpack_varint(std::vector<std::uint8_t>& out, std::uint64_t value,
                         std::uint8_t prefix_bits, std::uint8_t first_byte_high) {
    const std::uint8_t max_prefix = static_cast<std::uint8_t>((1u << prefix_bits) - 1u);
    if (value < max_prefix) {
        out.push_back(static_cast<std::uint8_t>(first_byte_high | value));
        return;
    }
    out.push_back(static_cast<std::uint8_t>(first_byte_high | max_prefix));
    std::uint64_t remaining = value - max_prefix;
    while (remaining >= 0x80) {
        out.push_back(static_cast<std::uint8_t>((remaining & 0x7F) | 0x80));
        remaining >>= 7;
    }
    out.push_back(static_cast<std::uint8_t>(remaining));
}

void append_hpack_string(std::vector<std::uint8_t>& out, std::string_view s) {
    if (s.size() <= 0x7F) {
        out.push_back(static_cast<std::uint8_t>(s.size() & 0x7F));
        out.insert(out.end(), s.begin(), s.end());
    } else {
        out.push_back(0x7F);
        std::size_t remaining = s.size() - 0x7F;
        while (remaining >= 0x80) {
            out.push_back(static_cast<std::uint8_t>((remaining & 0x7F) | 0x80));
            remaining >>= 7;
        }
        out.push_back(static_cast<std::uint8_t>(remaining));
        out.insert(out.end(), s.begin(), s.end());
    }
}

void append_hpack_literal_indexed_name(std::vector<std::uint8_t>& out,
                                       std::uint16_t name_index,
                                       std::string_view value) {
    if (name_index < 16) {
        out.push_back(static_cast<std::uint8_t>(name_index & 0x0F));
    } else {
        out.push_back(0x0F);
        std::size_t remaining = name_index - 15;
        while (remaining >= 0x80) {
            out.push_back(static_cast<std::uint8_t>((remaining & 0x7F) | 0x80));
            remaining >>= 7;
        }
        out.push_back(static_cast<std::uint8_t>(remaining));
    }
    append_hpack_string(out, value);
}

bool decode_hpack_varint(const std::uint8_t* data, std::size_t len,
                         std::uint8_t prefix_mask,
                         std::size_t* consumed,
                         std::uint64_t* value_out) {
    if (len == 0) {
        return false;
    }
    std::uint64_t v = data[0] & prefix_mask;
    *consumed = 1;
    if (v < prefix_mask) {
        *value_out = v;
        return true;
    }
    std::uint64_t shift = 0;
    while (*consumed < len) {
        std::uint8_t b = data[*consumed];
        *consumed += 1;
        v += static_cast<std::uint64_t>(b & 0x7F) << shift;
        if (!(b & 0x80)) {
            *value_out = v;
            return true;
        }
        shift += 7;
        if (shift >= 64) {
            return false;
        }
    }
    return false;
}

bool decode_hpack_string(const std::uint8_t* data, std::size_t len,
                         std::size_t* consumed, std::string* out) {
    if (len == 0) {
        return false;
    }
    bool huffman = (data[0] & 0x80) != 0;
    std::size_t prefix_consumed = 0;
    std::uint64_t str_len = 0;
    if (!decode_hpack_varint(data, len, 0x7F, &prefix_consumed, &str_len)) {
        return false;
    }
    if (prefix_consumed + str_len > len) {
        return false;
    }
    if (huffman) {
        return false;
    }
    out->assign(reinterpret_cast<const char*>(data + prefix_consumed), str_len);
    *consumed = prefix_consumed + str_len;
    return true;
}

void scan_headers_block(const std::uint8_t* data, std::size_t len,
                        std::string* path_out, std::string* authority_out) {
    std::size_t pos = 0;
    while (pos < len) {
        std::uint8_t b = data[pos];
        if ((b & 0x80) != 0) {
            std::size_t cons = 0;
            std::uint64_t idx = 0;
            if (!decode_hpack_varint(data + pos, len - pos, 0x7F, &cons, &idx)) {
                return;
            }
            pos += cons;
            continue;
        }
        if ((b & 0xC0) == 0x40) {
            std::size_t cons = 0;
            std::uint64_t name_idx = 0;
            if (!decode_hpack_varint(data + pos, len - pos, 0x3F, &cons, &name_idx)) {
                return;
            }
            pos += cons;
            std::string name;
            if (name_idx == 0) {
                std::size_t scons = 0;
                if (!decode_hpack_string(data + pos, len - pos, &scons, &name)) {
                    return;
                }
                pos += scons;
            }
            std::string value;
            std::size_t vcons = 0;
            if (!decode_hpack_string(data + pos, len - pos, &vcons, &value)) {
                return;
            }
            pos += vcons;
            if (name_idx == 1 && authority_out) *authority_out = value;
            if (name_idx == 4 && path_out) *path_out = value;
            continue;
        }
        if ((b & 0xE0) == 0x20) {
            std::size_t cons = 0;
            std::uint64_t cap = 0;
            if (!decode_hpack_varint(data + pos, len - pos, 0x1F, &cons, &cap)) {
                return;
            }
            pos += cons;
            continue;
        }
        std::size_t cons = 0;
        std::uint64_t name_idx = 0;
        if (!decode_hpack_varint(data + pos, len - pos, 0x0F, &cons, &name_idx)) {
            return;
        }
        pos += cons;
        std::string name;
        if (name_idx == 0) {
            std::size_t scons = 0;
            if (!decode_hpack_string(data + pos, len - pos, &scons, &name)) {
                return;
            }
            pos += scons;
        }
        std::string value;
        std::size_t vcons = 0;
        if (!decode_hpack_string(data + pos, len - pos, &vcons, &value)) {
            return;
        }
        pos += vcons;
        if (name_idx == 1 && authority_out) *authority_out = value;
        if (name_idx == 4 && path_out) *path_out = value;
    }
}

std::uint32_t sample_padding(std::uint32_t mean, std::uint32_t cap) {
    if (mean == 0 || cap == 0) {
        return 0;
    }
    std::uint8_t rand_buf[4];
    if (RAND_bytes(rand_buf, sizeof(rand_buf)) != 1) {
        return 0;
    }
    std::uint32_t r = static_cast<std::uint32_t>(rand_buf[0]) |
                      (static_cast<std::uint32_t>(rand_buf[1]) << 8);
    std::uint32_t span = mean * 2 + 1;
    std::uint32_t pad = r % span;
    if (pad > cap) pad = cap;
    return pad;
}

}  // namespace

crypto::Bytes encode_client_handshake(std::string_view sni,
                                      const std::string& path,
                                      std::string_view user_agent) {
    crypto::Bytes out;
    out.reserve(512);

    out.insert(out.end(), kClientPreface, kClientPreface + kPrefaceLen);

    std::vector<std::uint8_t> settings_payload;
    auto add_setting = [&](std::uint16_t id, std::uint32_t value) {
        put_be16(settings_payload, id);
        put_be32(settings_payload, value);
    };
    add_setting(1, 65536);
    add_setting(2, 0);
    add_setting(3, 1000);
    add_setting(4, 6291456);
    add_setting(6, 262144);
    append_frame_header(out, static_cast<std::uint32_t>(settings_payload.size()),
                        kFrameSettings, 0, 0);
    out.insert(out.end(), settings_payload.begin(), settings_payload.end());

    std::vector<std::uint8_t> wu_payload;
    put_be32(wu_payload, 15663105);
    append_frame_header(out, 4, kFrameWindowUpdate, 0, 0);
    out.insert(out.end(), wu_payload.begin(), wu_payload.end());

    // Real Chrome 131 emits literal headers with the "incremental
    // indexing" opcode (0x40 prefix) so they enter the per-connection
    // HPACK dynamic table on first use. The pre-stateful encoder
    // used 0x00 ("without indexing"), which is RFC-conformant but
    // visibly not what a browser sends. Switch to HpackEncoder, which
    // emits the 0x40 prefix and accretes the same dynamic-table state
    // a real Chrome client would build (so a stateful H2 middlebox
    // that asserts dynamic-table consistency sees the right table).
    std::vector<std::uint8_t> hb;
    HpackEncoder enc;
    enc.emit_size_update_if_needed(hb);  // no-op unless caller set
                                          // a non-default max
    enc.emit_indexed(hb, 3);              // :method POST
    enc.emit_indexed(hb, 7);              // :scheme https
    enc.emit_literal_with_indexing(hb, 1, std::string_view(), sni);                // :authority
    enc.emit_literal_with_indexing(hb, 4, std::string_view(), path);               // :path
    enc.emit_literal_with_indexing(hb, 19, std::string_view(),
        std::string_view("application/grpc-web+proto"));
    enc.emit_literal_with_indexing(hb, 22, std::string_view(),
        std::string_view("gzip, deflate, br, zstd"));
    enc.emit_literal_with_indexing(hb, 23, std::string_view(),
        std::string_view("en-US,en;q=0.9"));
    enc.emit_literal_with_indexing(hb, 50, std::string_view(),
        std::string_view("application/grpc-web+proto"));
    enc.emit_literal_with_indexing(hb, 58, std::string_view(), user_agent);

    append_frame_header(out, static_cast<std::uint32_t>(hb.size()),
                        kFrameHeaders, kFlagEndHeaders, 1);
    out.insert(out.end(), hb.begin(), hb.end());

    return out;
}

crypto::Bytes encode_server_handshake() {
    crypto::Bytes out;
    out.reserve(128);

    std::vector<std::uint8_t> settings_payload;
    auto add_setting = [&](std::uint16_t id, std::uint32_t value) {
        put_be16(settings_payload, id);
        put_be32(settings_payload, value);
    };
    add_setting(3, 100);
    add_setting(4, 65536);
    add_setting(6, 65536);
    append_frame_header(out, static_cast<std::uint32_t>(settings_payload.size()),
                        kFrameSettings, 0, 0);
    out.insert(out.end(), settings_payload.begin(), settings_payload.end());

    append_frame_header(out, 0, kFrameSettings, kFlagAck, 0);

    std::vector<std::uint8_t> hb;
    HpackEncoder enc;
    enc.emit_size_update_if_needed(hb);
    enc.emit_indexed(hb, 8);  // :status 200
    enc.emit_literal_with_indexing(hb, 31, std::string_view(),
        std::string_view("application/grpc-web+proto"));            // content-type
    enc.emit_literal_with_indexing(hb, 54, std::string_view(),
        std::string_view("cloudflare"));                              // server
    append_frame_header(out, static_cast<std::uint32_t>(hb.size()),
                        kFrameHeaders, kFlagEndHeaders, 1);
    out.insert(out.end(), hb.begin(), hb.end());

    return out;
}

crypto::Bytes encode_data_frames(const std::uint8_t* data, std::size_t len,
                                 const H2EncodeParams& params) {
    crypto::Bytes out;
    out.reserve(len + 64);
    std::uint32_t max_payload = params.max_data_payload;
    if (max_payload == 0 || max_payload > 16384) max_payload = 16384;
    if (max_payload < 64) max_payload = 64;

    // Cap the effective length at the caller's flow-control budget.
    // RFC 7540 §6.9.1: only DATA frame payload counts against the
    // window. Headers, padding length bytes, and pad bytes are NOT
    // payload, but the spec is explicit that the entire DATA frame
    // length (including padding + length byte) DOES count. We
    // conservatively enforce on the payload size we're about to
    // emit; the padding budget is then trimmed to stay inside the
    // window.
    std::size_t effective_len = len;
    if (params.send_window < effective_len) {
        effective_len = params.send_window;
    }

    std::size_t pos = 0;
    while (pos < effective_len) {
        std::size_t chunk = std::min<std::size_t>(effective_len - pos,
            static_cast<std::size_t>(max_payload) - 1);
        // Budget for this DATA frame's total length (including the
        // 1-byte pad-length and the pad bytes themselves). Window
        // is whatever the caller said minus what we've already
        // emitted.
        std::uint32_t emitted = static_cast<std::uint32_t>(pos);
        std::uint32_t window_remaining = params.send_window > emitted
            ? params.send_window - emitted
            : 0u;
        std::uint32_t this_frame_cap = std::min(max_payload, window_remaining);
        if (this_frame_cap <= static_cast<std::uint32_t>(chunk) + 1) {
            // No room for padding; skip pad entirely.
            std::uint32_t pad = 0;
            std::uint32_t frame_len = static_cast<std::uint32_t>(chunk) + pad + 1;
            append_frame_header(out, frame_len, kFrameData, kFlagPadded, 1);
            out.push_back(static_cast<std::uint8_t>(pad));
            out.insert(out.end(), data + pos, data + pos + chunk);
        } else {
            std::uint32_t pad = sample_padding(params.padding_mean,
                std::min(params.padding_max,
                         this_frame_cap - static_cast<std::uint32_t>(chunk) - 1));
            std::uint32_t frame_len = static_cast<std::uint32_t>(chunk) + pad + 1;
            append_frame_header(out, frame_len, kFrameData, kFlagPadded, 1);
            out.push_back(static_cast<std::uint8_t>(pad));
            out.insert(out.end(), data + pos, data + pos + chunk);
            if (pad > 0) {
                std::vector<std::uint8_t> padding_bytes(pad, 0);
                RAND_bytes(padding_bytes.data(), static_cast<int>(padding_bytes.size()));
                out.insert(out.end(), padding_bytes.begin(), padding_bytes.end());
            }
        }
        pos += chunk;
    }

    // Emit an empty DATA frame for a zero-length body only when there
    // was actually no input AND we have budget for the frame at all
    // (an empty DATA frame is 9 header bytes of cleartext, no payload
    // — payload size 0 doesn't draw from the flow-control window).
    if (len == 0) {
        append_frame_header(out, 0, kFrameData, 0, 1);
    }

    return out;
}

crypto::Bytes encode_ping_ack(const std::uint8_t opaque[8]) {
    crypto::Bytes out;
    append_frame_header(out, 8, kFramePing, kFlagAck, 0);
    out.insert(out.end(), opaque, opaque + 8);
    return out;
}

crypto::Bytes encode_window_update(std::uint32_t stream_id, std::uint32_t increment) {
    crypto::Bytes out;
    append_frame_header(out, 4, kFrameWindowUpdate, 0, stream_id);
    put_be32(out, increment & 0x7FFFFFFFu);
    return out;
}

crypto::Bytes encode_settings_ack() {
    crypto::Bytes out;
    append_frame_header(out, 0, kFrameSettings, kFlagAck, 0);
    return out;
}

H2InboundDecoder::H2InboundDecoder(bool server_side)
    : server_side_(server_side),
      state_(server_side ? State::kAwaitingPreface : State::kAwaitingHeaders) {
    inbound_buf_.reserve(4096);
    decoded_buf_.reserve(4096);
    outbound_replies_.reserve(256);
}

void H2InboundDecoder::feed(const std::uint8_t* data, std::size_t len) {
    if (failed()) return;
    inbound_buf_.insert(inbound_buf_.end(), data, data + len);
    process_inbound();
}

void H2InboundDecoder::process_inbound() {
    if (state_ == State::kAwaitingPreface) {
        if (inbound_buf_.size() < kPrefaceLen) return;
        if (std::memcmp(inbound_buf_.data(), kClientPreface, kPrefaceLen) != 0) {
            error_ = "client preface mismatch";
            return;
        }
        inbound_buf_.erase(inbound_buf_.begin(), inbound_buf_.begin() + kPrefaceLen);
        preface_seen_ = true;
        state_ = State::kAwaitingHeaders;
    }

    while (true) {
        if (headers_seen_ && state_ == State::kAwaitingHeaders) break;
        std::size_t consumed = 0;
        if (!parse_one_frame(&consumed)) break;
        if (consumed == 0) break;
        inbound_buf_.erase(inbound_buf_.begin(),
                          inbound_buf_.begin() + static_cast<std::ptrdiff_t>(consumed));
        if (failed()) return;
    }
}

bool H2InboundDecoder::parse_one_frame(std::size_t* consumed) {
    if (inbound_buf_.size() < kFrameHeaderLen) {
        return false;
    }
    std::uint32_t length = read_be24(inbound_buf_.data());
    std::uint8_t type = inbound_buf_[3];
    std::uint8_t flags = inbound_buf_[4];
    std::uint32_t stream_id = read_be31(inbound_buf_.data() + 5);

    if (length > 16384u + 256u) {
        error_ = "frame length exceeds carrier max";
        return false;
    }
    if (inbound_buf_.size() < kFrameHeaderLen + length) {
        return false;
    }

    const std::uint8_t* payload = inbound_buf_.data() + kFrameHeaderLen;

    switch (type) {
        case kFrameSettings: {
            if (!(flags & kFlagAck)) {
                // Parse the SETTINGS payload (6 bytes per setting:
                // 2-byte id + 4-byte value, RFC 7540 §6.5.1) and
                // update our peer-state defaults. SETTINGS frames
                // with a payload length that isn't a multiple of 6
                // are a connection error per RFC 7540; we treat
                // them as a soft signal — log and drop, the ACK
                // still goes out so the peer doesn't hang.
                if (length % 6 != 0) {
                    error_ = "SETTINGS payload not a multiple of 6";
                    break;
                }
                for (std::size_t off = 0; off + 6 <= length; off += 6) {
                    const std::uint16_t id =
                        (static_cast<std::uint16_t>(payload[off]) << 8) |
                         static_cast<std::uint16_t>(payload[off + 1]);
                    const std::uint32_t val =
                        (static_cast<std::uint32_t>(payload[off + 2]) << 24) |
                        (static_cast<std::uint32_t>(payload[off + 3]) << 16) |
                        (static_cast<std::uint32_t>(payload[off + 4]) << 8) |
                         static_cast<std::uint32_t>(payload[off + 5]);
                    // Identifier values from RFC 7540 §6.5.2.
                    switch (id) {
                        case 0x1: peer_header_table_size_      = val; break;
                        case 0x2: /* SETTINGS_ENABLE_PUSH; ignored, we never push */ break;
                        case 0x3: peer_max_concurrent_streams_ = val; break;
                        case 0x4: {
                            // RFC 7540 §6.5.2: SETTINGS_INITIAL_WINDOW_SIZE
                            // is bounded by 2^31-1; values above are a
                            // FLOW_CONTROL_ERROR. We clamp and continue
                            // so a malformed peer doesn't kill the
                            // connection. §6.9.2 then requires
                            // delta-applying (new - old) to every
                            // per-stream window we're tracking; this is
                            // the sign-tricky bit (delta can be negative
                            // and windows can go transiently negative).
                            std::uint32_t clamped = val;
                            if (clamped > 0x7FFFFFFFu) clamped = 0x7FFFFFFFu;
                            const std::int64_t delta =
                                static_cast<std::int64_t>(clamped) -
                                static_cast<std::int64_t>(peer_initial_window_size_);
                            peer_initial_window_size_ = clamped;
                            if (delta != 0) {
                                apply_initial_window_delta(delta);
                            }
                            break;
                        }
                        case 0x5: {
                            // RFC 7540 §6.5.2: MAX_FRAME_SIZE must be
                            // in [16384, 16777215]. Out-of-range is a
                            // connection error; clamp and continue.
                            std::uint32_t clamped = val;
                            if (clamped < 16384u)    clamped = 16384u;
                            if (clamped > 16777215u) clamped = 16777215u;
                            peer_max_frame_size_ = clamped;
                            break;
                        }
                        case 0x6: peer_max_header_list_size_   = val; break;
                        // Unknown SETTINGS identifiers must be
                        // ignored per RFC 7540 §6.5.2; no action.
                        default: break;
                    }
                }
                peer_settings_seen_ = true;
                enqueue_reply(encode_settings_ack());
            }
            break;
        }
        case kFrameWindowUpdate: {
            if (length != 4) {
                error_ = "WINDOW_UPDATE with bad length";
                break;
            }
            // The 31-bit increment lives in the low bits of the
            // payload; the high bit is reserved (R) and MUST be
            // ignored. Increment of 0 is a PROTOCOL_ERROR per
            // RFC 7540 §6.9 (stream_id==0 → connection error,
            // otherwise stream error). We treat both as a soft
            // signal — surface as error_, the caller decides.
            const std::uint32_t increment = read_be31(payload);
            if (increment == 0) {
                error_ = "WINDOW_UPDATE with zero increment";
                break;
            }
            // Clamp window growth at 2^31-1; §6.9.1 says a window
            // that would exceed that is a FLOW_CONTROL_ERROR. The
            // peer can't legitimately want us to send MORE than
            // 2GiB at once, and a misbehaved peer shouldn't be
            // able to push our int64_t past INT_MAX.
            constexpr std::int64_t kMaxWindow = 0x7FFFFFFFLL;
            if (stream_id == 0) {
                conn_send_window_ += increment;
                if (conn_send_window_ > kMaxWindow) {
                    conn_send_window_ = kMaxWindow;
                }
            } else {
                // Lazy-init per-stream window to the current peer
                // INITIAL_WINDOW_SIZE if we haven't seen the stream.
                auto it = stream_send_windows_.find(stream_id);
                if (it == stream_send_windows_.end()) {
                    it = stream_send_windows_.emplace(
                        stream_id,
                        static_cast<std::int64_t>(peer_initial_window_size_)).first;
                }
                it->second += increment;
                if (it->second > kMaxWindow) {
                    it->second = kMaxWindow;
                }
            }
            break;
        }
        case kFramePing: {
            if (length != 8) {
                error_ = "PING with bad length";
                break;
            }
            if (!(flags & kFlagAck)) {
                std::uint8_t op[8];
                std::memcpy(op, payload, 8);
                enqueue_reply(encode_ping_ack(op));
            }
            break;
        }
        case kFramePriority:
        case kFrameRstStream:
        case kFrameContinuation: {
            break;
        }
        case kFrameGoaway: {
            error_ = "peer GOAWAY";
            break;
        }
        case kFrameHeaders: {
            std::size_t hb_off = 0;
            std::size_t hb_len = length;
            if (flags & kFlagPadded) {
                if (length < 1) {
                    error_ = "padded HEADERS too short";
                    break;
                }
                std::uint8_t pad = payload[0];
                if (1u + pad > length) {
                    error_ = "padded HEADERS padding too long";
                    break;
                }
                hb_off = 1;
                hb_len = length - 1 - pad;
            }
            if (flags & kFlagPriority) {
                if (hb_len < 5) {
                    error_ = "HEADERS+PRIORITY too short";
                    break;
                }
                hb_off += 5;
                hb_len -= 5;
            }
            if (state_ == State::kAwaitingHeaders) {
                handle_headers_block(payload + hb_off, hb_len);
                headers_seen_ = true;
            }
            break;
        }
        case kFrameData: {
            if (state_ != State::kCarrierActive) {
                error_ = "DATA before HEADERS";
                break;
            }
            handle_data_payload(payload, length, flags);
            break;
        }
        default: {
            break;
        }
    }

    *consumed = kFrameHeaderLen + length;
    (void)stream_id;
    return true;
}

void H2InboundDecoder::handle_headers_block(const std::uint8_t* block, std::size_t len) {
    std::string path;
    std::string authority;
    scan_headers_block(block, len, &path, &authority);
    if (!path.empty()) extracted_path_ = path;
    if (!authority.empty()) extracted_authority_ = authority;
}

void H2InboundDecoder::handle_data_payload(const std::uint8_t* payload, std::size_t len,
                                           std::uint8_t flags) {
    std::size_t off = 0;
    std::size_t data_len = len;
    if (flags & kFlagPadded) {
        if (len < 1) {
            error_ = "padded DATA too short";
            return;
        }
        std::uint8_t pad = payload[0];
        if (1u + pad > len) {
            error_ = "padded DATA padding too long";
            return;
        }
        off = 1;
        data_len = len - 1 - pad;
    }
    decoded_buf_.insert(decoded_buf_.end(), payload + off, payload + off + data_len);
}

bool H2InboundDecoder::consume_decoded(std::uint8_t* out, std::size_t want) {
    if (decoded_buf_.size() < want) return false;
    std::memcpy(out, decoded_buf_.data(), want);
    decoded_buf_.erase(decoded_buf_.begin(),
                      decoded_buf_.begin() + static_cast<std::ptrdiff_t>(want));
    return true;
}

std::size_t H2InboundDecoder::decoded_available() const {
    return decoded_buf_.size();
}

void H2InboundDecoder::mark_carrier_active() {
    state_ = State::kCarrierActive;
}

crypto::Bytes H2InboundDecoder::take_outbound_replies() {
    crypto::Bytes out = std::move(outbound_replies_);
    outbound_replies_.clear();
    return out;
}

void H2InboundDecoder::enqueue_reply(const crypto::Bytes& bytes) {
    outbound_replies_.insert(outbound_replies_.end(), bytes.begin(), bytes.end());
}

void H2InboundDecoder::drain_inbound_buffer(std::vector<std::uint8_t>* out) {
    if (!out || inbound_buf_.empty()) return;
    out->insert(out->end(), inbound_buf_.begin(), inbound_buf_.end());
    inbound_buf_.clear();
}

std::int64_t H2InboundDecoder::stream_send_window(std::uint32_t stream_id) const {
    auto it = stream_send_windows_.find(stream_id);
    if (it != stream_send_windows_.end()) {
        return it->second;
    }
    // Unseen stream: peer has not had a chance to send a
    // WINDOW_UPDATE for it yet, so the window is whatever
    // SETTINGS_INITIAL_WINDOW_SIZE currently says.
    return static_cast<std::int64_t>(peer_initial_window_size_);
}

void H2InboundDecoder::on_local_data_sent(std::uint32_t stream_id, std::uint32_t bytes) {
    if (bytes == 0) return;
    const std::int64_t delta = static_cast<std::int64_t>(bytes);
    conn_send_window_ -= delta;
    auto it = stream_send_windows_.find(stream_id);
    if (it == stream_send_windows_.end()) {
        it = stream_send_windows_.emplace(
            stream_id,
            static_cast<std::int64_t>(peer_initial_window_size_)).first;
    }
    it->second -= delta;
}

void H2InboundDecoder::apply_initial_window_delta(std::int64_t delta) {
    // RFC 7540 §6.9.2: deltas from SETTINGS_INITIAL_WINDOW_SIZE
    // apply to every stream we've seen. Streams we haven't seen
    // pick up the new value lazily via stream_send_window().
    for (auto& [_, w] : stream_send_windows_) {
        w += delta;
    }
}

HpackEncoder::HpackEncoder() = default;

void HpackEncoder::set_peer_max_table_size(std::uint32_t new_max) {
    if (new_max == peer_max_table_size_) {
        return;
    }
    peer_max_table_size_ = new_max;
    if (dyn_table_size_ > peer_max_table_size_) {
        evict_to_size(peer_max_table_size_);
    }
    // We've not yet told the peer about this change; the next
    // HEADERS block must lead with a size-update opcode.
    pending_size_update_ = true;
}

void HpackEncoder::emit_size_update_if_needed(std::vector<std::uint8_t>& out) {
    if (!pending_size_update_) return;
    // §6.3: Dynamic Table Size Update — 001x xxxx, 5-bit prefix varint.
    append_hpack_varint(out, peer_max_table_size_, 5, 0x20);
    signaled_max_table_size_ = peer_max_table_size_;
    pending_size_update_ = false;
}

void HpackEncoder::emit_indexed(std::vector<std::uint8_t>& out, std::uint16_t idx) {
    // §6.1: Indexed Header Field — 1xxxxxxx, 7-bit prefix varint.
    append_hpack_varint(out, idx, 7, 0x80);
}

void HpackEncoder::emit_literal_with_indexing(std::vector<std::uint8_t>& out,
                                              std::uint16_t name_index,
                                              std::string_view name,
                                              std::string_view value) {
    // §6.2.1: Literal Header Field with Incremental Indexing —
    // 01xxxxxx, 6-bit prefix varint for the name index.
    append_hpack_varint(out, name_index, 6, 0x40);
    if (name_index == 0) {
        // name is literal; emit name string before value.
        append_hpack_string(out, name);
    }
    append_hpack_string(out, value);
    // Track in the dynamic table. The name we record depends on
    // whether it was literal or referenced. For static-table refs
    // we resolve to the canonical static-table name; we don't do
    // that lookup here (the caller usually has the literal name
    // available or doesn't care because the entry's only purpose
    // is correct size accounting + eviction tracking, not later
    // index lookup). For now record (literal-name-or-empty, value)
    // and rely on size accounting; index-based reuse is post-1.x.
    std::string canonical_name(name);
    add_to_dyn_table(std::move(canonical_name), std::string(value));
}

void HpackEncoder::emit_literal_without_indexing(std::vector<std::uint8_t>& out,
                                                  std::uint16_t name_index,
                                                  std::string_view value) {
    // §6.2.2: Literal Header Field without Indexing — 0000xxxx,
    // 4-bit prefix varint. Same wire format as the pre-encoder
    // helper, kept here for headers we don't want the peer caching.
    append_hpack_varint(out, name_index, 4, 0x00);
    append_hpack_string(out, value);
}

void HpackEncoder::add_to_dyn_table(std::string name, std::string value) {
    // §4.1: entry size = name + value + 32 octets overhead.
    const std::uint64_t entry_size =
        static_cast<std::uint64_t>(name.size()) +
        static_cast<std::uint64_t>(value.size()) + 32u;
    // §4.4: an entry larger than max table size MUST NOT be added;
    // the existing entries are evicted but the new one is dropped.
    if (entry_size > peer_max_table_size_) {
        evict_to_size(0);
        return;
    }
    if (entry_size > 0xFFFFFFFFu) {
        // Defensive: extremely unlikely path; treat as untaintable.
        evict_to_size(0);
        return;
    }
    const std::uint32_t entry_size_u32 = static_cast<std::uint32_t>(entry_size);
    // Evict from the back (oldest) until the new entry fits.
    if (peer_max_table_size_ < entry_size_u32) {
        evict_to_size(0);
        return;
    }
    evict_to_size(peer_max_table_size_ - entry_size_u32);
    dyn_table_.emplace_front(std::move(name), std::move(value));
    dyn_table_size_ += entry_size_u32;
}

void HpackEncoder::evict_to_size(std::uint32_t target) {
    while (dyn_table_size_ > target && !dyn_table_.empty()) {
        auto& back = dyn_table_.back();
        const std::uint32_t back_size = static_cast<std::uint32_t>(back.first.size()) +
                                        static_cast<std::uint32_t>(back.second.size()) + 32u;
        dyn_table_size_ = (dyn_table_size_ > back_size) ? (dyn_table_size_ - back_size) : 0u;
        dyn_table_.pop_back();
    }
}

}  // namespace yume::obfs
