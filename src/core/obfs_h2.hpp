/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "core/crypto.hpp"

namespace yume::obfs {

struct H2EncodeParams {
    std::uint32_t padding_mean{24};
    std::uint32_t padding_max{200};
    std::uint32_t max_data_payload{16384};
    // Per-call flow-control budget (the lesser of the conn-level and
    // per-stream send window the peer has granted us; RFC 7540 §6.9).
    // encode_data_frames will never emit more than `send_window`
    // payload bytes across all DATA frames in the returned buffer; if
    // the input is larger, the tail is dropped. Default (UINT32_MAX)
    // means "no flow-control limit" — appropriate when the caller has
    // not opted into window tracking.
    std::uint32_t send_window{0xFFFFFFFFu};
};

// Stateful HPACK encoder (RFC 7541). Real browsers (Chrome 131+,
// Firefox 133) emit literal headers with the "incremental indexing"
// opcode (0x40 prefix) so they accrete into the dynamic table on
// first use, then reference by index on subsequent HEADERS frames.
// The pre-1.x encoder always emitted "literal without indexing"
// (0x00 prefix), which is RFC-conformant but visibly not what a
// browser sends. This class lets the carrier handshake emit the
// browser-shaped opcode, maintain a per-connection dynamic table,
// and honor SETTINGS_HEADER_TABLE_SIZE changes from the peer
// (RFC 7541 §4.2 + §6.3 size-update opcode).
//
// The encoder is stateful but pure: every method writes into the
// caller's buffer. The lifetime of a HpackEncoder matches one H2
// connection's worth of HEADERS blocks; if we ever start emitting
// HEADERS more than once per connection (we don't today, but the
// fake-h2 path could), the same encoder must be reused so the
// dynamic table accumulates correctly.
class HpackEncoder {
public:
    HpackEncoder();

    // Latch the peer's SETTINGS_HEADER_TABLE_SIZE. Evicts to fit if
    // the new max is smaller than what we currently have. Marks the
    // encoder so the next emit_size_update_if_needed() call writes
    // the §6.3 size-update opcode at the start of the HEADERS block.
    void set_peer_max_table_size(std::uint32_t new_max);

    // Write a size-update opcode (RFC 7541 §6.3) to `out` IF the
    // peer's max table size changed since the last block. MUST be
    // called once at the start of each HEADERS payload (before the
    // first emit_*) so the decoder applies the new max before
    // interpreting any indexed references.
    void emit_size_update_if_needed(std::vector<std::uint8_t>& out);

    // §6.1: Indexed header (1xxxxxxx). idx is a 1-based index into
    // the combined static (1..61) + dynamic (62..) table. Does not
    // touch the dynamic table.
    void emit_indexed(std::vector<std::uint8_t>& out, std::uint16_t idx);

    // §6.2.1: Literal Header Field with Incremental Indexing
    // (01xxxxxx). `name_index` references a static-table name
    // (1..61) or 0 to mean "name is literal" (in which case `name`
    // must be supplied). The (resolved_name, value) pair is added
    // to the dynamic table — possibly evicting older entries to fit.
    void emit_literal_with_indexing(std::vector<std::uint8_t>& out,
                                    std::uint16_t name_index,
                                    std::string_view name,
                                    std::string_view value);

    // §6.2.2: Literal Header Field without Indexing (0000xxxx).
    // Same shape as the old append_hpack_literal_indexed_name; kept
    // for headers that legitimately should NOT enter the dynamic
    // table (e.g. one-shot path tokens we don't want the peer
    // caching). Does not touch the dynamic table.
    void emit_literal_without_indexing(std::vector<std::uint8_t>& out,
                                       std::uint16_t name_index,
                                       std::string_view value);

    // Diagnostics — exposed for tests.
    std::uint32_t dyn_table_size_bytes() const { return dyn_table_size_; }
    std::size_t   dyn_table_entry_count() const { return dyn_table_.size(); }
    std::uint32_t signaled_max_table_size() const { return signaled_max_table_size_; }
    std::uint32_t peer_max_table_size() const     { return peer_max_table_size_; }

private:
    // §4.1: entry size = name.size() + value.size() + 32 octets.
    void add_to_dyn_table(std::string name, std::string value);
    void evict_to_size(std::uint32_t target);

    std::deque<std::pair<std::string, std::string>> dyn_table_;
    std::uint32_t dyn_table_size_{0};
    std::uint32_t peer_max_table_size_{4096};
    std::uint32_t signaled_max_table_size_{4096};
    bool pending_size_update_{false};
};

crypto::Bytes encode_client_handshake(std::string_view sni,
                                      const std::string& path,
                                      std::string_view user_agent);

crypto::Bytes encode_server_handshake();

crypto::Bytes encode_data_frames(const std::uint8_t* data,
                                 std::size_t len,
                                 const H2EncodeParams& params);

crypto::Bytes encode_ping_ack(const std::uint8_t opaque[8]);
crypto::Bytes encode_window_update(std::uint32_t stream_id, std::uint32_t increment);
crypto::Bytes encode_settings_ack();

class H2InboundDecoder {
public:
    enum class State {
        kAwaitingPreface,
        kAwaitingHeaders,
        kCarrierActive,
    };

    explicit H2InboundDecoder(bool server_side);

    void feed(const std::uint8_t* data, std::size_t len);

    bool consume_decoded(std::uint8_t* out, std::size_t want);
    std::size_t decoded_available() const;

    bool client_preface_seen() const { return preface_seen_; }
    bool path_extracted() const { return !extracted_path_.empty(); }
    bool headers_seen() const { return headers_seen_; }
    const std::string& extracted_path() const { return extracted_path_; }
    const std::string& extracted_authority() const { return extracted_authority_; }
    std::size_t inbound_buffered() const { return inbound_buf_.size(); }
    void drain_inbound_buffer(std::vector<std::uint8_t>* out);

    void mark_carrier_active();
    State state() const { return state_; }

    crypto::Bytes take_outbound_replies();

    std::string error() const { return error_; }
    bool failed() const { return !error_.empty(); }

    // Peer-advertised HTTP/2 SETTINGS values (RFC 7540 §6.5.2).
    // Updated from incoming SETTINGS frames; default to the protocol
    // defaults until a peer SETTINGS arrives. Callers thread
    // peer_max_frame_size() into H2EncodeParams::max_data_payload so
    // outbound DATA frames stay inside the peer's advertised limit —
    // a peer that lowered MAX_FRAME_SIZE and saw an oversize DATA
    // would correctly flag a protocol violation.
    std::uint32_t peer_header_table_size() const   { return peer_header_table_size_; }
    std::uint32_t peer_max_concurrent_streams() const { return peer_max_concurrent_streams_; }
    std::uint32_t peer_initial_window_size() const { return peer_initial_window_size_; }
    std::uint32_t peer_max_frame_size() const      { return peer_max_frame_size_; }
    std::uint32_t peer_max_header_list_size() const { return peer_max_header_list_size_; }
    bool          peer_settings_seen() const       { return peer_settings_seen_; }

    // Send-side flow control (RFC 7540 §6.9). These track the credit
    // the peer has granted US to send DATA: WINDOW_UPDATE adds,
    // outgoing DATA debits, SETTINGS_INITIAL_WINDOW_SIZE deltas apply
    // to every per-stream window we know about (§6.9.2).
    //
    // Stored as int64_t because windows can validly go transiently
    // negative after a SETTINGS shrink. on_local_data_sent should not
    // be called while a window is <= 0 — the caller is responsible
    // for stalling. Initial values per spec: 65535 conn-level, and
    // peer_initial_window_size() per-stream at first-touch (lazy
    // init).
    std::int64_t conn_send_window() const { return conn_send_window_; }
    std::int64_t stream_send_window(std::uint32_t stream_id) const;
    void on_local_data_sent(std::uint32_t stream_id, std::uint32_t bytes);

private:
    void process_inbound();
    bool parse_one_frame(std::size_t* consumed);
    void handle_headers_block(const std::uint8_t* block, std::size_t len);
    void handle_data_payload(const std::uint8_t* payload, std::size_t len, std::uint8_t flags);
    void enqueue_reply(const crypto::Bytes& bytes);

    bool server_side_{true};
    State state_{State::kAwaitingPreface};
    bool preface_seen_{false};
    bool headers_seen_{false};
    std::vector<std::uint8_t> inbound_buf_;
    std::vector<std::uint8_t> decoded_buf_;
    std::vector<std::uint8_t> outbound_replies_;
    std::string extracted_path_;
    std::string extracted_authority_;
    std::string error_;

    // Peer SETTINGS, initialised to RFC 7540 §6.5.2 defaults. Updated
    // when a non-ACK SETTINGS frame arrives via parse_one_frame.
    std::uint32_t peer_header_table_size_{4096};
    std::uint32_t peer_max_concurrent_streams_{0xFFFFFFFFu};
    std::uint32_t peer_initial_window_size_{65535};
    std::uint32_t peer_max_frame_size_{16384};
    std::uint32_t peer_max_header_list_size_{0xFFFFFFFFu};
    bool peer_settings_seen_{false};

    // Flow-control credit the peer has granted us. conn_send_window_
    // is the connection-level credit (init 65535 per RFC). The map
    // is per-stream credit, lazily populated on first touch — entries
    // are added when a WINDOW_UPDATE arrives for an unseen stream or
    // when on_local_data_sent is called for one. The
    // peer_initial_window_size_ delta-apply in handle_settings_value
    // walks every map entry, never the (unbounded) full stream-id
    // space.
    std::int64_t conn_send_window_{65535};
    mutable std::unordered_map<std::uint32_t, std::int64_t> stream_send_windows_;
    // Helper invoked from the SETTINGS handler when
    // peer_initial_window_size_ changes. Applies the (new - old)
    // delta to every stream window currently in the map per
    // §6.9.2. Out-of-range results are not an error — they're
    // documented spec behaviour and resolved by a future
    // WINDOW_UPDATE.
    void apply_initial_window_delta(std::int64_t delta);
};

}  // namespace yume::obfs
