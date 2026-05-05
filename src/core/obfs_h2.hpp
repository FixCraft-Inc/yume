/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "core/crypto.hpp"

namespace yume::obfs {

struct H2EncodeParams {
    std::uint32_t padding_mean{24};
    std::uint32_t padding_max{200};
    std::uint32_t max_data_payload{16384};
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
};

}  // namespace yume::obfs
