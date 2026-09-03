/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * TransportCore inbound frame dispatch (handle_frame).
 */

#include "outbound/core.hpp"
#include "outbound/internal.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string_view>
#include <thread>

#include "core/security/inner_crypto.hpp"

namespace yume::outbound {

using namespace detail;

namespace {

constexpr std::size_t kMaxServerControlHostBytes = 255U;
constexpr std::array<std::string_view, 3> kServerControlOpenFields{
    "host", "port", "proto",
};

struct ServerControlOpen {
    std::string host;
    int port{0};
};

std::optional<ServerControlOpen> ParseServerControlOpen(
    const nlohmann::json& json) noexcept {
    try {
        if (!json.is_object() ||
            json.size() > kServerControlOpenFields.size()) {
            return std::nullopt;
        }
        for (auto it = json.begin(); it != json.end(); ++it) {
            if (std::find(kServerControlOpenFields.begin(),
                          kServerControlOpenFields.end(),
                          it.key()) == kServerControlOpenFields.end()) {
                return std::nullopt;
            }
        }
        if (!json.contains("host") || !json["host"].is_string() ||
            !json.contains("port")) {
            return std::nullopt;
        }
        const auto& host = json["host"].get_ref<const std::string&>();
        if (host.empty() || host.size() > kMaxServerControlHostBytes ||
            !std::all_of(host.begin(), host.end(), [](unsigned char byte) {
                return byte >= 0x21U && byte != 0x7fU;
            })) {
            return std::nullopt;
        }

        std::int64_t port = 0;
        if (json["port"].is_number_unsigned()) {
            const auto value = json["port"].get<std::uint64_t>();
            if (value > 65535U) return std::nullopt;
            port = static_cast<std::int64_t>(value);
        } else if (json["port"].is_number_integer()) {
            port = json["port"].get<std::int64_t>();
        } else {
            return std::nullopt;
        }
        if (port < 1 || port > 65535) return std::nullopt;

        if (json.contains("proto") &&
            (!json["proto"].is_string() ||
             json["proto"].get_ref<const std::string&>() != "tcp")) {
            return std::nullopt;
        }
        return ServerControlOpen{host, static_cast<int>(port)};
    } catch (...) {
        return std::nullopt;
    }
}

}  // namespace

void TransportCore::handle_frame(const protocol::Frame& frame,
                                 InboundCredit inbound_credit) {
    const uint8_t stream_id = frame.header.stream_id;
    // The AUTH v2 ratchet has already opened this frame and cleared its
    // sealed flag, so the payload here is plaintext.
    const Bytes* payload = &frame.payload;

    switch (frame.header.type) {
        case protocol::OPEN: {
            OpenHandler handler;
            ActivityHandler activity_handler;
            bool is_remote_listen = false;
            {
                std::lock_guard<std::mutex> lock(state_mu_);
                auto it_listen = pending_rlisten_.find(stream_id);
                if (it_listen != pending_rlisten_.end()) {
                    handler = std::move(it_listen->second);
                    pending_rlisten_.erase(it_listen);
                    is_remote_listen = true;
                } else {
                    auto it = pending_open_.find(stream_id);
                    if (it != pending_open_.end()) {
                        handler = std::move(it->second);
                        pending_open_.erase(it);
                    }
                }
                if (!is_remote_listen && (frame.header.flags & protocol::kFlagOpenOk) != 0) {
                    activity_handler = activity_handler_;
                }
            }
            if (handler) {
                const bool ok = (frame.header.flags & protocol::kFlagOpenOk) != 0;
                if (ok) {
                    if (activity_handler) {
                        activity_handler();
                    }
                    // Successful OPEN payloads carry protocol-specific
                    // acknowledgements (for example packet-bulk address/MTU
                    // assignment). Preserve them for every adapter.
                    handler(true, payload_to_string(*payload));
                } else {
                    handler(false, payload_to_string(*payload));
                }
            }
            break;
        }
        case protocol::ROPEN: {
            ReverseOpenHandler reverse_handler;
            {
                std::lock_guard<std::mutex> lock(state_mu_);
                reverse_handler = reverse_handler_;
            }
            if (!reverse_handler) {
                send_open_ack(stream_id, false, "reverse open unavailable");
                break;
            }
            int listen_id_value = 0;
            try {
                const auto json =
                    nlohmann::json::parse(payload_to_string(*payload));
                listen_id_value = json.value("listen_id", 0);
            } catch (...) {
                send_open_ack(stream_id, false, "invalid reverse open payload");
                break;
            }
            if (listen_id_value <= 0 || listen_id_value > 255 ||
                stream_id == 0) {
                send_open_ack(stream_id, false, "invalid reverse open payload");
                break;
            }
            if (!try_reserve_peer_stream_id(stream_id)) {
                send_open_ack(stream_id, false, "reverse stream id in use");
                break;
            }
            std::string reason;
            bool accepted = false;
            try {
                accepted = reverse_handler(
                    static_cast<uint8_t>(listen_id_value), stream_id, &reason);
            } catch (...) {
                reason = "reverse open handler failed";
            }
            if (!accepted) {
                unregister_stream(stream_id);
                send_open_ack(
                    stream_id, false,
                    reason.empty() ? "reverse open failed" : reason);
                break;
            }
            if (!peer_stream_registration_complete(stream_id)) {
                send_open_ack(stream_id, false,
                              "reverse open did not register stream");
            }
            break;
        }
        case protocol::SOPEN: {
            InboundOpenHandler inbound_open_handler;
            ServerStreamOpenHandler server_stream_open_handler;
            bool server_in_charge = false;
            {
                std::lock_guard<std::mutex> lock(state_mu_);
                inbound_open_handler = inbound_open_handler_;
                server_stream_open_handler = server_stream_open_handler_;
                server_in_charge = server_in_charge_;
            }
            nlohmann::json json;
            try {
                json = nlohmann::json::parse(payload_to_string(*payload));
            } catch (...) {
                send_open_ack(stream_id, false, "invalid control payload");
                break;
            }
            if (stream_id == 0) {
                send_open_ack(stream_id, false, "invalid stream id");
                break;
            }
            if (json.contains("channel_kind")) {
                if (!inbound_open_handler) {
                    send_open_ack(stream_id, false,
                                  "inbound control unavailable");
                    break;
                }
                if (!try_reserve_peer_stream_id(stream_id)) {
                    send_open_ack(stream_id, false,
                                  "inbound stream id in use");
                    break;
                }
                std::string reason;
                bool accepted = false;
                try {
                    accepted =
                        inbound_open_handler(stream_id, json, &reason);
                } catch (...) {
                    reason = "inbound control handler failed";
                }
                if (!accepted) {
                    unregister_stream(stream_id);
                    send_open_ack(
                        stream_id, false,
                        reason.empty() ? "inbound control open failed"
                                       : reason);
                    break;
                }
                if (!peer_stream_registration_complete(stream_id)) {
                    send_open_ack(stream_id, false,
                                  "inbound control did not register stream");
                    break;
                }
                send_open_ack(stream_id, true, "");
                break;
            }
            if (!server_in_charge) {
                send_open_ack(stream_id, false, "server control disabled");
                break;
            }
            auto control_open = ParseServerControlOpen(json);
            if (!control_open) {
                send_open_ack(stream_id, false, "invalid control target");
                break;
            }
            if (!server_stream_open_handler) {
                send_open_ack(stream_id, false,
                              "server control unavailable");
                break;
            }
            if (!try_reserve_peer_stream_id(stream_id)) {
                send_open_ack(stream_id, false,
                              "server control stream id in use");
                break;
            }
            std::string reason;
            bool accepted = false;
            try {
                accepted = server_stream_open_handler(
                    stream_id, control_open->host, control_open->port,
                    &reason);
            } catch (...) {
                reason = "local control open handler failed";
            }
            if (!accepted) {
                unregister_stream(stream_id);
                send_open_ack(
                    stream_id, false,
                    reason.empty() ? "local control open failed" : reason);
                break;
            }
            if (!peer_stream_registration_complete(stream_id)) {
                send_open_ack(stream_id, false,
                              "local control did not register stream");
            }
            break;
        }
        case protocol::CONTROL: {
            ControlHandler control_handler;
            {
                std::lock_guard<std::mutex> lock(state_mu_);
                control_handler = control_handler_;
            }
            if (control_handler) {
                try {
                    auto json = nlohmann::json::parse(payload_to_string(*payload));
                    control_handler(json);
                } catch (...) {
                }
            }
            break;
        }
        case protocol::DATA: {
            DataHandler on_data;
            ActivityHandler activity_handler;
            {
                std::lock_guard<std::mutex> lock(state_mu_);
                auto it = streams_.find(stream_id);
                if (it != streams_.end()) {
                    on_data = it->second.on_data;
                }
                if (!payload->empty()) {
                    activity_handler = activity_handler_;
                }
            }
            if (on_data) {
                if (activity_handler) {
                    activity_handler();
                }
                on_data(*payload, std::move(inbound_credit));
            }
            break;
        }
        case protocol::EXEC: {
            ExecHandler exec_handler;
            bool allow_exec = false;
            bool in_use = false;
            {
                std::lock_guard<std::mutex> lock(state_mu_);
                allow_exec = allow_exec_;
                exec_handler = exec_handler_;
                in_use = has_stream_id_locked(stream_id);
                if (allow_exec && exec_handler && !in_use) {
                    reserved_streams_.insert(stream_id);
                }
            }
            if (!allow_exec) {
                send_data(stream_id, Bytes({'E', 'X', 'E', 'C', ' ', 'd', 'e', 'n', 'i', 'e', 'd'}));
                send_close(stream_id, "exec denied");
                break;
            }
            if (!exec_handler) {
                send_close(stream_id, "exec unavailable");
                break;
            }
            if (in_use) {
                send_close(stream_id, "exec stream id in use");
                break;
            }
            exec_handler(stream_id, payload_to_string(*payload));
            break;
        }
        case protocol::CLOSE: {
            CloseHandler on_close;
            HalfCloseHandler on_half_close;
            const std::string reason = payload_to_string(*payload);
            const bool is_fin = (frame.header.flags & protocol::kFlagStreamFin) != 0;
            if (stream_id == 0 && !is_fin) {
                request_transport_close(reason.empty() ? "server closed" : reason);
                break;
            }
            {
                std::lock_guard<std::mutex> lock(state_mu_);
                auto it = streams_.find(stream_id);
                if (it != streams_.end()) {
                    if (is_fin && it->second.on_half_close) {
                        on_half_close = it->second.on_half_close;
                    } else {
                        on_close = std::move(it->second.on_close);
                        streams_.erase(it);
                    }
                }
                if (!is_fin || !on_half_close) {
                    pending_open_.erase(stream_id);
                    pending_rlisten_.erase(stream_id);
                    reserved_streams_.erase(stream_id);
                }
            }
            if (on_half_close) {
                on_half_close(reason);
                break;
            }
            if (on_close) {
                on_close(reason);
            }
            break;
        }
        case protocol::PING: {
            protocol::Frame pong{{0, protocol::PONG, 0, 0}, {}};
            queue_frame(pong);
            break;
        }
        case protocol::PONG: {
            std::lock_guard<std::mutex> lock(state_mu_);
            last_pong_ = std::chrono::steady_clock::now();
            break;
        }
        default:
            break;
    }
}

}  // namespace yume::outbound
