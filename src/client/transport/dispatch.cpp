/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 *
 * TransportCore inbound frame dispatch (handle_frame).
 * Extracted verbatim from client/transport/core.cpp. Same
 * yume::client::TransportCore class, no behavior change. Shared helpers
 * via client/transport/internal.hpp.
 */

#include "client/transport/core.hpp"
#include "client/transport/internal.hpp"

#include <algorithm>
#include <cstdio>
#include <thread>

#include "core/security/inner_crypto.hpp"

namespace yume::client {

using namespace detail;

void TransportCore::handle_frame(const protocol::Frame& frame) {
    const uint8_t stream_id = frame.header.stream_id;
    Bytes decrypted_payload;
    const Bytes* payload = &frame.payload;
    bool inner_encrypted = false;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        inner_encrypted = inner_key_.has_value() &&
                          ((frame.header.flags & protocol::kFlagInnerEncrypted) != 0);
    }
    if (inner_encrypted) {
        if (!decrypt_inner_payload(frame.header.type, stream_id, frame.payload, &decrypted_payload)) {
            request_transport_close("decrypt failed");
            return;
        }
        payload = &decrypted_payload;
    }

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
                    handler(true, is_remote_listen ? payload_to_string(*payload) : std::string{});
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
            if (reverse_handler) {
                try {
                    auto json = nlohmann::json::parse(payload_to_string(*payload));
                    const auto listen_id = static_cast<uint8_t>(json.value("listen_id", 0));
                    if (listen_id != 0) {
                        reverse_handler(listen_id, stream_id);
                    }
                } catch (...) {
                }
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
            try {
                auto json = nlohmann::json::parse(payload_to_string(*payload));
                if (json.contains("channel_kind")) {
                    if (inbound_open_handler) {
                        inbound_open_handler(stream_id, json);
                    } else {
                        send_open_ack(stream_id, false, "inbound control unavailable");
                    }
                    break;
                }
                if (!server_in_charge) {
                    send_open_ack(stream_id, false, "server control disabled");
                    break;
                }
                const std::string host = json.value("host", "");
                const int port = json.value("port", 0);
                const std::string proto = json.value("proto", "tcp");
                if (host.empty() || port <= 0) {
                    send_open_ack(stream_id, false, "invalid control target");
                    break;
                }
                if (proto != "tcp") {
                    send_open_ack(stream_id, false, "unsupported control proto");
                    break;
                }
                if (!server_stream_open_handler) {
                    send_open_ack(stream_id, false, "server control unavailable");
                    break;
                }
                std::string reason;
                if (!server_stream_open_handler(stream_id, host, port, &reason)) {
                    send_open_ack(stream_id, false, reason.empty() ? "local control open failed" : reason);
                    break;
                }
                std::lock_guard<std::mutex> lock(state_mu_);
                reserved_streams_.insert(stream_id);
            } catch (...) {
                send_open_ack(stream_id, false, "invalid control payload");
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
                on_data(*payload);
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

}  // namespace yume::client
