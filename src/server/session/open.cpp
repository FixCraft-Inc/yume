/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/session.hpp"
#include "server/runtime/manager.hpp"
#include "server/session/internal.hpp"

namespace yume::server {

using namespace detail;

bool Session::handle_reverse_open_reply(const protocol::Frame& frame) {
    const uint8_t stream_id = frame.header.stream_id;
    if (pending_reverse_.find(stream_id) == pending_reverse_.end()) {
        return false;
    }

    bool ok = (frame.header.flags & protocol::kFlagOpenOk) != 0;
    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() &&
        (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        crypto::Bytes decrypted;
        if (decrypt_inner_payload(
                frame.header.type, stream_id, frame.payload, &decrypted)) {
            payload = std::move(decrypted);
        } else {
            ok = false;
        }
    }
    if (!ok) {
        std::string reason(payload.begin(), payload.end());
        util::log_warn("reverse open failed: " + reason);
        handle_close(stream_id, "reverse open failed");
    } else {
        std::shared_ptr<RemoteStream> remote;
        {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            auto it = streams_.find(stream_id);
            if (it != streams_.end()) {
                remote = it->second;
            }
        }
        if (remote && remote->open_timer) {
            boost::system::error_code timer_ec;
            remote->open_timer->cancel(timer_ec);
            remote->open_timer.reset();
        }
        start_remote_read(stream_id);
    }
    pending_reverse_.erase(stream_id);
    return true;
}

bool Session::open_stream_id_available(uint8_t stream_id) {
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        if (stream_id_in_use_locked(stream_id)) {
            return false;
        }
    }
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        if (control_outbound_.find(stream_id) != control_outbound_.end() ||
            control_inbound_.find(stream_id) != control_inbound_.end() ||
            federated_streams_.find(stream_id) != federated_streams_.end()) {
            return false;
        }
    }
    return true;
}

bool Session::handle_relay_open(uint8_t stream_id,
                                const nlohmann::json& json,
                                const crypto::Bytes& payload) {
    if (!json.contains("target_id") || !json.contains("channel_kind") ||
        !json.contains("channel_id")) {
        return false;
    }

    const std::string target_id = json.value("target_id", "");
    const std::string from_id = json.value("from_id", client_id_);
    const std::string channel_id = json.value("channel_id", "");
    const auto channel_kind = control::channel_kind_from_string(
        json.value("channel_kind", "chat"));
    if (!cfg_.relay_enable) {
        send_open_reply(stream_id, false, "relay disabled");
        return true;
    }
    if (target_id.empty() || channel_id.empty() || from_id.empty()) {
        send_open_reply(stream_id, false, "invalid relay open");
        return true;
    }
    if (!is_federation_authenticated() && from_id != client_id_) {
        send_open_reply(stream_id, false, "relay origin mismatch");
        return true;
    }

    std::string federated_error;
    if (manager_ &&
        manager_->open_federated_channel(
            shared_from_this(), stream_id, json, &federated_error)) {
        if (!federated_error.empty()) {
            send_open_reply(stream_id, false, federated_error);
        }
        return true;
    }

    std::shared_ptr<Session> target;
    control::PendingInvite invite;
    std::string error;
    if (!manager_ ||
        !manager_->can_open_channel(channel_id,
                                    from_id,
                                    target_id,
                                    channel_kind,
                                    &target,
                                    &invite,
                                    &error)) {
        send_open_reply(
            stream_id, false, error.empty() ? "invite invalid" : error);
        return true;
    }
    if (channel_kind == control::ChannelKind::admin &&
        client_relay_mode_ != control::RelayMode::trusted) {
        send_open_reply(
            stream_id, false, "admin requires trusted relay mode");
        return true;
    }
    if (channel_kind == control::ChannelKind::chat && !client_allow_chat_) {
        send_open_reply(stream_id, false, "chat disabled");
        return true;
    }
    if (channel_kind == control::ChannelKind::file && !client_allow_file_) {
        send_open_reply(stream_id, false, "file relay disabled");
        return true;
    }
    if (channel_kind == control::ChannelKind::bytes && !client_allow_bytes_) {
        send_open_reply(stream_id, false, "byte relay disabled");
        return true;
    }
    if (target.get() == this) {
        send_open_reply(stream_id, false, "invalid relay target");
        return true;
    }

    const uint8_t target_stream = target->reserve_stream_id();
    if (target_stream == 0) {
        send_open_reply(stream_id, false, "no stream ids available");
        return true;
    }
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        control_outbound_[stream_id] = ControlLink{
            target,
            target_stream,
            true,
            false,
            channel_kind,
            channel_id,
            from_id,
            target_id};
    }
    {
        std::lock_guard<std::mutex> lock(target->control_mutex_);
        target->control_inbound_[target_stream] = ControlLink{
            shared_from_this(),
            stream_id,
            true,
            false,
            channel_kind,
            channel_id,
            from_id,
            target_id};
    }
    if (manager_) {
        control::ActiveRelayChannel channel;
        channel.channel_id = channel_id;
        channel.channel_kind = channel_kind;
        channel.left_endpoint_id = from_id;
        channel.right_endpoint_id = target_id;
        channel.left_stream_id = stream_id;
        channel.right_stream_id = target_stream;
        channel.pending = true;
        manager_->register_active_channel(channel);
        if (channel_kind == control::ChannelKind::admin) {
            manager_->add_admin_relationship(from_id, target_id);
        }
    }
    target->send_control_frame(protocol::SOPEN, target_stream, payload);
    return true;
}

void Session::handle_open(const protocol::Frame& frame) {
    const uint8_t stream_id = frame.header.stream_id;
    if (stream_id == 0) {
        send_open_reply(stream_id, false, "invalid stream id");
        return;
    }
    if (handle_reverse_open_reply(frame)) {
        return;
    }
    if (!open_stream_id_available(stream_id)) {
        send_open_reply(stream_id, false, "stream already exists");
        return;
    }

    crypto::Bytes payload = frame.payload;
    if (inner_key_.has_value() &&
        (frame.header.flags & protocol::kFlagInnerEncrypted)) {
        crypto::Bytes decrypted;
        if (decrypt_inner_payload(
                frame.header.type, stream_id, frame.payload, &decrypted)) {
            payload = std::move(decrypted);
        } else {
            util::log_warn(
                "session " + std::to_string(session_id_) +
                ": OPEN decrypt failed for stream " +
                std::to_string(stream_id));
            close_with_reason(
                "OPEN decrypt failed for stream " +
                std::to_string(stream_id));
            return;
        }
    }

    nlohmann::json open_json;
    std::string host;
    int port = 0;
    std::string proto;
    try {
        open_json = nlohmann::json::parse(
            std::string(payload.begin(), payload.end()));
        // Service routing must precede every generic/relay interpretation.
        if (handle_service_open(stream_id, open_json)) {
            return;
        }
        if (handle_relay_open(stream_id, open_json, payload)) {
            return;
        }
        host = open_json.value("host", "");
        port = open_json.value("port", 0);
        proto = open_json.value("proto", "");
    } catch (const std::exception&) {
        send_open_reply(stream_id, false, "invalid OPEN payload");
        return;
    }

    if (proto == std::string(protocol::packet_bulk::kOpenProto)) {
        handle_packet_open(stream_id);
        return;
    }
    if (proto == kBenchSinkProto || proto == kBenchSourceProto ||
        proto == kBenchEchoProto) {
        handle_bench_open(stream_id, proto, open_json);
        return;
    }
    if (proto == std::string(app_codec::kOpenProto)) {
        handle_codec_open(stream_id, open_json);
        return;
    }

    if (host.empty() || port <= 0) {
        send_open_reply(stream_id, false, "missing host/port");
        return;
    }
    if (is_blocked_host_literal(
            host, session_allow_local_ip_, session_control_full_)) {
        send_open_reply(stream_id, false, "blocked destination");
        return;
    }

    if (proto.empty()) {
        proto = "tcp";
    }
    if (proto == "udp") {
        start_udp_open(stream_id, host, port);
        return;
    }
    if (proto == "tcp") {
        start_tcp_open(stream_id, host, port);
        return;
    }
    send_open_reply(stream_id, false, "proto not supported");
}

bool Session::stream_id_in_use_locked(uint8_t stream_id) const {
    return stream_id == 0 ||
           streams_.find(stream_id) != streams_.end() ||
           udp_streams_.find(stream_id) != udp_streams_.end() ||
           codec_streams_.find(stream_id) != codec_streams_.end() ||
           service_streams_.find(stream_id) != service_streams_.end() ||
           bench_streams_.find(stream_id) != bench_streams_.end() ||
           reverse_listeners_.find(stream_id) != reverse_listeners_.end() ||
           pending_reverse_.find(stream_id) != pending_reverse_.end() ||
           (packet_stream_.has_value() &&
            packet_stream_->stream_id == stream_id);
}

uint8_t Session::reserve_stream_id() {
    for (int i = 1; i < 255; ++i) {
        const uint8_t candidate = static_cast<uint8_t>(i);
        bool streams_free = false;
        {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            streams_free = !stream_id_in_use_locked(candidate);
        }
        if (!streams_free) {
            continue;
        }
        {
            std::lock_guard<std::mutex> lock(control_mutex_);
            if (control_outbound_.find(candidate) != control_outbound_.end() ||
                control_inbound_.find(candidate) != control_inbound_.end() ||
                federated_streams_.find(candidate) !=
                    federated_streams_.end()) {
                continue;
            }
        }
        return candidate;
    }
    return 0;
}

}  // namespace yume::server
