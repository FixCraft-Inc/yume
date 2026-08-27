/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/session.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string_view>

#include "core/protocol/relay_policy.hpp"
#include "server/runtime/manager.hpp"
#include "server/session/internal.hpp"

namespace yume::server {

using namespace detail;

namespace {

constexpr std::size_t kMaxOpenHostBytes = 255U;
constexpr std::size_t kMaxOpenProtoBytes = 32U;
constexpr std::array<std::string_view, 3> kGenericOpenFields{
    "host", "port", "proto",
};

struct GenericOpenTarget {
    std::string host;
    int port{0};
    std::string proto{"tcp"};
};

std::optional<GenericOpenTarget> ParseGenericOpenTarget(
    const nlohmann::json& json) noexcept {
    try {
        if (!json.is_object() || json.size() > kGenericOpenFields.size()) {
            return std::nullopt;
        }
        for (auto it = json.begin(); it != json.end(); ++it) {
            if (std::find(kGenericOpenFields.begin(),
                          kGenericOpenFields.end(),
                          it.key()) == kGenericOpenFields.end()) {
                return std::nullopt;
            }
        }
        if (!json.contains("host") || !json["host"].is_string() ||
            !json.contains("port")) {
            return std::nullopt;
        }
        const auto& host = json["host"].get_ref<const std::string&>();
        if (host.empty() || host.size() > kMaxOpenHostBytes ||
            !std::all_of(host.begin(), host.end(), [](unsigned char byte) {
                return byte >= 0x21U && byte <= 0x7eU;
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

        std::string_view proto = "tcp";
        if (json.contains("proto")) {
            if (!json["proto"].is_string()) return std::nullopt;
            proto = json["proto"].get_ref<const std::string&>();
        }
        if (proto != "tcp" && proto != "udp") return std::nullopt;

        return GenericOpenTarget{
            host, static_cast<int>(port), std::string(proto)};
    } catch (...) {
        return std::nullopt;
    }
}

}  // namespace

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
    std::scoped_lock lock(streams_mutex_, control_mutex_);
    return !stream_id_in_use_locked(stream_id) &&
           control_outbound_.find(stream_id) == control_outbound_.end() &&
           control_inbound_.find(stream_id) == control_inbound_.end() &&
           federated_streams_.find(stream_id) == federated_streams_.end();
}

bool Session::handle_relay_open(uint8_t stream_id,
                                const nlohmann::json& json,
                                const crypto::Bytes& payload) {
    if (!json.contains("target_id") && !json.contains("channel_kind") &&
        !json.contains("channel_id")) {
        return false;
    }
    if (!json.contains("target_id") || !json["target_id"].is_string() ||
        !json.contains("relay_protocol_version") ||
        (!json["relay_protocol_version"].is_number_integer() &&
         !json["relay_protocol_version"].is_number_unsigned()) ||
        !json.contains("to_id") || !json["to_id"].is_string() ||
        !json.contains("from_id") || !json["from_id"].is_string() ||
        !json.contains("channel_id") || !json["channel_id"].is_string() ||
        !json.contains("channel_kind") || !json["channel_kind"].is_string() ||
        !json.contains("e2ee_required") ||
        !json["e2ee_required"].is_boolean() ||
        !json["e2ee_required"].get<bool>()) {
        send_open_reply(stream_id, false, "invalid relay OPEN claims");
        return true;
    }

    const auto& relay_version = json["relay_protocol_version"];
    const bool exact_relay_v2 = relay_version.is_number_unsigned()
        ? relay_version.get<std::uint64_t>() ==
              control::kRelayProtocolVersion
        : relay_version.get<std::int64_t>() ==
              control::kRelayProtocolVersion;
    if (!exact_relay_v2) {
        send_open_reply(stream_id, false,
                        "relay OPEN protocol version mismatch");
        return true;
    }

    const std::string target_id = json["target_id"].get<std::string>();
    const std::string to_id = json["to_id"].get<std::string>();
    const std::string from_id = json["from_id"].get<std::string>();
    const std::string channel_id = json["channel_id"].get<std::string>();
    const auto parsed_kind = control::try_relay_channel_kind(
        json["channel_kind"].get_ref<const std::string&>());
    if (!parsed_kind) {
        send_open_reply(stream_id, false, "invalid relay channel kind");
        return true;
    }
    const auto channel_kind = *parsed_kind;
    if (!cfg_.relay_enable) {
        send_open_reply(stream_id, false, "relay disabled");
        return true;
    }
    if (is_federation_authenticated() &&
        (!manager_ || !manager_->federation_enabled() ||
         !federation_hello_accepted_)) {
        send_open_reply(stream_id, false,
                        "enabled federation hello required");
        return true;
    }
    if (target_id.empty() || to_id.empty() || target_id != to_id ||
        channel_id.empty() || from_id.empty()) {
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
        !manager_->can_open_channel(shared_from_this(),
                                    channel_id,
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
    // Manager admission above is the authoritative source+target policy check.
    // In particular, an authenticated federation session represents a caller
    // whose trusted/admin half was checked by the source server; applying this
    // session object's default presence flags here would reject valid inbound
    // federation channels while adding no local-target protection.
    if (target.get() == this) {
        manager_->unregister_active_channel(channel_id);
        send_open_reply(stream_id, false, "invalid relay target");
        return true;
    }

    auto target_reservation = target->reserve_stream_id();
    if (!target_reservation) {
        manager_->unregister_active_channel(channel_id);
        send_open_reply(stream_id, false, "no stream ids available");
        return true;
    }
    const uint8_t target_stream = target_reservation.stream_id();
    // The signed federated transcript keeps the source server's visible
    // target id ("peer:remote-id"). Active-channel bookkeeping is local to
    // this Manager, so represent the remote caller in this server's namespace
    // and the target by its actual local id. This prevents a remote id from
    // colliding with a local endpoint and lets federated admin relationships
    // update the local target endpoint after the ACK.
    const std::string active_left_endpoint_id = is_federation_authenticated()
        ? federation_peer_id_ + ":" + from_id
        : from_id;
    const std::string active_right_endpoint_id = target->endpoint_id();
    bool source_inserted = false;
    try {
        {
            std::lock_guard<std::mutex> lock(control_mutex_);
            source_inserted = control_outbound_.try_emplace(
                stream_id, ControlLink{
                    target,
                    target_stream,
                    true,
                    false,
                    channel_kind,
                    channel_id,
                    active_left_endpoint_id,
                    active_right_endpoint_id}).second;
        }
        if (!source_inserted) {
            throw std::runtime_error("source relay stream id is already in use");
        }
        bool target_inserted = false;
        {
            std::lock_guard<std::mutex> lock(target->control_mutex_);
            target_inserted = target->control_inbound_.try_emplace(
                target_stream, ControlLink{
                    shared_from_this(),
                    stream_id,
                    true,
                    false,
                    channel_kind,
                    channel_id,
                    active_left_endpoint_id,
                    active_right_endpoint_id}).second;
        }
        if (!target_inserted) {
            throw std::runtime_error("target relay stream id is already in use");
        }
        target->send_control_frame(protocol::SOPEN, target_stream, payload);
    } catch (const std::exception& ex) {
        if (source_inserted) {
            std::lock_guard<std::mutex> lock(control_mutex_);
            control_outbound_.erase(stream_id);
        }
        {
            std::lock_guard<std::mutex> lock(target->control_mutex_);
            target->control_inbound_.erase(target_stream);
        }
        manager_->unregister_active_channel(channel_id);
        send_open_reply(stream_id, false,
                        std::string("relay stream setup failed: ") + ex.what());
        return true;
    }
    return true;
}

void Session::handle_open(const protocol::Frame& frame) {
    // Local OPEN publication and peer-originated cross-session allocation use
    // the same mutex. Every synchronous OPEN handler publishes its map entry
    // before returning, so this closes the availability-to-insert race without
    // retaining failed ids.
    std::unique_lock<std::recursive_mutex> allocation_lock(
        stream_id_allocation_mutex_);
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
    } catch (const std::exception&) {
        send_open_reply(stream_id, false, "invalid OPEN payload");
        return;
    }

    std::string_view proto;
    if (open_json.contains("proto")) {
        if (!open_json["proto"].is_string()) {
            send_open_reply(stream_id, false, "invalid OPEN payload");
            return;
        }
        proto = open_json["proto"].get_ref<const std::string&>();
        if (proto.size() > kMaxOpenProtoBytes) {
            send_open_reply(stream_id, false, "invalid OPEN payload");
            return;
        }
    }
    if (proto == std::string(protocol::packet_bulk::kOpenProto)) {
        handle_packet_open(stream_id);
        return;
    }
    if (proto == kBenchSinkProto || proto == kBenchSourceProto ||
        proto == kBenchEchoProto) {
        handle_bench_open(stream_id, std::string(proto), open_json);
        return;
    }
    if (proto == std::string(app_codec::kOpenProto)) {
        handle_codec_open(stream_id, open_json);
        return;
    }

    auto target = ParseGenericOpenTarget(open_json);
    if (!target) {
        send_open_reply(stream_id, false, "invalid OPEN target");
        return;
    }
    if (is_blocked_host_literal(
            target->host, session_allow_local_ip_, session_control_full_)) {
        send_open_reply(stream_id, false, "blocked destination");
        return;
    }

    if (target->proto == "udp") {
        start_udp_open(stream_id, target->host, target->port);
        return;
    }
    start_tcp_open(stream_id, target->host, target->port);
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

Session::StreamIdReservation Session::reserve_stream_id() {
    std::unique_lock<std::recursive_mutex> allocation_lock(
        stream_id_allocation_mutex_);
    std::scoped_lock map_lock(streams_mutex_, control_mutex_);
    for (int i = 1; i < 255; ++i) {
        const uint8_t candidate = static_cast<uint8_t>(i);
        if (!stream_id_in_use_locked(candidate) &&
            control_outbound_.find(candidate) == control_outbound_.end() &&
            control_inbound_.find(candidate) == control_inbound_.end() &&
            federated_streams_.find(candidate) == federated_streams_.end()) {
            return StreamIdReservation(candidate,
                                       std::move(allocation_lock));
        }
    }
    return {};
}

}  // namespace yume::server
