/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/session.hpp"

#include <algorithm>
#include <string>
#include <string_view>
#include <utility>

#include "server/runtime/manager.hpp"

namespace yume::server {

namespace {

inline constexpr char kServiceProto[] = "service.v1";

bool contains_string(const std::vector<std::string>& values, const std::string& value) {
    return std::find(values.begin(), values.end(), value) != values.end();
}

bool valid_service_name(std::string_view service) {
    if (service.empty() || service.size() > 128) {
        return false;
    }
    return std::all_of(service.begin(), service.end(), [](unsigned char ch) {
        return (ch >= 'a' && ch <= 'z') ||
               (ch >= 'A' && ch <= 'Z') ||
               (ch >= '0' && ch <= '9') ||
               ch == '-' || ch == '_' || ch == '.' || ch == ':';
    });
}

}  // namespace

bool Session::handle_service_open(uint8_t stream_id, const nlohmann::json& json) {
    if (json.value("proto", "") != kServiceProto) {
        return false;
    }
    const std::string service = json.value("service", "");
    if (!valid_service_name(service)) {
        send_open_reply(stream_id, false, "invalid service");
        return true;
    }
    if (!contains_string(cfg_.allowed_services, service) ||
        session_allowed_services_.find(service) == session_allowed_services_.end()) {
        send_open_reply(stream_id, false, "service not permitted");
        return true;
    }
    if (!manager_) {
        send_open_reply(stream_id, false, "service manager unavailable");
        return true;
    }

    runtime::ServicePeerInfo peer_info;
    peer_info.service = service;
    peer_info.peer = client_id_;
    peer_info.auth_fingerprint_sha256 = auth_fingerprint_;
    peer_info.session_id = client_id_;
    peer_info.server_session_id = std::to_string(session_id_);
    peer_info.remote_addr = client_wan_ip_;

    auto stream = std::make_shared<runtime::ServiceStream>(
        service,
        client_id_,
        std::move(peer_info));
    std::weak_ptr<Session> weak_self = shared_from_this();
    stream->set_callbacks(
        [weak_self, stream_id](runtime::ServiceStream::Bytes data, std::string* error) {
            auto self = weak_self.lock();
            if (!self) {
                if (error) *error = "session closed";
                return false;
            }
            self->send_service_data(stream_id, std::move(data));
            return true;
        },
        [weak_self, stream_id](std::string reason) {
            if (auto self = weak_self.lock()) {
                self->send_service_close(stream_id, std::move(reason));
            }
        },
        [weak_self, stream_id](std::string reason) {
            if (auto self = weak_self.lock()) {
                self->send_service_fin(stream_id, std::move(reason));
            }
        });

    std::string enqueue_error;
    if (!manager_->enqueue_service_stream(service, stream, &enqueue_error)) {
        stream->set_callbacks({}, {}, {});
        send_open_reply(stream_id, false,
                        enqueue_error.empty() ? "service unavailable" : enqueue_error);
        return true;
    }
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        service_streams_[stream_id] = std::move(stream);
    }
    send_open_reply(stream_id, true, "");
    return true;
}

bool Session::handle_service_data(uint8_t stream_id, const crypto::Bytes& payload) {
    std::shared_ptr<runtime::ServiceStream> stream;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = service_streams_.find(stream_id);
        if (it == service_streams_.end()) {
            return false;
        }
        stream = it->second;
    }
    stream->receive_data(payload);
    return true;
}

bool Session::handle_service_fin(uint8_t stream_id, const std::string& reason) {
    std::shared_ptr<runtime::ServiceStream> stream;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = service_streams_.find(stream_id);
        if (it == service_streams_.end()) {
            return false;
        }
        stream = it->second;
    }
    stream->receive_fin(reason);
    return true;
}

bool Session::handle_service_close(uint8_t stream_id, const std::string& reason) {
    std::shared_ptr<runtime::ServiceStream> stream;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = service_streams_.find(stream_id);
        if (it == service_streams_.end()) {
            return false;
        }
        stream = it->second;
        service_streams_.erase(it);
    }
    stream->receive_close(reason);
    return true;
}

void Session::send_service_data(uint8_t stream_id, runtime::ServiceStream::Bytes payload) {
    boost::asio::post(strand_, [self = shared_from_this(), stream_id, payload = std::move(payload)]() mutable {
        self->send_control_frame(protocol::DATA, stream_id, payload);
    });
}

void Session::send_service_close(uint8_t stream_id, std::string reason) {
    boost::asio::post(strand_, [self = shared_from_this(), stream_id, reason = std::move(reason)]() mutable {
        self->send_control_close(stream_id, reason);
        std::lock_guard<std::mutex> lock(self->streams_mutex_);
        self->service_streams_.erase(stream_id);
    });
}

void Session::send_service_fin(uint8_t stream_id, std::string reason) {
    boost::asio::post(strand_, [self = shared_from_this(), stream_id, reason = std::move(reason)]() mutable {
        self->send_control_fin(stream_id, reason);
    });
}

}  // namespace yume::server
