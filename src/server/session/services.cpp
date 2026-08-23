/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/session.hpp"

#include <algorithm>
#include <chrono>
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
    std::weak_ptr<runtime::ServiceStream> weak_stream = stream;
    stream->set_callbacks(
        [weak_self, weak_stream, stream_id](
            runtime::ServiceStream::Bytes data,
            std::uint32_t timeout_ms,
            runtime::ServiceStream::WriteCompletion completion,
            std::string* error) {
            auto self = weak_self.lock();
            if (!self) {
                if (error) *error = "session closed";
                return runtime::ServiceStream::WriteResult::Closed;
            }
            return self->send_service_data(
                stream_id, std::move(data), timeout_ms, weak_stream,
                std::move(completion), error);
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
        },
        [weak_self] {
            const auto self = weak_self.lock();
            return self && !self->strand_.running_in_this_thread();
        });

    auto admission_permit = service_stream_admission_gate_.try_acquire();
    const bool session_stopping =
        !admission_permit || service_write_queue_.stopped();
    if (session_stopping) {
        stream->set_callbacks({}, {}, {});
        send_open_reply(stream_id, false, "session closing");
        return true;
    }

    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        service_streams_[stream_id] = stream;
    }
    std::string enqueue_error;
    if (!manager_->enqueue_service_stream(service, stream, &enqueue_error)) {
        {
            std::lock_guard<std::mutex> lock(streams_mutex_);
            auto it = service_streams_.find(stream_id);
            if (it != service_streams_.end()) {
                it->second->set_callbacks({}, {}, {});
                service_streams_.erase(it);
            }
        }
        send_open_reply(stream_id, false,
                        enqueue_error.empty() ? "service unavailable" : enqueue_error);
        return true;
    }
    send_open_reply(stream_id, true, "");
    return true;
}

bool Session::handle_service_data(
    uint8_t stream_id,
    const crypto::Bytes& payload,
    runtime::InboundCredit* inbound_credit) {
    std::shared_ptr<runtime::ServiceStream> stream;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        auto it = service_streams_.find(stream_id);
        if (it == service_streams_.end()) {
            return false;
        }
        stream = it->second;
    }
    std::string error;
    runtime::InboundCredit credit;
    if (inbound_credit) {
        credit = std::move(*inbound_credit);
    }
    if (!stream->receive_data(payload, std::move(credit), &error)) {
        const std::string reason = "service inbound queue overflow" +
                                   (error.empty() ? std::string() : ": " + error);
        util::log_warn("session " + std::to_string(session_id_) + ": service stream " +
                       std::to_string(stream_id) + " " + reason);
        handle_service_close(stream_id, reason, true);
        send_control_close(stream_id, reason);
    }
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

bool Session::handle_service_close(uint8_t stream_id,
                                   const std::string& reason,
                                   bool discard_buffered) {
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
    // Publish the terminal stream state before waking capacity waiters. A
    // writer racing this CLOSE then observes cancellation instead of claiming
    // newly released queue space for a stream the peer has already closed.
    stream->receive_close(reason, discard_buffered);
    if (service_write_queue_.cancel_stream(stream_id, reason)) {
        schedule_service_write_drain();
    }
    return true;
}

runtime::ServiceStream::WriteResult Session::send_service_data(
    uint8_t stream_id,
    runtime::ServiceStream::Bytes payload,
    std::uint32_t timeout_ms,
    std::weak_ptr<runtime::ServiceStream> owner,
    runtime::ServiceStream::WriteCompletion completion,
    std::string* error) {
    using Admission = runtime::ServiceWriteAdmissionQueue::AdmissionResult;
    using Result = runtime::ServiceStream::WriteResult;

    bool needs_dispatch = false;
    try {
        // A positive ABI deadline may block an application thread, but the
        // Session strand must always remain able to drain the queue and settle
        // completions. A reentrant on-strand write therefore degrades to the
        // same atomic poll used by timeout_ms == 0.
        const auto admission_timeout = strand_.running_in_this_thread()
            ? std::chrono::milliseconds::zero()
            : std::chrono::milliseconds(timeout_ms);
        const auto admission = service_write_queue_.enqueue(
            stream_id,
            std::move(payload),
            admission_timeout,
            std::move(completion),
            [owner] {
                const auto stream = owner.lock();
                return !stream || stream->closed();
            },
            &needs_dispatch,
            error);
        switch (admission) {
        case Admission::Accepted:
            // Accepted means the bounded FIFO owns the complete payload. The
            // later completion reports transport disposition only; it is not
            // retroactively used as an admission result.
            if (needs_dispatch) {
                schedule_service_write_drain();
            }
            return Result::Accepted;
        case Admission::WouldBlock:
            return Result::WouldBlock;
        case Admission::Timeout:
            return Result::Timeout;
        case Admission::Stopped:
            return Result::Closed;
        case Admission::Invalid:
            return Result::Invalid;
        }
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return Result::Failed;
    } catch (...) {
        if (error) *error = "failed to enqueue service write";
        return Result::Failed;
    }
    if (error) *error = "unknown service write admission result";
    return Result::Failed;
}

void Session::schedule_service_write_drain() {
    try {
        boost::asio::post(
            strand_,
            [self = shared_from_this()] {
                self->drain_service_write_on_strand();
            });
    } catch (...) {
        // The payload was already admitted, so it must be settled through its
        // completion rather than returned as an ambiguous failed admission.
        stop_service_streams("failed to schedule service write drain");
    }
}

void Session::drain_service_write_on_strand() {
    auto entry = service_write_queue_.take_next();
    if (!entry.has_value()) {
        return;
    }

    const std::uint64_t sequence = entry->sequence;
    auto completion = std::move(entry->completion);
    try {
        send_control_frame(
            protocol::DATA, entry->stream_id, entry->payload, 0,
            [self = shared_from_this(), sequence,
             completion = std::move(completion)](
                const boost::system::error_code& ec,
                std::size_t) mutable {
                bool needs_dispatch = false;
                const bool completed = self->service_write_queue_.finish(
                    sequence, &needs_dispatch);
                if (completed && completion) {
                    try {
                        completion(!ec, ec ? ec.message() : std::string{});
                    } catch (...) {
                        // Transport settlement must continue even if an
                        // embedder-owned callback violates its contract.
                    }
                }
                if (needs_dispatch) {
                    self->schedule_service_write_drain();
                }
            });
    } catch (const std::exception& ex) {
        bool needs_dispatch = false;
        const bool completed = service_write_queue_.finish(
            sequence, &needs_dispatch);
        if (completed && completion) {
            try {
                completion(false, ex.what());
            } catch (...) {
            }
        }
        if (needs_dispatch) {
            schedule_service_write_drain();
        }
        close_with_reason("service transport write failed");
    } catch (...) {
        bool needs_dispatch = false;
        const bool completed = service_write_queue_.finish(
            sequence, &needs_dispatch);
        if (completed && completion) {
            try {
                completion(false, "service transport write failed");
            } catch (...) {
            }
        }
        if (needs_dispatch) {
            schedule_service_write_drain();
        }
        close_with_reason("service transport write failed");
    }
}

void Session::stop_service_streams(const std::string& reason) {
    const std::string terminal_reason = reason.empty()
        ? "session closing" : reason;
    // Reject new OPEN publications first, then wait for any OPEN transaction
    // that linearized before this stop request to finish publishing into both
    // the Session map and Manager queue. The following snapshot therefore
    // cannot miss a handle that Manager can expose to an application.
    service_stream_admission_gate_.stop();
    service_write_queue_.stop(terminal_reason);

    std::vector<std::shared_ptr<runtime::ServiceStream>> streams;
    {
        std::lock_guard<std::mutex> lock(streams_mutex_);
        streams.reserve(service_streams_.size());
        for (const auto& entry : service_streams_) {
            streams.push_back(entry.second);
        }
    }
    // Publish closure outside streams_mutex_: receive_close() releases any
    // retained H2 credit, whose handler may post back into this Session.
    for (const auto& stream : streams) {
        if (stream) {
            stream->receive_close(terminal_reason);
        }
    }
}

void Session::send_service_close(uint8_t stream_id, std::string reason) {
    if (service_write_queue_.cancel_stream(stream_id, reason)) {
        schedule_service_write_drain();
    }
    try {
        boost::asio::post(strand_, [self = shared_from_this(), stream_id,
                                    reason = std::move(reason)]() mutable {
            self->send_control_close(stream_id, reason);
            std::lock_guard<std::mutex> lock(self->streams_mutex_);
            self->service_streams_.erase(stream_id);
        });
    } catch (...) {
        stop_service_streams("failed to schedule service close");
    }
}

void Session::send_service_fin(uint8_t stream_id, std::string reason) {
    boost::asio::post(strand_, [self = shared_from_this(), stream_id, reason = std::move(reason)]() mutable {
        self->send_control_fin(stream_id, reason);
    });
}

}  // namespace yume::server
