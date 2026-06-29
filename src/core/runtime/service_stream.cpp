/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "core/runtime/service_stream.hpp"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <utility>

namespace yume::runtime {

ServiceStream::ServiceStream(std::string service, std::string peer)
    : ServiceStream(std::move(service), std::move(peer), {}) {}

ServiceStream::ServiceStream(std::string service,
                             std::string peer,
                             ServicePeerInfo peer_info)
    : service_(std::move(service))
    , peer_(std::move(peer))
    , peer_info_(std::move(peer_info)) {
    if (peer_info_.service.empty()) {
        peer_info_.service = service_;
    }
    if (peer_info_.peer.empty()) {
        peer_info_.peer = peer_;
    }
    if (peer_info_.session_id.empty()) {
        peer_info_.session_id = peer_;
    }
}

ServiceStream::~ServiceStream() {
    close("stream destroyed");
}

const std::string& ServiceStream::service() const noexcept {
    return service_;
}

const std::string& ServiceStream::peer() const noexcept {
    return peer_;
}

ServicePeerInfo ServiceStream::peer_info() const {
    std::lock_guard<std::mutex> lock(mu_);
    return peer_info_;
}

void ServiceStream::set_callbacks(WriteCallback write_cb,
                                  CloseCallback close_cb,
                                  CloseCallback shutdown_write_cb) {
    std::lock_guard<std::mutex> lock(mu_);
    write_cb_ = std::move(write_cb);
    close_cb_ = std::move(close_cb);
    shutdown_write_cb_ = std::move(shutdown_write_cb);
}

bool ServiceStream::write(const void* data, std::size_t size, std::string* error) {
    if (size > 0 && data == nullptr) {
        if (error) *error = "data is null";
        return false;
    }

    WriteCallback cb;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (local_closed_ || remote_closed_) {
            if (error) *error = close_reason_.empty() ? "stream closed" : close_reason_;
            return false;
        }
        if (local_fin_sent_) {
            if (error) *error = "stream write side is shut down";
            return false;
        }
        cb = write_cb_;
    }
    if (!cb) {
        if (error) *error = "stream is not connected";
        return false;
    }

    Bytes payload;
    if (size > 0) {
        const auto* begin = static_cast<const std::uint8_t*>(data);
        payload.assign(begin, begin + size);
    }
    return cb(std::move(payload), error);
}

bool ServiceStream::shutdown_write(std::string* error) {
    CloseCallback cb;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (local_closed_) {
            return true;
        }
        if (local_fin_sent_) {
            return true;
        }
        local_fin_sent_ = true;
        cb = shutdown_write_cb_;
    }
    if (!cb) {
        if (error) *error = "stream is not connected";
        return false;
    }
    cb("write side closed");
    return true;
}

void ServiceStream::close(std::string reason) {
    CloseCallback cb;
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (local_closed_) {
            return;
        }
        const bool notify_remote = !remote_closed_;
        local_closed_ = true;
        remote_closed_ = true;
        if (close_reason_.empty()) {
            close_reason_ = reason.empty() ? "stream closed" : std::move(reason);
        }
        incoming_.clear();
        current_.clear();
        current_offset_ = 0;
        if (notify_remote) {
            cb = close_cb_;
        }
    }
    cv_.notify_all();
    if (cb) {
        cb(close_reason_);
    }
}

ServiceStream::ReadResult ServiceStream::read(void* out,
                                              std::size_t capacity,
                                              std::uint32_t timeout_ms,
                                              std::size_t* bytes_read,
                                              std::string* reason) {
    if (bytes_read) {
        *bytes_read = 0;
    }
    if (capacity > 0 && out == nullptr) {
        if (reason) *reason = "output buffer is null";
        return ReadResult::Closed;
    }

    std::unique_lock<std::mutex> lock(mu_);
    auto has_data_or_closed = [this]() {
        return current_offset_ < current_.size() || !incoming_.empty() ||
               remote_fin_ || remote_closed_ || local_closed_;
    };
    if (!has_data_or_closed()) {
        if (timeout_ms == 0) {
            return ReadResult::Timeout;
        }
        if (!cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), has_data_or_closed)) {
            return ReadResult::Timeout;
        }
    }

    if (current_offset_ >= current_.size() && !incoming_.empty()) {
        current_ = std::move(incoming_.front());
        incoming_.pop_front();
        current_offset_ = 0;
    }

    if (current_offset_ < current_.size()) {
        const std::size_t n = std::min(capacity, current_.size() - current_offset_);
        if (n > 0) {
            std::memcpy(out, current_.data() + current_offset_, n);
            current_offset_ += n;
        }
        if (current_offset_ >= current_.size()) {
            current_.clear();
            current_offset_ = 0;
        }
        if (bytes_read) {
            *bytes_read = n;
        }
        return ReadResult::Data;
    }

    if (remote_fin_) {
        if (reason) *reason = close_reason_;
        return ReadResult::Eof;
    }
    if (remote_closed_ || local_closed_) {
        if (reason) *reason = close_reason_;
        return ReadResult::Closed;
    }
    return ReadResult::Timeout;
}

void ServiceStream::receive_data(Bytes data) {
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (local_closed_ || remote_closed_ || data.empty()) {
            return;
        }
        incoming_.push_back(std::move(data));
    }
    cv_.notify_all();
}

void ServiceStream::receive_fin(std::string reason) {
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (remote_closed_ || remote_fin_) {
            return;
        }
        remote_fin_ = true;
        if (close_reason_.empty()) {
            close_reason_ = std::move(reason);
        }
    }
    cv_.notify_all();
}

void ServiceStream::receive_close(std::string reason) {
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (remote_closed_) {
            return;
        }
        remote_closed_ = true;
        if (close_reason_.empty()) {
            close_reason_ = reason.empty() ? "remote closed" : std::move(reason);
        }
    }
    cv_.notify_all();
}

bool ServiceStream::closed() const {
    std::lock_guard<std::mutex> lock(mu_);
    return local_closed_ || remote_closed_;
}

}  // namespace yume::runtime
