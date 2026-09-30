/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/session_keeper.hpp"

#include <algorithm>
#include <new>
#include <string>
#include <utility>

namespace yume::runtime {
namespace {

using engine::Result;
using engine::Status;
using engine::StatusCode;

engine::SessionTraffic add(engine::SessionTraffic total,
                           const engine::SessionTraffic& more) noexcept {
    total.payload_bytes_sent += more.payload_bytes_sent;
    total.payload_bytes_received += more.payload_bytes_received;
    total.record_bytes_sent += more.record_bytes_sent;
    total.record_bytes_received += more.record_bytes_received;
    return total;
}

std::string describe(std::string_view prefix, const Status& status) {
    std::string text(prefix);
    if (!status.message().empty()) {
        text += ": ";
        text += status.message();
    }
    return text;
}

}  // namespace

SessionKeeper::SessionKeeper(
    std::shared_ptr<providers::AsioExecutionContext> context,
    SessionKeeperOptions options, Failure on_failure)
    : context_(std::move(context)),
      options_(std::move(options)),
      on_failure_(std::move(on_failure)),
      timer_(context_->executor()),
      backoff_(options_.reconnect_initial) {}

SessionKeeper::~SessionKeeper() noexcept = default;

SessionKeeper::SessionEnded SessionKeeper::session_ended() {
    return [weak = weak_from_this()](
               std::shared_ptr<engine::SessionEngine> session,
               Status reason) noexcept {
        if (const auto self = weak.lock())
            self->on_session_ended(session, reason);
    };
}

void SessionKeeper::attach(std::shared_ptr<NativeEndpoint> endpoint) noexcept {
    endpoint_ = std::move(endpoint);
}

void SessionKeeper::start() noexcept {
    connect();
}

void SessionKeeper::say(std::string_view text) noexcept {
    if (!options_.report) return;
    try {
        options_.report(text);
    } catch (...) {
    }
}

std::shared_ptr<engine::SessionEngine> SessionKeeper::active_session()
    const noexcept {
    return session_ && session_->state() == engine::SessionState::Active
               ? session_
               : nullptr;
}

// Applies one state change to the published status, then reports it. A
// failed string copy keeps the state change and the older text.
template <typename Change>
void SessionKeeper::transition(Change change) noexcept {
    NativeClientStatus copy;
    bool notify = static_cast<bool>(options_.on_status);
    {
        std::lock_guard<std::mutex> lock(status_mutex_);
        try {
            change(published_);
        } catch (...) {
        }
        if (notify) {
            try {
                copy = published_;
                copy.traffic = traffic_locked();
            } catch (...) {
                notify = false;
            }
        }
    }
    if (notify) {
        try {
            options_.on_status(copy);
        } catch (...) {
        }
    }
}

engine::SessionTraffic SessionKeeper::traffic_locked() const noexcept {
    return counted_session_
               ? add(finished_traffic_, counted_session_->traffic())
               : finished_traffic_;
}

// Folds a finished session into the totals and stops counting it.
void SessionKeeper::retire_counted_session() noexcept {
    std::lock_guard<std::mutex> lock(status_mutex_);
    if (!counted_session_) return;
    finished_traffic_ = add(finished_traffic_, counted_session_->traffic());
    counted_session_.reset();
}

NativeClientStatus SessionKeeper::status() const {
    std::lock_guard<std::mutex> lock(status_mutex_);
    NativeClientStatus copy = published_;
    copy.traffic = traffic_locked();
    return copy;
}

void SessionKeeper::record_failure(const Status& failure) noexcept {
    transition(
        [&](NativeClientStatus& current) { current.last_failure = failure; });
}

void SessionKeeper::connect() noexcept {
    if (closing_ || !endpoint_) return;
    Status status;
    try {
        status = endpoint_->async_start_session(
            [weak = weak_from_this()](
                Result<std::shared_ptr<engine::SessionEngine>> result) {
                if (const auto self = weak.lock())
                    self->on_session(std::move(result));
            });
    } catch (const std::bad_alloc&) {
        status = Status(StatusCode::ResourceExhausted);
    } catch (...) {
        status = Status(StatusCode::Internal);
    }
    if (!status.ok()) {
        try {
            say(describe("session start refused", status));
        } catch (...) {
        }
        schedule_reconnect(&status);
        return;
    }
    transition([](NativeClientStatus& current) {
        current.state = NativeClientState::Connecting;
        current.retry_delay = std::chrono::milliseconds(0);
    });
}

void SessionKeeper::on_session(
    Result<std::shared_ptr<engine::SessionEngine>> result) noexcept {
    if (closing_) {
        if (result.ok() && result.value())
            result.value()->stop(Status(StatusCode::Closed));
        return;
    }
    if (!result.ok()) {
        try {
            say(describe("session failed", result.status()));
        } catch (...) {
        }
        schedule_reconnect(&result.status());
        return;
    }
    session_ = std::move(result).take_value();
    authenticated_at_ = Clock::now();
    {
        std::lock_guard<std::mutex> lock(status_mutex_);
        counted_session_ = session_;
    }
    const auto peer = session_->authenticated_peer();
    const auto epoch_bytes = session_->epoch_bytes();
    transition([&](NativeClientStatus& current) {
        current.state = NativeClientState::Connected;
        current.connected_since = authenticated_at_;
        current.retry_delay = std::chrono::milliseconds(0);
        ++current.sessions;
        current.failed_attempts = 0U;
        current.epoch_bytes = epoch_bytes;
        current.server_identity.clear();
        if (peer.ok()) current.server_identity = peer.value().identity();
    });
    say("session authenticated");
    if (options_.on_authenticated) {
        const auto active = session_;
        try {
            options_.on_authenticated(active);
        } catch (...) {
        }
    }
}

void SessionKeeper::on_session_ended(
    const std::shared_ptr<engine::SessionEngine>& ended,
    const Status& reason) noexcept {
    if (closing_ || session_ != ended) return;
    session_.reset();
    retire_counted_session();
    transition([&](NativeClientStatus& current) {
        current.server_identity.clear();
        current.epoch_bytes.reset();
        current.last_failure = reason;
    });
    say("session ended, reconnecting");
    // Reconnect at once only after a session that stayed up for the longest
    // backoff. A path that drops every connection right after AUTH would
    // otherwise redial in a tight loop, which stands out on the wire and uses
    // up entries in the server's admission replay cache, shared by every
    // client.
    if (Clock::now() - authenticated_at_ >= options_.reconnect_max) {
        backoff_ = options_.reconnect_initial;
        connect();
    } else {
        schedule_reconnect();
    }
}

// The retry timer is armed before the status update, so a status copy never
// takes the allocation that arming depends on.
void SessionKeeper::schedule_reconnect(const Status* failure) noexcept {
    if (closing_) return;
    const auto delay = backoff_;
    backoff_ = std::min(backoff_ * 2, options_.reconnect_max);
    try {
        timer_.expires_after(delay);
        timer_.async_wait(
            [weak = weak_from_this()](const boost::system::error_code& error) {
                const auto self = weak.lock();
                if (!self || self->closing_) return;
                if (error) {
                    self->fail(Status(StatusCode::Internal));
                    return;
                }
                self->connect();
            });
    } catch (const std::bad_alloc&) {
        fail(Status(StatusCode::ResourceExhausted));
        return;
    } catch (...) {
        fail(Status(StatusCode::Internal));
        return;
    }
    transition([&](NativeClientStatus& current) {
        current.state = NativeClientState::Waiting;
        current.server_identity.clear();
        current.epoch_bytes.reset();
        current.retry_delay = delay;
        if (failure) {
            ++current.failed_attempts;
            current.last_failure = *failure;
        }
    });
}

void SessionKeeper::fail(Status status) noexcept {
    if (closing_) return;
    auto failure = std::exchange(on_failure_, {});
    if (failure) {
        try {
            failure(std::move(status));
            return;
        } catch (...) {
        }
    }
    record_failure(status);
    close();
}

void SessionKeeper::close() noexcept {
    if (closing_) return;
    closing_ = true;
    boost::system::error_code ignored;
    timer_.cancel(ignored);
    session_.reset();
    retire_counted_session();
    on_failure_ = {};
    transition([](NativeClientStatus& current) {
        current.state = NativeClientState::Closed;
        current.server_identity.clear();
        current.epoch_bytes.reset();
        current.retry_delay = std::chrono::milliseconds(0);
    });
}

}  // namespace yume::runtime
