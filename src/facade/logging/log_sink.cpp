/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/logging/log_sink.hpp"

#include <algorithm>
#include <chrono>
#include <utility>

#if YUME_FACADE_HAVE_SPDLOG
#include <spdlog/sinks/base_sink.h>
#include <spdlog/spdlog.h>
#endif

namespace yume::facade {

#if YUME_FACADE_HAVE_SPDLOG
namespace {

class FacadeSpdSink : public spdlog::sinks::base_sink<std::mutex> {
public:
    explicit FacadeSpdSink(LogSink& target) : target_(target) {}

protected:
    void sink_it_(const spdlog::details::log_msg& msg) override {
        LogEntry entry;
        entry.ts = std::chrono::system_clock::now();
        switch (msg.level) {
            case spdlog::level::trace:    entry.level = LogLevel::Trace; break;
            case spdlog::level::debug:    entry.level = LogLevel::Debug; break;
            case spdlog::level::info:     entry.level = LogLevel::Info; break;
            case spdlog::level::warn:     entry.level = LogLevel::Warn; break;
            case spdlog::level::err:      entry.level = LogLevel::Error; break;
            case spdlog::level::critical: entry.level = LogLevel::Critical; break;
            default:                      entry.level = LogLevel::Info; break;
        }
        entry.component.assign(msg.logger_name.data(), msg.logger_name.size());
        entry.message.assign(msg.payload.data(), msg.payload.size());
        target_.push(std::move(entry));
    }
    void flush_() override {}

private:
    LogSink& target_;
};

}  // namespace
#endif

const char* to_string(ConnectionState s) noexcept {
    switch (s) {
        case ConnectionState::Idle:           return "idle";
        case ConnectionState::Resolving:      return "resolving";
        case ConnectionState::Connecting:     return "connecting";
        case ConnectionState::TlsHandshake:   return "tls_handshake";
        case ConnectionState::Authenticating: return "authenticating";
        case ConnectionState::Connected:      return "connected";
        case ConnectionState::Reconnecting:   return "reconnecting";
        case ConnectionState::Failed:         return "failed";
        case ConnectionState::Disconnected:   return "disconnected";
    }
    return "unknown";
}

const char* display_label(ConnectionState s) noexcept {
    switch (s) {
        case ConnectionState::Idle:           return "Idle";
        case ConnectionState::Resolving:      return "Resolving";
        case ConnectionState::Connecting:     return "Connecting";
        case ConnectionState::TlsHandshake:   return "TLS handshake";
        case ConnectionState::Authenticating: return "Authenticating";
        case ConnectionState::Connected:      return "Connected";
        case ConnectionState::Reconnecting:   return "Reconnecting";
        case ConnectionState::Failed:         return "Failed";
        case ConnectionState::Disconnected:   return "Disconnected";
    }
    return "Unknown";
}

const char* to_string(LogLevel lvl) noexcept {
    switch (lvl) {
        case LogLevel::Trace:    return "trace";
        case LogLevel::Debug:    return "debug";
        case LogLevel::Info:     return "info";
        case LogLevel::Warn:     return "warn";
        case LogLevel::Error:    return "error";
        case LogLevel::Critical: return "critical";
    }
    return "info";
}

LogSink& LogSink::instance() {
    static LogSink s;
    return s;
}

LogSink::LogSink() {
    ring_.resize(kCapacity);
    install_spdlog_sink();
}

void LogSink::install_spdlog_sink() {
#if YUME_FACADE_HAVE_SPDLOG
    try {
        auto sink = std::make_shared<FacadeSpdSink>(*this);
        if (auto logger = spdlog::default_logger()) {
            // Replace the spdlog default logger's sinks rather than
            // append. spdlog ships a stdout colour sink by default;
            // appending would mean every log line is both shown in
            // the GUI viewer AND printed to the terminal that
            // launched yume-gui. yume_facade is only linked into the
            // GUI binary (the CLI does its own spdlog setup), so
            // claiming the sink list here is safe.
            logger->sinks().clear();
            logger->sinks().push_back(sink);
        }
    } catch (...) {
        // Best-effort: if spdlog isn't initialised we just remain a passive
        // ring buffer reachable via push().
    }
#endif
}

void LogSink::push(LogEntry entry) {
    std::vector<std::pair<int, Subscriber>> subs_copy;
    LogEntry delivered = entry;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (size_ < kCapacity) {
            ring_[(head_ + size_) % kCapacity] = std::move(entry);
            ++size_;
        } else {
            ring_[head_] = std::move(entry);
            head_ = (head_ + 1) % kCapacity;
            ++dropped_;
        }
        subs_copy = subscribers_;
    }
    // Consumer callbacks may re-enter the sink, unsubscribe themselves, or
    // throw. Invoke a stable copy after releasing the ring lock and contain
    // failures so diagnostics cannot unwind a transport/lifecycle worker.
    for (auto& [token, cb] : subs_copy) {
        (void)token;
        if (!cb) continue;
        try {
            cb(delivered);
        } catch (...) {
        }
    }
}

void LogSink::push(LogLevel level, std::string component, std::string message) {
    LogEntry entry;
    entry.ts = std::chrono::system_clock::now();
    entry.level = level;
    entry.component = std::move(component);
    entry.message = std::move(message);
    push(std::move(entry));
}

std::vector<LogEntry> LogSink::snapshot(std::size_t max) const {
    std::lock_guard<std::mutex> lock(mtx_);
    const std::size_t n = std::min(max, size_);
    std::vector<LogEntry> out;
    out.reserve(n);
    const std::size_t start = (head_ + size_ - n) % kCapacity;
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(ring_[(start + i) % kCapacity]);
    }
    return out;
}

std::size_t LogSink::dropped() const noexcept {
    std::lock_guard<std::mutex> lock(mtx_);
    return dropped_;
}

void LogSink::clear() {
    std::lock_guard<std::mutex> lock(mtx_);
    head_ = 0;
    size_ = 0;
    dropped_ = 0;
}

int LogSink::subscribe(Subscriber cb) {
    std::lock_guard<std::mutex> lock(mtx_);
    const int token = next_token_++;
    subscribers_.emplace_back(token, std::move(cb));
    return token;
}

void LogSink::unsubscribe(int token) {
    std::lock_guard<std::mutex> lock(mtx_);
    subscribers_.erase(
        std::remove_if(subscribers_.begin(), subscribers_.end(),
                       [token](auto const& p) { return p.first == token; }),
        subscribers_.end());
}

}  // namespace yume::facade
