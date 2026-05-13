/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace yume::facade {

enum class ConnectionState {
    Idle,
    Resolving,
    Connecting,
    TlsHandshake,
    Authenticating,
    Connected,
    Reconnecting,
    Failed,
    Disconnected,
};

const char* to_string(ConnectionState s) noexcept;
// UI-friendly title-cased form ("Disconnected", "Connecting", ...).
const char* display_label(ConnectionState s) noexcept;

struct ClientStatus {
    ConnectionState state{ConnectionState::Idle};
    std::string message;
    std::string server_endpoint;
    std::string profile;
    std::string inner_mode;
    std::uint64_t bytes_sent{0};
    std::uint64_t bytes_received{0};
    double tx_rate_bps{0.0};
    double rx_rate_bps{0.0};
    std::chrono::system_clock::time_point connected_since{};
};

struct ServerStatus {
    bool running{false};
    std::string listen_endpoint;
    std::string ipc_path;
    std::string message;
    std::size_t active_sessions{0};
    std::size_t authorized_keys_count{0};
    std::uint64_t bytes_in{0};
    std::uint64_t bytes_out{0};
    std::chrono::system_clock::time_point started{};
};

enum class LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Critical,
};

const char* to_string(LogLevel lvl) noexcept;

struct LogEntry {
    std::chrono::system_clock::time_point ts{};
    LogLevel level{LogLevel::Info};
    std::string component;
    std::string message;
};

}  // namespace yume::facade
