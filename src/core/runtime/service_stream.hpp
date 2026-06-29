/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace yume::runtime {

struct ServicePeerInfo {
    std::string service;
    std::string peer;
    std::string auth_fingerprint_sha256;
    std::string session_id;
    std::string server_session_id;
    std::string remote_addr;
};

class ServiceStream {
public:
    using Bytes = std::vector<std::uint8_t>;
    using WriteCallback = std::function<bool(Bytes, std::string*)>;
    using CloseCallback = std::function<void(std::string)>;

    enum class ReadResult {
        Data,
        Eof,
        Timeout,
        Closed,
    };

    ServiceStream(std::string service, std::string peer);
    ServiceStream(std::string service, std::string peer, ServicePeerInfo peer_info);
    ~ServiceStream();

    ServiceStream(const ServiceStream&) = delete;
    ServiceStream& operator=(const ServiceStream&) = delete;

    const std::string& service() const noexcept;
    const std::string& peer() const noexcept;
    ServicePeerInfo peer_info() const;

    void set_callbacks(WriteCallback write_cb,
                       CloseCallback close_cb,
                       CloseCallback shutdown_write_cb);

    bool write(const void* data, std::size_t size, std::string* error);
    bool shutdown_write(std::string* error);
    void close(std::string reason);

    ReadResult read(void* out,
                    std::size_t capacity,
                    std::uint32_t timeout_ms,
                    std::size_t* bytes_read,
                    std::string* reason);

    void receive_data(Bytes data);
    void receive_fin(std::string reason);
    void receive_close(std::string reason);

    bool closed() const;

private:
    std::string service_;
    std::string peer_;
    ServicePeerInfo peer_info_;

    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::deque<Bytes> incoming_;
    Bytes current_;
    std::size_t current_offset_{0};
    bool remote_fin_{false};
    bool remote_closed_{false};
    bool local_closed_{false};
    bool local_fin_sent_{false};
    std::string close_reason_;

    WriteCallback write_cb_;
    CloseCallback close_cb_;
    CloseCallback shutdown_write_cb_;
};

}  // namespace yume::runtime
