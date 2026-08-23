/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/ssl.hpp>

#include <openssl/ssl.h>

namespace yume::client {

class HelperProcessLifetime {
public:
    virtual ~HelperProcessLifetime() = default;
};

struct TlsConnectionMetadata {
    std::string alpn;
    std::string leaf_fingerprint_sha256;
    std::vector<std::uint8_t> exporter;
};

// One asynchronous plaintext stream for every client transport consumer.
// OpenSSL performs TLS in-process; the Chrome backend receives authenticated
// plaintext from a per-connection helper over a private Unix socketpair.
class ClientTransportStream {
public:
    using OpenSslStream =
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
    using HelperSocket = boost::asio::local::stream_protocol::socket;
    using executor_type = boost::asio::any_io_executor;

    explicit ClientTransportStream(OpenSslStream&& stream);
    ClientTransportStream(HelperSocket&& socket,
                          TlsConnectionMetadata metadata,
                          std::shared_ptr<HelperProcessLifetime> helper_lifetime);
    ~ClientTransportStream();

    ClientTransportStream(ClientTransportStream&&) noexcept = default;
    ClientTransportStream& operator=(ClientTransportStream&&) noexcept = delete;
    ClientTransportStream(const ClientTransportStream&) = delete;
    ClientTransportStream& operator=(const ClientTransportStream&) = delete;

    executor_type get_executor();

    template <typename MutableBufferSequence, typename ReadToken>
    auto async_read_some(const MutableBufferSequence& buffers,
                         ReadToken&& token) {
        return std::visit(
            [&](auto& stream) {
                return stream->async_read_some(
                    buffers, std::forward<ReadToken>(token));
            },
            stream_);
    }

    template <typename ConstBufferSequence, typename WriteToken>
    auto async_write_some(const ConstBufferSequence& buffers,
                          WriteToken&& token) {
        return std::visit(
            [&](auto& stream) {
                return stream->async_write_some(
                    buffers, std::forward<WriteToken>(token));
            },
            stream_);
    }

    template <typename MutableBufferSequence>
    std::size_t read_some(const MutableBufferSequence& buffers,
                          boost::system::error_code& error) {
        return std::visit(
            [&](auto& stream) { return stream->read_some(buffers, error); },
            stream_);
    }

    template <typename ConstBufferSequence>
    std::size_t write_some(const ConstBufferSequence& buffers,
                           boost::system::error_code& error) {
        return std::visit(
            [&](auto& stream) { return stream->write_some(buffers, error); },
            stream_);
    }

    bool is_helper() const noexcept;
    OpenSslStream* openssl_stream() noexcept;
    void set_metadata(TlsConnectionMetadata metadata);
    const TlsConnectionMetadata& metadata() const noexcept { return metadata_; }
    std::vector<std::uint8_t> take_exporter();

    // Pins SO_RCVBUF/SO_SNDBUF. Do NOT call this on the tunnel socket: any
    // explicit value sets SOCK_{RCV,SND}BUF_LOCK on Linux and disables window
    // autotuning for the connection's lifetime, which caps throughput at a
    // fraction of the bandwidth-delay product on a delayed path. Retained for
    // loopback sockets, where there is no BDP to grow into.
    void set_socket_buffers(int bytes);
    void cancel_and_close() noexcept;
    void shutdown_and_close() noexcept;

private:
    std::variant<std::unique_ptr<OpenSslStream>,
                 std::unique_ptr<HelperSocket>> stream_;
    TlsConnectionMetadata metadata_;
    std::shared_ptr<HelperProcessLifetime> helper_lifetime_;
};

}  // namespace yume::client
