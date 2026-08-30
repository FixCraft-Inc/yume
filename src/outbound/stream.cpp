/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "outbound/stream.hpp"

#include "core/security/secure_erase.hpp"

namespace yume::outbound {

ClientTransportStream::ClientTransportStream(OpenSslStream&& stream)
    : stream_(std::make_unique<OpenSslStream>(std::move(stream))) {}

ClientTransportStream::ClientTransportStream(
        HelperSocket&& socket,
        TlsConnectionMetadata metadata,
        std::shared_ptr<HelperProcessLifetime> helper_lifetime)
    : stream_(std::make_unique<HelperSocket>(std::move(socket))),
      metadata_(std::move(metadata)),
      helper_lifetime_(std::move(helper_lifetime)) {}

ClientTransportStream::~ClientTransportStream() {
    security::secure_erase(metadata_.exporter);
}

ClientTransportStream::executor_type ClientTransportStream::get_executor() {
    return std::visit([](auto& stream) { return stream->get_executor(); }, stream_);
}

bool ClientTransportStream::is_helper() const noexcept {
    return std::holds_alternative<std::unique_ptr<HelperSocket>>(stream_);
}

ClientTransportStream::OpenSslStream*
ClientTransportStream::openssl_stream() noexcept {
    auto* stream = std::get_if<std::unique_ptr<OpenSslStream>>(&stream_);
    return stream ? stream->get() : nullptr;
}

void ClientTransportStream::set_metadata(TlsConnectionMetadata metadata) {
    security::secure_erase(metadata_.exporter);
    metadata_ = std::move(metadata);
}

std::vector<std::uint8_t> ClientTransportStream::take_exporter() {
    std::vector<std::uint8_t> exporter = std::move(metadata_.exporter);
    metadata_.exporter.clear();
    return exporter;
}

void ClientTransportStream::set_socket_buffers(int bytes) {
    auto* stream = std::get_if<std::unique_ptr<OpenSslStream>>(&stream_);
    if (!stream) {
        return;
    }
    boost::system::error_code ignored;
    (*stream)->lowest_layer().set_option(
        boost::asio::socket_base::receive_buffer_size(bytes), ignored);
    (*stream)->lowest_layer().set_option(
        boost::asio::socket_base::send_buffer_size(bytes), ignored);
}

void ClientTransportStream::cancel_and_close() noexcept {
    std::visit([](auto& stream) {
        boost::system::error_code ignored;
        using Stream = typename std::decay_t<decltype(stream)>::element_type;
        if constexpr (std::is_same_v<Stream, OpenSslStream>) {
            stream->lowest_layer().cancel(ignored);
            stream->lowest_layer().shutdown(
                boost::asio::ip::tcp::socket::shutdown_both, ignored);
            stream->lowest_layer().close(ignored);
        } else {
            stream->cancel(ignored);
            stream->shutdown(boost::asio::socket_base::shutdown_both, ignored);
            stream->close(ignored);
        }
    }, stream_);
}

void ClientTransportStream::shutdown_and_close() noexcept {
    std::visit([](auto& stream) {
        boost::system::error_code ignored;
        using Stream = typename std::decay_t<decltype(stream)>::element_type;
        if constexpr (std::is_same_v<Stream, OpenSslStream>) {
            stream->shutdown(ignored);
            stream->lowest_layer().close(ignored);
        } else {
            stream->shutdown(boost::asio::socket_base::shutdown_both, ignored);
            stream->close(ignored);
        }
    }, stream_);
}

}  // namespace yume::outbound
