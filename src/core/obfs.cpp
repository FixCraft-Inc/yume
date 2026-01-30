/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "core/obfs.hpp"

#include <openssl/ssl.h>

#include <chrono>
#include <random>
#include <thread>

namespace yume::obfs {

namespace {
constexpr unsigned char kAlpnProtos[] = {
    2, 'h', '2',
    8, 'h', 't', 't', 'p', '/', '1', '.', '1'
};

int alpn_select_cb(SSL* /*ssl*/, const unsigned char** out, unsigned char* outlen,
                   const unsigned char* in, unsigned int inlen, void* /*arg*/) {
    int rc = SSL_select_next_proto(const_cast<unsigned char**>(out), outlen,
                                   kAlpnProtos, sizeof(kAlpnProtos),
                                   in, inlen);
    return (rc == OPENSSL_NPN_NEGOTIATED) ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_NOACK;
}
}  // namespace

boost::asio::ssl::context create_server_context(const std::string& cert_path,
                                               const std::string& key_path) {
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls_server);
    ctx.set_options(boost::asio::ssl::context::default_workarounds |
                    boost::asio::ssl::context::no_sslv2 |
                    boost::asio::ssl::context::no_sslv3 |
                    boost::asio::ssl::context::no_tlsv1 |
                    boost::asio::ssl::context::no_tlsv1_1 |
                    boost::asio::ssl::context::no_tlsv1_2);

    SSL_CTX_set_min_proto_version(ctx.native_handle(), TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx.native_handle(), TLS1_3_VERSION);

    ctx.use_certificate_chain_file(cert_path);
    ctx.use_private_key_file(key_path, boost::asio::ssl::context::file_format::pem);

    configure_alpn(ctx, true);
    return ctx;
}

boost::asio::ssl::context create_client_context() {
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tls_client);
    ctx.set_options(boost::asio::ssl::context::default_workarounds |
                    boost::asio::ssl::context::no_sslv2 |
                    boost::asio::ssl::context::no_sslv3 |
                    boost::asio::ssl::context::no_tlsv1 |
                    boost::asio::ssl::context::no_tlsv1_1 |
                    boost::asio::ssl::context::no_tlsv1_2);

    SSL_CTX_set_min_proto_version(ctx.native_handle(), TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx.native_handle(), TLS1_3_VERSION);

    configure_alpn(ctx, false);
    return ctx;
}

void configure_alpn(boost::asio::ssl::context& ctx, bool is_server) {
    SSL_CTX* native = ctx.native_handle();
    if (is_server) {
        SSL_CTX_set_alpn_select_cb(native, alpn_select_cb, nullptr);
    } else {
        SSL_CTX_set_alpn_protos(native, kAlpnProtos, sizeof(kAlpnProtos));
    }
}

void apply_jitter(int max_jitter_ms) {
    if (max_jitter_ms <= 0) {
        return;
    }
    thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<int> dist(0, max_jitter_ms);
    std::this_thread::sleep_for(std::chrono::milliseconds(dist(rng)));
}

void send_dummy_http_response(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream) {
    static const char kResp[] =
        "HTTP/1.1 404 Not Found\r\n"
        "Server: yumed\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n";
    boost::asio::write(stream, boost::asio::buffer(kResp, sizeof(kResp) - 1));
}

}  // namespace yume::obfs
