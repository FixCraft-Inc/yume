/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "core/obfs.hpp"

#include "core/http_profile.hpp"

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
constexpr unsigned char kAlpnHttp1[] = {
    8, 'h', 't', 't', 'p', '/', '1', '.', '1'
};

int alpn_select_cb(SSL* /*ssl*/, const unsigned char** out, unsigned char* outlen,
                   const unsigned char* in, unsigned int inlen, void* arg) {
    const unsigned char* protos = kAlpnProtos;
    unsigned int protos_len = sizeof(kAlpnProtos);
    if (arg) {
        protos = static_cast<const unsigned char*>(arg);
        protos_len = static_cast<unsigned int>(protos[0]) + 1;
    }
    int rc = SSL_select_next_proto(const_cast<unsigned char**>(out), outlen,
                                   protos, protos_len,
                                   in, inlen);
    return (rc == OPENSSL_NPN_NEGOTIATED) ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_NOACK;
}
}  // namespace

boost::asio::ssl::context create_server_context(const std::string& cert_path,
                                               const std::string& key_path,
                                               bool allow_h2) {
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tlsv13_server);
    ctx.set_options(boost::asio::ssl::context::default_workarounds);
    SSL_CTX_set_min_proto_version(ctx.native_handle(), TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx.native_handle(), TLS1_3_VERSION);

    ctx.use_certificate_chain_file(cert_path);
    ctx.use_private_key_file(key_path, boost::asio::ssl::context::file_format::pem);

    configure_alpn(ctx, true, allow_h2);
    return ctx;
}

boost::asio::ssl::context create_client_context() {
    boost::asio::ssl::context ctx(boost::asio::ssl::context::tlsv13_client);
    ctx.set_options(boost::asio::ssl::context::default_workarounds);
    SSL_CTX_set_min_proto_version(ctx.native_handle(), TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx.native_handle(), TLS1_3_VERSION);

    configure_alpn(ctx, false, true);
    return ctx;
}

void configure_alpn(boost::asio::ssl::context& ctx, bool is_server, bool allow_h2) {
    SSL_CTX* native = ctx.native_handle();
    const unsigned char* protos = kAlpnProtos;
    unsigned int protos_len = sizeof(kAlpnProtos);
    if (!allow_h2) {
        protos = kAlpnHttp1;
        protos_len = sizeof(kAlpnHttp1);
    }
    if (is_server) {
        SSL_CTX_set_alpn_select_cb(native, alpn_select_cb, allow_h2 ? nullptr : const_cast<unsigned char*>(protos));
    } else {
        SSL_CTX_set_alpn_protos(native, protos, protos_len);
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

void send_dummy_http_response(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                              const std::string& profile_name) {
    // Resolve the profile; fall back to yumed if unknown so a typo
    // doesn't take down a connection. yumed is the historical default
    // and preserves pre-1.0 byte-for-byte behavior unless an operator
    // passed --hide-in-the-crowd.
    auto profile = yume::http_profile::server(profile_name.empty() ? "yumed" : profile_name);
    if (!profile.has_value()) {
        profile = yume::http_profile::server("yumed");
    }
    const std::string resp = yume::http_profile::render_404(*profile, /*connection_close=*/true);
    boost::asio::write(stream, boost::asio::buffer(resp));
}

}  // namespace yume::obfs
