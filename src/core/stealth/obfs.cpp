/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "core/stealth/obfs.hpp"

#include <openssl/ssl.h>

#include <stdexcept>

namespace yume::obfs {

namespace {
bool protocol_list_contains(const unsigned char* protos,
                            unsigned int protos_len,
                            const std::string& needle,
                            const unsigned char** selected,
                            unsigned char* selected_len) {
    if (!protos || needle.size() > 255) {
        return false;
    }
    unsigned int pos = 0;
    while (pos < protos_len) {
        const unsigned int len = protos[pos++];
        if (len == 0 || pos + len > protos_len) {
            return false;
        }
        const char* proto = reinterpret_cast<const char*>(protos + pos);
        if (needle.size() == len && needle.compare(0, needle.size(), proto, len) == 0) {
            if (selected) {
                *selected = protos + pos;
            }
            if (selected_len) {
                *selected_len = static_cast<unsigned char>(len);
            }
            return true;
        }
        pos += len;
    }
    return false;
}

int alpn_select_cb(SSL* /*ssl*/, const unsigned char** out, unsigned char* outlen,
                   const unsigned char* in, unsigned int inlen, void* arg) {
    const bool allow_h2 = arg ? *static_cast<const bool*>(arg) : true;
    for (const auto& proto : carrier_alpn_protocols(allow_h2)) {
        if (protocol_list_contains(in, inlen, proto, out, outlen)) {
            return SSL_TLSEXT_ERR_OK;
        }
    }
    return SSL_TLSEXT_ERR_NOACK;
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
    if (is_server) {
        static bool kAllowH2 = true;
        static bool kHttp1Only = false;
        SSL_CTX_set_alpn_select_cb(native, alpn_select_cb, allow_h2 ? &kAllowH2 : &kHttp1Only);
    } else {
        const auto protos = carrier_alpn_wire(allow_h2);
        if (SSL_CTX_set_alpn_protos(native,
                                    protos.data(),
                                    static_cast<unsigned int>(protos.size())) != 0) {
            throw std::runtime_error("failed to configure TLS ALPN protocols");
        }
    }
}

std::vector<std::string> carrier_alpn_protocols(bool allow_h2) {
    if (allow_h2) {
        return {"h2", "http/1.1"};
    }
    return {"http/1.1"};
}

std::vector<unsigned char> carrier_alpn_wire(bool allow_h2) {
    std::vector<unsigned char> out;
    for (const auto& proto : carrier_alpn_protocols(allow_h2)) {
        if (proto.empty() || proto.size() > 255) {
            throw std::invalid_argument("invalid ALPN protocol length");
        }
        out.push_back(static_cast<unsigned char>(proto.size()));
        out.insert(out.end(), proto.begin(), proto.end());
    }
    return out;
}

std::string select_carrier_alpn(const unsigned char* peer_protos,
                                unsigned int peer_protos_len,
                                bool allow_h2) {
    for (const auto& proto : carrier_alpn_protocols(allow_h2)) {
        if (protocol_list_contains(peer_protos, peer_protos_len, proto, nullptr, nullptr)) {
            return proto;
        }
    }
    return {};
}

std::string selected_alpn(const SSL* ssl) {
    const unsigned char* data = nullptr;
    unsigned int len = 0;
    SSL_get0_alpn_selected(ssl, &data, &len);
    if (!data || len == 0) {
        return {};
    }
    return std::string(reinterpret_cast<const char*>(data), static_cast<std::size_t>(len));
}

}  // namespace yume::obfs
