/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Renders the ClientHello the production openssl-diagnostic backend actually
// emits and writes the raw bytes to a file, so the wire gates can compare
// emitted bytes against the committed browser capture instead of comparing
// config to config. Nothing here constructs a ClientHello by hand: it drives
// the real StealthContext and captures what OpenSSL puts on the wire.
//
// The handshake is run against a memory BIO with no peer, so no network
// traffic is generated and no server is required -- OpenSSL writes the
// ClientHello into the write BIO and then blocks waiting for a ServerHello
// that never arrives, which is exactly the point we snapshot.

#include <openssl/ssl.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "core/stealth/cover_profile.hpp"
#include "core/stealth/tls_stealth.hpp"

namespace {

int usage() {
    std::fprintf(stderr,
                 "usage: yume_tls_clienthello_dump --output PATH [--sni NAME]\n");
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    std::string output;
    std::string sni = "example.org";
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--output" && i + 1 < argc)   output = argv[++i];
        else if (arg == "--sni" && i + 1 < argc) sni = argv[++i];
        else return usage();
    }
    if (output.empty()) return usage();

    try {
        yume::tls_stealth::StealthConfig config;
        yume::tls_stealth::StealthContext context(config);
        context.apply_stealth_profile(yume::cover_profile::active().tls_profile);

        SSL_CTX* ctx = context.get_context().native_handle();
        SSL* ssl = SSL_new(ctx);
        if (ssl == nullptr) {
            std::fprintf(stderr, "SSL_new failed\n");
            return 1;
        }
        if (SSL_set_tlsext_host_name(ssl, sni.c_str()) != 1) {
            std::fprintf(stderr, "failed to set SNI\n");
            SSL_free(ssl);
            return 1;
        }
        BIO* read_bio = BIO_new(BIO_s_mem());
        BIO* write_bio = BIO_new(BIO_s_mem());
        if (read_bio == nullptr || write_bio == nullptr) {
            std::fprintf(stderr, "failed to allocate handshake BIOs\n");
            BIO_free(read_bio);
            BIO_free(write_bio);
            SSL_free(ssl);
            return 1;
        }
        SSL_set_bio(ssl, read_bio, write_bio);  // takes ownership of both
        SSL_set_connect_state(ssl);
        const int handshake_rc = SSL_do_handshake(ssl);
        const int handshake_error = SSL_get_error(ssl, handshake_rc);
        if (handshake_rc == 1 || handshake_error != SSL_ERROR_WANT_READ) {
            std::fprintf(stderr,
                         "ClientHello render failed unexpectedly (SSL error %d)\n",
                         handshake_error);
            SSL_free(ssl);
            return 1;
        }

        char* data = nullptr;
        const long length = BIO_get_mem_data(write_bio, &data);
        if (length <= 0 || data == nullptr) {
            std::fprintf(stderr, "no ClientHello was rendered\n");
            SSL_free(ssl);
            return 1;
        }
        std::FILE* out = std::fopen(output.c_str(), "wb");
        if (out == nullptr) {
            std::fprintf(stderr, "cannot open %s\n", output.c_str());
            SSL_free(ssl);
            return 1;
        }
        const size_t written =
            std::fwrite(data, 1, static_cast<size_t>(length), out);
        const bool ok = written == static_cast<size_t>(length);
        if (std::fclose(out) != 0 || !ok) {
            std::fprintf(stderr, "short write to %s\n", output.c_str());
            SSL_free(ssl);
            return 1;
        }
        SSL_free(ssl);
        std::fprintf(stderr, "wrote %ld ClientHello bytes to %s\n",
                     length, output.c_str());
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "clienthello dump failed: %s\n", error.what());
        return 1;
    }
}
