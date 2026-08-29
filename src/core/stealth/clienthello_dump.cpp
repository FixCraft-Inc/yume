/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Renders the ClientHello emitted by either native OpenSSL backend and writes
// raw bytes to files, so the wire gates can compare
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
#include <exception>
#include <limits>
#include <string>
#include <vector>

#include "core/stealth/cover_profile.hpp"
#include "core/stealth/tls_stealth.hpp"

namespace {

int usage() {
    std::fprintf(stderr,
                 "usage: yume_tls_clienthello_dump --output PATH [--sni NAME] "
                 "[--backend openssl-diagnostic|openssl-chrome151] [--count N]\n"
                 "When N > 1, files are written as PATH.0 through PATH.(N-1).\n");
    return 2;
}

bool render_client_hello(SSL_CTX* ctx, const std::string& sni,
                         std::vector<unsigned char>* output) {
    SSL* ssl = SSL_new(ctx);
    if (ssl == nullptr) {
        std::fprintf(stderr, "SSL_new failed\n");
        return false;
    }
    if (SSL_set_tlsext_host_name(ssl, sni.c_str()) != 1) {
        std::fprintf(stderr, "failed to set SNI\n");
        SSL_free(ssl);
        return false;
    }
    BIO* read_bio = BIO_new(BIO_s_mem());
    BIO* write_bio = BIO_new(BIO_s_mem());
    if (read_bio == nullptr || write_bio == nullptr) {
        std::fprintf(stderr, "failed to allocate handshake BIOs\n");
        BIO_free(read_bio);
        BIO_free(write_bio);
        SSL_free(ssl);
        return false;
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
        return false;
    }

    char* data = nullptr;
    const long length = BIO_get_mem_data(write_bio, &data);
    if (length <= 0 || data == nullptr) {
        std::fprintf(stderr, "no ClientHello was rendered\n");
        SSL_free(ssl);
        return false;
    }
    const auto* begin = reinterpret_cast<const unsigned char*>(data);
    output->assign(begin, begin + length);
    SSL_free(ssl);
    return true;
}

bool write_bytes(const std::string& path,
                 const std::vector<unsigned char>& bytes) {
    std::FILE* out = std::fopen(path.c_str(), "wb");
    if (out == nullptr) {
        std::fprintf(stderr, "cannot open %s\n", path.c_str());
        return false;
    }
    const size_t written = std::fwrite(bytes.data(), 1, bytes.size(), out);
    const bool ok = written == bytes.size();
    if (std::fclose(out) != 0 || !ok) {
        std::fprintf(stderr, "short write to %s\n", path.c_str());
        return false;
    }
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    std::string output;
    std::string sni = "example.org";
    std::string backend = "openssl-diagnostic";
    unsigned count = 1;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--output" && i + 1 < argc)   output = argv[++i];
        else if (arg == "--sni" && i + 1 < argc) sni = argv[++i];
        else if (arg == "--backend" && i + 1 < argc) backend = argv[++i];
        else if (arg == "--count" && i + 1 < argc) {
            unsigned long parsed = 0;
            std::size_t consumed = 0;
            const std::string value = argv[++i];
            try {
                parsed = std::stoul(value, &consumed);
            } catch (const std::exception&) {
                return usage();
            }
            if (consumed != value.size() || parsed == 0 || parsed > 64 ||
                parsed > std::numeric_limits<unsigned>::max()) {
                return usage();
            }
            count = static_cast<unsigned>(parsed);
        }
        else return usage();
    }
    if (output.empty() ||
        (backend != "openssl-diagnostic" && backend != "openssl-chrome151")) {
        return usage();
    }

    try {
        yume::tls_stealth::StealthConfig config;
        config.enabled = true;
        config.native_chrome_client_hello = backend == "openssl-chrome151";
        config.target_profile = yume::cover_profile::active().tls_profile;
        yume::tls_stealth::StealthContext context(config);

        SSL_CTX* ctx = context.get_context().native_handle();
        for (unsigned index = 0; index < count; ++index) {
            std::vector<unsigned char> bytes;
            const std::string path = count == 1
                ? output : output + "." + std::to_string(index);
            if (!render_client_hello(ctx, sni, &bytes) ||
                !write_bytes(path, bytes)) {
                return 1;
            }
            std::fprintf(stderr, "wrote %zu ClientHello bytes to %s\n",
                         bytes.size(), path.c_str());
        }
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "clienthello dump failed: %s\n", error.what());
        return 1;
    }
}
