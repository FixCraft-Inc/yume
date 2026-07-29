/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Exercises the AUTH channel binding against real TLS 1.3 handshakes driven
 * over BIO pairs. The properties that matter for the relay threat are that
 * both endpoints of one connection agree, and that two connections never do.
 */

#include "core/security/channel_binding.hpp"

#include <cassert>
#include <stdexcept>
#include <vector>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace {

using Bytes = std::vector<std::uint8_t>;

template <typename Fn>
bool Throws(Fn&& fn) {
    try {
        fn();
        return false;
    } catch (const std::exception&) {
        return true;
    }
}

struct SelfSignedIdentity {
    EVP_PKEY* key{nullptr};
    X509* cert{nullptr};

    ~SelfSignedIdentity() {
        if (cert) X509_free(cert);
        if (key) EVP_PKEY_free(key);
    }
};

// A throwaway Ed25519 leaf. The test never validates the chain; it only needs
// a handshake that completes so the exporter is defined.
void MakeSelfSigned(SelfSignedIdentity* out) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    assert(ctx != nullptr);
    assert(EVP_PKEY_keygen_init(ctx) == 1);
    assert(EVP_PKEY_keygen(ctx, &out->key) == 1);
    EVP_PKEY_CTX_free(ctx);

    out->cert = X509_new();
    assert(out->cert != nullptr);
    assert(X509_set_version(out->cert, 2) == 1);
    assert(ASN1_INTEGER_set(X509_get_serialNumber(out->cert), 1) == 1);
    assert(X509_gmtime_adj(X509_getm_notBefore(out->cert), 0) != nullptr);
    assert(X509_gmtime_adj(X509_getm_notAfter(out->cert), 3600) != nullptr);
    assert(X509_set_pubkey(out->cert, out->key) == 1);

    X509_NAME* name = X509_get_subject_name(out->cert);
    assert(X509_NAME_add_entry_by_txt(
               name, "CN", MBSTRING_ASC,
               reinterpret_cast<const unsigned char*>("yume-test"), -1, -1,
               0) == 1);
    assert(X509_set_issuer_name(out->cert, name) == 1);
    assert(X509_sign(out->cert, out->key, nullptr) > 0);
}

// Runs one full TLS 1.3 handshake in memory and returns both endpoints' view
// of the binding.
void HandshakeOnce(const SelfSignedIdentity& identity,
                   Bytes* client_binding,
                   Bytes* server_binding) {
    SSL_CTX* client_ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX* server_ctx = SSL_CTX_new(TLS_server_method());
    assert(client_ctx != nullptr && server_ctx != nullptr);
    for (SSL_CTX* ctx : {client_ctx, server_ctx}) {
        assert(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) == 1);
        assert(SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) == 1);
    }
    assert(SSL_CTX_use_certificate(server_ctx, identity.cert) == 1);
    assert(SSL_CTX_use_PrivateKey(server_ctx, identity.key) == 1);
    SSL_CTX_set_verify(client_ctx, SSL_VERIFY_NONE, nullptr);

    SSL* client = SSL_new(client_ctx);
    SSL* server = SSL_new(server_ctx);
    assert(client != nullptr && server != nullptr);

    BIO* client_side = nullptr;
    BIO* server_side = nullptr;
    assert(BIO_new_bio_pair(&client_side, 0, &server_side, 0) == 1);
    SSL_set_bio(client, client_side, client_side);
    SSL_set_bio(server, server_side, server_side);
    SSL_set_connect_state(client);
    SSL_set_accept_state(server);

    // Neither endpoint completes on its own: alternate until both report a
    // finished handshake or the pair stops making progress.
    bool client_done = false;
    bool server_done = false;
    for (int round = 0; round < 64 && !(client_done && server_done); ++round) {
        if (!client_done && SSL_do_handshake(client) == 1) client_done = true;
        if (!server_done && SSL_do_handshake(server) == 1) server_done = true;
    }
    assert(client_done && server_done);

    *client_binding = yume::security::ExportChannelBinding(client);
    *server_binding = yume::security::ExportChannelBinding(server);

    SSL_free(client);
    SSL_free(server);
    SSL_CTX_free(client_ctx);
    SSL_CTX_free(server_ctx);
}

}  // namespace

int main() {
    SelfSignedIdentity identity;
    MakeSelfSigned(&identity);

    Bytes client_binding;
    Bytes server_binding;
    HandshakeOnce(identity, &client_binding, &server_binding);

    // Both ends of one connection derive the same value, so an honest client
    // and server agree without the exporter ever appearing on the wire.
    assert(client_binding.size() == yume::security::kChannelBindingLen);
    assert(server_binding.size() == yume::security::kChannelBindingLen);
    assert(client_binding == server_binding);
    assert(client_binding != Bytes(yume::security::kChannelBindingLen, 0));

    // The relay property: a node terminating TLS with the client and opening a
    // second connection to a real server holds two unrelated bindings, so the
    // client's signature cannot verify at the far end.
    Bytes second_client;
    Bytes second_server;
    HandshakeOnce(identity, &second_client, &second_server);
    assert(second_client == second_server);
    assert(second_client != client_binding);

    // Fail closed rather than returning a placeholder value.
    assert(Throws([] {
        (void)yume::security::ExportChannelBinding(nullptr);
    }));

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    assert(ctx != nullptr);
    SSL* unconnected = SSL_new(ctx);
    assert(unconnected != nullptr);
    assert(Throws([&] {
        (void)yume::security::ExportChannelBinding(unconnected);
    }));
    SSL_free(unconnected);
    SSL_CTX_free(ctx);
    return 0;
}
