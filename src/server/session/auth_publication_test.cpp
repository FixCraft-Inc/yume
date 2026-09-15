/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/session.hpp"

#include <array>
#include <cstdlib>
#include <memory>
#include <new>
#include <stdexcept>
#include <string>

#include <openssl/x509.h>

#include "core/security/auth_v2.hpp"
#include "core/security/channel_binding.hpp"
#include "core/security/secret_file.hpp"
#include "test_support/allocation_failure.hpp"

namespace yume::server {

struct SessionAuthPublicationTestPeer {
    static SSL* tls(Session& session) { return session.stream_.native_handle(); }

    static bool published(const Session& session) noexcept {
        return session.authorization_tier_ == authorization::SessionTier::Authorized;
    }

    static bool empty(const Session& session) noexcept {
        return session.authorization_tier_ == authorization::SessionTier::Unauthenticated &&
            !session.ratchet_ && !session.admin_authenticated_ &&
            !session.operator_authenticated_ && session.auth_fingerprint_.empty() &&
            session.admin_fingerprint_.empty() && session.client_id_.empty() &&
            session.session_allowed_codecs_.empty() && session.session_allowed_services_.empty();
    }

    static bool admin(const Session& session) noexcept {
        return published(session) && session.ratchet_ && session.admin_authenticated_ &&
            !session.auth_fingerprint_.empty() && !session.admin_fingerprint_.empty() &&
            session.inner_mode_ == "ratchet" && session.inner_kdf_ == "hkdf";
    }

    static bool authenticate(Session& session, const protocol::Frame& frame) {
        return session.handle_auth(frame);
    }

    static crypto::Bytes prepare_challenge(Session& session) {
        auto ephemeral = std::make_unique<Session::AuthV2Ephemeral>();
        ephemeral->mlkem = basefwx::pq::GenerateKeyPair(basefwx::pq::KemAlgorithm::MlKem1024);
        ephemeral->x25519 = basefwx::x25519::GenerateKeyPair();
        ephemeral->psk_salt.assign(32, 0x41);
        ephemeral->transcript_salt.assign(32, 0x42);
        session.challenge_ = auth_v2::BuildChallenge(
            crypto::Bytes(32, 0x43), ephemeral->mlkem.public_key,
            ephemeral->x25519.public_key, ephemeral->psk_salt,
            ephemeral->transcript_salt, 8, ratchet::kExtremePolicy);
        session.auth_v2_ephemeral_ = std::move(ephemeral);
        return session.challenge_;
    }
};

}  // namespace yume::server

namespace {
using Peer = yume::server::SessionAuthPublicationTestPeer;
using Bytes = yume::crypto::Bytes;
thread_local const yume::server::Session* fail_after_publication = nullptr;
thread_local bool injected = false;

// The first allocation after publication belongs to optional last_seen work.
// Observe the real Session state so the test fails if AUTH returns false after
// publishing it. One-shot failure leaves diagnostics and test teardown usable.
void fail_first_allocation_after_publication(std::size_t) {
    if (fail_after_publication && Peer::published(*fail_after_publication)) {
        fail_after_publication = nullptr;
        injected = true;
        throw std::bad_alloc();
    }
}
}

namespace {

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

// Use Session's own SSL object and a BIO pair. This drives real TLS/exporter
// and composite/KEM code without launching a daemon or writing credentials.
void finish_tls(SSL* server, boost::asio::ssl::context& context) {
    using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using Cert = std::unique_ptr<X509, decltype(&X509_free)>;
    using Tls = std::unique_ptr<SSL, decltype(&SSL_free)>;
    Key key(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"), EVP_PKEY_free);
    Cert cert(X509_new(), X509_free);
    require(key && cert, "TLS identity allocation failed");
    require(X509_set_version(cert.get(), 2) == 1 &&
            ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) == 1 &&
            X509_gmtime_adj(X509_getm_notBefore(cert.get()), 0) &&
            X509_gmtime_adj(X509_getm_notAfter(cert.get()), 3600) &&
            X509_set_pubkey(cert.get(), key.get()) == 1, "TLS identity setup failed");
    auto* name = X509_get_subject_name(cert.get());
    require(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                reinterpret_cast<const unsigned char*>("auth-test"), -1, -1, 0) == 1 &&
            X509_set_issuer_name(cert.get(), name) == 1 &&
            X509_sign(cert.get(), key.get(), nullptr) > 0,
            "TLS identity signing failed");
    require(SSL_use_certificate(server, cert.get()) == 1 &&
            SSL_use_PrivateKey(server, key.get()) == 1, "TLS server identity failed");
    Tls client(SSL_new(context.native_handle()), SSL_free);
    require(client != nullptr, "TLS client allocation failed");
    for (SSL* tls : {server, client.get()}) {
        require(SSL_set_min_proto_version(tls, TLS1_3_VERSION) == 1 &&
                SSL_set_max_proto_version(tls, TLS1_3_VERSION) == 1, "TLS version failed");
    }
    SSL_set_verify(client.get(), SSL_VERIFY_NONE, nullptr);
    BIO* client_side = nullptr;
    BIO* server_side = nullptr;
    require(BIO_new_bio_pair(&client_side, 0, &server_side, 0) == 1, "BIO pair failed");
    SSL_set_bio(server, server_side, server_side);
    SSL_set_bio(client.get(), client_side, client_side);
    SSL_set_accept_state(server);
    SSL_set_connect_state(client.get());
    for (int round = 0; round < 64; ++round) {
        if (!SSL_is_init_finished(client.get())) (void)SSL_do_handshake(client.get());
        if (!SSL_is_init_finished(server)) (void)SSL_do_handshake(server);
        if (SSL_is_init_finished(client.get()) && SSL_is_init_finished(server)) break;
    }
    require(SSL_is_init_finished(server) && SSL_is_init_finished(client.get()),
            "TLS pair did not complete");
    require(yume::security::ExportChannelBinding(server) ==
            yume::security::ExportChannelBinding(client.get()), "TLS bindings differ");
}

enum class AuthCase { Valid, MetadataFailure, BadAdminSignature, BadX25519, WrongExporter };

void test_auth(AuthCase which, const yume::crypto::CompositeKeyPair& visitor,
               const yume::crypto::CompositeKeyPair& admin) {
    using namespace yume;
    const auto encode = [](const crypto::CompositeKeyPair& pair) {
        return crypto::encode_composite_identity(pair.classical.public_key.get(),
                                                  pair.pq.public_key.get());
    };
    const Bytes visitor_identity = encode(visitor);
    const Bytes admin_identity = encode(admin);
    const auto store_for = [](const Bytes& identity) {
        return std::make_shared<const std::vector<Bytes>>(std::vector<Bytes>{
            crypto::composite_canonical_encoding(crypto::parse_composite_identity(identity))});
    };
    boost::asio::io_context io;
    boost::asio::ssl::context tls_context(boost::asio::ssl::context::tls);
    server::ServerConfig config;
    config.anonym = which != AuthCase::MetadataFailure;
    // Invalid even if the injector regresses, so the fixture cannot create a file.
    config.auth_keys_meta = std::string("unusable\0metadata", 17);
    config.inner_psk_material = std::make_shared<security::Secret32>(
        std::array<std::uint8_t, 32>{0x51});
    server::Session session(boost::asio::ip::tcp::socket(io), tls_context, config,
        store_for(visitor_identity), {}, {}, {}, store_for(admin_identity), {}, 7, nullptr);
    finish_tls(Peer::tls(session), tls_context);
    const Bytes challenge = Peer::prepare_challenge(session);
    const auto parsed = auth_v2::ParseChallenge(challenge);
    auto kem = basefwx::pq::KemEncrypt(basefwx::pq::KemAlgorithm::MlKem1024,
                                       parsed.mlkem_public_key);
    auto x25519 = basefwx::x25519::GenerateKeyPair();
    if (which == AuthCase::BadX25519) x25519.public_key.assign(32, 0);
    Bytes binding = security::ExportChannelBinding(Peer::tls(session));
    if (which == AuthCase::WrongExporter) binding[0] ^= 1;
    const Bytes unsigned_response = auth_v2::BuildUnsignedResponse(
        x25519.public_key, kem.ciphertext, visitor_identity, 8, ratchet::kExtremePolicy);
    const Bytes signature = crypto::sign_composite(visitor,
        auth_v2::BuildSignatureInput(challenge, unsigned_response, binding));
    Bytes admin_signature = crypto::sign_composite(admin,
        auth_v2::BuildAdminSignatureInput(challenge, unsigned_response, binding, visitor_identity));
    if (which == AuthCase::BadAdminSignature) admin_signature.back() ^= 1;
    Bytes response = auth_v2::BuildResponse(x25519.public_key, kem.ciphertext,
        visitor_identity, 8, ratchet::kExtremePolicy, signature, admin_identity, admin_signature);
    protocol::Frame frame{{static_cast<std::uint32_t>(response.size()), protocol::AUTH, 0, 0},
                          std::move(response)};
    if (which == AuthCase::MetadataFailure) {
        injected = false;
        fail_after_publication = &session;
        yume::test::before_allocate = fail_first_allocation_after_publication;
    }
    const bool accepted = Peer::authenticate(session, frame);
    yume::test::before_allocate = nullptr;
    fail_after_publication = nullptr;
    if (which == AuthCase::Valid || which == AuthCase::MetadataFailure) {
        require(accepted && Peer::admin(session), which == AuthCase::MetadataFailure
            ? "last_seen failure reversed committed AUTH"
            : "valid AUTH did not publish its admin state");
        if (which == AuthCase::MetadataFailure) require(injected, "metadata failure was not injected");
    } else {
        require(!accepted && Peer::empty(session), "failed AUTH published identity, policy or ratchet state");
    }
}

}  // namespace

int main() {
    const auto visitor = yume::crypto::generate_composite_keypair();
    const auto admin = yume::crypto::generate_composite_keypair();
    for (const auto which : {AuthCase::Valid, AuthCase::MetadataFailure,
             AuthCase::BadAdminSignature, AuthCase::BadX25519, AuthCase::WrongExporter}) {
        test_auth(which, visitor, admin);
    }
}
