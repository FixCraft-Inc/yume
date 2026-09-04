/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/ytp1_tls13_secure_channel.hpp"

#include <array>
#include <cassert>
#include <cstddef>
#include <deque>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace yume::providers {
namespace {

using namespace engine;

template <typename T>
T take(Result<T> result) {
    assert(result.ok());
    return std::move(result).take_value();
}

Buffer bytes(std::string_view text, std::size_t limit = 1024U) {
    return take(Buffer::copy_from(
        {reinterpret_cast<const std::byte*>(text.data()), text.size()}, limit));
}

std::string text(const Buffer& buffer) {
    return {reinterpret_cast<const char*>(buffer.bytes().data()), buffer.size()};
}

struct PairState final {
    struct Side final {
        std::deque<Buffer> inbound;
        ByteChannel::ReadCompletion pending;
        std::size_t pending_maximum{0U};
        bool closed{false};
        bool write_shutdown{false};
    };
    std::array<Side, 2> sides;
};

class PairChannel final : public ByteChannel {
public:
    PairChannel(std::shared_ptr<PairState> state, std::size_t side,
                ExecutorAffinity affinity) noexcept
        : state_(std::move(state)), side_(side), affinity_(affinity) {}
    ~PairChannel() override { close(); }

    ExecutorAffinity executor_affinity() const noexcept override { return affinity_; }
    std::size_t max_read_size() const noexcept override { return 97U; }
    std::size_t max_write_size() const noexcept override { return 97U; }

    void async_read(std::size_t maximum, CancellationToken cancellation,
                    ReadCompletion completion) override {
        if (!completion) return;
        if (cancellation.is_cancelled()) {
            completion(Result<Buffer>(Status(StatusCode::Cancelled)));
            return;
        }
        auto& local = state_->sides[side_];
        auto& peer = state_->sides[1U - side_];
        if (maximum == 0U || maximum > max_read_size()) {
            completion(Result<Buffer>(Status(StatusCode::InvalidArgument)));
        } else if (!local.inbound.empty()) {
            Buffer source = std::move(local.inbound.front());
            local.inbound.pop_front();
            const std::size_t amount = std::min(maximum, source.size());
            Buffer delivered = take(Buffer::copy_from(source.bytes().first(amount), maximum));
            if (amount < source.size()) {
                local.inbound.push_front(take(Buffer::copy_from(
                    source.bytes().subspan(amount), source.max_size())));
            }
            completion(Result<Buffer>(std::move(delivered)));
        } else if (peer.write_shutdown || peer.closed || local.closed) {
            completion(Result<Buffer>(Status(StatusCode::Closed)));
        } else {
            assert(!local.pending);
            local.pending = std::move(completion);
            local.pending_maximum = maximum;
        }
    }

    void async_write(Buffer buffer, CancellationToken cancellation,
                     WriteCompletion completion) override {
        if (!completion) return;
        auto& local = state_->sides[side_];
        auto& peer = state_->sides[1U - side_];
        if (cancellation.is_cancelled()) {
            completion(Status(StatusCode::Cancelled), 0U);
            return;
        }
        if (local.closed || local.write_shutdown || peer.closed) {
            completion(Status(StatusCode::Closed), 0U);
            return;
        }
        assert(buffer.size() <= max_write_size());
        const std::size_t count = buffer.size();
        if (peer.pending) {
            auto reader = std::move(peer.pending);
            const std::size_t amount = std::min(peer.pending_maximum, buffer.size());
            Buffer delivered = take(Buffer::copy_from(buffer.bytes().first(amount),
                                                      peer.pending_maximum));
            if (amount < buffer.size()) {
                peer.inbound.push_back(take(Buffer::copy_from(
                    buffer.bytes().subspan(amount), max_write_size())));
            }
            reader(Result<Buffer>(std::move(delivered)));
        } else {
            peer.inbound.push_back(std::move(buffer));
        }
        completion(Status::success(), count);
    }

    Status shutdown_write() noexcept override {
        auto& local = state_->sides[side_];
        auto& peer = state_->sides[1U - side_];
        local.write_shutdown = true;
        if (peer.pending) {
            auto reader = std::move(peer.pending);
            reader(Result<Buffer>(Status(StatusCode::Closed)));
        }
        return Status::success();
    }
    void cancel() noexcept override {
        auto& local = state_->sides[side_];
        if (local.pending) {
            auto reader = std::move(local.pending);
            reader(Result<Buffer>(Status(StatusCode::Cancelled)));
        }
    }
    void close() noexcept override {
        auto& local = state_->sides[side_];
        auto& peer = state_->sides[1U - side_];
        if (local.closed) return;
        local.closed = true;
        if (local.pending) {
            auto reader = std::move(local.pending);
            reader(Result<Buffer>(Status(StatusCode::Closed)));
        }
        if (peer.pending) {
            auto reader = std::move(peer.pending);
            reader(Result<Buffer>(Status(StatusCode::Closed)));
        }
    }

private:
    std::shared_ptr<PairState> state_;
    std::size_t side_;
    ExecutorAffinity affinity_;
};

struct PemIdentity final { std::vector<std::byte> certificate; std::vector<std::byte> key; };

std::vector<std::byte> bio_contents(BIO* bio) {
    BUF_MEM* memory = nullptr;
    BIO_get_mem_ptr(bio, &memory);
    assert(memory && memory->length > 0U);
    const auto* begin = reinterpret_cast<const std::byte*>(memory->data);
    return {begin, begin + memory->length};
}

PemIdentity make_identity() {
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"), EVP_PKEY_free);
    std::unique_ptr<X509, decltype(&X509_free)> certificate(X509_new(), X509_free);
    assert(key && certificate);
    assert(X509_set_version(certificate.get(), 2L) == 1);
    assert(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1L) == 1);
    assert(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60L));
    assert(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600L));
    assert(X509_set_pubkey(certificate.get(), key.get()) == 1);
    X509_NAME* name = X509_get_subject_name(certificate.get());
    assert(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                      reinterpret_cast<const unsigned char*>("localhost"),
                                      -1, -1, 0) == 1);
    assert(X509_set_issuer_name(certificate.get(), name) == 1);
    X509V3_CTX context{};
    X509V3_set_ctx(&context, certificate.get(), certificate.get(), nullptr, nullptr, 0);
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> san(
        X509V3_EXT_conf_nid(nullptr, &context, NID_subject_alt_name,
                           const_cast<char*>("DNS:localhost")),
        X509_EXTENSION_free);
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> ca(
        X509V3_EXT_conf_nid(nullptr, &context, NID_basic_constraints,
                           const_cast<char*>("critical,CA:TRUE")),
        X509_EXTENSION_free);
    assert(san && ca);
    assert(X509_add_ext(certificate.get(), san.get(), -1) == 1);
    assert(X509_add_ext(certificate.get(), ca.get(), -1) == 1);
    assert(X509_sign(certificate.get(), key.get(), nullptr) > 0);
    std::unique_ptr<BIO, decltype(&BIO_free)> cert_bio(BIO_new(BIO_s_mem()), BIO_free);
    std::unique_ptr<BIO, decltype(&BIO_free)> key_bio(BIO_new(BIO_s_mem()), BIO_free);
    assert(PEM_write_bio_X509(cert_bio.get(), certificate.get()) == 1);
    assert(PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr, nullptr,
                                    0, nullptr, nullptr) == 1);
    return {bio_contents(cert_bio.get()), bio_contents(key_bio.get())};
}

void establish(std::shared_ptr<Ytp1Tls13SecureChannelProvider> client_provider,
               std::shared_ptr<Ytp1Tls13SecureChannelProvider> server_provider,
               std::unique_ptr<SecureChannel>& client,
               std::unique_ptr<SecureChannel>& server) {
    auto pair = std::make_shared<PairState>();
    client_provider->async_wrap(
        std::make_unique<PairChannel>(pair, 0U, ExecutorAffinity(77U)),
        EndpointRole::Client, {}, [&](Result<std::unique_ptr<SecureChannel>> result) {
            assert(result.ok()); client = std::move(result).take_value();
        });
    server_provider->async_wrap(
        std::make_unique<PairChannel>(pair, 1U, ExecutorAffinity(77U)),
        EndpointRole::Server, {}, [&](Result<std::unique_ptr<SecureChannel>> result) {
            assert(result.ok()); server = std::move(result).take_value();
        });
    assert(client && server);
}

void test_success_io_exporter_and_bounds() {
    const PemIdentity identity = make_identity();
    auto client_provider = take(Ytp1Tls13SecureChannelProvider::create_client(
        {"localhost", identity.certificate, {}, {}, {}}));
    auto server_provider = take(Ytp1Tls13SecureChannelProvider::create_server(
        {identity.certificate, identity.key, {}, {}}));
    assert(client_provider->descriptor().provider_id() == "tls13-native");
    assert(client_provider->descriptor().capabilities().contains(Capability::Tls13));
    std::unique_ptr<SecureChannel> client;
    std::unique_ptr<SecureChannel> server;
    establish(client_provider, server_provider, client, server);
    assert(client->descriptor().provider_id() == "tls13-native");
    assert(client->executor_affinity() == ExecutorAffinity(77U));
    assert(client->peer_evidence().authenticated());
    assert(client->peer_evidence().peer_role() == EndpointRole::Server);
    assert(!server->peer_evidence().authenticated());

    const std::array<std::byte, 2> context_a{std::byte{1}, std::byte{2}};
    const std::array<std::byte, 2> context_b{std::byte{1}, std::byte{3}};
    Buffer client_export = take(client->export_keying_material("EXPORTER-yume-test", context_a, 32U));
    Buffer server_export = take(server->export_keying_material("EXPORTER-yume-test", context_a, 32U));
    Buffer separated = take(server->export_keying_material("EXPORTER-yume-test", context_b, 32U));
    assert(std::equal(client_export.bytes().begin(), client_export.bytes().end(),
                      server_export.bytes().begin(), server_export.bytes().end()));
    assert(!std::equal(client_export.bytes().begin(), client_export.bytes().end(),
                       separated.bytes().begin(), separated.bytes().end()));

    std::optional<Result<Buffer>> received;
    server->async_read(1024U, {}, [&](Result<Buffer> result) { received.emplace(std::move(result)); });
    bool wrote = false;
    client->async_write(bytes("fragmented-memory-bio-message"), {},
                        [&](Status status, std::size_t count) {
                            assert(status.ok()); assert(count == 29U); wrote = true;
                        });
    assert(wrote && received && received->ok());
    assert(text(received->value()) == "fragmented-memory-bio-message");

    bool rejected = false;
    server->async_read(server->max_read_size() + 1U, {}, [&](Result<Buffer> result) {
        assert(!result.ok() && result.status().code() == StatusCode::InvalidArgument);
        rejected = true;
    });
    assert(rejected);

    // Re-entrant rejected submissions arrive while the state driver is still
    // invoking the outer callback. Each owns a distinct completion; a single
    // shared "immediate" slot used to overwrite the first nested callback.
    unsigned int nested_rejections = 0U;
    server->async_read(
        server->max_read_size() + 1U, {},
        [&](Result<Buffer> outer) {
            assert(!outer.ok() &&
                   outer.status().code() == StatusCode::InvalidArgument);
            ++nested_rejections;
            for (unsigned int index = 0U; index < 2U; ++index) {
                server->async_read(
                    server->max_read_size() + 1U, {},
                    [&](Result<Buffer> nested) {
                        assert(!nested.ok() &&
                               nested.status().code() ==
                                   StatusCode::InvalidArgument);
                        ++nested_rejections;
                    });
            }
        });
    assert(nested_rejections == 3U);
    CancellationSource cancelled;
    cancelled.cancel();
    bool read_cancelled = false;
    server->async_read(16U, cancelled.token(), [&](Result<Buffer> result) {
        assert(!result.ok() && result.status().code() == StatusCode::Cancelled);
        read_cancelled = true;
    });
    assert(read_cancelled);

    CancellationSource write_cancellation;
    write_cancellation.cancel();
    bool write_cancelled = false;
    client->async_write(bytes("cancelled"), write_cancellation.token(),
                        [&](Status status, std::size_t count) {
                            assert(status.code() == StatusCode::Cancelled);
                            assert(count == 0U);
                            write_cancelled = true;
                        });
    assert(write_cancelled);

    bool close_seen = false;
    server->async_read(16U, {}, [&](Result<Buffer> result) {
        assert(!result.ok() && result.status().code() == StatusCode::Closed);
        close_seen = true;
    });
    assert(client->shutdown_write().ok());
    assert(close_seen);

    std::optional<Result<Buffer>> tail;
    client->async_read(16U, {}, [&](Result<Buffer> result) {
        tail.emplace(std::move(result));
    });
    bool tail_written = false;
    server->async_write(bytes("tail"), {}, [&](Status status, std::size_t count) {
        assert(status.ok() && count == 4U);
        tail_written = true;
    });
    assert(tail_written && tail && tail->ok() && text(tail->value()) == "tail");
}

void test_role_hostname_and_handshake_cancellation_fail_closed() {
    const PemIdentity identity = make_identity();
    auto client_provider = take(Ytp1Tls13SecureChannelProvider::create_client(
        {"wrong.example", identity.certificate, {}, {}, {}}));
    auto server_provider = take(Ytp1Tls13SecureChannelProvider::create_server(
        {identity.certificate, identity.key, {}, {}}));
    auto pair = std::make_shared<PairState>();
    bool role_failed = false;
    client_provider->async_wrap(
        std::make_unique<PairChannel>(pair, 0U, ExecutorAffinity(9U)),
        EndpointRole::Server, {}, [&](Result<std::unique_ptr<SecureChannel>> result) {
            assert(!result.ok() && result.status().code() == StatusCode::ProviderMismatch);
            role_failed = true;
        });
    assert(role_failed);

    pair = std::make_shared<PairState>();
    bool client_failed = false;
    bool server_failed = false;
    client_provider->async_wrap(
        std::make_unique<PairChannel>(pair, 0U, ExecutorAffinity(9U)),
        EndpointRole::Client, {}, [&](Result<std::unique_ptr<SecureChannel>> result) {
            assert(!result.ok()); client_failed = true;
        });
    server_provider->async_wrap(
        std::make_unique<PairChannel>(pair, 1U, ExecutorAffinity(9U)),
        EndpointRole::Server, {}, [&](Result<std::unique_ptr<SecureChannel>> result) {
            if (!result.ok()) server_failed = true;
        });
    assert(client_failed || server_failed);

    pair = std::make_shared<PairState>();
    CancellationSource cancellation;
    cancellation.cancel();
    bool cancelled = false;
    auto valid_client = take(Ytp1Tls13SecureChannelProvider::create_client(
        {"localhost", identity.certificate, {}, {}, {}}));
    valid_client->async_wrap(
        std::make_unique<PairChannel>(pair, 0U, ExecutorAffinity(9U)),
        EndpointRole::Client, cancellation.token(),
        [&](Result<std::unique_ptr<SecureChannel>> result) {
            assert(!result.ok() && result.status().code() == StatusCode::Cancelled);
            cancelled = true;
        });
    assert(cancelled);
}

void test_untrusted_certificate_fails_closed() {
    const PemIdentity trusted = make_identity();
    const PemIdentity untrusted = make_identity();
    auto client_provider = take(Ytp1Tls13SecureChannelProvider::create_client(
        {"localhost", trusted.certificate, {}, {}, {}}));
    auto server_provider = take(Ytp1Tls13SecureChannelProvider::create_server(
        {untrusted.certificate, untrusted.key, {}, {}}));
    auto pair = std::make_shared<PairState>();
    bool failed = false;
    client_provider->async_wrap(
        std::make_unique<PairChannel>(pair, 0U, ExecutorAffinity(11U)),
        EndpointRole::Client, {}, [&](Result<std::unique_ptr<SecureChannel>> result) {
            if (!result.ok()) failed = true;
        });
    server_provider->async_wrap(
        std::make_unique<PairChannel>(pair, 1U, ExecutorAffinity(11U)),
        EndpointRole::Server, {}, [&](Result<std::unique_ptr<SecureChannel>> result) {
            if (!result.ok()) failed = true;
        });
    assert(failed);
}

void test_mutual_tls_outer_client_evidence() {
    const PemIdentity server_identity = make_identity();
    const PemIdentity client_identity = make_identity();
    Ytp1Tls13ClientConfigView client_config{
        "localhost", server_identity.certificate, {}, {}, {}};
    client_config.certificate_chain_pem = client_identity.certificate;
    client_config.private_key_pem = client_identity.key;
    auto client_provider = take(
        Ytp1Tls13SecureChannelProvider::create_client(client_config));
    auto server_provider = take(Ytp1Tls13SecureChannelProvider::create_server(
        {server_identity.certificate, server_identity.key,
         client_identity.certificate, {}}));
    std::unique_ptr<SecureChannel> client;
    std::unique_ptr<SecureChannel> server;
    establish(client_provider, server_provider, client, server);
    assert(server->peer_evidence().authenticated());
    assert(server->peer_evidence().peer_role() == EndpointRole::Client);
    assert(server->peer_evidence().authentication_scheme() == "tls13-x509");
}

}  // namespace
}  // namespace yume::providers

int main() {
    yume::providers::test_success_io_exporter_and_bounds();
    yume::providers::test_role_hostname_and_handshake_cancellation_fail_closed();
    yume::providers::test_untrusted_certificate_fails_closed();
    yume::providers::test_mutual_tls_outer_client_evidence();
    return 0;
}
