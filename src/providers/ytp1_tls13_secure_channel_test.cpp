/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/ytp1_tls13_secure_channel.hpp"
#include "core/stealth/cover_profile.hpp"
#include "core/stealth/tls_client_profile.hpp"
#include "core/stealth/tls_fingerprint.hpp"
#include "test_support/allocation_failure.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstddef>
#include <deque>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <openssl/pem.h>
#include <openssl/ssl.h>
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
        ByteChannel::WriteCompletion pending_write;
        std::size_t pending_maximum{0U};
        bool defer_write_completion{false};
        bool closed{false};
        bool write_shutdown{false};
    };
    std::array<Side, 2> sides;
};

class AllocationDenial final {
public:
    AllocationDenial() noexcept { test::fail_allocations.store(true); }
    ~AllocationDenial() { test::fail_allocations.store(false); }
    AllocationDenial(const AllocationDenial&) = delete;
    AllocationDenial& operator=(const AllocationDenial&) = delete;
};

struct AllocationObservation final {
    void* storage{nullptr};
    std::size_t size{0U};
    unsigned before{0U};
    unsigned after{0U};
    unsigned released{0U};
};
thread_local AllocationObservation allocation_observation;

void test_allocation_hooks_cover_nothrow() {
    // Explicit allocation-function calls prevent new-expression elision from
    // hiding a missing overload. The TLS handshake below also exercises the
    // production new(nothrow)[] / delete[] custom-extension lifetime.
    struct AllocationCase final {
        void* (*allocate)(std::size_t);
        void (*release)(void*) noexcept;
        bool nothrow;
    };
    const std::array cases{
        AllocationCase{[](std::size_t size) { return ::operator new(size); },
                       [](void* value) noexcept { ::operator delete(value); }, false},
        AllocationCase{[](std::size_t size) { return ::operator new[](size); },
                       [](void* value) noexcept { ::operator delete[](value); }, false},
        AllocationCase{[](std::size_t size) { return ::operator new(size, std::nothrow); },
                       [](void* value) noexcept { ::operator delete(value); }, true},
        AllocationCase{[](std::size_t size) { return ::operator new[](size, std::nothrow); },
                       [](void* value) noexcept { ::operator delete[](value); }, true},
        AllocationCase{[](std::size_t size) { return ::operator new(size, std::nothrow); },
                       [](void* value) noexcept { ::operator delete(value, std::nothrow); }, true},
        AllocationCase{[](std::size_t size) { return ::operator new[](size, std::nothrow); },
                       [](void* value) noexcept { ::operator delete[](value, std::nothrow); }, true},
        AllocationCase{[](std::size_t size) { return ::operator new(size); },
                       [](void* value) noexcept { ::operator delete(value, std::size_t{9U}); }, false},
        AllocationCase{[](std::size_t size) { return ::operator new[](size); },
                       [](void* value) noexcept { ::operator delete[](value, std::size_t{9U}); }, false}};
    for (const auto& operation : cases) {
        allocation_observation = {};
        test::before_allocate = [](std::size_t size) {
            ++allocation_observation.before;
            allocation_observation.size = size;
        };
        test::after_allocate = [](void* storage, std::size_t size) {
            ++allocation_observation.after;
            assert(size == allocation_observation.size);
            allocation_observation.storage = storage;
        };
        test::before_deallocate = [](void* storage) noexcept {
            assert(storage == allocation_observation.storage);
            assert(*static_cast<unsigned char*>(storage) == 0x5aU);
            ++allocation_observation.released;
        };
        void* storage = operation.allocate(9U);
        assert(storage && storage == allocation_observation.storage);
        *static_cast<unsigned char*>(storage) = 0x5aU;
        operation.release(storage);
        test::before_allocate = nullptr;
        test::after_allocate = nullptr;
        test::before_deallocate = nullptr;
        assert(allocation_observation.before == 1U && allocation_observation.after == 1U &&
               allocation_observation.released == 1U && allocation_observation.size == 9U);

        // The same countdown crosses throwing and nothrow allocation families.
        test::arm_allocation_failure(2U);
        storage = ::operator new(1U);
        ::operator delete(storage);
        storage = nullptr;
        bool threw = false;
        try { storage = operation.allocate(9U); }
        catch (const std::bad_alloc&) { threw = true; }
        const bool fired = test::disarm_allocation_failure();
        assert(fired && !storage && threw == !operation.nothrow);
        storage = operation.allocate(9U);
        assert(storage);
        operation.release(storage);

        {
            AllocationDenial deny;
            for (unsigned attempt = 0U; attempt < 2U; ++attempt) {
                storage = nullptr;
                threw = false;
                try { storage = operation.allocate(9U); }
                catch (const std::bad_alloc&) { threw = true; }
                assert(!storage && threw == !operation.nothrow);
            }
        }
        if (operation.nothrow) {
            test::before_allocate = [](std::size_t) { throw 17; };
            storage = operation.allocate(9U);
            test::before_allocate = nullptr;
            assert(!storage);
        }
    }
    // Zero-sized nothrow allocations are valid, owned storage too.
    auto* scalar = ::operator new(0U, std::nothrow);
    auto* array = ::operator new[](0U, std::nothrow);
    assert(scalar && array);
    ::operator delete(scalar);
    ::operator delete[](array);
}

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
        if (local.defer_write_completion) {
            assert(!local.pending_write);
            local.pending_write = std::move(completion);
        } else {
            completion(Status::success(), count);
        }
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
        if (local.pending_write) {
            auto writer = std::move(local.pending_write);
            writer(Status(StatusCode::Closed), 0U);
        }
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
    // The browser profile does not offer Ed25519 TLS certificate signatures.
    // This outer TLS identity is independent of YTP's composite peer identity.
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"), EVP_PKEY_free);
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
    assert(X509_sign(certificate.get(), key.get(), EVP_sha256()) > 0);
    std::unique_ptr<BIO, decltype(&BIO_free)> cert_bio(BIO_new(BIO_s_mem()), BIO_free);
    std::unique_ptr<BIO, decltype(&BIO_free)> key_bio(BIO_new(BIO_s_mem()), BIO_free);
    assert(PEM_write_bio_X509(cert_bio.get(), certificate.get()) == 1);
    assert(PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr, nullptr,
                                    0, nullptr, nullptr) == 1);
    return {bio_contents(cert_bio.get()), bio_contents(key_bio.get())};
}

void test_client_hello_uses_browser_profile() {
    const PemIdentity identity = make_identity();
    auto provider = take(Ytp1Tls13SecureChannelProvider::create_client(
        {"localhost", identity.certificate, {}, {}, {}}));
    auto pair = std::make_shared<PairState>();
    CancellationSource cancellation;
    unsigned int completions = 0U;
    provider->async_wrap(
        std::make_unique<PairChannel>(pair, 0U, ExecutorAffinity(81U)),
        EndpointRole::Client, cancellation.token(),
        [&](Result<std::unique_ptr<SecureChannel>> result) {
            assert(!result.ok());
            assert(result.status().code() == StatusCode::Cancelled);
            ++completions;
        });
    assert(completions == 0U);
    std::vector<std::uint8_t> wire;
    for (const auto& fragment : pair->sides[1].inbound) {
        for (const auto value : fragment.bytes()) {
            wire.push_back(std::to_integer<std::uint8_t>(value));
        }
    }
    assert(!wire.empty());
    // Capture the actual provider output across ByteChannel fragmentation.
    // Matching these fields does not establish full-session stealth.
    const auto observed = tls_fingerprint::parse_client_hello(
        wire.data(), wire.size());
    const auto& profile = cover_profile::active();
    const auto equal = [](const auto& left, const auto& right) {
        return std::equal(left.begin(), left.end(), right.begin(), right.end());
    };
    assert(!observed.ja4_hash.empty());
    assert(equal(observed.ja3_components.cipher_suites,
                 profile.tls_cipher_suites));
    assert(equal(observed.ja3_components.supported_groups,
                 profile.tls_supported_groups));
    assert(equal(observed.ja4_components.signature_algorithms,
                 profile.tls_signature_algorithms));
    assert(equal(observed.alpn_protocols, profile.tls_alpn_protocols));
    auto actual_extensions = observed.ja3_components.extensions;
    std::vector<std::uint16_t> expected_extensions(
        profile.tls_extensions.begin(), profile.tls_extensions.end());
    std::sort(actual_extensions.begin(), actual_extensions.end());
    std::sort(expected_extensions.begin(), expected_extensions.end());
    assert(actual_extensions == expected_extensions);
    cancellation.cancel();
    assert(completions == 1U);
}

void test_required_profile_refuses_invalid_context_and_unknown_profile() {
    bool rejected = false;
    try {
        (void)tls_stealth::configure_client_profile(
            nullptr, cover_profile::active().tls_profile, true);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    assert(rejected);
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(
        SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    assert(context);
    rejected = false;
    try {
        (void)tls_stealth::configure_client_profile(
            context.get(), tls_fingerprint::BrowserProfile::UNKNOWN, true);
    } catch (const std::runtime_error&) {
        rejected = true;
    }
    assert(rejected);
}

void test_handshake_cancellation_during_pending_write() {
    const PemIdentity identity = make_identity();
    auto provider = take(Ytp1Tls13SecureChannelProvider::create_client(
        {"localhost", identity.certificate, {}, {}, {}}));
    auto pair = std::make_shared<PairState>();
    pair->sides[0].defer_write_completion = true;
    CancellationSource cancellation;
    unsigned int completions = 0U;
    provider->async_wrap(
        std::make_unique<PairChannel>(pair, 0U, ExecutorAffinity(83U)),
        EndpointRole::Client, cancellation.token(),
        [&](Result<std::unique_ptr<SecureChannel>> result) {
            assert(!result.ok());
            assert(result.status().code() == StatusCode::Cancelled);
            ++completions;
        });
    assert(completions == 0U);
    assert(pair->sides[0].pending_write);
    // Closing the transport completes its pending write with Closed. That
    // cleanup result must not replace the handshake's earlier cancellation.
    cancellation.cancel();
    assert(pair->sides[0].closed);
    assert(!pair->sides[0].pending_write);
    assert(completions == 1U);
    cancellation.cancel();
    assert(completions == 1U);
}

void test_browser_offer_does_not_allow_negotiated_downgrade(
    int peer_version, bool peer_selects_h2) {
    const PemIdentity identity = make_identity();
    auto provider = take(Ytp1Tls13SecureChannelProvider::create_client(
        {"localhost", identity.certificate, {}, {}, {}}));
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(
        SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
    assert(context);
    assert(SSL_CTX_set_min_proto_version(context.get(), peer_version) == 1);
    assert(SSL_CTX_set_max_proto_version(context.get(), peer_version) == 1);
    std::unique_ptr<BIO, decltype(&BIO_free)> certificate_bio(
        BIO_new_mem_buf(identity.certificate.data(),
                        static_cast<int>(identity.certificate.size())), BIO_free);
    std::unique_ptr<BIO, decltype(&BIO_free)> key_bio(
        BIO_new_mem_buf(identity.key.data(), static_cast<int>(identity.key.size())),
        BIO_free);
    assert(certificate_bio && key_bio);
    std::unique_ptr<X509, decltype(&X509_free)> certificate(
        PEM_read_bio_X509(certificate_bio.get(), nullptr, nullptr, nullptr), X509_free);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        PEM_read_bio_PrivateKey(key_bio.get(), nullptr, nullptr, nullptr), EVP_PKEY_free);
    assert(certificate && key);
    assert(SSL_CTX_use_certificate(context.get(), certificate.get()) == 1);
    assert(SSL_CTX_use_PrivateKey(context.get(), key.get()) == 1);
    SSL_CTX_set_alpn_select_cb(
        context.get(),
        +[](SSL*, const unsigned char** out, unsigned char* out_length,
            const unsigned char* offered, unsigned int offered_length,
            void* argument) -> int {
            static constexpr std::array<unsigned char, 3> h2{2U, 'h', '2'};
            static constexpr std::array<unsigned char, 9> http11{
                8U, 'h', 't', 't', 'p', '/', '1', '.', '1'};
            const bool select_h2 = *static_cast<bool*>(argument);
            return SSL_select_next_proto(
                       const_cast<unsigned char**>(out), out_length,
                       select_h2 ? h2.data() : http11.data(),
                       select_h2 ? h2.size() : http11.size(),
                       offered, offered_length) == OPENSSL_NPN_NEGOTIATED
                       ? SSL_TLSEXT_ERR_OK : SSL_TLSEXT_ERR_ALERT_FATAL;
        },
        &peer_selects_h2);
    std::unique_ptr<SSL, decltype(&SSL_free)> peer(SSL_new(context.get()), SSL_free);
    std::unique_ptr<BIO, decltype(&BIO_free)> input(BIO_new(BIO_s_mem()), BIO_free);
    std::unique_ptr<BIO, decltype(&BIO_free)> output(BIO_new(BIO_s_mem()), BIO_free);
    assert(peer && input && output);
    BIO_set_mem_eof_return(input.get(), -1);
    BIO* const peer_input = input.get();
    BIO* const peer_output = output.get();
    SSL_set_bio(peer.get(), input.release(), output.release());
    SSL_set_accept_state(peer.get());

    auto pair = std::make_shared<PairState>();
    PairChannel peer_channel(pair, 1U, ExecutorAffinity(82U));
    unsigned int completions = 0U;
    provider->async_wrap(
        std::make_unique<PairChannel>(pair, 0U, ExecutorAffinity(82U)),
        EndpointRole::Client, {},
        [&](Result<std::unique_ptr<SecureChannel>> result) {
            assert(!result.ok());
            assert(result.status().code() == StatusCode::ProviderMismatch);
            ++completions;
        });
    for (std::size_t step = 0U; step < 128U && completions == 0U; ++step) {
        while (!pair->sides[1].inbound.empty()) {
            const Buffer& fragment = pair->sides[1].inbound.front();
            assert(BIO_write(peer_input, fragment.bytes().data(),
                             static_cast<int>(fragment.size())) ==
                   static_cast<int>(fragment.size()));
            pair->sides[1].inbound.pop_front();
        }
        const int result = SSL_do_handshake(peer.get());
        assert(result == 1 || SSL_get_error(peer.get(), result) == SSL_ERROR_WANT_READ);
        while (BIO_ctrl_pending(peer_output) != 0U && completions == 0U) {
            std::array<std::byte, 97U> fragment{};
            const int count = BIO_read(peer_output, fragment.data(), fragment.size());
            assert(count > 0);
            peer_channel.async_write(
                take(Buffer::copy_from(
                    std::span(fragment).first(static_cast<std::size_t>(count)),
                    fragment.size())), {},
                [](Status status, std::size_t count_written) {
                    assert(status.ok() && count_written > 0U);
                });
        }
    }
    assert(SSL_version(peer.get()) == peer_version);
    assert(completions == 1U);
    assert(pair->sides[0].closed);
}

std::shared_ptr<PairState> establish(
    std::shared_ptr<Ytp1Tls13SecureChannelProvider> client_provider,
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
    return pair;
}

void test_close_settles_pending_io(bool pending_write) {
    const PemIdentity identity = make_identity();
    auto client_provider = take(Ytp1Tls13SecureChannelProvider::create_client(
        {"localhost", identity.certificate, {}, {}, {}}));
    auto server_provider = take(Ytp1Tls13SecureChannelProvider::create_server(
        {identity.certificate, identity.key, {}, {}}));
    std::unique_ptr<SecureChannel> client;
    std::unique_ptr<SecureChannel> server;
    auto pair = establish(client_provider, server_provider, client, server);
    unsigned int completions = 0U;
    if (pending_write) {
        pair->sides[0].defer_write_completion = true;
        client->async_write(bytes("pending"), {},
            [&](Status status, std::size_t count) {
                assert(status.code() == StatusCode::Closed);
                assert(count == 0U);
                ++completions;
            });
        assert(pair->sides[0].pending_write);
    } else {
        client->async_read(16U, {}, [&](Result<Buffer> result) {
            assert(!result.ok());
            assert(result.status().code() == StatusCode::Closed);
            ++completions;
        });
        assert(pair->sides[0].pending);
    }
    assert(completions == 0U);
    client->close();
    assert(pair->sides[0].closed);
    assert(completions == 1U);
    client->close();
    assert(completions == 1U);
}

void test_upstream_failure_settles_during_allocation_denial(
    bool handshake, bool write_failure) {
    const PemIdentity identity = make_identity();
    auto client_provider = take(Ytp1Tls13SecureChannelProvider::create_client(
        {"localhost", identity.certificate, {}, {}, {}}));
    std::unique_ptr<SecureChannel> client;
    std::unique_ptr<SecureChannel> server;
    std::shared_ptr<PairState> pair;
    unsigned int read_completions = 0U;
    unsigned int write_completions = 0U;
    unsigned int wrap_completions = 0U;
    if (handshake) {
        pair = std::make_shared<PairState>();
        pair->sides[0].defer_write_completion = write_failure;
        client_provider->async_wrap(
            std::make_unique<PairChannel>(pair, 0U, ExecutorAffinity(91U)),
            EndpointRole::Client, {},
            [&](Result<std::unique_ptr<SecureChannel>> result) {
                assert(!result.ok());
                assert(result.status().code() == StatusCode::FailedPrecondition);
                ++wrap_completions;
            });
        assert(wrap_completions == 0U);
    } else {
        auto server_provider = take(Ytp1Tls13SecureChannelProvider::create_server(
            {identity.certificate, identity.key, {}, {}}));
        pair = establish(client_provider, server_provider, client, server);
        client->async_read(16U, {}, [&](Result<Buffer> result) {
            assert(!result.ok());
            assert(result.status().code() == StatusCode::FailedPrecondition);
            ++read_completions;
        });
        pair->sides[0].defer_write_completion = true;
        client->async_write(bytes("pending"), {},
            [&](Status status, std::size_t count) {
                assert(status.code() == StatusCode::FailedPrecondition);
                assert(count == 0U);
                ++write_completions;
            });
        assert(pair->sides[0].pending && pair->sides[0].pending_write);
    }

    // Construct the upstream diagnostic before denying allocation. Copying
    // it inside a noexcept callback used to terminate or lose the callback
    // already moved out of TLS state. Both pending directions must settle.
    Status upstream(StatusCode::FailedPrecondition, std::string(512U, 'x'));
    if (write_failure) {
        auto completion = std::move(pair->sides[0].pending_write);
        assert(completion);
        AllocationDenial denial;
        completion(std::move(upstream), 0U);
    } else {
        auto completion = std::move(pair->sides[0].pending);
        assert(completion);
        AllocationDenial denial;
        completion(Result<Buffer>(std::move(upstream)));
    }
    assert(pair->sides[0].closed);
    assert(!pair->sides[0].pending && !pair->sides[0].pending_write);
    if (handshake) {
        assert(wrap_completions == 1U);
    } else {
        assert(read_completions == 1U && write_completions == 1U);
        client->close();
        assert(read_completions == 1U && write_completions == 1U);
    }
}

void test_state_and_registration_allocation_failures_settle_wrap() {
    const PemIdentity identity = make_identity();
    auto provider = take(Ytp1Tls13SecureChannelProvider::create_server(
        {identity.certificate, identity.key, {}, {}}));
    bool reached_successful_start = false;
    for (std::size_t nth = 1U; nth <= 64U; ++nth) {
        auto pair = std::make_shared<PairState>();
        auto channel = std::make_unique<PairChannel>(pair, 0U, ExecutorAffinity(93U));
        CancellationSource cancellation;
        unsigned int completions = 0U;
        StatusCode outcome = StatusCode::Ok;
        SecureChannelProvider::Completion completion =
            [&](Result<std::unique_ptr<SecureChannel>> result) {
                assert(!result.ok());
                outcome = result.status().code();
                ++completions;
            };
        test::arm_allocation_failure(nth);
        provider->async_wrap(std::move(channel), EndpointRole::Server,
                             cancellation.token(), std::move(completion));
        const bool fired = test::disarm_allocation_failure();
        cancellation.cancel();
        assert(completions == 1U && pair->sides[0].closed);
        assert(outcome == (fired ? StatusCode::ResourceExhausted
                                 : StatusCode::Cancelled));
        if (!fired) {
            reached_successful_start = true;
            break;
        }
    }
    assert(reached_successful_start);
}

void test_registration_failure_settles_pending_io(bool write) {
    const PemIdentity identity = make_identity();
    auto client_provider = take(Ytp1Tls13SecureChannelProvider::create_client(
        {"localhost", identity.certificate, {}, {}, {}}));
    auto server_provider = take(Ytp1Tls13SecureChannelProvider::create_server(
        {identity.certificate, identity.key, {}, {}}));
    std::unique_ptr<SecureChannel> client;
    std::unique_ptr<SecureChannel> server;
    auto pair = establish(client_provider, server_provider, client, server);
    CancellationSource cancellation;
    unsigned int completions = 0U;
    Buffer payload = bytes("pending");
    SecureChannel::ReadCompletion read_completion = [&](Result<Buffer> result) {
        assert(!result.ok() && result.status().code() == StatusCode::ResourceExhausted);
        ++completions;
    };
    SecureChannel::WriteCompletion write_completion = [&](Status status, std::size_t count) {
        assert(status.code() == StatusCode::ResourceExhausted && count == 0U);
        ++completions;
    };
    {
        AllocationDenial denial;
        if (write) {
            client->async_write(std::move(payload), cancellation.token(),
                                std::move(write_completion));
        } else {
            client->async_read(16U, cancellation.token(), std::move(read_completion));
        }
    }
    assert(completions == 1U && pair->sides[0].closed);
    cancellation.cancel();
    client->close();
    assert(completions == 1U);
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

void test_server_cover_negotiation_and_promotion(int version,
                                                std::string_view protocol) {
    const PemIdentity identity = make_identity();
    auto provider = take(Ytp1Tls13SecureChannelProvider::create_server(
        {identity.certificate, identity.key, {}, {}}));
    auto pair = std::make_shared<PairState>();
    PairChannel raw_transport(pair, 0U, ExecutorAffinity(91U));
    std::unique_ptr<Ytp1TlsServerConnection> cover;
    provider->async_wrap_server_cover(
        std::make_unique<PairChannel>(pair, 1U, ExecutorAffinity(91U)), {},
        [&](Result<std::unique_ptr<Ytp1TlsServerConnection>> result) {
            cover = take(std::move(result));
        });
    // The SSL_CTX must remain owned through the connection after the provider
    // handle disappears, including the eventual promoted SecureChannel.
    provider.reset();

    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context(
        SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    assert(context);
    assert(SSL_CTX_set_min_proto_version(context.get(), version) == 1);
    assert(SSL_CTX_set_max_proto_version(context.get(), version) == 1);
    std::unique_ptr<SSL, decltype(&SSL_free)> peer(SSL_new(context.get()), SSL_free);
    assert(peer);
    assert(SSL_set_tlsext_host_name(peer.get(), "actual.example") == 1);
    if (!protocol.empty()) {
        std::vector<unsigned char> alpn{static_cast<unsigned char>(protocol.size())};
        alpn.insert(alpn.end(), protocol.begin(), protocol.end());
        assert(SSL_set_alpn_protos(peer.get(), alpn.data(), alpn.size()) == 0);
    }
    BIO* const input = BIO_new(BIO_s_mem());
    BIO* const output = BIO_new(BIO_s_mem());
    assert(input && output);
    BIO_set_mem_eof_return(input, -1);
    SSL_set_bio(peer.get(), input, output);
    SSL_set_connect_state(peer.get());
    const auto receive_ciphertext = [&] {
        while (!pair->sides[0].inbound.empty()) {
            const auto& fragment = pair->sides[0].inbound.front();
            assert(BIO_write(input, fragment.bytes().data(), fragment.size()) ==
                   static_cast<int>(fragment.size()));
            pair->sides[0].inbound.pop_front();
        }
    };
    const auto send_ciphertext = [&] {
        while (BIO_ctrl_pending(output) != 0U) {
            std::array<std::byte, 97U> fragment{};
            const int count = BIO_read(output, fragment.data(), fragment.size());
            assert(count > 0);
            raw_transport.async_write(take(Buffer::copy_from(
                std::span(fragment).first(static_cast<std::size_t>(count)),
                fragment.size())), {}, [](Status status, std::size_t sent) {
                    assert(status.ok() && sent > 0U);
                });
        }
    };
    for (std::size_t attempt = 0U; attempt < 128U; ++attempt) {
        receive_ciphertext();
        const int result = SSL_do_handshake(peer.get());
        assert(result == 1 || SSL_get_error(peer.get(), result) == SSL_ERROR_WANT_READ);
        send_ciphertext();
        if (cover && SSL_is_init_finished(peer.get())) break;
    }
    assert(cover && SSL_is_init_finished(peer.get()));
    assert(cover->tls_version() == version);
    assert(cover->negotiated_protocol() == protocol);
    assert(cover->server_name() == "actual.example");
    assert(cover->executor_affinity() == ExecutorAffinity(91U));
    std::optional<Result<Buffer>> request;
    cover->async_read(1024U, {}, [&](Result<Buffer> result) {
        request.emplace(std::move(result));
    });
    assert(!request);
    // Even eligible TLS cannot move while a cover read retains ownership.
    assert(!cover->promote().ok());
    constexpr std::string_view get = "GET / HTTP/1.1\r\nHost: actual.example\r\n\r\n";
    assert(SSL_write(peer.get(), get.data(), get.size()) == static_cast<int>(get.size()));
    send_ciphertext();
    assert(request && request->ok() && text(request->value()) == get);

    std::array<unsigned char, 32> peer_exporter{};
    constexpr std::string_view label = "EXPORTER-yume-test-cover";
    assert(SSL_export_keying_material(peer.get(), peer_exporter.data(),
        peer_exporter.size(), label.data(), label.size(), nullptr, 0U, 1) == 1);
    const auto before = take(cover->export_keying_material(label, {}, 32U));
    assert(std::equal(before.bytes().begin(), before.bytes().end(),
        reinterpret_cast<const std::byte*>(peer_exporter.data())));

    auto promotion = cover->promote();
    if (version != TLS1_3_VERSION || protocol != "h2") {
        assert(!promotion.ok());
        assert(promotion.status().code() == StatusCode::FailedPrecondition);
        // Refusing YTP promotion leaves an ordinary usable TLS cover channel.
        bool wrote = false;
        cover->async_write(bytes("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"), {},
            [&](Status status, std::size_t count) { assert(status.ok() && count); wrote = true; });
        assert(wrote);
    } else {
        auto channel = take(std::move(promotion));
        assert(channel->descriptor().provider_id() == kYtp1Tls13SecureChannelProviderId);
        assert(channel->descriptor().capabilities().contains(Capability::Tls13));
        assert(channel->executor_affinity() == ExecutorAffinity(91U));
        assert(!cover->promote().ok());
        cover->close();
        cover.reset();
        assert(!pair->sides[1].closed);
        const auto after = take(channel->export_keying_material(label, {}, 32U));
        assert(std::equal(before.bytes().begin(), before.bytes().end(), after.bytes().begin()));
        bool wrote = false;
        channel->async_write(bytes("retained TLS state"), {},
            [&](Status status, std::size_t count) { assert(status.ok() && count); wrote = true; });
        assert(wrote);
        receive_ciphertext();
        std::array<char, 128> plaintext{};
        const int count = SSL_read(peer.get(), plaintext.data(), plaintext.size());
        assert(count == 18 && std::string_view(plaintext.data(), count) == "retained TLS state");
    }
}

void test_server_cover_cancellation_and_teardown() {
    const PemIdentity identity = make_identity();
    auto provider = take(Ytp1Tls13SecureChannelProvider::create_server(
        {identity.certificate, identity.key, {}, {}}));
    auto pair = std::make_shared<PairState>();
    CancellationSource cancellation;
    unsigned int completions = 0U;
    provider->async_wrap_server_cover(
        std::make_unique<PairChannel>(pair, 1U, ExecutorAffinity(92U)),
        cancellation.token(),
        [&](Result<std::unique_ptr<Ytp1TlsServerConnection>> result) {
            assert(!result.ok() && result.status().code() == StatusCode::Cancelled);
            ++completions;
        });
    assert(pair->sides[1].pending);
    cancellation.cancel();
    cancellation.cancel();
    assert(completions == 1U && pair->sides[1].closed);
}

void test_simultaneous_read_and_write() {
    const PemIdentity identity = make_identity();
    auto client_provider = take(Ytp1Tls13SecureChannelProvider::create_client(
        {"localhost", identity.certificate, {}, {}, {}}));
    auto server_provider = take(Ytp1Tls13SecureChannelProvider::create_server(
        {identity.certificate, identity.key, {}, {}}));
    std::unique_ptr<SecureChannel> client;
    std::unique_ptr<SecureChannel> server;
    auto pair = establish(client_provider, server_provider, client, server);
    unsigned int reads = 0U;
    unsigned int writes = 0U;
    client->async_read(64U, {}, [&](Result<Buffer> result) {
        assert(result.ok() && text(result.value()) == "response");
        ++reads;
    });
    assert(pair->sides[0].pending);
    client->async_write(bytes("request"), {}, [&](Status status, std::size_t count) {
        assert(status.ok() && count == 7U);
        ++writes;
    });
    server->async_read(64U, {}, [&](Result<Buffer> result) {
        assert(result.ok() && text(result.value()) == "request");
        ++reads;
    });
    server->async_write(bytes("response"), {}, [&](Status status, std::size_t count) {
        assert(status.ok() && count == 8U);
        ++writes;
    });
    assert(reads == 2U && writes == 2U);
}

void test_immediate_callback_releases_final_channel(bool write) {
    const PemIdentity identity = make_identity();
    auto client_provider = take(Ytp1Tls13SecureChannelProvider::create_client(
        {"localhost", identity.certificate, {}, {}, {}}));
    auto server_provider = take(Ytp1Tls13SecureChannelProvider::create_server(
        {identity.certificate, identity.key, {}, {}}));
    std::unique_ptr<SecureChannel> client;
    std::unique_ptr<SecureChannel> server;
    auto pair = establish(client_provider, server_provider, client, server);
    unsigned int completed = 0U;
    if (write) {
        // Empty writes complete without a transport operation retaining the
        // state. Its dispatcher must survive destruction inside this callback.
        client->async_write(bytes(""), {}, [&](Status status, std::size_t count) {
            assert(status.ok() && count == 0U);
            client.reset();
            ++completed;
        });
    } else {
        client->async_read(0U, {}, [&](Result<Buffer> result) {
            assert(!result.ok() && result.status().code() == StatusCode::InvalidArgument);
            client.reset();
            ++completed;
        });
    }
    assert(completed == 1U && !client && pair->sides[0].closed);
}

}  // namespace
}  // namespace yume::providers

int main() {
    yume::providers::test_allocation_hooks_cover_nothrow();
    yume::providers::test_required_profile_refuses_invalid_context_and_unknown_profile();
    yume::providers::test_handshake_cancellation_during_pending_write();
    yume::providers::test_close_settles_pending_io(false);
    yume::providers::test_close_settles_pending_io(true);
    yume::providers::test_upstream_failure_settles_during_allocation_denial(true, false);
    yume::providers::test_upstream_failure_settles_during_allocation_denial(true, true);
    yume::providers::test_upstream_failure_settles_during_allocation_denial(false, false);
    yume::providers::test_upstream_failure_settles_during_allocation_denial(false, true);
    yume::providers::test_state_and_registration_allocation_failures_settle_wrap();
    yume::providers::test_registration_failure_settles_pending_io(false);
    yume::providers::test_registration_failure_settles_pending_io(true);
    yume::providers::test_client_hello_uses_browser_profile();
    yume::providers::test_browser_offer_does_not_allow_negotiated_downgrade(
        TLS1_2_VERSION, true);
    yume::providers::test_browser_offer_does_not_allow_negotiated_downgrade(
        TLS1_3_VERSION, false);
    yume::providers::test_success_io_exporter_and_bounds();
    yume::providers::test_role_hostname_and_handshake_cancellation_fail_closed();
    yume::providers::test_untrusted_certificate_fails_closed();
    yume::providers::test_mutual_tls_outer_client_evidence();
    yume::providers::test_server_cover_negotiation_and_promotion(TLS1_2_VERSION, "http/1.1");
    yume::providers::test_server_cover_negotiation_and_promotion(TLS1_2_VERSION, "h2");
    yume::providers::test_server_cover_negotiation_and_promotion(TLS1_3_VERSION, "http/1.1");
    yume::providers::test_server_cover_negotiation_and_promotion(TLS1_3_VERSION, "h2");
    yume::providers::test_server_cover_negotiation_and_promotion(TLS1_2_VERSION, "");
    yume::providers::test_server_cover_cancellation_and_teardown();
    yume::providers::test_simultaneous_read_and_write();
    yume::providers::test_immediate_callback_releases_final_channel(false);
    yume::providers::test_immediate_callback_releases_final_channel(true);
    return 0;
}
