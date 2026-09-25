/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/ytp1_tls13_secure_channel.hpp"
#include "stealth/cover_profile.hpp"
#include "stealth/tls_client_profile.hpp"

#include <algorithm>
#include <array>
#include <mutex>
#include <new>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace yume::providers {
namespace {

using engine::Buffer;
using engine::CancellationRegistration;
using engine::CancellationToken;
using engine::Capability;
using engine::CapabilitySet;
using engine::EndpointRole;
using engine::ExecutorAffinity;
using engine::ProviderDescriptor;
using engine::ProviderKind;
using engine::Result;
using engine::SecureChannel;
using engine::SecureChannelPeerEvidence;
using engine::Status;
using engine::StatusCode;

using SslCtxPtr = std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)>;
using SslPtr = std::unique_ptr<SSL, decltype(&SSL_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
struct X509InfoStackDeleter final {
    void operator()(STACK_OF(X509_INFO)* stack) const noexcept {
        sk_X509_INFO_pop_free(stack, X509_INFO_free);
    }
};
using X509InfoStackPtr =
    std::unique_ptr<STACK_OF(X509_INFO), X509InfoStackDeleter>;

constexpr std::size_t kMaxServerNameBytes = 253U;
constexpr std::size_t kAbsoluteMaxCredentialPemBytes = 1024U * 1024U;
constexpr std::size_t kMaxHandshakeCiphertextBytes = 4U * 1024U * 1024U;
constexpr std::array<unsigned char, 3> kH2Alpn{2U, 'h', '2'};
constexpr std::array<unsigned char, 12> kCoverAlpn{
    2U, 'h', '2', 8U, 'h', 't', 't', 'p', '/', '1', '.', '1'};
int kCoverConnectionMarker;

Status safe_status(StatusCode code, std::string_view message) noexcept {
    try {
        return Status(code, message);
    } catch (...) {
        return Status(code);
    }
}

Status safe_status(const Status& status) noexcept {
    return safe_status(status.code(), status.message());
}

Status cancelled_status() noexcept {
    return safe_status(StatusCode::Cancelled,
                       "TLS secure-channel operation cancelled");
}

Status closed_status() noexcept {
    return safe_status(StatusCode::Closed, "TLS secure channel is closed");
}

template <typename Callback, typename... Args>
void invoke_noexcept(Callback& callback, Args&&... args) noexcept {
    if (!callback) {
        return;
    }
    try {
        callback(std::forward<Args>(args)...);
    } catch (...) {
        // Provider/user callbacks are outside this provider's trust boundary.
    }
}

bool valid_limits(const Ytp1Tls13Limits& limits) noexcept {
    return limits.max_plaintext_bytes > 0U &&
           limits.max_plaintext_bytes <= engine::kAbsoluteMaxBufferBytes &&
           limits.max_encrypted_chunk_bytes > 0U &&
           limits.max_encrypted_chunk_bytes <= engine::kAbsoluteMaxBufferBytes &&
           limits.max_credential_pem_bytes > 0U &&
           limits.max_credential_pem_bytes <= kAbsoluteMaxCredentialPemBytes;
}

bool valid_server_name(std::string_view name) noexcept {
    if (name.empty() || name.size() > kMaxServerNameBytes ||
        name.front() == '.' || name.back() == '.') {
        return false;
    }
    return std::all_of(name.begin(), name.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
               (c >= '0' && c <= '9') || c == '.' || c == '-';
    });
}

BioPtr pem_bio(std::span<const std::byte> pem) noexcept {
    if (pem.empty() || pem.size() > static_cast<std::size_t>(INT_MAX)) {
        return BioPtr(nullptr, BIO_free);
    }
    return BioPtr(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())),
                  BIO_free);
}

bool add_trust_anchors(SSL_CTX* context,
                       std::span<const std::byte> pem) noexcept {
    BioPtr bio = pem_bio(pem);
    if (!bio) {
        return false;
    }
    STACK_OF(X509_INFO)* raw = PEM_X509_INFO_read_bio(bio.get(), nullptr,
                                                      nullptr, nullptr);
    X509InfoStackPtr infos(raw);
    if (!infos || sk_X509_INFO_num(infos.get()) <= 0) {
        return false;
    }
    X509_STORE* store = SSL_CTX_get_cert_store(context);
    bool added = false;
    for (int index = 0; index < sk_X509_INFO_num(infos.get()); ++index) {
        X509_INFO* info = sk_X509_INFO_value(infos.get(), index);
        if (!info || !info->x509) {
            continue;
        }
        if (X509_STORE_add_cert(store, info->x509) != 1) {
            const unsigned long error = ERR_peek_last_error();
            if (ERR_GET_REASON(error) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
                ERR_clear_error();
                return false;
            }
            ERR_clear_error();
        }
        added = true;
    }
    return added;
}

bool install_server_identity(SSL_CTX* context,
                             std::span<const std::byte> chain_pem,
                             std::span<const std::byte> key_pem) noexcept {
    BioPtr chain = pem_bio(chain_pem);
    if (!chain) {
        return false;
    }
    X509Ptr leaf(PEM_read_bio_X509_AUX(chain.get(), nullptr, nullptr, nullptr),
                 X509_free);
    if (!leaf || SSL_CTX_use_certificate(context, leaf.get()) != 1) {
        return false;
    }
    while (true) {
        ERR_clear_error();
        X509* next = PEM_read_bio_X509(chain.get(), nullptr, nullptr, nullptr);
        if (!next) {
            ERR_clear_error();
            break;
        }
        X509Ptr certificate(next, X509_free);
        if (SSL_CTX_add1_chain_cert(context, certificate.get()) != 1) {
            return false;
        }
    }
    BioPtr key = pem_bio(key_pem);
    if (!key) {
        return false;
    }
    PkeyPtr private_key(
        PEM_read_bio_PrivateKey(key.get(), nullptr, nullptr, nullptr),
        EVP_PKEY_free);
    return private_key &&
           SSL_CTX_use_PrivateKey(context, private_key.get()) == 1 &&
           SSL_CTX_check_private_key(context) == 1;
}

int select_h2(SSL* ssl, const unsigned char** out, unsigned char* out_length,
              const unsigned char* offered, unsigned int offered_length,
              void*) noexcept {
    const bool cover = SSL_get_app_data(ssl) == &kCoverConnectionMarker;
    const std::span<const unsigned char> protocols = cover
        ? std::span<const unsigned char>(kCoverAlpn)
        : std::span<const unsigned char>(kH2Alpn);
    if (SSL_select_next_proto(const_cast<unsigned char**>(out), out_length,
                              protocols.data(), protocols.size(), offered,
                              offered_length) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    return SSL_TLSEXT_ERR_OK;
}

Result<ProviderDescriptor> make_descriptor() {
    return ProviderDescriptor::create(
        std::string(kYtp1Tls13SecureChannelProviderId),
        ProviderKind::SecureChannel,
        kYtp1Tls13SecureChannelProviderApiVersion,
        engine::mandatory_capabilities(ProviderKind::SecureChannel)
            .with(Capability::Tls13));
}

Result<SecureChannelPeerEvidence> certificate_evidence(
    SSL* ssl, EndpointRole peer_role, std::string identity) {
    X509Ptr certificate(SSL_get1_peer_certificate(ssl), X509_free);
    if (!certificate) {
        return Result<SecureChannelPeerEvidence>(safe_status(
            StatusCode::FailedPrecondition,
            "TLS peer did not provide the required certificate"));
    }
    const int length = i2d_X509(certificate.get(), nullptr);
    if (length <= 0 ||
        static_cast<std::size_t>(length) > engine::kMaxPeerEvidenceBytes) {
        return Result<SecureChannelPeerEvidence>(safe_status(
            StatusCode::ResourceExhausted,
            "TLS peer certificate evidence exceeds its bound"));
    }
    std::vector<std::byte> der;
    try {
        der.resize(static_cast<std::size_t>(length));
    } catch (...) {
        return Result<SecureChannelPeerEvidence>(safe_status(
            StatusCode::ResourceExhausted,
            "TLS peer certificate evidence allocation failed"));
    }
    auto* cursor = reinterpret_cast<unsigned char*>(der.data());
    if (i2d_X509(certificate.get(), &cursor) != length) {
        return Result<SecureChannelPeerEvidence>(safe_status(
            StatusCode::Internal, "TLS peer certificate encoding failed"));
    }
    if (identity.empty()) {
        std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
        unsigned int digest_length = 0U;
        if (X509_digest(certificate.get(), EVP_sha256(), digest.data(),
                        &digest_length) != 1 || digest_length != SHA256_DIGEST_LENGTH) {
            return Result<SecureChannelPeerEvidence>(safe_status(
                StatusCode::Internal, "TLS peer certificate digest failed"));
        }
        static constexpr char kHex[] = "0123456789abcdef";
        identity.reserve(digest_length * 2U);
        for (unsigned int index = 0U; index < digest_length; ++index) {
            identity.push_back(kHex[digest[index] >> 4U]);
            identity.push_back(kHex[digest[index] & 0x0fU]);
        }
        OPENSSL_cleanse(digest.data(), digest.size());
    }
    return SecureChannelPeerEvidence::authenticated(
        peer_role, std::move(identity), "tls13-x509", std::move(der));
}

}  // namespace

struct Ytp1Tls13SecureChannelProvider::Impl final {
    Impl(SslCtxPtr value, ProviderDescriptor provider_descriptor,
         EndpointRole role, std::string name,
         Ytp1Tls13Limits configured_limits, bool mutual) noexcept
        : context(std::move(value)), descriptor(std::move(provider_descriptor)),
          configured_role(role),
          server_name(std::move(name)), limits(configured_limits),
          mutual_tls(mutual) {}

    SslCtxPtr context{nullptr, SSL_CTX_free};
    ProviderDescriptor descriptor;
    EndpointRole configured_role{EndpointRole::Client};
    std::string server_name;
    Ytp1Tls13Limits limits;
    bool mutual_tls{false};
};

namespace {

class TlsChannelState;

class ServerTlsConnection final : public Ytp1TlsServerConnection {
public:
    explicit ServerTlsConnection(std::shared_ptr<TlsChannelState> state) noexcept
        : state_(std::move(state)) {}
    ~ServerTlsConnection() override;
    ExecutorAffinity executor_affinity() const noexcept override;
    std::size_t max_read_size() const noexcept override;
    std::size_t max_write_size() const noexcept override;
    void async_read(std::size_t, CancellationToken, ReadCompletion) override;
    void async_write(Buffer, CancellationToken, WriteCompletion) override;
    Status shutdown_write() noexcept override;
    void cancel() noexcept override;
    void close() noexcept override;
    std::uint16_t tls_version() const noexcept override;
    std::string_view negotiated_protocol() const noexcept override;
    std::string_view server_name() const noexcept override;
    Result<Buffer> export_keying_material(
        std::string_view, std::span<const std::byte>, std::size_t) override;
    Result<std::unique_ptr<SecureChannel>> promote() override;

private:
    std::shared_ptr<TlsChannelState> state_;
};

class TlsChannel final : public SecureChannel {
public:
    explicit TlsChannel(std::shared_ptr<TlsChannelState> state) noexcept
        : state_(std::move(state)) {}
    ~TlsChannel() override;

    ExecutorAffinity executor_affinity() const noexcept override;
    std::size_t max_read_size() const noexcept override;
    std::size_t max_write_size() const noexcept override;
    void async_read(std::size_t, CancellationToken, ReadCompletion) override;
    void async_write(Buffer, CancellationToken, WriteCompletion) override;
    Status shutdown_write() noexcept override;
    void cancel() noexcept override;
    void close() noexcept override;
    const SecureChannelPeerEvidence& peer_evidence() const noexcept override;
    const ProviderDescriptor& descriptor() const noexcept override;
    Result<Buffer> export_keying_material(
        std::string_view, std::span<const std::byte>, std::size_t) override;

private:
    std::shared_ptr<TlsChannelState> state_;
};

enum class Phase : std::uint8_t { Handshake, Active, Failed, Closed };

struct PendingRead final {
    std::uint64_t id{0U};
    std::size_t maximum{0U};
    SecureChannel::ReadCompletion completion;
    CancellationRegistration cancellation;
    std::optional<Status> terminal;
};

struct PendingWrite final {
    std::uint64_t id{0U};
    Buffer buffer;
    std::size_t offset{0U};
    SecureChannel::WriteCompletion completion;
    CancellationRegistration cancellation;
    std::optional<Status> terminal;
};

class TlsChannelState final
    : public std::enable_shared_from_this<TlsChannelState> {
public:
    TlsChannelState(std::shared_ptr<Ytp1Tls13SecureChannelProvider::Impl> owner,
                    std::unique_ptr<engine::ByteChannel> transport,
                    SslPtr ssl, BIO* read_bio, BIO* write_bio,
                    bool cover_mode)
        : owner_(std::move(owner)), transport_(std::move(transport)),
          ssl_(std::move(ssl)), read_bio_(read_bio), write_bio_(write_bio),
          affinity_(transport_->executor_affinity()), cover_mode_(cover_mode) {}

    ~TlsChannelState() noexcept { close(); }

    void start(CancellationToken cancellation,
               engine::SecureChannelProvider::Completion completion,
               Ytp1Tls13SecureChannelProvider::ServerCoverCompletion cover_completion) {
        // Construction can allocate cancellation state. Transfer callbacks
        // only after it succeeds, then contain registration failures here.
        handshake_completion_ = std::move(completion);
        cover_completion_ = std::move(cover_completion);
        try {
            auto registration = cancellation.register_callback(
                [weak = weak_from_this()]() noexcept {
                    if (const auto state = weak.lock()) {
                        state->fail(cancelled_status());
                    }
                });
            if (!registration.ok()) {
                fail(registration.status());
                return;
            }
            {
                std::lock_guard<std::mutex> lock(mutex_);
                handshake_cancellation_ = std::move(registration).take_value();
            }
        } catch (const std::bad_alloc&) {
            fail(safe_status(StatusCode::ResourceExhausted,
                             "TLS handshake cancellation registration failed"));
            return;
        } catch (...) {
            fail(safe_status(StatusCode::Internal,
                             "TLS handshake cancellation registration threw"));
            return;
        }
        drive();
    }

    ExecutorAffinity affinity() const noexcept { return affinity_; }
    std::size_t max_plaintext() const noexcept {
        return owner_->limits.max_plaintext_bytes;
    }
    const SecureChannelPeerEvidence& evidence() const noexcept {
        return *evidence_;
    }
    const ProviderDescriptor& descriptor() const noexcept {
        return owner_->descriptor;
    }
    std::uint16_t tls_version() const noexcept { return tls_version_; }
    std::string_view negotiated_protocol() const noexcept { return protocol_; }
    std::string_view server_name() const noexcept { return received_server_name_; }

    Result<std::unique_ptr<SecureChannel>> promote() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!cover_mode_ || promoted_ || phase_ != Phase::Active ||
            tls_version_ != TLS1_3_VERSION || protocol_ != "h2") {
            return Result<std::unique_ptr<SecureChannel>>(safe_status(
                StatusCode::FailedPrecondition,
                "cover connection is not an unpromoted TLS 1.3/H2 channel"));
        }
        if (read_ || write_ || transport_read_pending_ ||
            transport_write_pending_ || immediate_head_ ||
            shutdown_requested_ || remote_closed_) {
            return Result<std::unique_ptr<SecureChannel>>(safe_status(
                StatusCode::FailedPrecondition,
                "cover operations must settle before TLS promotion"));
        }
        try {
            std::unique_ptr<SecureChannel> channel =
                std::make_unique<TlsChannel>(shared_from_this());
            promoted_ = true;
            return Result<std::unique_ptr<SecureChannel>>(std::move(channel));
        } catch (...) {
            return Result<std::unique_ptr<SecureChannel>>(safe_status(
                StatusCode::ResourceExhausted,
                "TLS promotion allocation failed"));
        }
    }

    void async_read(std::size_t maximum, CancellationToken token,
                    SecureChannel::ReadCompletion completion) {
        if (!completion) {
            return;
        }
        std::uint64_t id = 0U;
        Status immediate = Status::success();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (maximum == 0U || maximum > owner_->limits.max_plaintext_bytes) {
                immediate = safe_status(StatusCode::InvalidArgument,
                                        "TLS read exceeds its bound");
            } else if (phase_ != Phase::Active || remote_closed_) {
                immediate = closed_status();
            } else if (read_) {
                immediate = safe_status(StatusCode::ResourceExhausted,
                                        "TLS read already pending");
            } else {
                id = next_id_++;
                read_.emplace(PendingRead{id, maximum, std::move(completion),
                                          {}, {}});
            }
        }
        if (!immediate.ok()) {
            queue_read_completion(
                std::move(completion), std::move(immediate));
            return;
        }
        if (id != 0U) {
            try {
                auto registration = token.register_callback(
                    [weak = weak_from_this(), id]() noexcept {
                        if (const auto state = weak.lock()) {
                            state->cancel_read(id);
                        }
                    });
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (read_ && read_->id == id) {
                        if (registration.ok()) {
                            read_->cancellation =
                                std::move(registration).take_value();
                        } else {
                            read_->terminal = safe_status(registration.status());
                        }
                    }
                }
            } catch (const std::bad_alloc&) {
                fail(safe_status(StatusCode::ResourceExhausted,
                                 "TLS read cancellation registration failed"));
                return;
            } catch (...) {
                fail(safe_status(StatusCode::Internal,
                                 "TLS read cancellation registration threw"));
                return;
            }
        }
        drive();
    }

    void async_write(Buffer buffer, CancellationToken token,
                     SecureChannel::WriteCompletion completion) {
        if (!completion) {
            return;
        }
        std::uint64_t id = 0U;
        Status immediate = Status::success();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (buffer.size() > owner_->limits.max_plaintext_bytes) {
                immediate = safe_status(StatusCode::ResourceExhausted,
                                        "TLS write exceeds its bound");
            } else if (phase_ != Phase::Active || shutdown_requested_) {
                immediate = closed_status();
            } else if (write_) {
                immediate = safe_status(StatusCode::ResourceExhausted,
                                        "TLS write already pending");
            } else {
                id = next_id_++;
                write_.emplace(PendingWrite{id, std::move(buffer), 0U,
                                            std::move(completion), {}, {}});
            }
        }
        if (!immediate.ok()) {
            queue_write_completion(
                std::move(completion), std::move(immediate));
            return;
        }
        if (id != 0U) {
            try {
                auto registration = token.register_callback(
                    [weak = weak_from_this(), id]() noexcept {
                        if (const auto state = weak.lock()) {
                            state->cancel_write(id);
                        }
                    });
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    if (write_ && write_->id == id) {
                        if (registration.ok()) {
                            write_->cancellation =
                                std::move(registration).take_value();
                        } else {
                            write_->terminal = safe_status(registration.status());
                        }
                    }
                }
            } catch (const std::bad_alloc&) {
                fail(safe_status(StatusCode::ResourceExhausted,
                                 "TLS write cancellation registration failed"));
                return;
            } catch (...) {
                fail(safe_status(StatusCode::Internal,
                                 "TLS write cancellation registration threw"));
                return;
            }
        }
        drive();
    }

    Status shutdown_write() noexcept {
        try {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (phase_ != Phase::Active) {
                    return closed_status();
                }
                shutdown_requested_ = true;
            }
            drive();
            return Status::success();
        } catch (...) {
            return safe_status(StatusCode::Internal,
                               "TLS write shutdown failed");
        }
    }

    void cancel() noexcept {
        try {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (read_) read_->terminal = cancelled_status();
                if (write_ && write_->offset == 0U)
                    write_->terminal = cancelled_status();
            }
            transport_->cancel();
            drive();
        } catch (...) {
        }
    }

    void close() noexcept {
        try {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (phase_ == Phase::Closed) return;
                if (phase_ != Phase::Failed) terminal_ = closed_status();
                phase_ = Phase::Closed;
                need_transport_close_ = true;
            }
            drive();
        } catch (...) {
            try { transport_->close(); } catch (...) {}
        }
    }

    Result<Buffer> exporter(std::string_view label,
                            std::span<const std::byte> context,
                            std::size_t output_size) {
        if (label.empty() || label.size() > engine::kMaxExporterLabelBytes ||
            context.size() > engine::kMaxExporterContextBytes ||
            output_size == 0U || output_size > engine::kMaxExporterOutputBytes) {
            return Result<Buffer>(safe_status(
                StatusCode::InvalidArgument, "TLS exporter input exceeds its bound"));
        }
        auto output = Buffer::allocate(output_size,
                                       engine::kMaxExporterOutputBytes);
        if (!output.ok()) return output;
        Buffer buffer = std::move(output).take_value();
        std::lock_guard<std::mutex> lock(mutex_);
        if (phase_ != Phase::Active) {
            return Result<Buffer>(closed_status());
        }
        const auto* context_data = reinterpret_cast<const unsigned char*>(
            context.data());
        if (SSL_export_keying_material(
                ssl_.get(), reinterpret_cast<unsigned char*>(
                    buffer.mutable_bytes().data()), output_size,
                label.data(), label.size(), context_data, context.size(), 1) != 1) {
            return Result<Buffer>(safe_status(
                StatusCode::Internal, "TLS exporter derivation failed"));
        }
        return Result<Buffer>(std::move(buffer));
    }

private:
    enum class ActionKind : std::uint8_t {
        None, TransportRead, TransportWrite, TransportShutdownWrite,
        TransportClose,
        HandshakeSuccess, HandshakeFailure, ReadSuccess, ReadFailure,
        WriteComplete
    };
    struct Action final {
        ActionKind kind{ActionKind::None};
        std::optional<Buffer> buffer;
        Status status;
        std::size_t count{0U};
        engine::SecureChannelProvider::Completion handshake;
        Ytp1Tls13SecureChannelProvider::ServerCoverCompletion cover;
        SecureChannel::ReadCompletion read;
        SecureChannel::WriteCompletion write;
    };
    struct ImmediateAction final {
        explicit ImmediateAction(Action&& value) noexcept
            : action(std::move(value)) {}

        Action action;
        std::unique_ptr<ImmediateAction> next;
    };

    void queue_action(Action action) noexcept {
        const auto keep_alive = weak_from_this().lock();
        std::unique_ptr<ImmediateAction> node;
        try {
            node = std::make_unique<ImmediateAction>(std::move(action));
        } catch (...) {
            // Allocation failed before the callback moved into shared state.
            // Completing inline still preserves exactly-once settlement.
            execute(std::move(action));
            return;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ImmediateAction* const inserted = node.get();
            if (immediate_tail_) {
                immediate_tail_->next = std::move(node);
            } else {
                immediate_head_ = std::move(node);
            }
            immediate_tail_ = inserted;
        }
        drive();
    }

    void queue_read_completion(SecureChannel::ReadCompletion completion,
                               Status status) noexcept {
        Action action;
        action.kind = ActionKind::ReadFailure;
        action.read = std::move(completion);
        action.status = std::move(status);
        queue_action(std::move(action));
    }

    void queue_write_completion(SecureChannel::WriteCompletion completion,
                                Status status) noexcept {
        Action action;
        action.kind = ActionKind::WriteComplete;
        action.write = std::move(completion);
        action.status = std::move(status);
        queue_action(std::move(action));
    }

    void cancel_read(std::uint64_t id) noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (read_ && read_->id == id) read_->terminal = cancelled_status();
        }
        drive();
    }
    void cancel_write(std::uint64_t id) noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (write_ && write_->id == id && write_->offset == 0U)
                write_->terminal = cancelled_status();
        }
        drive();
    }
    void fail(const Status& status) noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (phase_ == Phase::Failed || phase_ == Phase::Closed) return;
            phase_ = Phase::Failed;
            terminal_ = safe_status(status);
            need_transport_close_ = true;
        }
        drive();
    }

    void drive() noexcept {
        // An immediate completion may destroy the final public channel with
        // no transport callback holding this state. Retain it through the
        // complete dispatch loop. weak_from_this also permits destructor
        // cleanup, where no new shared owner can be acquired.
        const auto keep_alive = weak_from_this().lock();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (driving_) return;
            driving_ = true;
        }
        while (true) {
            Action action;
            try {
                {
                    std::lock_guard<std::mutex> lock(mutex_);
                    action = next_action_locked();
                    if (action.kind == ActionKind::None) {
                        driving_ = false;
                        return;
                    }
                }
            } catch (const std::bad_alloc&) {
                std::lock_guard<std::mutex> lock(mutex_);
                phase_ = Phase::Failed;
                terminal_ = safe_status(StatusCode::ResourceExhausted,
                                        "TLS state allocation failed");
                need_transport_close_ = true;
                continue;
            } catch (...) {
                std::lock_guard<std::mutex> lock(mutex_);
                phase_ = Phase::Failed;
                terminal_ = safe_status(StatusCode::Internal,
                                        "TLS state transition failed");
                need_transport_close_ = true;
                continue;
            }
            execute(std::move(action));
        }
    }

    Action next_action_locked() {
        // None means no runnable work. A terminal transition must instead
        // produce its cleanup/completion action without waiting for more I/O.
        Action action;
        if (need_transport_close_) {
            need_transport_close_ = false;
            action.kind = ActionKind::TransportClose;
            return action;
        }
        if (immediate_head_) {
            std::unique_ptr<ImmediateAction> queued =
                std::move(immediate_head_);
            immediate_head_ = std::move(queued->next);
            if (!immediate_head_) immediate_tail_ = nullptr;
            return std::move(queued->action);
        }
        if ((phase_ == Phase::Failed || phase_ == Phase::Closed) &&
            (handshake_completion_ || cover_completion_)) {
            action.kind = ActionKind::HandshakeFailure;
            action.status = safe_status(terminal_);
            action.handshake = std::move(handshake_completion_);
            action.cover = std::move(cover_completion_);
            return action;
        }
        if (phase_ == Phase::Failed || phase_ == Phase::Closed) {
            if (read_ && !read_->terminal) read_->terminal = safe_status(terminal_);
            if (write_ && !write_->terminal) write_->terminal = safe_status(terminal_);
        }
        if (read_ && read_->terminal) {
            action.kind = ActionKind::ReadFailure;
            action.read = std::move(read_->completion);
            action.status = std::move(*read_->terminal);
            read_.reset();
            return action;
        }
        if (write_ && write_->terminal) {
            action.kind = ActionKind::WriteComplete;
            action.write = std::move(write_->completion);
            action.status = std::move(*write_->terminal);
            write_.reset();
            return action;
        }
        if (phase_ == Phase::Failed || phase_ == Phase::Closed) {
            return action;
        }
        // Ciphertext handed to the underlying writer still belongs to its
        // application write. Do not complete that write or drain another BIO
        // chunk until delivery settles. Reads and writes have separate owners:
        // an outstanding socket read must not suppress outbound TLS traffic.
        if (transport_write_pending_) return action;
        if (shutdown_sent_ && !transport_write_shutdown_ &&
            BIO_ctrl_pending(write_bio_) == 0U) {
            transport_write_shutdown_ = true;
            action.kind = ActionKind::TransportShutdownWrite;
            return action;
        }
        if (BIO_ctrl_pending(write_bio_) > 0) {
            auto allocated = Buffer::allocate(
                std::min<std::size_t>(BIO_ctrl_pending(write_bio_),
                                      std::min(owner_->limits.max_encrypted_chunk_bytes,
                                               transport_->max_write_size())),
                owner_->limits.max_encrypted_chunk_bytes);
            if (!allocated.ok()) {
                phase_ = Phase::Failed; terminal_ = safe_status(allocated.status());
                need_transport_close_ = true; return next_action_locked();
            }
            Buffer buffer = std::move(allocated).take_value();
            std::size_t consumed = 0U;
            if (BIO_read_ex(write_bio_, buffer.mutable_bytes().data(),
                            buffer.size(), &consumed) != 1 || consumed == 0U ||
                !buffer.resize(consumed).ok()) {
                phase_ = Phase::Failed;
                terminal_ = safe_status(StatusCode::Internal,
                                        "TLS ciphertext drain failed");
                need_transport_close_ = true; return next_action_locked();
            }
            action.kind = ActionKind::TransportWrite;
            action.count = consumed;
            action.buffer.emplace(std::move(buffer));
            transport_write_pending_ = true;
            io_expected_ = consumed;
            return action;
        }
        if (phase_ == Phase::Handshake) {
            const int result = SSL_do_handshake(ssl_.get());
            if (result == 1) {
                tls_version_ = static_cast<std::uint16_t>(SSL_version(ssl_.get()));
                if (!cover_mode_ && tls_version_ != TLS1_3_VERSION) {
                    phase_ = Phase::Failed;
                    terminal_ = safe_status(StatusCode::ProviderMismatch,
                                            "TLS peer negotiated a non-TLS-1.3 version");
                    need_transport_close_ = true; return next_action_locked();
                }
                const unsigned char* selected = nullptr;
                unsigned int selected_length = 0U;
                SSL_get0_alpn_selected(ssl_.get(), &selected, &selected_length);
                if ((!cover_mode_ && (selected_length != 2U || !selected ||
                                      selected[0] != 'h' || selected[1] != '2')) ||
                    selected_length > 255U) {
                    phase_ = Phase::Failed;
                    terminal_ = safe_status(StatusCode::ProviderMismatch,
                                            "TLS peer did not negotiate exact ALPN h2");
                    need_transport_close_ = true; return next_action_locked();
                }
                if (selected_length != 0U) {
                    protocol_.assign(reinterpret_cast<const char*>(selected),
                                     selected_length);
                }
                if (const char* name = SSL_get_servername(
                        ssl_.get(), TLSEXT_NAMETYPE_host_name)) {
                    const std::string_view received(name);
                    if (received.size() > kMaxServerNameBytes) {
                        phase_ = Phase::Failed;
                        terminal_ = safe_status(StatusCode::ResourceExhausted,
                                                "TLS server name exceeds its bound");
                        need_transport_close_ = true;
                        return next_action_locked();
                    }
                    received_server_name_.assign(received);
                }
                Result<SecureChannelPeerEvidence> made =
                    owner_->configured_role == EndpointRole::Client
                        ? certificate_evidence(ssl_.get(), EndpointRole::Server,
                                               owner_->server_name)
                        : (owner_->mutual_tls
                               ? certificate_evidence(ssl_.get(), EndpointRole::Client, {})
                               : Result<SecureChannelPeerEvidence>(
                                     SecureChannelPeerEvidence::anonymous_client()));
                if (!made.ok()) {
                    phase_ = Phase::Failed; terminal_ = safe_status(made.status());
                    need_transport_close_ = true; return next_action_locked();
                }
                evidence_.emplace(std::move(made).take_value());
                phase_ = Phase::Active;
                handshake_cancellation_.unregister();
                action.kind = ActionKind::HandshakeSuccess;
                action.handshake = std::move(handshake_completion_);
                action.cover = std::move(cover_completion_);
                return action;
            }
            return tls_want_action_locked(result, "TLS handshake failed");
        }
        if (write_) {
            if (write_->offset == write_->buffer.size()) {
                action.kind = ActionKind::WriteComplete;
                action.write = std::move(write_->completion);
                action.status = Status::success();
                action.count = write_->offset;
                write_.reset();
                return action;
            }
            std::size_t consumed = 0U;
            const auto remaining = write_->buffer.bytes().subspan(write_->offset);
            const int result = SSL_write_ex(ssl_.get(), remaining.data(),
                                            remaining.size(), &consumed);
            if (result == 1 && consumed > 0U) {
                write_->offset += consumed;
                return next_action_locked();
            }
            return tls_want_action_locked(result, "TLS application write failed");
        }
        if (shutdown_requested_ && !shutdown_sent_) {
            const int result = SSL_shutdown(ssl_.get());
            if (result >= 0) {
                shutdown_sent_ = true;
                return next_action_locked();
            }
            return tls_want_action_locked(result, "TLS close-notify failed");
        }
        if (read_) {
            auto allocated = Buffer::allocate(read_->maximum, read_->maximum);
            if (!allocated.ok()) {
                read_->terminal = safe_status(allocated.status()); return next_action_locked();
            }
            Buffer buffer = std::move(allocated).take_value();
            std::size_t received = 0U;
            const int result = SSL_read_ex(ssl_.get(), buffer.mutable_bytes().data(),
                                           buffer.size(), &received);
            if (result == 1 && received > 0U && buffer.resize(received).ok()) {
                action.kind = ActionKind::ReadSuccess;
                action.read = std::move(read_->completion);
                action.buffer.emplace(std::move(buffer));
                read_.reset();
                return action;
            }
            const int error = SSL_get_error(ssl_.get(), result);
            if (error == SSL_ERROR_ZERO_RETURN) {
                remote_closed_ = true;
                read_->terminal = closed_status();
                return next_action_locked();
            }
            return tls_want_action_locked(result, "TLS application read failed");
        }
        return action;
    }

    Action tls_want_action_locked(int result, std::string_view message) {
        Action action;
        const int error = SSL_get_error(ssl_.get(), result);
        if (BIO_ctrl_pending(write_bio_) > 0) return next_action_locked();
        if (error == SSL_ERROR_WANT_READ) {
            if (transport_read_pending_) return action;
            const std::size_t maximum = std::min(owner_->limits.max_encrypted_chunk_bytes,
                                                 transport_->max_read_size());
            if (maximum == 0U) {
                phase_ = Phase::Failed;
                terminal_ = safe_status(StatusCode::FailedPrecondition,
                                        "underlying channel has no read capacity");
                need_transport_close_ = true; return next_action_locked();
            }
            action.kind = ActionKind::TransportRead;
            action.count = maximum;
            transport_read_pending_ = true;
            return action;
        }
        if (error == SSL_ERROR_WANT_WRITE) return action;
        phase_ = Phase::Failed;
        terminal_ = safe_status(StatusCode::FailedPrecondition, message);
        need_transport_close_ = true;
        ERR_clear_error();
        return next_action_locked();
    }

    void execute(Action action) noexcept {
        try {
        switch (action.kind) {
        case ActionKind::TransportRead:
            transport_->async_read(action.count, internal_cancellation_.token(),
                [self = shared_from_this()](Result<Buffer> result) noexcept {
                    self->on_transport_read(std::move(result));
                });
            break;
        case ActionKind::TransportWrite:
            transport_->async_write(std::move(*action.buffer),
                internal_cancellation_.token(),
                [self = shared_from_this()](Status status, std::size_t count) noexcept {
                    self->on_transport_write(std::move(status), count);
                });
            break;
        case ActionKind::TransportShutdownWrite: {
            const Status status = transport_->shutdown_write();
            if (!status.ok()) {
                fail(status);
            }
            break;
        }
        case ActionKind::TransportClose:
            internal_cancellation_.cancel();
            try { transport_->close(); } catch (...) {}
            break;
        case ActionKind::HandshakeSuccess: {
            if (action.cover) {
                try {
                    std::unique_ptr<Ytp1TlsServerConnection> connection =
                        std::make_unique<ServerTlsConnection>(shared_from_this());
                    Result<std::unique_ptr<Ytp1TlsServerConnection>> result(
                        std::move(connection));
                    invoke_noexcept(action.cover, std::move(result));
                } catch (...) {
                    Result<std::unique_ptr<Ytp1TlsServerConnection>> failure(
                        safe_status(StatusCode::ResourceExhausted,
                                    "TLS cover connection allocation failed"));
                    invoke_noexcept(action.cover, std::move(failure));
                    close();
                }
                break;
            }
            std::unique_ptr<SecureChannel> channel;
            try { channel = std::make_unique<TlsChannel>(shared_from_this()); }
            catch (...) {
                Result<std::unique_ptr<SecureChannel>> failure(safe_status(
                    StatusCode::ResourceExhausted, "TLS channel allocation failed"));
                invoke_noexcept(action.handshake, std::move(failure));
                close();
                break;
            }
            Result<std::unique_ptr<SecureChannel>> result(std::move(channel));
            invoke_noexcept(action.handshake, std::move(result));
            break;
        }
        case ActionKind::HandshakeFailure: {
            if (action.cover) {
                Result<std::unique_ptr<Ytp1TlsServerConnection>> result(
                    std::move(action.status));
                invoke_noexcept(action.cover, std::move(result));
                break;
            }
            Result<std::unique_ptr<SecureChannel>> result(
                std::move(action.status));
            invoke_noexcept(action.handshake, std::move(result));
            break;
        }
        case ActionKind::ReadSuccess: {
            Result<Buffer> result(std::move(*action.buffer));
            invoke_noexcept(action.read, std::move(result));
            break;
        }
        case ActionKind::ReadFailure: {
            Result<Buffer> result(std::move(action.status));
            invoke_noexcept(action.read, std::move(result));
            break;
        }
        case ActionKind::WriteComplete:
            invoke_noexcept(
                action.write, std::move(action.status), action.count);
            break;
        case ActionKind::None:
            break;
        }
        } catch (const std::bad_alloc&) {
            fail(safe_status(StatusCode::ResourceExhausted,
                             "TLS callback dispatch allocation failed"));
        } catch (...) {
            fail(safe_status(StatusCode::Internal,
                             "TLS transport callback threw"));
        }
    }

    void on_transport_read(Result<Buffer> result) noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_read_pending_ = false;
            // Transport teardown can complete an outstanding operation inline.
            // Retain the original failure and do not feed late bytes into TLS.
            if (phase_ != Phase::Failed && phase_ != Phase::Closed) {
                if (!result.ok()) {
                    phase_ = Phase::Failed; terminal_ = safe_status(result.status());
                    need_transport_close_ = true;
                } else {
                    Buffer buffer = std::move(result).take_value();
                    if (phase_ == Phase::Handshake &&
                        (buffer.size() > kMaxHandshakeCiphertextBytes ||
                         handshake_ciphertext_bytes_ >
                             kMaxHandshakeCiphertextBytes - buffer.size())) {
                        phase_ = Phase::Failed;
                        terminal_ = safe_status(
                            StatusCode::ResourceExhausted,
                            "TLS handshake input budget exhausted");
                        need_transport_close_ = true;
                    } else {
                        std::size_t written = 0U;
                        if (buffer.empty() ||
                            BIO_write_ex(read_bio_, buffer.bytes().data(),
                                         buffer.size(), &written) != 1 ||
                            written != buffer.size()) {
                            phase_ = Phase::Failed;
                            terminal_ = safe_status(
                                StatusCode::Internal,
                                "TLS ciphertext input failed");
                            need_transport_close_ = true;
                        } else if (phase_ == Phase::Handshake) {
                            handshake_ciphertext_bytes_ += buffer.size();
                        }
                    }
                }
            }
        }
        drive();
    }
    void on_transport_write(Status status, std::size_t count) noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            transport_write_pending_ = false;
            if (phase_ != Phase::Failed && phase_ != Phase::Closed &&
                (!status.ok() || count != io_expected_)) {
                phase_ = Phase::Failed;
                terminal_ = status.ok()
                    ? safe_status(StatusCode::Internal,
                                  "underlying channel partially wrote TLS ciphertext")
                    : std::move(status);
                need_transport_close_ = true;
            }
        }
        drive();
    }

    std::shared_ptr<Ytp1Tls13SecureChannelProvider::Impl> owner_;
    std::unique_ptr<engine::ByteChannel> transport_;
    SslPtr ssl_{nullptr, SSL_free};
    BIO* read_bio_{nullptr};
    BIO* write_bio_{nullptr};
    ExecutorAffinity affinity_;
    mutable std::mutex mutex_;
    Phase phase_{Phase::Handshake};
    std::optional<SecureChannelPeerEvidence> evidence_;
    engine::SecureChannelProvider::Completion handshake_completion_;
    Ytp1Tls13SecureChannelProvider::ServerCoverCompletion cover_completion_;
    CancellationRegistration handshake_cancellation_;
    engine::CancellationSource internal_cancellation_;
    std::optional<PendingRead> read_;
    std::optional<PendingWrite> write_;
    std::unique_ptr<ImmediateAction> immediate_head_;
    ImmediateAction* immediate_tail_{nullptr};
    Status terminal_{StatusCode::Internal, "TLS state failed"};
    std::uint64_t next_id_{1U};
    std::size_t io_expected_{0U};
    std::size_t handshake_ciphertext_bytes_{0U};
    std::uint16_t tls_version_{0U};
    std::string protocol_;
    std::string received_server_name_;
    bool cover_mode_{false};
    bool promoted_{false};
    bool transport_read_pending_{false};
    bool transport_write_pending_{false};
    bool driving_{false};
    bool need_transport_close_{false};
    bool shutdown_requested_{false};
    bool shutdown_sent_{false};
    bool transport_write_shutdown_{false};
    bool remote_closed_{false};
};

TlsChannel::~TlsChannel() { state_->close(); }
ExecutorAffinity TlsChannel::executor_affinity() const noexcept { return state_->affinity(); }
std::size_t TlsChannel::max_read_size() const noexcept { return state_->max_plaintext(); }
std::size_t TlsChannel::max_write_size() const noexcept { return state_->max_plaintext(); }
void TlsChannel::async_read(std::size_t n, CancellationToken c, ReadCompletion done) {
    state_->async_read(n, std::move(c), std::move(done));
}
void TlsChannel::async_write(Buffer b, CancellationToken c, WriteCompletion done) {
    state_->async_write(std::move(b), std::move(c), std::move(done));
}
Status TlsChannel::shutdown_write() noexcept { return state_->shutdown_write(); }
void TlsChannel::cancel() noexcept { state_->cancel(); }
void TlsChannel::close() noexcept { state_->close(); }
const SecureChannelPeerEvidence& TlsChannel::peer_evidence() const noexcept { return state_->evidence(); }
const ProviderDescriptor& TlsChannel::descriptor() const noexcept { return state_->descriptor(); }
Result<Buffer> TlsChannel::export_keying_material(
    std::string_view label, std::span<const std::byte> context, std::size_t size) {
    return state_->exporter(label, context, size);
}

ServerTlsConnection::~ServerTlsConnection() { close(); }
ExecutorAffinity ServerTlsConnection::executor_affinity() const noexcept {
    return state_ ? state_->affinity() : ExecutorAffinity{};
}
std::size_t ServerTlsConnection::max_read_size() const noexcept {
    return state_ ? state_->max_plaintext() : 0U;
}
std::size_t ServerTlsConnection::max_write_size() const noexcept {
    return max_read_size();
}
void ServerTlsConnection::async_read(std::size_t maximum,
                                     CancellationToken cancellation,
                                     ReadCompletion completion) {
    if (state_) {
        state_->async_read(maximum, std::move(cancellation), std::move(completion));
    } else {
        Result<Buffer> result(closed_status());
        invoke_noexcept(completion, std::move(result));
    }
}
void ServerTlsConnection::async_write(Buffer buffer,
                                      CancellationToken cancellation,
                                      WriteCompletion completion) {
    if (state_) {
        state_->async_write(std::move(buffer), std::move(cancellation),
                            std::move(completion));
    } else {
        invoke_noexcept(completion, closed_status(), 0U);
    }
}
Status ServerTlsConnection::shutdown_write() noexcept {
    return state_ ? state_->shutdown_write() : closed_status();
}
void ServerTlsConnection::cancel() noexcept { if (state_) state_->cancel(); }
void ServerTlsConnection::close() noexcept { if (state_) state_->close(); }
std::uint16_t ServerTlsConnection::tls_version() const noexcept {
    return state_ ? state_->tls_version() : 0U;
}
std::string_view ServerTlsConnection::negotiated_protocol() const noexcept {
    return state_ ? state_->negotiated_protocol() : std::string_view{};
}
std::string_view ServerTlsConnection::server_name() const noexcept {
    return state_ ? state_->server_name() : std::string_view{};
}
Result<Buffer> ServerTlsConnection::export_keying_material(
    std::string_view label, std::span<const std::byte> context, std::size_t size) {
    return state_ ? state_->exporter(label, context, size)
                  : Result<Buffer>(closed_status());
}
Result<std::unique_ptr<SecureChannel>> ServerTlsConnection::promote() {
    if (!state_) return Result<std::unique_ptr<SecureChannel>>(closed_status());
    auto result = state_->promote();
    if (result.ok()) state_.reset();
    return result;
}

}  // namespace

Ytp1Tls13SecureChannelProvider::Ytp1Tls13SecureChannelProvider(
    ProviderDescriptor descriptor, std::shared_ptr<Impl> impl) noexcept
    : descriptor_(std::move(descriptor)), impl_(std::move(impl)) {}

Ytp1Tls13SecureChannelProvider::~Ytp1Tls13SecureChannelProvider() = default;

engine::EndpointRole Ytp1Tls13SecureChannelProvider::local_role() const noexcept {
    return impl_->configured_role;
}

Result<std::shared_ptr<Ytp1Tls13SecureChannelProvider>>
Ytp1Tls13SecureChannelProvider::create_client(
    const Ytp1Tls13ClientConfigView& config) {
    const bool has_certificate = !config.certificate_chain_pem.empty();
    const bool has_private_key = !config.private_key_pem.empty();
    if (!valid_limits(config.limits) || !valid_server_name(config.server_name) ||
        config.trust_anchors_pem.empty() ||
        config.trust_anchors_pem.size() > config.limits.max_credential_pem_bytes ||
        has_certificate != has_private_key ||
        config.certificate_chain_pem.size() >
            config.limits.max_credential_pem_bytes ||
        config.private_key_pem.size() >
            config.limits.max_credential_pem_bytes) {
        return Result<std::shared_ptr<Ytp1Tls13SecureChannelProvider>>(
            safe_status(StatusCode::InvalidArgument, "invalid TLS client configuration"));
    }
    SslCtxPtr context(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    if (!context ||
        !add_trust_anchors(context.get(), config.trust_anchors_pem) ||
        (has_certificate &&
         !install_server_identity(context.get(), config.certificate_chain_pem,
                                  config.private_key_pem))) {
        return Result<std::shared_ptr<Ytp1Tls13SecureChannelProvider>>(
            safe_status(StatusCode::FailedPrecondition, "TLS client context initialization failed"));
    }
    SSL_CTX_set_verify(context.get(), SSL_VERIFY_PEER, nullptr);
    try {
        const auto& profile = cover_profile::active();
        if (profile.tls_required_version != TLS1_3_VERSION) {
            return Result<std::shared_ptr<Ytp1Tls13SecureChannelProvider>>(
                safe_status(StatusCode::ProviderMismatch,
                            "TLS cover profile does not require TLS 1.3"));
        }
        // The browser-shaped offer includes TLS 1.2 and HTTP/1.1. Publication
        // still requires negotiated TLS 1.3 and h2 in TlsChannelState.
        const auto warnings = tls_stealth::configure_client_profile(
            context.get(), profile.tls_profile, true);
        if (!warnings.empty()) {
            return Result<std::shared_ptr<Ytp1Tls13SecureChannelProvider>>(
                safe_status(StatusCode::FailedPrecondition,
                            "TLS browser profile could not be applied exactly"));
        }
    } catch (const std::bad_alloc&) {
        return Result<std::shared_ptr<Ytp1Tls13SecureChannelProvider>>(
            safe_status(StatusCode::ResourceExhausted,
                        "TLS browser profile allocation failed"));
    } catch (...) {
        return Result<std::shared_ptr<Ytp1Tls13SecureChannelProvider>>(
            safe_status(StatusCode::FailedPrecondition,
                        "TLS browser profile requires supported patched OpenSSL"));
    }
    auto descriptor = make_descriptor();
    if (!descriptor.ok()) return Result<std::shared_ptr<Ytp1Tls13SecureChannelProvider>>(descriptor.status());
    try {
        ProviderDescriptor concrete = std::move(descriptor).take_value();
        auto impl = std::make_shared<Impl>(std::move(context), concrete,
                                           EndpointRole::Client,
                                           std::string(config.server_name), config.limits, false);
        return Result<std::shared_ptr<Ytp1Tls13SecureChannelProvider>>(
            std::shared_ptr<Ytp1Tls13SecureChannelProvider>(
                new Ytp1Tls13SecureChannelProvider(std::move(concrete),
                                                    std::move(impl))));
    } catch (...) {
        return Result<std::shared_ptr<Ytp1Tls13SecureChannelProvider>>(
            safe_status(StatusCode::ResourceExhausted, "TLS provider allocation failed"));
    }
}

Result<std::shared_ptr<Ytp1Tls13SecureChannelProvider>>
Ytp1Tls13SecureChannelProvider::create_server(
    const Ytp1Tls13ServerConfigView& config) {
    if (!valid_limits(config.limits) || config.certificate_chain_pem.empty() ||
        config.private_key_pem.empty() ||
        config.certificate_chain_pem.size() > config.limits.max_credential_pem_bytes ||
        config.private_key_pem.size() > config.limits.max_credential_pem_bytes ||
        config.client_trust_anchors_pem.size() > config.limits.max_credential_pem_bytes) {
        return Result<std::shared_ptr<Ytp1Tls13SecureChannelProvider>>(
            safe_status(StatusCode::InvalidArgument, "invalid TLS server configuration"));
    }
    SslCtxPtr context(SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
    const bool mutual = !config.client_trust_anchors_pem.empty();
    if (!context || SSL_CTX_set_min_proto_version(context.get(), TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(context.get(), TLS1_3_VERSION) != 1 ||
        !install_server_identity(context.get(), config.certificate_chain_pem,
                                 config.private_key_pem) ||
        (mutual && !add_trust_anchors(context.get(),
                                     config.client_trust_anchors_pem))) {
        return Result<std::shared_ptr<Ytp1Tls13SecureChannelProvider>>(
            safe_status(StatusCode::FailedPrecondition, "TLS server context initialization failed"));
    }
    SSL_CTX_set_alpn_select_cb(context.get(), select_h2, nullptr);
    SSL_CTX_set_verify(context.get(), mutual ? SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
                                             : SSL_VERIFY_NONE, nullptr);
    auto descriptor = make_descriptor();
    if (!descriptor.ok()) return Result<std::shared_ptr<Ytp1Tls13SecureChannelProvider>>(descriptor.status());
    try {
        ProviderDescriptor concrete = std::move(descriptor).take_value();
        auto impl = std::make_shared<Impl>(std::move(context), concrete,
                                           EndpointRole::Server,
                                           std::string{}, config.limits, mutual);
        return Result<std::shared_ptr<Ytp1Tls13SecureChannelProvider>>(
            std::shared_ptr<Ytp1Tls13SecureChannelProvider>(
                new Ytp1Tls13SecureChannelProvider(std::move(concrete),
                                                    std::move(impl))));
    } catch (...) {
        return Result<std::shared_ptr<Ytp1Tls13SecureChannelProvider>>(
            safe_status(StatusCode::ResourceExhausted, "TLS provider allocation failed"));
    }
}

const ProviderDescriptor&
Ytp1Tls13SecureChannelProvider::descriptor() const noexcept { return descriptor_; }

void Ytp1Tls13SecureChannelProvider::async_wrap(
    std::unique_ptr<engine::ByteChannel> channel, EndpointRole local_role,
    CancellationToken cancellation, Completion completion) {
    async_wrap_impl(std::move(channel), local_role, std::move(cancellation),
                    std::move(completion), {});
}

void Ytp1Tls13SecureChannelProvider::async_wrap_server_cover(
    std::unique_ptr<engine::ByteChannel> channel,
    CancellationToken cancellation, ServerCoverCompletion completion) {
    async_wrap_impl(std::move(channel), EndpointRole::Server,
                    std::move(cancellation), {}, std::move(completion));
}

void Ytp1Tls13SecureChannelProvider::async_wrap_impl(
    std::unique_ptr<engine::ByteChannel> channel, EndpointRole local_role,
    CancellationToken cancellation, Completion completion,
    ServerCoverCompletion cover_completion) {
    if (!completion && !cover_completion) return;
    const bool cover = static_cast<bool>(cover_completion);
    const auto fail = [&](Status status) noexcept {
        if (cover) {
            Result<std::unique_ptr<Ytp1TlsServerConnection>> result(std::move(status));
            invoke_noexcept(cover_completion, std::move(result));
        } else {
            Result<std::unique_ptr<SecureChannel>> result(std::move(status));
            invoke_noexcept(completion, std::move(result));
        }
    };
    if (cancellation.is_cancelled()) {
        if (channel) channel->close();
        fail(cancelled_status());
        return;
    }
    if (!channel || local_role != impl_->configured_role ||
        !channel->executor_affinity().valid() || channel->max_read_size() == 0U ||
        channel->max_write_size() == 0U) {
        fail(safe_status(
            local_role != impl_->configured_role ? StatusCode::ProviderMismatch
                                                 : StatusCode::InvalidArgument,
            "TLS provider role or byte channel is invalid"));
        if (channel) channel->close();
        return;
    }
    SslPtr ssl(SSL_new(impl_->context.get()), SSL_free);
    BIO* read_bio = BIO_new(BIO_s_mem());
    BIO* write_bio = BIO_new(BIO_s_mem());
    if (!ssl || !read_bio || !write_bio) {
        if (read_bio) BIO_free(read_bio);
        if (write_bio) BIO_free(write_bio);
        channel->close();
        fail(safe_status(
            StatusCode::ResourceExhausted, "TLS session allocation failed"));
        return;
    }
    BIO_set_mem_eof_return(read_bio, -1);
    BIO_set_mem_eof_return(write_bio, -1);
    SSL_set_bio(ssl.get(), read_bio, write_bio);
    if (local_role == EndpointRole::Client) {
        SSL_set_connect_state(ssl.get());
        if (SSL_set_tlsext_host_name(ssl.get(), impl_->server_name.c_str()) != 1 ||
            SSL_set1_host(ssl.get(), impl_->server_name.c_str()) != 1) {
            channel->close();
            fail(safe_status(
                StatusCode::FailedPrecondition, "TLS client verification setup failed"));
            return;
        }
    } else {
        SSL_set_accept_state(ssl.get());
        if (cover) {
            if (SSL_set_min_proto_version(ssl.get(), TLS1_2_VERSION) != 1 ||
                SSL_set_app_data(ssl.get(), &kCoverConnectionMarker) != 1) {
                channel->close();
                fail(safe_status(StatusCode::FailedPrecondition,
                                 "TLS cover negotiation setup failed"));
                return;
            }
        }
    }
    try {
        auto state = std::make_shared<TlsChannelState>(
            impl_, std::move(channel), std::move(ssl), read_bio, write_bio,
            cover);
        state->start(std::move(cancellation), std::move(completion),
                     std::move(cover_completion));
    } catch (...) {
        // Callbacks stay here until the complete state exists. Failed
        // construction releases its moved channel/SSL through their owners;
        // failure before that move still leaves channel with this scope.
        if (channel) channel->close();
        fail(safe_status(
            StatusCode::ResourceExhausted, "TLS state allocation failed"));
    }
}

}  // namespace yume::providers
