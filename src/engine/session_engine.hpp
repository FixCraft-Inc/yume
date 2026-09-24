/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "engine/engine_builder.hpp"

namespace yume::engine {

inline constexpr std::size_t kSessionExporterBytes = 32U;
inline constexpr std::size_t kMaxSessionSecurityOverheadBytes = 4096U;
inline constexpr std::size_t kMaxSessionRekeyPayloadBytes = 64U * 1024U;
inline constexpr std::uint32_t kMaxSessionConcurrentRekeys = 64U;
inline constexpr auto kMaxRekeyAckTimeout = std::chrono::seconds(30);

enum class SessionState : std::uint8_t {
    Created,
    Authenticating,
    AwaitingCapabilities,
    Active,
    Closing,
    Closed,
    Failed,
};

enum class AuthenticationMessageKind : std::uint8_t {
    Challenge,
    Response,
    Accepted,
};

// A token identifies one directional, one-use record key. Sequence numbers
// are monotonically increasing for the entire direction and never reset when
// the epoch changes.
struct RecordKeyToken final {
    std::uint32_t epoch{0U};
    std::uint64_t sequence{0U};

    friend constexpr bool operator==(RecordKeyToken,
                                     RecordKeyToken) noexcept = default;
};

struct SessionLimits final {
    std::uint32_t max_frame_payload{64U * 1024U};
    std::uint32_t max_streams{256U};
    std::uint32_t max_pending_opens{32U};
    std::uint32_t max_control_messages{128U};
    std::size_t max_queued_bytes{8U * 1024U * 1024U};
    std::size_t max_stream_queued_bytes{512U * 1024U};
    std::uint32_t max_packet_size{64U * 1024U};
    std::uint32_t initial_connection_credit{4U * 1024U * 1024U};
    std::uint32_t max_connection_credit{16U * 1024U * 1024U};
    std::uint32_t initial_stream_credit{256U * 1024U};
    std::uint32_t max_stream_credit{4U * 1024U * 1024U};
    std::uint32_t max_concurrent_rekeys{2U};
    std::size_t max_rekey_payload{kMaxSessionRekeyPayloadBytes};
    std::size_t max_security_overhead{256U};
    // Local retention bound, measured from scheduling INIT, including provider
    // work and carrier queueing. This does not change a wire/security domain.
    std::chrono::milliseconds rekey_ack_timeout{kMaxRekeyAckTimeout};
};

// Validates the single runtime limit contract before opening transport resources.
Status validate_session_limits(const SessionLimits& limits);

// Every view is borrowed only for initialize(). The provider must copy any
// state it needs. The exporter is obtained from this session's SecureChannel;
// the authenticated capability bytes are the canonical YTP/1 manifest that
// the engine later requires the peer to repeat inside a protected record.
struct SessionAuthenticationContext final {
    EndpointRole local_role;
    std::string_view suite_id;
    std::span<const std::byte> security_parameters;
    std::span<const std::byte> channel_exporter;
    const SecureChannelPeerEvidence& secure_channel_peer;
    std::span<const std::byte> local_capability_manifest;
};

struct AuthenticationOutput final {
    std::optional<AuthenticationMessageKind> outbound_kind;
    std::optional<Buffer> outbound_message;
    bool established{false};
    std::optional<PeerEvidence> authenticated_peer;
    std::vector<std::byte> authenticated_peer_capability_manifest;
};

// Cryptographic providers are session instances, not registry entries. They
// own composite signature/KEM/KDF/AEAD state and must bind RecordKeyToken into
// the YTP/1 AAD and derive a fresh key for every token. SessionEngine owns wire
// ordering, replay rejection, resource policy, and the AUTH state machine.
class SessionSecurityProvider {
public:
    virtual ~SessionSecurityProvider() = default;

    virtual std::string_view provider_id() const noexcept = 0;
    virtual std::string_view suite_id() const noexcept = 0;
    virtual std::span<const std::byte> security_parameters() const noexcept = 0;
    virtual std::size_t max_sealed_overhead() const noexcept = 0;

    virtual Status initialize(
        const SessionAuthenticationContext& context) = 0;
    virtual Result<AuthenticationOutput> start_authentication() = 0;
    virtual Result<AuthenticationOutput> process_authentication(
        AuthenticationMessageKind kind,
        std::span<const std::byte> canonical_message) = 0;

    virtual Result<Buffer> seal_record(
        RecordKeyToken token,
        std::span<const std::byte> plaintext) = 0;
    virtual Result<Buffer> open_record(
        RecordKeyToken token,
        std::span<const std::byte> ciphertext) = 0;

    // INIT is carried under the current directional record AEAD. ACK is the
    // sole bare post-AUTH YTP record: accept_inbound_rekey() must authenticate
    // its returned payload under the candidate new root, and
    // finish_outbound_rekey() must verify that confirmation before committing
    // the outbound root. This avoids retaining an old root when opposite
    // directions rekey simultaneously.
    virtual Result<Buffer> begin_outbound_rekey(
        std::uint32_t next_epoch) = 0;
    virtual Result<Buffer> accept_inbound_rekey(
        std::uint32_t next_epoch,
        std::span<const std::byte> initiation) = 0;
    virtual Status finish_outbound_rekey(
        std::uint32_t next_epoch,
        std::span<const std::byte> acknowledgement) = 0;

    // Cancels and wipes pending authentication/rekey/key material. It must be
    // idempotent and must not throw during teardown.
    virtual void cancel() noexcept = 0;
};

// The frozen EngineGraph owns one exact factory. Each session receives a
// fresh, single-owner provider instance; mutable key state is never shared
// across endpoints and no process-global provider registry is consulted.
class SessionSecurityProviderFactory {
public:
    virtual ~SessionSecurityProviderFactory() = default;
    virtual const ProviderDescriptor& descriptor() const noexcept = 0;
    virtual Result<std::unique_ptr<SessionSecurityProvider>> create(
        EndpointRole local_role) = 0;
};

// Cumulative local counts for one session, for status displays. Payload
// counts DATA and PACKET bytes. Record counts are carrier records including
// AUTH, control frames and protection overhead. An outbound record counts
// once it is queued for the carrier. Received payload counts after flow
// credit admits it. Counts carry no content, keys or peer-chosen values.
struct SessionTraffic final {
    std::uint64_t payload_bytes_sent{0U};
    std::uint64_t payload_bytes_received{0U};
    std::uint64_t record_bytes_sent{0U};
    std::uint64_t record_bytes_received{0U};
};

class SessionEngine final
    : public std::enable_shared_from_this<SessionEngine> {
public:
    using StartCompletion = std::function<void(Status)>;
    using ClosedCompletion = std::function<void(Status)>;
    using OpenCompletion =
        std::function<void(Result<std::shared_ptr<StreamResponder>>)>;

    static Result<std::shared_ptr<SessionEngine>> create(
        std::shared_ptr<const EngineGraph> graph,
        std::unique_ptr<Carrier> carrier,
        SessionLimits limits = {});

    SessionEngine(const SessionEngine&) = delete;
    SessionEngine& operator=(const SessionEngine&) = delete;
    ~SessionEngine() noexcept;

    ExecutorAffinity executor_affinity() const noexcept;
    SessionState state() const noexcept;
    Status terminal_status() const;
    // Callable from any thread, including after termination.
    SessionTraffic traffic() const noexcept;

    // Copy of the post-YTP peer evidence while the session is Active, so a
    // local opener can report who authenticated the stream without deriving
    // identity from configuration or outer TLS. Fails with
    // FailedPrecondition before activation and after termination.
    Result<PeerEvidence> authenticated_peer() const;

    // Exactly one start completion is accepted. It runs when authenticated
    // peer capabilities have been verified and the session becomes Active,
    // or with the terminal failure/cancellation status.
    void async_start(StartCompletion completion);

    // One observer for the session's lifetime. Runs once after stop has settled
    // pending start/stream callbacks and released their queues, outside engine
    // locks. It may run inline if teardown already finished, otherwise on the
    // thread that finishes teardown. Exceptions are contained. The owner must
    // dispatch onto its executor when necessary. This does not wait for OS I/O
    // cancellation handlers to drain. Empty/duplicate registration is refused.
    Status notify_when_closed(ClosedCompletion completion);

    void async_open(std::string_view service_name,
                    ServiceKind service_kind,
                    OpenCompletion completion);
    void async_open(std::string_view service_name,
                    ServiceKind service_kind,
                    std::optional<RouteDestination> destination,
                    OpenCompletion completion);

    // OPEN completes only after authenticated peer acceptance. Cancellation
    // before acceptance sends an abort and settles the pending callback once.
    void async_open(std::string_view service_name,
                    ServiceKind service_kind,
                    std::optional<RouteDestination> destination,
                    CancellationToken cancellation,
                    OpenCompletion completion);

    // Starts a rekey for the local outbound direction. At most the configured
    // number of directional rekey operations may be in flight.
    Status initiate_rekey();

    // The owner must schedule expiry even when the peer sends nothing. Polling
    // at intervals no longer than rekey_ack_timeout is sufficient if each poll
    // also schedules an earlier pending deadline. ACK admission independently
    // rejects expiration so a delayed timer cannot admit a late confirmation.
    std::optional<std::chrono::steady_clock::time_point> rekey_deadline() const noexcept;
    bool expire_rekey(std::chrono::steady_clock::time_point now) noexcept;

    // Idempotent terminal teardown. Unknown/provider callbacks are never
    // invoked while the engine lock is held and callback exceptions are
    // contained. Teardown does not depend on diagnostic allocations.
    void stop(Status reason = Status(StatusCode::Cancelled)) noexcept;

private:
    friend class EngineStreamResponder;
    class Impl;
    explicit SessionEngine(std::unique_ptr<Impl> impl) noexcept;

    static AuthorizedRouteRequest make_authorized_route_request(
        StreamId stream_id,
        std::string service_name,
        PeerEvidence peer_evidence,
        RouteDestination destination);

    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::engine
