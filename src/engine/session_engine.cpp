/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "engine/session_engine.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <limits>
#include <mutex>
#include <new>
#include <string>
#include <unordered_map>
#include <utility>

#include "engine/secure_erase.hpp"
#include "ytp/protocol.hpp"
#include "ytp/security.hpp"

namespace yume::engine {
namespace {

constexpr std::size_t kProtectedEnvelopeBytes = 16U;
constexpr std::uint8_t kProtectedEnvelopeVersion = 1U;
constexpr std::size_t kClosePayloadBytes = 1U;
constexpr std::size_t kRekeyEpochBytes = 4U;
constexpr std::size_t kPingPayloadBytes = 8U;

enum class StreamCloseCode : std::uint8_t {
    Normal = 0U,
    Unauthorized = 1U,
    Unsupported = 2U,
    HandlerFailure = 3U,
    Aborted = 4U,
};

EndpointRole peer_role(EndpointRole local_role) noexcept {
    return local_role == EndpointRole::Client ? EndpointRole::Server
                                               : EndpointRole::Client;
}

Result<EndpointRole> from_ytp_role(ytp1::EndpointRole role) {
    switch (role) {
    case ytp1::EndpointRole::Client:
        return Result<EndpointRole>(EndpointRole::Client);
    case ytp1::EndpointRole::Server:
        return Result<EndpointRole>(EndpointRole::Server);
    }
    return Result<EndpointRole>(Status(
        StatusCode::InvalidArgument, "unknown YTP/1 endpoint role"));
}

Result<ytp1::ServiceKind> to_ytp_service_kind(ServiceKind kind) {
    switch (kind) {
    case ServiceKind::ByteStream:
        return Result<ytp1::ServiceKind>(ytp1::ServiceKind::ByteStream);
    case ServiceKind::PacketChannel:
        return Result<ytp1::ServiceKind>(ytp1::ServiceKind::Packet);
    }
    return Result<ytp1::ServiceKind>(Status(
        StatusCode::InvalidArgument, "unknown engine service kind"));
}

Result<ServiceKind> from_ytp_service_kind(ytp1::ServiceKind kind) {
    switch (kind) {
    case ytp1::ServiceKind::ByteStream:
        return Result<ServiceKind>(ServiceKind::ByteStream);
    case ytp1::ServiceKind::Packet:
        return Result<ServiceKind>(ServiceKind::PacketChannel);
    }
    return Result<ServiceKind>(Status(
        StatusCode::InvalidArgument, "unknown YTP/1 service kind"));
}

Result<RouteDestination> from_ytp_destination(
    const ytp1::Destination& destination) {
    NetworkProtocol protocol = NetworkProtocol::Tcp;
    switch (destination.transport) {
    case ytp1::TransportProtocol::Tcp:
        protocol = NetworkProtocol::Tcp;
        break;
    case ytp1::TransportProtocol::Udp:
        protocol = NetworkProtocol::Udp;
        break;
    case ytp1::TransportProtocol::None:
        return Result<RouteDestination>(Status(
            StatusCode::InvalidArgument,
            "absent YTP destination cannot become a route destination"));
    default:
        return Result<RouteDestination>(Status(
            StatusCode::InvalidArgument,
            "YTP destination has an unknown transport"));
    }

    switch (destination.address_kind) {
    case ytp1::AddressKind::Ipv4: {
        std::array<std::uint8_t, 4> address{};
        std::copy_n(destination.address.begin(), address.size(),
                    address.begin());
        return RouteDestination::ipv4(protocol, address, destination.port);
    }
    case ytp1::AddressKind::Ipv6:
        return RouteDestination::ipv6(protocol, destination.address,
                                      destination.port);
    case ytp1::AddressKind::Dns:
        try {
            return RouteDestination::dns_name(
                protocol, destination.dns_name, destination.port);
        } catch (const std::bad_alloc&) {
            return Result<RouteDestination>(Status(
                StatusCode::ResourceExhausted,
                "route destination allocation failed"));
        }
    case ytp1::AddressKind::None:
        break;
    }
    return Result<RouteDestination>(Status(
        StatusCode::InvalidArgument,
        "YTP destination has an unknown address kind"));
}

Result<ytp1::Destination> to_ytp_destination(
    const RouteDestination& destination) {
    ytp1::Destination encoded;
    switch (destination.protocol()) {
    case NetworkProtocol::Tcp:
        encoded.transport = ytp1::TransportProtocol::Tcp;
        break;
    case NetworkProtocol::Udp:
        encoded.transport = ytp1::TransportProtocol::Udp;
        break;
    default:
        return Result<ytp1::Destination>(Status(
            StatusCode::InvalidArgument,
            "route destination has an unknown transport"));
    }
    encoded.port = destination.port();
    switch (destination.address_kind()) {
    case RouteAddressKind::Ipv4:
        encoded.address_kind = ytp1::AddressKind::Ipv4;
        encoded.address_length = 4U;
        std::copy(destination.address_bytes().begin(),
                  destination.address_bytes().end(), encoded.address.begin());
        break;
    case RouteAddressKind::Ipv6:
        encoded.address_kind = ytp1::AddressKind::Ipv6;
        encoded.address_length = 16U;
        std::copy(destination.address_bytes().begin(),
                  destination.address_bytes().end(), encoded.address.begin());
        break;
    case RouteAddressKind::DnsName:
        encoded.address_kind = ytp1::AddressKind::Dns;
        try {
            encoded.dns_name.assign(destination.dns_name());
        } catch (const std::bad_alloc&) {
            return Result<ytp1::Destination>(Status(
                StatusCode::ResourceExhausted,
                "route destination allocation failed"));
        }
        break;
    }
    return Result<ytp1::Destination>(std::move(encoded));
}

Result<AuthenticationMessageKind> from_ytp_auth_kind(
    ytp1::AuthMessageType kind) {
    switch (kind) {
    case ytp1::AuthMessageType::Challenge:
        return Result<AuthenticationMessageKind>(
            AuthenticationMessageKind::Challenge);
    case ytp1::AuthMessageType::Response:
        return Result<AuthenticationMessageKind>(
            AuthenticationMessageKind::Response);
    case ytp1::AuthMessageType::Accepted:
        return Result<AuthenticationMessageKind>(
            AuthenticationMessageKind::Accepted);
    case ytp1::AuthMessageType::RekeyInit:
    case ytp1::AuthMessageType::RekeyAck:
        return Result<AuthenticationMessageKind>(Status(
            StatusCode::FailedPrecondition,
            "rekey message is not valid in the AUTH exchange"));
    }
    return Result<AuthenticationMessageKind>(Status(
        StatusCode::InvalidArgument, "unknown YTP/1 AUTH message kind"));
}

ytp1::RecordType auth_record_type(AuthenticationMessageKind kind) noexcept {
    switch (kind) {
    case AuthenticationMessageKind::Challenge:
    case AuthenticationMessageKind::Response:
        return ytp1::RecordType::Auth;
    case AuthenticationMessageKind::Accepted:
        return ytp1::RecordType::AuthResult;
    }
    return ytp1::RecordType::Auth;
}

std::span<const std::uint8_t> as_u8(
    std::span<const std::byte> input) noexcept {
    return {reinterpret_cast<const std::uint8_t*>(input.data()), input.size()};
}

std::span<const std::byte> as_bytes(
    std::span<const std::uint8_t> input) noexcept {
    return {reinterpret_cast<const std::byte*>(input.data()), input.size()};
}

std::span<const std::byte> text_bytes(std::string_view input) noexcept {
    return {reinterpret_cast<const std::byte*>(input.data()), input.size()};
}

std::uint32_t read_u32(std::span<const std::byte> input,
                       std::size_t offset) noexcept {
    return (static_cast<std::uint32_t>(input[offset]) << 24U) |
           (static_cast<std::uint32_t>(input[offset + 1U]) << 16U) |
           (static_cast<std::uint32_t>(input[offset + 2U]) << 8U) |
           static_cast<std::uint32_t>(input[offset + 3U]);
}

std::uint64_t read_u64(std::span<const std::byte> input,
                       std::size_t offset) noexcept {
    std::uint64_t value = 0U;
    for (std::size_t index = 0U; index < 8U; ++index) {
        value = (value << 8U) |
                static_cast<std::uint64_t>(input[offset + index]);
    }
    return value;
}

void write_u32(std::span<std::byte> output,
               std::size_t offset,
               std::uint32_t value) noexcept {
    output[offset] = static_cast<std::byte>(value >> 24U);
    output[offset + 1U] = static_cast<std::byte>(value >> 16U);
    output[offset + 2U] = static_cast<std::byte>(value >> 8U);
    output[offset + 3U] = static_cast<std::byte>(value);
}

void write_u64(std::span<std::byte> output,
               std::size_t offset,
               std::uint64_t value) noexcept {
    for (std::size_t index = 0U; index < 8U; ++index) {
        const std::size_t shift = (7U - index) * 8U;
        output[offset + index] = static_cast<std::byte>(value >> shift);
    }
}

Status protocol_failure(std::string_view message) {
    return Status(StatusCode::FailedPrecondition, message);
}

Status validate_limits(const SessionLimits& limits) {
    if (limits.max_frame_payload == 0U ||
        limits.max_frame_payload > ytp1::kDefaultMaxFramePayload) {
        return Status(StatusCode::InvalidArgument,
                      "session frame limit is outside the YTP/1 bound");
    }
    if (limits.max_streams == 0U ||
        limits.max_streams > ytp1::kMaxCapabilityConcurrentStreams ||
        limits.max_pending_opens == 0U ||
        limits.max_pending_opens > limits.max_streams) {
        return Status(StatusCode::InvalidArgument,
                      "session stream or pending-open limit is invalid");
    }
    if (limits.max_control_messages == 0U ||
        limits.max_queued_bytes == 0U ||
        limits.max_queued_bytes > kAbsoluteMaxBufferBytes ||
        limits.max_stream_queued_bytes == 0U ||
        limits.max_stream_queued_bytes > limits.max_queued_bytes) {
        return Status(StatusCode::InvalidArgument,
                      "session queue limits are invalid");
    }
    if (limits.max_packet_size == 0U ||
        limits.max_packet_size > limits.max_frame_payload) {
        return Status(StatusCode::InvalidArgument,
                      "session packet limit exceeds the frame limit");
    }
    if (limits.initial_connection_credit == 0U ||
        limits.initial_connection_credit > limits.max_connection_credit ||
        limits.max_connection_credit > ytp1::kMaxCreditIncrement ||
        limits.initial_stream_credit == 0U ||
        limits.initial_stream_credit > limits.max_stream_credit ||
        limits.max_stream_credit > ytp1::kMaxCreditIncrement) {
        return Status(StatusCode::InvalidArgument,
                      "session flow-credit limits are invalid");
    }
    if (limits.max_concurrent_rekeys == 0U ||
        limits.max_concurrent_rekeys > kMaxSessionConcurrentRekeys ||
        limits.max_rekey_payload == 0U ||
        limits.max_rekey_payload > kMaxSessionRekeyPayloadBytes ||
        limits.max_security_overhead >
            kMaxSessionSecurityOverheadBytes) {
        return Status(StatusCode::InvalidArgument,
                      "session rekey or security-overhead limit is invalid");
    }
    return Status::success();
}

template <typename Completion, typename... Args>
void invoke_noexcept(Completion& completion, Args&&... args) noexcept {
    if (!completion) {
        return;
    }
    try {
        completion(std::forward<Args>(args)...);
    } catch (...) {
        // Application callbacks are containment boundaries.
    }
}

}  // namespace

class EngineStreamResponder final : public StreamResponder {
public:
    EngineStreamResponder(std::weak_ptr<SessionEngine> engine,
                          StreamId stream_id,
                          ServiceKind service_kind,
                          ExecutorAffinity affinity,
                          std::size_t max_write_size) noexcept
        : engine_(std::move(engine)),
          stream_id_(stream_id),
          service_kind_(service_kind),
          affinity_(affinity),
          max_write_size_(max_write_size) {}

    ExecutorAffinity executor_affinity() const noexcept override {
        return affinity_;
    }
    ServiceKind service_kind() const noexcept override {
        return service_kind_;
    }
    std::size_t max_write_size() const noexcept override {
        return max_write_size_;
    }

    void async_read(CancellationToken cancellation,
                    ReadCompletion completion) override;
    void async_write(Buffer payload,
                     CancellationToken cancellation,
                     WriteCompletion completion) override;
    Status shutdown_write() noexcept override;
    void close(Status reason) noexcept override;

private:
    std::weak_ptr<SessionEngine> engine_;
    StreamId stream_id_;
    ServiceKind service_kind_;
    ExecutorAffinity affinity_;
    std::size_t max_write_size_{0U};
};

class SessionEngine::Impl final {
public:
    Impl(std::shared_ptr<const EngineGraph> graph,
         std::unique_ptr<Carrier> carrier,
         std::unique_ptr<SessionSecurityProvider> security,
         SessionLimits limits,
         std::vector<std::byte> local_capabilities,
         ytp1::CapabilityManifest local_manifest) noexcept
        : graph_(std::move(graph)),
          carrier_(std::move(carrier)),
          security_(std::move(security)),
          limits_(limits),
          local_capabilities_(std::move(local_capabilities)),
          local_manifest_(std::move(local_manifest)),
          next_local_stream_id_(graph_->local_role() == EndpointRole::Client
                                    ? 1U
                                    : 2U),
          affinity_(carrier_->executor_affinity()) {}

    void bind(SessionEngine* owner) noexcept { owner_ = owner; }

    ExecutorAffinity executor_affinity() const noexcept { return affinity_; }

    SessionState state() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return state_;
    }

    Status terminal_status() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return terminal_status_;
    }

    void async_start(StartCompletion completion);
    void async_open(std::string_view service_name,
                    ServiceKind service_kind,
                    std::optional<RouteDestination> destination,
                    OpenCompletion completion);
    Status initiate_rekey();
    void stop(Status reason, bool failed) noexcept;

    void stream_read(StreamId stream_id,
                     CancellationToken cancellation,
                     StreamResponder::ReadCompletion completion);
    void stream_write(StreamId stream_id,
                      Buffer payload,
                      CancellationToken cancellation,
                      StreamResponder::WriteCompletion completion);
    Status stream_shutdown(StreamId stream_id) noexcept;
    void stream_close(StreamId stream_id, Status reason) noexcept;

private:
    struct PendingWrite final {
        PendingWrite(std::uint64_t operation_id_value,
                     Buffer value,
                     StreamResponder::WriteCompletion callback) noexcept
            : operation_id(operation_id_value),
              payload(std::move(value)),
              completion(std::move(callback)) {}

        std::uint64_t operation_id{0U};
        Buffer payload;
        StreamResponder::WriteCompletion completion;
        CancellationRegistration cancellation;
    };

    struct PendingRead final {
        PendingRead(std::uint64_t operation_id_value,
                    StreamResponder::ReadCompletion callback) noexcept
            : operation_id(operation_id_value),
              completion(std::move(callback)) {}

        std::uint64_t operation_id{0U};
        StreamResponder::ReadCompletion completion;
        CancellationRegistration cancellation;
    };

    struct StreamStateData final {
        StreamStateData(StreamId value,
                        std::string name,
                        ServiceKind kind_value,
                        bool opened_by_peer_value) noexcept
            : id(value),
              service_name(std::move(name)),
              kind(kind_value),
              opened_by_peer(opened_by_peer_value) {}

        StreamId id;
        std::string service_name;
        ServiceKind kind;
        bool opened_by_peer{false};
        bool closed{false};
        bool local_write_shutdown_requested{false};
        bool local_write_closed{false};
        bool peer_write_closed{false};
        std::uint64_t outbound_credit{0U};
        std::uint64_t inbound_credit{0U};
        std::size_t inbound_queued_bytes{0U};
        std::size_t outbound_queued_bytes{0U};
        std::size_t outbound_publications{0U};
        std::deque<ReceivedRecord> inbound;
        std::optional<PendingRead> pending_read;
        std::deque<PendingWrite> pending_writes;
        std::shared_ptr<EngineStreamResponder> responder;
    };

    struct OutboundItem final {
        OutboundItem(Buffer value,
                     bool is_control_value,
                     std::size_t completion_bytes_value,
                     Carrier::SendCompletion callback) noexcept
            : wire(std::move(value)),
              is_control(is_control_value),
              completion_bytes(completion_bytes_value),
              completion(std::move(callback)) {}

        Buffer wire;
        bool is_control{false};
        std::size_t completion_bytes{0U};
        Carrier::SendCompletion completion;
    };

    struct ActiveSend final {
        bool is_control{false};
        std::size_t wire_bytes{0U};
        std::size_t completion_bytes{0U};
        Carrier::SendCompletion completion;
    };

    struct DeferredRecord final {
        DeferredRecord(ytp1::RecordType type_value,
                       StreamId stream_id_value,
                       Buffer value,
                       bool is_control_value,
                       std::size_t completion_bytes_value,
                       Carrier::SendCompletion callback) noexcept
            : type(type_value),
              stream_id(stream_id_value),
              payload(std::move(value)),
              is_control(is_control_value),
              completion_bytes(completion_bytes_value),
              completion(std::move(callback)) {}

        ytp1::RecordType type;
        StreamId stream_id;
        Buffer payload;
        bool is_control{false};
        std::size_t completion_bytes{0U};
        Carrier::SendCompletion completion;
    };

    Status initialize_security();
    Status handle_start_output(AuthenticationOutput output);
    Status handle_authentication_record(ytp1::RecordType outer_type,
                                        std::span<const std::byte> payload);
    Status validate_auth_message(AuthenticationMessageKind expected_kind,
                                 EndpointRole expected_sender,
                                 std::span<const std::byte> encoded) const;
    Status accept_established_output(AuthenticationOutput& output);
    Status advertise_post_authentication_state();

    Status enqueue_record(ytp1::RecordType type,
                          StreamId stream_id,
                          std::span<const std::byte> payload,
                          bool protect,
                          bool is_control,
                          std::size_t completion_bytes = 0U,
                          Carrier::SendCompletion completion = {},
                          bool bypass_rekey_barrier = false);
    Status defer_record(ytp1::RecordType type,
                        StreamId stream_id,
                        std::span<const std::byte> payload,
                        bool is_control,
                        std::size_t completion_bytes,
                        Carrier::SendCompletion completion);
    Status flush_deferred_records();
    Result<Buffer> encode_frame(ytp1::RecordType type,
                                StreamId stream_id,
                                std::span<const std::byte> payload) const;
    Result<Buffer> protect_frame(Buffer plaintext,
                                 RecordKeyToken token);
    void request_send_pump() noexcept;
    void on_send_complete(Status status, std::size_t transferred) noexcept;

    void request_receive_pump() noexcept;
    void on_receive(Result<ReceivedRecord> result) noexcept;
    Status process_received(ReceivedRecord record);
    Status process_protected_record(ReceivedRecord record);
    Status process_decoded_record(const ytp1::RecordView& record,
                                  CarrierCredit outer_credit);

    Status process_capabilities(std::span<const std::byte> payload);
    Status process_open(const ytp1::RecordView& record);
    Status process_application_data(const ytp1::RecordView& record,
                                    CarrierCredit outer_credit);
    Status process_close(const ytp1::RecordView& record);
    Status process_connection_credit(std::span<const std::byte> payload);
    Status process_stream_credit(const ytp1::RecordView& record);
    Status process_rekey_init(std::span<const std::byte> payload);
    Status process_rekey_ack(std::span<const std::byte> payload);

    void return_receive_credit(StreamId stream_id,
                               std::size_t bytes) noexcept;
    void drain_pending_writes(StreamId stream_id) noexcept;
    Status send_stream_credit(StreamId stream_id, std::uint32_t increment);
    Status send_close(StreamId stream_id, StreamCloseCode code);
    Status finish_stream_shutdown_if_ready(StreamId stream_id) noexcept;
    void remove_stream(StreamId stream_id, Status reason) noexcept;
    void cancel_pending_read(StreamId stream_id,
                             std::uint64_t operation_id,
                             Status reason) noexcept;
    void cancel_pending_write(StreamId stream_id,
                              std::uint64_t operation_id,
                              Status reason) noexcept;

    const ytp1::Capability* local_capability(
        std::string_view name,
        ServiceKind kind) const noexcept;
    const ytp1::Capability* peer_capability(
        std::string_view name,
        ServiceKind kind) const noexcept;
    std::size_t service_stream_count_locked(std::string_view name,
                                            ServiceKind kind) const noexcept;
    void fail(Status status) noexcept;
    bool terminal_locked() const noexcept {
        return state_ == SessionState::Closing ||
               state_ == SessionState::Closed ||
               state_ == SessionState::Failed;
    }

    std::weak_ptr<SessionEngine> weak_owner() const noexcept {
        return owner_ ? owner_->weak_from_this()
                      : std::weak_ptr<SessionEngine>{};
    }

    SessionEngine* owner_{nullptr};
    std::shared_ptr<const EngineGraph> graph_;
    std::unique_ptr<Carrier> carrier_;
    std::unique_ptr<SessionSecurityProvider> security_;
    SessionLimits limits_;
    std::vector<std::byte> local_capabilities_;
    ytp1::CapabilityManifest local_manifest_;

    mutable std::mutex mutex_;
    std::mutex security_mutex_;
    // Serializes protected token allocation, one-use sealing, and queue
    // publication so concurrent callers cannot put sequence N+1 on the
    // carrier before sequence N.
    std::mutex outbound_record_mutex_;
    SessionState state_{SessionState::Created};
    Status terminal_status_{};
    StartCompletion start_completion_;
    std::optional<AuthenticationMessageKind> expected_auth_kind_;
    std::optional<PeerEvidence> authenticated_peer_;
    std::vector<std::byte> authenticated_peer_capabilities_;
    ytp1::CapabilityManifest peer_manifest_;

    std::unordered_map<std::uint32_t, std::shared_ptr<StreamStateData>>
        streams_;
    std::uint32_t next_local_stream_id_{0U};
    bool local_stream_ids_exhausted_{false};
    std::uint32_t last_peer_stream_id_{0U};
    std::uint32_t pending_opens_{0U};
    std::uint64_t next_operation_id_{1U};
    bool operation_ids_exhausted_{false};
    std::size_t pending_write_bytes_{0U};
    std::size_t inbound_queued_bytes_{0U};

    std::uint64_t outbound_connection_credit_{0U};
    std::uint64_t inbound_connection_credit_{0U};

    std::uint32_t outbound_epoch_{0U};
    std::uint32_t inbound_epoch_{0U};
    std::uint64_t next_outbound_sequence_{0U};
    std::uint64_t next_inbound_sequence_{0U};
    bool outbound_sequence_exhausted_{false};
    bool inbound_sequence_exhausted_{false};
    bool outbound_rekey_pending_{false};
    std::uint32_t outbound_rekey_epoch_{0U};
    std::uint32_t rekey_work_{0U};

    std::deque<OutboundItem> outbound_queue_;
    std::deque<DeferredRecord> deferred_records_;
    std::optional<ActiveSend> active_send_;
    std::size_t queued_wire_bytes_{0U};
    std::uint32_t queued_control_messages_{0U};
    bool send_in_progress_{false};
    bool send_pump_running_{false};
    bool send_pump_again_{false};

    bool receive_in_progress_{false};
    bool receive_pump_running_{false};
    bool receive_pump_again_{false};
    CancellationSource cancellation_;
    ExecutorAffinity affinity_;
};

Result<std::shared_ptr<SessionEngine>> SessionEngine::create(
    std::shared_ptr<const EngineGraph> graph,
    std::unique_ptr<Carrier> carrier,
    SessionLimits limits) {
    if (!graph || !carrier) {
        return Result<std::shared_ptr<SessionEngine>>(Status(
            StatusCode::InvalidArgument,
            "session graph and carrier are required"));
    }
    const Status limit_status = validate_limits(limits);
    if (!limit_status.ok()) {
        return Result<std::shared_ptr<SessionEngine>>(limit_status);
    }
    if (graph->suite().wire_protocol() != "YTP/1") {
        return Result<std::shared_ptr<SessionEngine>>(Status(
            StatusCode::ProviderMismatch,
            "engine graph is not an exact YTP/1 composition"));
    }
    const ProviderRequirement* secure_requirement =
        graph->suite().provider_requirement(ProviderKind::SecureChannel);
    const ProviderRequirement* carrier_requirement =
        graph->suite().provider_requirement(ProviderKind::Carrier);
    if (!secure_requirement || !carrier_requirement ||
        !secure_requirement->required_capabilities().contains(
            Capability::Tls13)) {
        return Result<std::shared_ptr<SessionEngine>>(Status(
            StatusCode::ProviderMismatch,
            "YTP/1 requires exact TLS 1.3 and carrier provenance"));
    }
    const auto descriptor_matches = [](
        const ProviderDescriptor& descriptor,
        const ProviderRequirement& requirement) noexcept {
        return descriptor.kind() == requirement.kind() &&
               descriptor.provider_id() == requirement.provider_id() &&
               descriptor.api_version() == requirement.api_version() &&
               descriptor.capabilities().contains_all(
                   requirement.required_capabilities());
    };
    if (!descriptor_matches(carrier->descriptor(), *carrier_requirement) ||
        !descriptor_matches(carrier->secure_channel().descriptor(),
                            *secure_requirement)) {
        return Result<std::shared_ptr<SessionEngine>>(Status(
            StatusCode::ProviderMismatch,
            "carrier or secure-channel instance does not match the frozen graph"));
    }
    const auto factory = graph->session_security_provider_factory();
    if (!factory) {
        return Result<std::shared_ptr<SessionEngine>>(Status(
            StatusCode::FailedPrecondition,
            "frozen engine graph lacks its security-provider factory"));
    }
    Result<std::unique_ptr<SessionSecurityProvider>> created_security(Status(
        StatusCode::Internal,
        "security-provider factory did not return an instance"));
    try {
        created_security = factory->create(graph->local_role());
    } catch (const std::bad_alloc&) {
        return Result<std::shared_ptr<SessionEngine>>(Status(
            StatusCode::ResourceExhausted,
            "security-provider factory allocation failed"));
    } catch (...) {
        return Result<std::shared_ptr<SessionEngine>>(Status(
            StatusCode::Internal,
            "security-provider factory threw"));
    }
    if (!created_security.ok()) {
        return Result<std::shared_ptr<SessionEngine>>(
            created_security.status());
    }
    std::unique_ptr<SessionSecurityProvider> security_provider =
        std::move(created_security).take_value();
    if (!security_provider ||
        security_provider->provider_id() !=
            factory->descriptor().provider_id() ||
        security_provider->suite_id() != ytp1::kSuiteId) {
        return Result<std::shared_ptr<SessionEngine>>(Status(
            StatusCode::ProviderMismatch,
            "security provider ID or YTP/1 suite does not match"));
    }
    const auto required_parameters =
        as_bytes(ytp1::RequiredSecurityParameters());
    const auto provider_parameters =
        security_provider->security_parameters();
    if (!std::equal(required_parameters.begin(), required_parameters.end(),
                    provider_parameters.begin(), provider_parameters.end())) {
        return Result<std::shared_ptr<SessionEngine>>(Status(
            StatusCode::ProviderMismatch,
            "security provider parameters do not exactly match YTP/1"));
    }
    if (security_provider->max_sealed_overhead() >
            limits.max_security_overhead ||
        security_provider->max_sealed_overhead() >
            kMaxSessionSecurityOverheadBytes) {
        return Result<std::shared_ptr<SessionEngine>>(Status(
            StatusCode::ProviderMismatch,
            "security provider overhead exceeds the configured bound"));
    }
    if (!carrier->executor_affinity().valid() ||
        carrier->secure_channel().executor_affinity() !=
            carrier->executor_affinity()) {
        return Result<std::shared_ptr<SessionEngine>>(Status(
            StatusCode::ProviderMismatch,
            "carrier and secure-channel executor affinity do not match"));
    }
    if (carrier->secure_channel().peer_evidence().peer_role() !=
        peer_role(graph->local_role())) {
        return Result<std::shared_ptr<SessionEngine>>(Status(
            StatusCode::ProviderMismatch,
            "secure-channel peer role does not match the endpoint role"));
    }

    const std::size_t maximum_plaintext = ytp1::kFrameHeaderSize +
                                          limits.max_frame_payload;
    if (maximum_plaintext > kAbsoluteMaxBufferBytes ||
        maximum_plaintext >
            kAbsoluteMaxBufferBytes - kProtectedEnvelopeBytes ||
        security_provider->max_sealed_overhead() >
            kAbsoluteMaxBufferBytes - maximum_plaintext -
                kProtectedEnvelopeBytes) {
        return Result<std::shared_ptr<SessionEngine>>(Status(
            StatusCode::InvalidArgument,
            "session record limits exceed the engine buffer bound"));
    }
    const std::size_t maximum_wire = maximum_plaintext +
        kProtectedEnvelopeBytes + security_provider->max_sealed_overhead();
    if (carrier->max_record_size() < maximum_wire) {
        return Result<std::shared_ptr<SessionEngine>>(Status(
            StatusCode::ProviderMismatch,
            "carrier record bound is smaller than the session composition"));
    }

    try {
        ytp1::CapabilityManifest local_manifest;
        local_manifest.entries.reserve(graph->suite().services().size());
        for (const ServiceRequirement& service :
             graph->suite().services()) {
            auto kind = to_ytp_service_kind(service.service_kind());
            if (!kind.ok()) {
                return Result<std::shared_ptr<SessionEngine>>(kind.status());
            }
            local_manifest.entries.push_back(ytp1::Capability{
                service.service_name(),
                std::move(kind).take_value(),
                std::min(service.max_concurrent_streams(),
                         limits.max_streams)});
        }
        auto encoded = ytp1::EncodeCapabilityManifest(local_manifest);
        if (!encoded.ok()) {
            return Result<std::shared_ptr<SessionEngine>>(Status(
                StatusCode::InvalidArgument,
                "engine graph cannot be encoded as YTP/1 capabilities"));
        }
        std::vector<std::byte> local_capabilities(
            encoded.value->size());
        std::memcpy(local_capabilities.data(), encoded.value->data(),
                    encoded.value->size());

        auto impl = std::make_unique<Impl>(
            std::move(graph), std::move(carrier),
            std::move(security_provider), limits,
            std::move(local_capabilities), std::move(local_manifest));
        auto engine = std::shared_ptr<SessionEngine>(
            new SessionEngine(std::move(impl)));
        engine->impl_->bind(engine.get());
        return Result<std::shared_ptr<SessionEngine>>(std::move(engine));
    } catch (const std::bad_alloc&) {
        return Result<std::shared_ptr<SessionEngine>>(Status(
            StatusCode::ResourceExhausted,
            "session construction allocation failed"));
    } catch (...) {
        return Result<std::shared_ptr<SessionEngine>>(Status(
            StatusCode::Internal,
            "session construction failed unexpectedly"));
    }
}

SessionEngine::SessionEngine(std::unique_ptr<Impl> impl) noexcept
    : impl_(std::move(impl)) {}

AuthorizedRouteRequest SessionEngine::make_authorized_route_request(
    StreamId stream_id,
    std::string service_name,
    PeerEvidence peer_evidence,
    RouteDestination destination) {
    return AuthorizedRouteRequest(
        stream_id, std::move(service_name), std::move(peer_evidence),
        std::move(destination));
}

SessionEngine::~SessionEngine() noexcept {
    if (impl_) {
        impl_->stop(Status(StatusCode::Closed, "session destroyed"), false);
    }
}

ExecutorAffinity SessionEngine::executor_affinity() const noexcept {
    return impl_->executor_affinity();
}

SessionState SessionEngine::state() const noexcept {
    return impl_->state();
}

Status SessionEngine::terminal_status() const {
    return impl_->terminal_status();
}

void SessionEngine::async_start(StartCompletion completion) {
    impl_->async_start(std::move(completion));
}

void SessionEngine::async_open(std::string_view service_name,
                               ServiceKind service_kind,
                               OpenCompletion completion) {
    impl_->async_open(service_name, service_kind, std::nullopt,
                      std::move(completion));
}

void SessionEngine::async_open(
    std::string_view service_name,
    ServiceKind service_kind,
    std::optional<RouteDestination> destination,
    OpenCompletion completion) {
    impl_->async_open(service_name, service_kind, std::move(destination),
                      std::move(completion));
}

Status SessionEngine::initiate_rekey() {
    return impl_->initiate_rekey();
}

void SessionEngine::stop(Status reason) noexcept {
    impl_->stop(std::move(reason), false);
}

void EngineStreamResponder::async_read(CancellationToken cancellation,
                                       ReadCompletion completion) {
    if (auto engine = engine_.lock()) {
        engine->impl_->stream_read(stream_id_, std::move(cancellation),
                                   std::move(completion));
        return;
    }
    auto result = Result<ReceivedRecord>(Status(
        StatusCode::Closed, "session no longer exists"));
    invoke_noexcept(completion, std::move(result));
}

void EngineStreamResponder::async_write(Buffer payload,
                                        CancellationToken cancellation,
                                        WriteCompletion completion) {
    if (auto engine = engine_.lock()) {
        engine->impl_->stream_write(stream_id_, std::move(payload),
                                    std::move(cancellation),
                                    std::move(completion));
        return;
    }
    invoke_noexcept(completion,
                    Status(StatusCode::Closed,
                           "session no longer exists"),
                    0U);
}

Status EngineStreamResponder::shutdown_write() noexcept {
    if (auto engine = engine_.lock()) {
        return engine->impl_->stream_shutdown(stream_id_);
    }
    return Status(StatusCode::Closed, "session no longer exists");
}

void EngineStreamResponder::close(Status reason) noexcept {
    if (auto engine = engine_.lock()) {
        engine->impl_->stream_close(stream_id_, std::move(reason));
    }
}

void SessionEngine::Impl::async_start(StartCompletion completion) {
    if (!completion) {
        return;
    }
    Status rejection = Status::success();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (state_ != SessionState::Created) {
            rejection = Status(
                StatusCode::FailedPrecondition,
                "session start is accepted exactly once");
        } else {
            state_ = SessionState::Authenticating;
            start_completion_ = std::move(completion);
        }
    }
    if (!rejection.ok()) {
        invoke_noexcept(completion, std::move(rejection));
        return;
    }

    const Status initialization = initialize_security();
    if (!initialization.ok()) {
        fail(initialization);
        return;
    }

    Result<AuthenticationOutput> output(Status(
        StatusCode::Internal, "authentication provider did not run"));
    try {
        std::lock_guard<std::mutex> security_lock(security_mutex_);
        output = security_->start_authentication();
    } catch (const std::bad_alloc&) {
        fail(Status(StatusCode::ResourceExhausted,
                    "authentication provider allocation failed"));
        return;
    } catch (...) {
        fail(Status(StatusCode::Internal,
                    "authentication provider threw during start"));
        return;
    }
    if (!output.ok()) {
        fail(output.status());
        return;
    }
    const Status output_status =
        handle_start_output(std::move(output).take_value());
    if (!output_status.ok()) {
        fail(output_status);
        return;
    }
    request_receive_pump();
}

Status SessionEngine::Impl::initialize_security() {
    Result<Buffer> exporter(Status(
        StatusCode::Internal, "secure-channel exporter did not run"));
    try {
        exporter = carrier_->secure_channel().export_keying_material(
            ytp1::kExporterLabel, text_bytes(ytp1::kSuiteId),
            kSessionExporterBytes);
    } catch (const std::bad_alloc&) {
        return Status(StatusCode::ResourceExhausted,
                      "secure-channel exporter allocation failed");
    } catch (...) {
        return Status(StatusCode::Internal,
                      "secure-channel exporter threw");
    }
    if (!exporter.ok()) {
        return exporter.status();
    }
    Buffer exporter_bytes = std::move(exporter).take_value();
    ScopedByteWipe exporter_wipe(exporter_bytes.mutable_bytes());
    if (exporter_bytes.size() != kSessionExporterBytes) {
        return Status(StatusCode::ProviderMismatch,
                      "secure-channel exporter returned the wrong size");
    }

    const SessionAuthenticationContext context{
        graph_->local_role(),
        ytp1::kSuiteId,
        as_bytes(ytp1::RequiredSecurityParameters()),
        exporter_bytes.bytes(),
        carrier_->secure_channel().peer_evidence(),
        local_capabilities_};
    try {
        std::lock_guard<std::mutex> security_lock(security_mutex_);
        return security_->initialize(context);
    } catch (const std::bad_alloc&) {
        return Status(StatusCode::ResourceExhausted,
                      "security-provider initialization allocation failed");
    } catch (...) {
        return Status(StatusCode::Internal,
                      "security provider threw during initialization");
    }
}

Status SessionEngine::Impl::handle_start_output(
    AuthenticationOutput output) {
    const EndpointRole local_role = graph_->local_role();
    if (output.established || output.authenticated_peer.has_value() ||
        !output.authenticated_peer_capability_manifest.empty()) {
        return protocol_failure(
            "security provider established before the peer AUTH exchange");
    }

    if (local_role == EndpointRole::Client) {
        if (output.outbound_kind.has_value() ||
            output.outbound_message.has_value()) {
            return protocol_failure(
                "client security provider sent before AUTH challenge");
        }
        std::lock_guard<std::mutex> lock(mutex_);
        expected_auth_kind_ = AuthenticationMessageKind::Challenge;
        return Status::success();
    }

    if (!output.outbound_kind.has_value() ||
        !output.outbound_message.has_value() ||
        *output.outbound_kind != AuthenticationMessageKind::Challenge) {
        return protocol_failure(
            "server security provider did not produce one AUTH challenge");
    }
    const Status validation = validate_auth_message(
        AuthenticationMessageKind::Challenge, local_role,
        output.outbound_message->bytes());
    if (!validation.ok()) {
        return validation;
    }
    const Status send = enqueue_record(
        ytp1::RecordType::Auth, StreamId::control(),
        output.outbound_message->bytes(), false, true);
    if (!send.ok()) {
        return send;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    expected_auth_kind_ = AuthenticationMessageKind::Response;
    return Status::success();
}

Status SessionEngine::Impl::validate_auth_message(
    AuthenticationMessageKind expected_kind,
    EndpointRole expected_sender,
    std::span<const std::byte> encoded) const {
    if (encoded.empty() || encoded.size() > ytp1::kMaxAuthRecordSize ||
        encoded.size() > limits_.max_frame_payload) {
        return protocol_failure("AUTH message exceeds its exact bound");
    }
    const auto decoded = ytp1::DecodeAuthRecord(as_u8(encoded));
    if (!decoded.ok()) {
        return protocol_failure("AUTH message is malformed or mismatched");
    }
    auto decoded_kind = from_ytp_auth_kind(decoded.value->type);
    auto decoded_role = from_ytp_role(decoded.value->sender_role);
    if (!decoded_kind.ok() || !decoded_role.ok() ||
        decoded_kind.value() != expected_kind ||
        decoded_role.value() != expected_sender) {
        return protocol_failure("AUTH message kind or sender role is wrong");
    }
    return Status::success();
}

Status SessionEngine::Impl::handle_authentication_record(
    ytp1::RecordType outer_type,
    std::span<const std::byte> payload) {
    std::optional<AuthenticationMessageKind> expected;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (state_ != SessionState::Authenticating ||
            !expected_auth_kind_.has_value()) {
            return protocol_failure("unexpected AUTH record");
        }
        expected = expected_auth_kind_;
    }
    if (auth_record_type(*expected) != outer_type) {
        return protocol_failure("AUTH outer record type is wrong");
    }
    const Status validation = validate_auth_message(
        *expected, peer_role(graph_->local_role()), payload);
    if (!validation.ok()) {
        return validation;
    }

    Result<AuthenticationOutput> provider_result(Status(
        StatusCode::Internal, "authentication provider did not run"));
    try {
        std::lock_guard<std::mutex> security_lock(security_mutex_);
        provider_result = security_->process_authentication(*expected,
                                                             payload);
    } catch (const std::bad_alloc&) {
        return Status(StatusCode::ResourceExhausted,
                      "authentication provider allocation failed");
    } catch (...) {
        return Status(StatusCode::Internal,
                      "authentication provider threw while processing AUTH");
    }
    if (!provider_result.ok()) {
        return provider_result.status();
    }
    AuthenticationOutput output =
        std::move(provider_result).take_value();

    if (*expected == AuthenticationMessageKind::Challenge) {
        if (graph_->local_role() != EndpointRole::Client ||
            output.established ||
            output.authenticated_peer.has_value() ||
            !output.authenticated_peer_capability_manifest.empty() ||
            output.outbound_kind != AuthenticationMessageKind::Response ||
            !output.outbound_message.has_value()) {
            return protocol_failure(
                "client provider produced an invalid AUTH response state");
        }
        const Status outgoing = validate_auth_message(
            AuthenticationMessageKind::Response, graph_->local_role(),
            output.outbound_message->bytes());
        if (!outgoing.ok()) {
            return outgoing;
        }
        const Status send = enqueue_record(
            ytp1::RecordType::Auth, StreamId::control(),
            output.outbound_message->bytes(), false, true);
        if (!send.ok()) {
            return send;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        expected_auth_kind_ = AuthenticationMessageKind::Accepted;
        return Status::success();
    }

    if (*expected == AuthenticationMessageKind::Response) {
        if (graph_->local_role() != EndpointRole::Server ||
            output.outbound_kind != AuthenticationMessageKind::Accepted ||
            !output.outbound_message.has_value() || !output.established) {
            return protocol_failure(
                "server provider produced an invalid AUTH acceptance state");
        }
        const Status outgoing = validate_auth_message(
            AuthenticationMessageKind::Accepted, graph_->local_role(),
            output.outbound_message->bytes());
        if (!outgoing.ok()) {
            return outgoing;
        }
        const Status send = enqueue_record(
            ytp1::RecordType::AuthResult, StreamId::control(),
            output.outbound_message->bytes(), false, true);
        if (!send.ok()) {
            return send;
        }
        const Status accepted = accept_established_output(output);
        if (!accepted.ok()) {
            return accepted;
        }
        return advertise_post_authentication_state();
    }

    if (graph_->local_role() != EndpointRole::Client ||
        output.outbound_kind.has_value() ||
        output.outbound_message.has_value() || !output.established) {
        return protocol_failure(
            "client provider produced an invalid AUTH accepted state");
    }
    const Status accepted = accept_established_output(output);
    if (!accepted.ok()) {
        return accepted;
    }
    return advertise_post_authentication_state();
}

Status SessionEngine::Impl::accept_established_output(
    AuthenticationOutput& output) {
    if (!output.authenticated_peer.has_value() ||
        output.authenticated_peer->peer_role() !=
            peer_role(graph_->local_role()) ||
        output.authenticated_peer_capability_manifest.empty() ||
        output.authenticated_peer_capability_manifest.size() >
            ytp1::kMaxCapabilityManifestSize) {
        return protocol_failure(
            "established provider output lacks bounded peer evidence");
    }
    const auto decoded = ytp1::DecodeCapabilityManifest(
        as_u8(output.authenticated_peer_capability_manifest));
    if (!decoded.ok()) {
        return protocol_failure(
            "authenticated peer capability manifest is not canonical");
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (state_ != SessionState::Authenticating) {
            return protocol_failure("AUTH established in the wrong state");
        }
        authenticated_peer_ = std::move(output.authenticated_peer);
        authenticated_peer_capabilities_ =
            std::move(output.authenticated_peer_capability_manifest);
        peer_manifest_ = *decoded.value;
        expected_auth_kind_.reset();
        state_ = SessionState::AwaitingCapabilities;
    }
    return Status::success();
}

Status SessionEngine::Impl::advertise_post_authentication_state() {
    const Status capabilities = enqueue_record(
        ytp1::RecordType::Capabilities, StreamId::control(),
        local_capabilities_, true, true);
    if (!capabilities.ok()) {
        return capabilities;
    }
    const auto encoded_credit = ytp1::EncodeCreditUpdate(
        limits_.initial_connection_credit);
    if (!encoded_credit.ok()) {
        return Status(StatusCode::Internal,
                      "validated connection credit could not be encoded");
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        inbound_connection_credit_ = limits_.initial_connection_credit;
    }
    return enqueue_record(
        ytp1::RecordType::ConnectionCredit, StreamId::control(),
        as_bytes(*encoded_credit.value), true, true);
}

Result<Buffer> SessionEngine::Impl::encode_frame(
    ytp1::RecordType type,
    StreamId stream_id,
    std::span<const std::byte> payload) const {
    if (payload.size() > limits_.max_frame_payload ||
        payload.size() > std::numeric_limits<std::uint32_t>::max()) {
        return Result<Buffer>(Status(
            StatusCode::ResourceExhausted,
            "YTP/1 frame payload exceeds the configured bound"));
    }
    const auto ytp_stream = ytp1::StreamId::FromWire(stream_id.value());
    if (!ytp_stream.ok()) {
        return Result<Buffer>(Status(
            StatusCode::InvalidArgument, "engine stream ID is not YTP/1"));
    }
    const ytp1::FrameHeader header{
        type,
        0U,
        *ytp_stream.value,
        static_cast<std::uint32_t>(payload.size())};
    std::array<std::uint8_t, ytp1::kFrameHeaderSize> encoded_header{};
    const ytp1::Status header_status = ytp1::EncodeFrameHeader(
        header, encoded_header, limits_.max_frame_payload);
    if (!header_status.ok()) {
        return Result<Buffer>(Status(
            StatusCode::InvalidArgument,
            "record type and stream class do not form a valid YTP/1 frame"));
    }
    const std::size_t total = ytp1::kFrameHeaderSize + payload.size();
    auto result = Buffer::allocate(total, total);
    if (!result.ok()) {
        return result;
    }
    Buffer output = std::move(result).take_value();
    std::memcpy(output.mutable_bytes().data(), encoded_header.data(),
                encoded_header.size());
    if (!payload.empty()) {
        std::memcpy(output.mutable_bytes().data() + ytp1::kFrameHeaderSize,
                    payload.data(), payload.size());
    }
    return Result<Buffer>(std::move(output));
}

Result<Buffer> SessionEngine::Impl::protect_frame(
    Buffer plaintext,
    RecordKeyToken token) {
    Result<Buffer> sealed(Status(
        StatusCode::Internal, "security provider did not seal the record"));
    try {
        std::lock_guard<std::mutex> security_lock(security_mutex_);
        sealed = security_->seal_record(token, plaintext.bytes());
    } catch (const std::bad_alloc&) {
        return Result<Buffer>(Status(
            StatusCode::ResourceExhausted,
            "security provider allocation failed while sealing"));
    } catch (...) {
        return Result<Buffer>(Status(
            StatusCode::Internal,
            "security provider threw while sealing a record"));
    }
    if (!sealed.ok()) {
        return Result<Buffer>(sealed.status());
    }
    Buffer ciphertext = std::move(sealed).take_value();
    if (ciphertext.empty() ||
        ciphertext.size() < plaintext.size() ||
        ciphertext.size() - plaintext.size() >
            security_->max_sealed_overhead() ||
        ciphertext.size() >
            kAbsoluteMaxBufferBytes - kProtectedEnvelopeBytes) {
        return Result<Buffer>(Status(
            StatusCode::ProviderMismatch,
            "security provider returned an invalid sealed-record size"));
    }

    const std::size_t total = kProtectedEnvelopeBytes + ciphertext.size();
    auto result = Buffer::allocate(total, total);
    if (!result.ok()) {
        return result;
    }
    Buffer output = std::move(result).take_value();
    auto bytes = output.mutable_bytes();
    bytes[0] = static_cast<std::byte>(kProtectedEnvelopeVersion);
    bytes[1] = std::byte{0};
    bytes[2] = std::byte{0};
    bytes[3] = std::byte{0};
    write_u32(bytes, 4U, token.epoch);
    write_u64(bytes, 8U, token.sequence);
    std::memcpy(bytes.data() + kProtectedEnvelopeBytes,
                ciphertext.bytes().data(), ciphertext.size());
    return Result<Buffer>(std::move(output));
}

Status SessionEngine::Impl::defer_record(
    ytp1::RecordType type,
    StreamId stream_id,
    std::span<const std::byte> payload,
    bool is_control,
    std::size_t completion_bytes,
    Carrier::SendCompletion completion) {
    const std::size_t overhead = ytp1::kFrameHeaderSize +
        kProtectedEnvelopeBytes + security_->max_sealed_overhead();
    if (payload.size() > limits_.max_frame_payload ||
        payload.size() > limits_.max_queued_bytes ||
        overhead > limits_.max_queued_bytes - payload.size()) {
        return Status(StatusCode::ResourceExhausted,
                      "deferred record exceeds the queue bound");
    }
    const std::size_t reservation = overhead + payload.size();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (terminal_locked()) {
            return Status(StatusCode::Closed, "session is closed");
        }
        if (is_control &&
            queued_control_messages_ >= limits_.max_control_messages) {
            return Status(StatusCode::ResourceExhausted,
                          "control-message queue is full");
        }
        const std::size_t retained = queued_wire_bytes_ +
                                     pending_write_bytes_;
        if (retained > limits_.max_queued_bytes ||
            reservation > limits_.max_queued_bytes - retained) {
            return Status(StatusCode::ResourceExhausted,
                          "session outbound queue is full");
        }
        queued_wire_bytes_ += reservation;
        if (is_control) {
            ++queued_control_messages_;
        }
    }

    auto copy = Buffer::copy_from(payload,
                                  std::max<std::size_t>(1U, payload.size()));
    if (!copy.ok()) {
        std::lock_guard<std::mutex> lock(mutex_);
        queued_wire_bytes_ -= reservation;
        if (is_control) {
            --queued_control_messages_;
        }
        return copy.status();
    }
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        if (terminal_locked()) {
            queued_wire_bytes_ -= reservation;
            if (is_control) {
                --queued_control_messages_;
            }
            return Status(StatusCode::Closed, "session is closed");
        }
        deferred_records_.emplace_back(
            type, stream_id, std::move(copy).take_value(), is_control,
            completion_bytes, std::move(completion));
        return Status::success();
    } catch (const std::bad_alloc&) {
        std::lock_guard<std::mutex> lock(mutex_);
        queued_wire_bytes_ -= reservation;
        if (is_control) {
            --queued_control_messages_;
        }
        return Status(StatusCode::ResourceExhausted,
                      "deferred-record queue allocation failed");
    }
}

Status SessionEngine::Impl::enqueue_record(
    ytp1::RecordType type,
    StreamId stream_id,
    std::span<const std::byte> payload,
    bool protect,
    bool is_control,
    std::size_t completion_bytes,
    Carrier::SendCompletion completion,
    bool bypass_rekey_barrier) {
    std::unique_lock<std::mutex> ordering_lock;
    if (protect) {
        ordering_lock = std::unique_lock<std::mutex>(
            outbound_record_mutex_);
    }
    if (payload.size() > limits_.max_frame_payload) {
        return Status(StatusCode::ResourceExhausted,
                      "record payload exceeds the frame bound");
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (terminal_locked()) {
            return Status(StatusCode::Closed, "session is closed");
        }
        if (protect && outbound_rekey_pending_ &&
            !bypass_rekey_barrier) {
            // Copying happens after the state check. defer_record repeats all
            // resource checks while holding the lock it owns.
        } else {
            bypass_rekey_barrier = true;
        }
    }
    if (protect && !bypass_rekey_barrier) {
        return defer_record(type, stream_id, payload, is_control,
                            completion_bytes, std::move(completion));
    }

    const std::size_t envelope = protect
        ? kProtectedEnvelopeBytes + security_->max_sealed_overhead()
        : 0U;
    const std::size_t fixed = ytp1::kFrameHeaderSize + envelope;
    if (payload.size() > limits_.max_queued_bytes ||
        fixed > limits_.max_queued_bytes - payload.size()) {
        return Status(StatusCode::ResourceExhausted,
                      "record exceeds the outbound queue bound");
    }
    const std::size_t reservation = fixed + payload.size();
    std::optional<RecordKeyToken> token;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (terminal_locked()) {
            return Status(StatusCode::Closed, "session is closed");
        }
        if (!protect) {
            const bool auth_flight =
                state_ == SessionState::Authenticating &&
                (type == ytp1::RecordType::Auth ||
                 type == ytp1::RecordType::AuthResult);
            const bool rekey_ack =
                state_ == SessionState::Active &&
                type == ytp1::RecordType::RekeyAck;
            if (!auth_flight && !rekey_ack) {
                return Status(
                    StatusCode::FailedPrecondition,
                    "unprotected record is invalid in the session state");
            }
        }
        if (protect && state_ != SessionState::AwaitingCapabilities &&
            state_ != SessionState::Active) {
            return Status(StatusCode::FailedPrecondition,
                          "protected record sent before AUTH completion");
        }
        if (is_control &&
            queued_control_messages_ >= limits_.max_control_messages) {
            return Status(StatusCode::ResourceExhausted,
                          "control-message queue is full");
        }
        const std::size_t retained = queued_wire_bytes_ +
                                     pending_write_bytes_;
        if (retained > limits_.max_queued_bytes ||
            reservation > limits_.max_queued_bytes - retained) {
            return Status(StatusCode::ResourceExhausted,
                          "session outbound queue is full");
        }
        if (protect) {
            if (outbound_sequence_exhausted_) {
                return Status(StatusCode::ResourceExhausted,
                              "outbound record sequence is exhausted");
            }
            token = RecordKeyToken{outbound_epoch_,
                                   next_outbound_sequence_};
            if (next_outbound_sequence_ ==
                std::numeric_limits<std::uint64_t>::max()) {
                outbound_sequence_exhausted_ = true;
            } else {
                ++next_outbound_sequence_;
            }
        }
        queued_wire_bytes_ += reservation;
        if (is_control) {
            ++queued_control_messages_;
        }
    }

    auto encoded = encode_frame(type, stream_id, payload);
    if (!encoded.ok()) {
        const Status failure = encoded.status();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queued_wire_bytes_ -= reservation;
            if (is_control) {
                --queued_control_messages_;
            }
        }
        if (protect) {
            // The provider's one-use sequence has already been consumed. A
            // retry would create a wire-visible gap, so this session cannot
            // continue safely.
            ordering_lock.unlock();
            fail(failure);
        }
        return failure;
    }
    Result<Buffer> wire(std::move(encoded).take_value());
    if (protect) {
        wire = protect_frame(std::move(wire).take_value(), *token);
    }
    if (!wire.ok()) {
        const Status failure = wire.status();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queued_wire_bytes_ -= reservation;
            if (is_control) {
                --queued_control_messages_;
            }
        }
        if (protect) {
            ordering_lock.unlock();
            fail(failure);
        }
        return failure;
    }
    Buffer wire_buffer = std::move(wire).take_value();
    if (wire_buffer.size() > carrier_->max_record_size() ||
        wire_buffer.size() > reservation) {
        const Status failure(
            StatusCode::ProviderMismatch,
            "composed record exceeds its reserved carrier bound");
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queued_wire_bytes_ -= reservation;
            if (is_control) {
                --queued_control_messages_;
            }
        }
        if (protect) {
            ordering_lock.unlock();
            fail(failure);
        }
        return failure;
    }
    const std::size_t actual = wire_buffer.size();
    try {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (terminal_locked()) {
                queued_wire_bytes_ -= reservation;
                if (is_control) {
                    --queued_control_messages_;
                }
                return Status(StatusCode::Closed, "session is closed");
            }
            outbound_queue_.emplace_back(
                std::move(wire_buffer), is_control, completion_bytes,
                std::move(completion));
            queued_wire_bytes_ -= reservation - actual;
        }
    } catch (const std::bad_alloc&) {
        const Status failure(
            StatusCode::ResourceExhausted,
            "outbound record queue allocation failed");
        {
            std::lock_guard<std::mutex> lock(mutex_);
            queued_wire_bytes_ -= reservation;
            if (is_control) {
                --queued_control_messages_;
            }
        }
        if (protect) {
            ordering_lock.unlock();
            fail(failure);
        }
        return failure;
    }
    if (ordering_lock.owns_lock()) {
        ordering_lock.unlock();
    }
    request_send_pump();
    return Status::success();
}

Status SessionEngine::Impl::flush_deferred_records() {
    std::deque<DeferredRecord> deferred;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (outbound_rekey_pending_) {
            return Status(StatusCode::FailedPrecondition,
                          "outbound rekey barrier is still active");
        }
        deferred.swap(deferred_records_);
        for (const DeferredRecord& record : deferred) {
            const std::size_t reservation = ytp1::kFrameHeaderSize +
                kProtectedEnvelopeBytes +
                security_->max_sealed_overhead() + record.payload.size();
            queued_wire_bytes_ -= reservation;
            if (record.is_control) {
                --queued_control_messages_;
            }
        }
    }
    for (DeferredRecord& record : deferred) {
        const Status status = enqueue_record(
            record.type, record.stream_id, record.payload.bytes(), true,
            record.is_control, record.completion_bytes,
            std::move(record.completion));
        if (!status.ok()) {
            return status;
        }
    }
    return Status::success();
}

void SessionEngine::Impl::request_send_pump() noexcept {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (send_pump_running_) {
            send_pump_again_ = true;
            return;
        }
        send_pump_running_ = true;
    }

    for (;;) {
        std::optional<Buffer> wire;
        CancellationToken cancellation;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            send_pump_again_ = false;
            if (terminal_locked() || send_in_progress_ ||
                outbound_queue_.empty()) {
                send_pump_running_ = false;
                return;
            }
            OutboundItem item = std::move(outbound_queue_.front());
            outbound_queue_.pop_front();
            const std::size_t wire_size = item.wire.size();
            active_send_.emplace(ActiveSend{
                item.is_control, wire_size, item.completion_bytes,
                std::move(item.completion)});
            wire.emplace(std::move(item.wire));
            send_in_progress_ = true;
            cancellation = cancellation_.token();
        }

        const std::weak_ptr<SessionEngine> weak = weak_owner();
        try {
            carrier_->async_send(
                std::move(*wire), std::move(cancellation),
                [weak](Status status, std::size_t transferred) noexcept {
                    if (auto engine = weak.lock()) {
                        engine->impl_->on_send_complete(
                            std::move(status), transferred);
                    }
                });
        } catch (...) {
            on_send_complete(Status(
                StatusCode::Internal, "carrier threw while sending"), 0U);
        }

        std::lock_guard<std::mutex> lock(mutex_);
        if (send_in_progress_) {
            send_pump_running_ = false;
            return;
        }
    }
}

void SessionEngine::Impl::on_send_complete(
    Status status,
    std::size_t transferred) noexcept {
    Carrier::SendCompletion completion;
    std::size_t completion_bytes = 0U;
    bool must_fail = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!send_in_progress_ || !active_send_.has_value()) {
            return;
        }
        ActiveSend active = std::move(*active_send_);
        active_send_.reset();
        send_in_progress_ = false;
        queued_wire_bytes_ -= active.wire_bytes;
        if (active.is_control) {
            --queued_control_messages_;
        }
        if (status.ok() && transferred != active.wire_bytes) {
            status = Status(StatusCode::Internal,
                            "carrier reported a partial record send");
        }
        completion = std::move(active.completion);
        completion_bytes = status.ok() ? active.completion_bytes : 0U;
        must_fail = !status.ok() && !terminal_locked();
    }
    invoke_noexcept(completion, status, completion_bytes);
    if (must_fail) {
        fail(status);
        return;
    }
    request_send_pump();
}

void SessionEngine::Impl::request_receive_pump() noexcept {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (receive_pump_running_) {
            receive_pump_again_ = true;
            return;
        }
        receive_pump_running_ = true;
    }

    for (;;) {
        CancellationToken cancellation;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            receive_pump_again_ = false;
            if (terminal_locked() || receive_in_progress_) {
                receive_pump_running_ = false;
                return;
            }
            receive_in_progress_ = true;
            cancellation = cancellation_.token();
        }

        const std::weak_ptr<SessionEngine> weak = weak_owner();
        try {
            carrier_->async_receive(
                std::move(cancellation),
                [weak](Result<ReceivedRecord> result) noexcept {
                    if (auto engine = weak.lock()) {
                        engine->impl_->on_receive(std::move(result));
                    }
                });
        } catch (...) {
            on_receive(Result<ReceivedRecord>(Status(
                StatusCode::Internal,
                "carrier threw while receiving")));
        }

        std::lock_guard<std::mutex> lock(mutex_);
        if (receive_in_progress_) {
            receive_pump_running_ = false;
            return;
        }
    }
}

void SessionEngine::Impl::on_receive(
    Result<ReceivedRecord> result) noexcept {
    Status status = Status::success();
    if (!result.ok()) {
        status = result.status();
    } else {
        try {
            status = process_received(std::move(result).take_value());
        } catch (const std::bad_alloc&) {
            status = Status(StatusCode::ResourceExhausted,
                            "session receive allocation failed");
        } catch (...) {
            status = Status(StatusCode::Internal,
                            "session receive processing threw");
        }
    }

    bool already_terminal = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        receive_in_progress_ = false;
        already_terminal = terminal_locked();
    }
    if (!status.ok() && !already_terminal) {
        fail(status);
        return;
    }
    if (!already_terminal) {
        request_receive_pump();
    }
}

Status SessionEngine::Impl::process_received(ReceivedRecord record) {
    SessionState current;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        current = state_;
    }
    if (record.payload().empty() ||
        record.payload().size() > carrier_->max_record_size()) {
        return protocol_failure("carrier delivered an invalid record size");
    }

    if (current == SessionState::Authenticating) {
        const auto decoded = ytp1::DecodeRecord(
            as_u8(record.payload().bytes()), limits_.max_frame_payload);
        if (!decoded.ok() ||
            (decoded.value->header.type != ytp1::RecordType::Auth &&
             decoded.value->header.type != ytp1::RecordType::AuthResult)) {
            return protocol_failure(
                "non-AUTH or malformed record arrived during authentication");
        }
        return handle_authentication_record(
            decoded.value->header.type,
            as_bytes(decoded.value->payload));
    }
    if (current != SessionState::AwaitingCapabilities &&
        current != SessionState::Active) {
        return protocol_failure("record arrived outside a live session");
    }

    // REKEY_ACK is the sole post-AUTH record carried without the YTP record
    // AEAD. Its provider payload is authenticated under the candidate new
    // directional root. Keeping the acknowledgement outside the old/new
    // record epochs lets opposite-direction rekeys cross without retaining a
    // retired root. TLS still protects the carrier. Every other post-AUTH
    // record remains protected and an ACK is admitted only in Active state.
    const auto unprotected = ytp1::DecodeRecord(
        as_u8(record.payload().bytes()), limits_.max_frame_payload);
    if (unprotected.ok()) {
        if (current != SessionState::Active ||
            unprotected.value->header.type != ytp1::RecordType::RekeyAck) {
            return protocol_failure(
                "unexpected unprotected post-AUTH record");
        }
        return process_rekey_ack(as_bytes(unprotected.value->payload));
    }
    const auto raw = record.payload().bytes();
    if (raw.size() >= 2U && raw[0] == std::byte{1} &&
        raw[1] == static_cast<std::byte>(ytp1::RecordType::RekeyAck)) {
        return protocol_failure("unprotected REKEY_ACK is malformed");
    }
    return process_protected_record(std::move(record));
}

Status SessionEngine::Impl::process_protected_record(
    ReceivedRecord record) {
    const auto wire = record.payload().bytes();
    if (wire.size() <= kProtectedEnvelopeBytes ||
        wire[0] != static_cast<std::byte>(kProtectedEnvelopeVersion) ||
        wire[1] != std::byte{0} || wire[2] != std::byte{0} ||
        wire[3] != std::byte{0}) {
        return protocol_failure("protected record envelope is malformed");
    }
    const RecordKeyToken token{
        read_u32(wire, 4U), read_u64(wire, 8U)};
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (inbound_sequence_exhausted_ || token.epoch != inbound_epoch_ ||
            token.sequence != next_inbound_sequence_) {
            return protocol_failure(
                "protected record is replayed, out of order, or in the wrong epoch");
        }
        if (next_inbound_sequence_ ==
            std::numeric_limits<std::uint64_t>::max()) {
            inbound_sequence_exhausted_ = true;
        } else {
            ++next_inbound_sequence_;
        }
    }

    Result<Buffer> opened(Status(
        StatusCode::Internal, "security provider did not open the record"));
    try {
        std::lock_guard<std::mutex> security_lock(security_mutex_);
        opened = security_->open_record(
            token, wire.subspan(kProtectedEnvelopeBytes));
    } catch (const std::bad_alloc&) {
        return Status(StatusCode::ResourceExhausted,
                      "security provider allocation failed while opening");
    } catch (...) {
        return Status(StatusCode::Internal,
                      "security provider threw while opening a record");
    }
    if (!opened.ok()) {
        return opened.status();
    }
    Buffer plaintext = std::move(opened).take_value();
    if (plaintext.size() < ytp1::kFrameHeaderSize ||
        plaintext.size() > ytp1::kFrameHeaderSize +
                               limits_.max_frame_payload) {
        return protocol_failure(
            "security provider returned an invalid plaintext size");
    }
    const auto decoded = ytp1::DecodeRecord(
        as_u8(plaintext.bytes()), limits_.max_frame_payload);
    if (!decoded.ok()) {
        return protocol_failure("protected YTP/1 record is malformed");
    }
    CarrierCredit outer_credit = record.take_credit();
    return process_decoded_record(*decoded.value,
                                  std::move(outer_credit));
}

Status SessionEngine::Impl::process_decoded_record(
    const ytp1::RecordView& record,
    CarrierCredit outer_credit) {
    SessionState current;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        current = state_;
    }
    if (current == SessionState::AwaitingCapabilities &&
        record.header.type != ytp1::RecordType::Capabilities) {
        return protocol_failure(
            "peer sent protected traffic before capabilities");
    }
    if (current == SessionState::Active &&
        record.header.type == ytp1::RecordType::Capabilities) {
        return protocol_failure("peer repeated its capability manifest");
    }

    switch (record.header.type) {
    case ytp1::RecordType::Capabilities:
        return process_capabilities(as_bytes(record.payload));
    case ytp1::RecordType::Open:
        return process_open(record);
    case ytp1::RecordType::Data:
    case ytp1::RecordType::Packet:
        return process_application_data(record, std::move(outer_credit));
    case ytp1::RecordType::Close:
        return process_close(record);
    case ytp1::RecordType::ConnectionCredit:
        return process_connection_credit(as_bytes(record.payload));
    case ytp1::RecordType::StreamCredit:
        return process_stream_credit(record);
    case ytp1::RecordType::RekeyInit:
        return process_rekey_init(as_bytes(record.payload));
    case ytp1::RecordType::RekeyAck:
        return protocol_failure(
            "REKEY_ACK must use its authenticated unprotected form");
    case ytp1::RecordType::Ping:
        if (record.payload.size() != kPingPayloadBytes) {
            return protocol_failure("PING payload has the wrong size");
        }
        return enqueue_record(
            ytp1::RecordType::Pong, StreamId::control(),
            as_bytes(record.payload), true, true);
    case ytp1::RecordType::Pong:
        if (record.payload.size() != kPingPayloadBytes) {
            return protocol_failure("PONG payload has the wrong size");
        }
        return Status::success();
    case ytp1::RecordType::Auth:
    case ytp1::RecordType::AuthResult:
        return protocol_failure("AUTH record appeared after authentication");
    }
    return protocol_failure("unknown YTP/1 record type");
}

Status SessionEngine::Impl::process_capabilities(
    std::span<const std::byte> payload) {
    std::vector<std::byte> expected;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (state_ != SessionState::AwaitingCapabilities) {
            return protocol_failure("capabilities arrived in the wrong state");
        }
        expected = authenticated_peer_capabilities_;
    }
    if (payload.size() != expected.size() ||
        !std::equal(payload.begin(), payload.end(), expected.begin())) {
        return protocol_failure(
            "peer capabilities differ from authenticated AUTH bytes");
    }
    const auto decoded = ytp1::DecodeCapabilityManifest(as_u8(payload));
    if (!decoded.ok()) {
        return protocol_failure("peer capabilities are not canonical");
    }

    StartCompletion completion;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (state_ != SessionState::AwaitingCapabilities) {
            return protocol_failure("capability state changed unexpectedly");
        }
        peer_manifest_ = *decoded.value;
        state_ = SessionState::Active;
        completion = std::move(start_completion_);
    }
    Status success = Status::success();
    invoke_noexcept(completion, success);
    return Status::success();
}

const ytp1::Capability* SessionEngine::Impl::local_capability(
    std::string_view name,
    ServiceKind kind) const noexcept {
    for (const ytp1::Capability& capability : local_manifest_.entries) {
        auto mapped = from_ytp_service_kind(capability.service_kind);
        if (mapped.ok() && mapped.value() == kind &&
            capability.service_name == name) {
            return &capability;
        }
    }
    return nullptr;
}

const ytp1::Capability* SessionEngine::Impl::peer_capability(
    std::string_view name,
    ServiceKind kind) const noexcept {
    for (const ytp1::Capability& capability : peer_manifest_.entries) {
        auto mapped = from_ytp_service_kind(capability.service_kind);
        if (mapped.ok() && mapped.value() == kind &&
            capability.service_name == name) {
            return &capability;
        }
    }
    return nullptr;
}

std::size_t SessionEngine::Impl::service_stream_count_locked(
    std::string_view name,
    ServiceKind kind) const noexcept {
    return static_cast<std::size_t>(std::count_if(
        streams_.begin(), streams_.end(),
        [name, kind](const auto& entry) {
            return !entry.second->closed && entry.second->kind == kind &&
                   entry.second->service_name == name;
        }));
}

Status SessionEngine::Impl::process_open(
    const ytp1::RecordView& record) {
    const auto decoded = ytp1::DecodeOpen(record.payload);
    if (!decoded.ok()) {
        return protocol_failure("OPEN payload is malformed");
    }
    auto kind = from_ytp_service_kind(decoded.value->service_kind);
    if (!kind.ok()) {
        return kind.status();
    }
    std::optional<RouteDestination> destination;
    if (decoded.value->destination.transport !=
        ytp1::TransportProtocol::None) {
        auto route = from_ytp_destination(decoded.value->destination);
        if (!route.ok()) {
            return protocol_failure(
                "OPEN destination could not become a canonical route");
        }
        destination.emplace(std::move(route).take_value());
    }
    auto stream_id = StreamId::peer_application(
        record.header.stream_id.value(), graph_->local_role());
    if (!stream_id.ok()) {
        return protocol_failure("OPEN stream ownership is invalid");
    }

    std::shared_ptr<StreamHandler> handler;
    std::optional<PeerEvidence> peer;
    std::optional<StreamCloseCode> rejection;
    bool pending_released = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (state_ != SessionState::Active) {
            return protocol_failure("OPEN arrived before session activation");
        }
        if (record.header.stream_id.value() <= last_peer_stream_id_) {
            return protocol_failure("peer OPEN stream ID was reused or regressed");
        }
        // Once observed, a peer-owned ID is consumed even when policy rejects
        // the OPEN. It can never be retried with different metadata.
        last_peer_stream_id_ = record.header.stream_id.value();
        if (streams_.size() >= limits_.max_streams ||
            pending_opens_ >= limits_.max_pending_opens) {
            return Status(StatusCode::ResourceExhausted,
                          "peer OPEN exceeds the session stream bound");
        }
        const ytp1::Capability* advertised = local_capability(
            decoded.value->service_name, kind.value());
        if (!advertised) {
            rejection = StreamCloseCode::Unsupported;
        } else if (service_stream_count_locked(decoded.value->service_name,
                                               kind.value()) >=
                   advertised->max_concurrent_streams) {
            return Status(StatusCode::ResourceExhausted,
                          "peer OPEN exceeds the advertised service bound");
        } else {
            handler = graph_->stream_handler(decoded.value->service_name,
                                             kind.value());
        }
        if (!rejection.has_value() &&
            (!handler || handler->service_kind() != kind.value())) {
            return protocol_failure(
                "advertised service has no exact stream handler");
        }
        if (!authenticated_peer_.has_value()) {
            return protocol_failure("OPEN lacks authenticated peer evidence");
        }
        peer = authenticated_peer_;
        if (!rejection.has_value()) {
            ++pending_opens_;
        }
    }
    if (rejection.has_value()) {
        return send_close(stream_id.value(), *rejection);
    }

    auto context_result = StreamOpenContext::create(
        stream_id.value(), decoded.value->service_name, kind.value(),
        std::move(*peer), std::move(destination));
    if (!context_result.ok()) {
        std::lock_guard<std::mutex> lock(mutex_);
        --pending_opens_;
        return context_result.status();
    }
    StreamOpenContext context = std::move(context_result).take_value();
    Status authorization(StatusCode::Internal,
                         "stream handler did not authorize OPEN");
    try {
        authorization = handler->authorize(context);
    } catch (...) {
        authorization = Status(StatusCode::Internal,
                               "stream handler threw during authorization");
    }
    if (!authorization.ok()) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            --pending_opens_;
        }
        return send_close(stream_id.value(),
                          StreamCloseCode::Unauthorized);
    }

    const RouteDestination* route_destination = context.destination_if();
    if (route_destination) {
        const Capability required_route =
            route_destination->protocol() == NetworkProtocol::Tcp
            ? Capability::DirectTcp
            : Capability::DirectUdp;
        if (!handler->descriptor().capabilities().contains(required_route)) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                --pending_opens_;
            }
            return send_close(stream_id.value(),
                              StreamCloseCode::Unsupported);
        }
    }

    std::optional<AuthorizedRouteRequest> authorized_route;
    if (route_destination) {
        try {
            authorized_route.emplace(make_authorized_route_request(
                stream_id.value(), decoded.value->service_name,
                context.peer_evidence(), *route_destination));
        } catch (const std::bad_alloc&) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                --pending_opens_;
            }
            return Status(StatusCode::ResourceExhausted,
                          "authorized route allocation failed");
        }
    }

    std::shared_ptr<StreamStateData> stream;
    std::shared_ptr<EngineStreamResponder> responder;
    try {
        stream = std::make_shared<StreamStateData>(
            stream_id.value(), decoded.value->service_name, kind.value(),
            true);
        const std::size_t max_write = kind.value() == ServiceKind::PacketChannel
            ? limits_.max_packet_size
            : limits_.max_frame_payload;
        responder = std::make_shared<EngineStreamResponder>(
            weak_owner(), stream_id.value(), kind.value(), affinity_,
            max_write);
        stream->responder = responder;
        stream->inbound_credit = limits_.initial_stream_credit;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            --pending_opens_;
            pending_released = true;
            if (terminal_locked() || streams_.size() >= limits_.max_streams) {
                return Status(StatusCode::Closed,
                              "session closed while authorizing OPEN");
            }
            const auto [_, inserted] = streams_.emplace(
                stream_id.value().value(), stream);
            if (!inserted) {
                return protocol_failure("peer OPEN reused an active stream ID");
            }
        }
    } catch (const std::bad_alloc&) {
        if (!pending_released) {
            std::lock_guard<std::mutex> lock(mutex_);
            --pending_opens_;
        }
        return Status(StatusCode::ResourceExhausted,
                      "peer OPEN allocation failed");
    }

    const Status credit = send_stream_credit(
        stream_id.value(), limits_.initial_stream_credit);
    if (!credit.ok()) {
        remove_stream(stream_id.value(), credit);
        return credit;
    }
    try {
        if (authorized_route) {
            handler->on_route(std::move(*authorized_route), responder);
        } else {
            handler->on_open(std::move(context), responder);
        }
    } catch (...) {
        remove_stream(stream_id.value(), Status(
            StatusCode::Internal, "stream handler threw while opening"));
        const Status close_status = send_close(
            stream_id.value(), StreamCloseCode::HandlerFailure);
        return close_status.ok()
            ? Status::success()
            : close_status;
    }
    return Status::success();
}

Status SessionEngine::Impl::process_application_data(
    const ytp1::RecordView& record,
    CarrierCredit outer_credit) {
    const std::uint32_t value = record.header.stream_id.value();
    const EndpointRole owner = (value & 1U) != 0U
        ? EndpointRole::Client
        : EndpointRole::Server;
    auto stream_id = StreamId::application(value, owner);
    if (!stream_id.ok()) {
        return protocol_failure("application record stream ID is invalid");
    }
    if (record.payload.empty()) {
        return protocol_failure("empty DATA/PACKET record is forbidden");
    }

    std::shared_ptr<StreamStateData> stream;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = streams_.find(value);
        if (it == streams_.end() || it->second->closed) {
            return protocol_failure("data arrived after stream close");
        }
        stream = it->second;
        if (stream->peer_write_closed) {
            return protocol_failure(
                "data arrived after the peer shut down its write side");
        }
        const bool correct_type =
            (record.header.type == ytp1::RecordType::Data &&
             stream->kind == ServiceKind::ByteStream) ||
            (record.header.type == ytp1::RecordType::Packet &&
             stream->kind == ServiceKind::PacketChannel);
        if (!correct_type) {
            return protocol_failure("record type does not match stream kind");
        }
        if (stream->kind == ServiceKind::PacketChannel &&
            record.payload.size() > limits_.max_packet_size) {
            return protocol_failure("packet exceeds the session packet bound");
        }
        if (record.payload.size() > stream->inbound_credit ||
            record.payload.size() > inbound_connection_credit_) {
            return protocol_failure("peer exceeded granted flow credit");
        }
        if (!stream->pending_read.has_value() &&
            (record.payload.size() > limits_.max_stream_queued_bytes -
                                         stream->inbound_queued_bytes ||
             record.payload.size() > limits_.max_queued_bytes -
                                         inbound_queued_bytes_)) {
            return Status(StatusCode::ResourceExhausted,
                          "inbound application queue is full");
        }
    }

    auto copied = Buffer::copy_from(
        as_bytes(record.payload), limits_.max_frame_payload);
    if (!copied.ok()) {
        return copied.status();
    }
    std::shared_ptr<CarrierCredit> outer;
    try {
        outer = std::make_shared<CarrierCredit>(std::move(outer_credit));
    } catch (const std::bad_alloc&) {
        return Status(StatusCode::ResourceExhausted,
                      "receive-credit lease allocation failed");
    }
    const std::weak_ptr<SessionEngine> weak = weak_owner();
    std::optional<CarrierCredit::ReleaseHandler> release;
    try {
        release.emplace(
            [weak, stream_id = stream_id.value(), outer](std::size_t bytes) {
                if (auto engine = weak.lock()) {
                    engine->impl_->return_receive_credit(stream_id, bytes);
                }
                outer->release_now();
            });
    } catch (const std::bad_alloc&) {
        return Status(StatusCode::ResourceExhausted,
                      "receive-credit callback allocation failed");
    }

    std::optional<PendingRead> pending_read;
    std::optional<ReceivedRecord> application_record;
    Status publication = Status::success();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = streams_.find(value);
        if (it == streams_.end() || it->second.get() != stream.get() ||
            stream->closed) {
            return Status(StatusCode::Closed,
                          "stream closed while queuing received data");
        }
        if (stream->peer_write_closed) {
            return protocol_failure(
                "data arrived after the peer shut down its write side");
        }
        if (record.payload.size() > stream->inbound_credit ||
            record.payload.size() > inbound_connection_credit_) {
            return protocol_failure("peer exceeded granted flow credit");
        }
        if (!stream->pending_read.has_value() &&
            (record.payload.size() > limits_.max_stream_queued_bytes -
                                         stream->inbound_queued_bytes ||
             record.payload.size() > limits_.max_queued_bytes -
                                         inbound_queued_bytes_)) {
            return Status(StatusCode::ResourceExhausted,
                          "inbound application queue is full");
        }

        stream->inbound_credit -= record.payload.size();
        inbound_connection_credit_ -= record.payload.size();
        application_record.emplace(
            std::move(copied).take_value(),
            CarrierCredit(record.payload.size(), std::move(*release)));
        if (stream->pending_read.has_value()) {
            pending_read.emplace(std::move(*stream->pending_read));
            stream->pending_read.reset();
        } else {
            try {
                stream->inbound.emplace_back(
                    std::move(*application_record));
                stream->inbound_queued_bytes += record.payload.size();
                inbound_queued_bytes_ += record.payload.size();
            } catch (const std::bad_alloc&) {
                publication = Status(
                    StatusCode::ResourceExhausted,
                    "inbound application queue allocation failed");
            }
        }
    }
    if (!publication.ok()) {
        return publication;
    }
    if (pending_read.has_value()) {
        auto result = Result<ReceivedRecord>(
            std::move(*application_record));
        invoke_noexcept(pending_read->completion, std::move(result));
    }
    return Status::success();
}

Status SessionEngine::Impl::process_close(
    const ytp1::RecordView& record) {
    if (record.payload.size() != kClosePayloadBytes) {
        return protocol_failure("CLOSE payload has the wrong size");
    }
    const std::uint8_t close_code = record.payload[0];
    if (close_code > static_cast<std::uint8_t>(StreamCloseCode::Aborted)) {
        return protocol_failure("CLOSE payload has an unknown code");
    }
    const std::uint32_t value = record.header.stream_id.value();
    const EndpointRole owner = (value & 1U) != 0U
        ? EndpointRole::Client
        : EndpointRole::Server;
    auto stream_id = StreamId::application(value, owner);
    if (!stream_id.ok()) {
        return protocol_failure("CLOSE stream ID is invalid");
    }
    const auto code = static_cast<StreamCloseCode>(close_code);
    if (code != StreamCloseCode::Normal) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (streams_.find(value) == streams_.end()) {
                return protocol_failure("CLOSE repeated a closed stream ID");
            }
        }
        remove_stream(stream_id.value(), Status(
            StatusCode::Closed, "peer aborted the stream"));
        return Status::success();
    }

    StreamResponder::ReadCompletion read;
    bool fully_closed = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = streams_.find(value);
        if (it == streams_.end() || it->second->closed ||
            it->second->peer_write_closed) {
            return protocol_failure("CLOSE repeated a closed write side");
        }
        it->second->peer_write_closed = true;
        if (it->second->inbound.empty() &&
            it->second->pending_read.has_value()) {
            read = std::move(it->second->pending_read->completion);
            it->second->pending_read.reset();
        }
        fully_closed = it->second->local_write_closed &&
                       it->second->inbound.empty();
    }
    if (fully_closed) {
        remove_stream(stream_id.value(), Status(
            StatusCode::Closed, "stream is fully closed"));
    }
    if (read) {
        auto result = Result<ReceivedRecord>(Status(
            StatusCode::Closed, "peer shut down the stream write side"));
        invoke_noexcept(read, std::move(result));
    }
    return Status::success();
}

Status SessionEngine::Impl::process_connection_credit(
    std::span<const std::byte> payload) {
    const auto decoded = ytp1::DecodeCreditUpdate(as_u8(payload));
    if (!decoded.ok()) {
        return protocol_failure("connection-credit update is malformed");
    }
    std::vector<StreamId> pending;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (*decoded.value > limits_.max_connection_credit -
                                 outbound_connection_credit_) {
            return protocol_failure(
                "connection-credit update exceeds the configured bound");
        }
        outbound_connection_credit_ += *decoded.value;
        pending.reserve(streams_.size());
        for (const auto& [_, stream] : streams_) {
            if (!stream->pending_writes.empty()) {
                pending.push_back(stream->id);
            }
        }
    }
    for (StreamId stream_id : pending) {
        drain_pending_writes(stream_id);
    }
    return Status::success();
}

Status SessionEngine::Impl::process_stream_credit(
    const ytp1::RecordView& record) {
    const auto decoded = ytp1::DecodeCreditUpdate(record.payload);
    if (!decoded.ok()) {
        return protocol_failure("stream-credit update is malformed");
    }
    const std::uint32_t value = record.header.stream_id.value();
    const EndpointRole owner = (value & 1U) != 0U
        ? EndpointRole::Client
        : EndpointRole::Server;
    auto stream_id = StreamId::application(value, owner);
    if (!stream_id.ok()) {
        return protocol_failure("stream-credit stream ID is invalid");
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = streams_.find(value);
        if (it == streams_.end() || it->second->closed) {
            return protocol_failure("credit arrived after stream close");
        }
        if (*decoded.value > limits_.max_stream_credit -
                                 it->second->outbound_credit) {
            return protocol_failure(
                "stream-credit update exceeds the configured bound");
        }
        it->second->outbound_credit += *decoded.value;
    }
    drain_pending_writes(stream_id.value());
    return Status::success();
}

void SessionEngine::Impl::async_open(
    std::string_view service_name,
    ServiceKind service_kind,
    std::optional<RouteDestination> destination,
    OpenCompletion completion) {
    if (!completion) {
        return;
    }
    if (!valid_service_name(service_name)) {
        auto result = Result<std::shared_ptr<StreamResponder>>(Status(
            StatusCode::InvalidArgument, "service name is invalid"));
        invoke_noexcept(completion, std::move(result));
        return;
    }
    auto ytp_kind = to_ytp_service_kind(service_kind);
    if (!ytp_kind.ok()) {
        auto result = Result<std::shared_ptr<StreamResponder>>(
            ytp_kind.status());
        invoke_noexcept(completion, std::move(result));
        return;
    }
    if (destination &&
        ((service_kind == ServiceKind::ByteStream &&
          destination->protocol() != NetworkProtocol::Tcp) ||
         (service_kind == ServiceKind::PacketChannel &&
          destination->protocol() != NetworkProtocol::Udp))) {
        auto result = Result<std::shared_ptr<StreamResponder>>(Status(
            StatusCode::InvalidArgument,
            "route protocol does not match the service kind"));
        invoke_noexcept(completion, std::move(result));
        return;
    }

    StreamId stream_id = StreamId::control();
    std::shared_ptr<StreamStateData> stream;
    std::shared_ptr<EngineStreamResponder> responder;
    Status admission = Status::success();
    bool pending_released = false;
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        if (state_ != SessionState::Active) {
            admission = Status(StatusCode::FailedPrecondition,
                               "session is not active");
        } else if (local_stream_ids_exhausted_) {
            admission = Status(StatusCode::ResourceExhausted,
                               "local stream-ID space is exhausted");
        } else if (streams_.size() >= limits_.max_streams ||
                   pending_opens_ >= limits_.max_pending_opens) {
            admission = Status(StatusCode::ResourceExhausted,
                               "session stream capacity is exhausted");
        } else {
            const ytp1::Capability* advertised = peer_capability(
                service_name, service_kind);
            if (!advertised) {
                admission = Status(StatusCode::NotFound,
                                   "peer did not advertise this service and kind");
            } else if (service_stream_count_locked(service_name,
                                                   service_kind) >=
                       advertised->max_concurrent_streams) {
                admission = Status(StatusCode::ResourceExhausted,
                                   "peer service stream limit is exhausted");
            } else {
                auto id = StreamId::application(
                    next_local_stream_id_, graph_->local_role());
                if (!id.ok()) {
                    admission = id.status();
                } else {
                    stream_id = id.value();
                    if (next_local_stream_id_ >
                        StreamId::kMaxApplicationValue - 2U) {
                        local_stream_ids_exhausted_ = true;
                    } else {
                        next_local_stream_id_ += 2U;
                    }
                    ++pending_opens_;
                }
            }
        }
    } catch (const std::bad_alloc&) {
        admission = Status(StatusCode::ResourceExhausted,
                           "stream-open admission allocation failed");
    }
    if (!admission.ok()) {
        auto result = Result<std::shared_ptr<StreamResponder>>(admission);
        invoke_noexcept(completion, std::move(result));
        return;
    }

    try {
        stream = std::make_shared<StreamStateData>(
            stream_id, std::string(service_name), service_kind, false);
        const std::size_t max_write = service_kind == ServiceKind::PacketChannel
            ? limits_.max_packet_size
            : limits_.max_frame_payload;
        responder = std::make_shared<EngineStreamResponder>(
            weak_owner(), stream_id, service_kind, affinity_, max_write);
        stream->responder = responder;
        stream->inbound_credit = limits_.initial_stream_credit;
        Status publication = Status::success();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            --pending_opens_;
            pending_released = true;
            if (terminal_locked()) {
                publication = Status(StatusCode::Closed,
                                     "session closed during stream open");
            } else {
                const auto [_, inserted] = streams_.emplace(
                    stream_id.value(), stream);
                if (!inserted) {
                    publication = Status(
                        StatusCode::Internal,
                        "allocated local stream ID already exists");
                }
            }
        }
        if (!publication.ok()) {
            auto result = Result<std::shared_ptr<StreamResponder>>(
                publication);
            invoke_noexcept(completion, std::move(result));
            return;
        }
    } catch (const std::bad_alloc&) {
        if (!pending_released) {
            std::lock_guard<std::mutex> lock(mutex_);
            --pending_opens_;
        }
        auto result = Result<std::shared_ptr<StreamResponder>>(Status(
            StatusCode::ResourceExhausted,
            "stream-open allocation failed"));
        invoke_noexcept(completion, std::move(result));
        return;
    }

    try {
        ytp1::OpenRequest request;
        request.service_kind = ytp_kind.value();
        request.service_name.assign(service_name);
        if (destination) {
            auto encoded_destination = to_ytp_destination(*destination);
            if (!encoded_destination.ok()) {
                remove_stream(stream_id, encoded_destination.status());
                auto result = Result<std::shared_ptr<StreamResponder>>(
                    encoded_destination.status());
                invoke_noexcept(completion, std::move(result));
                return;
            }
            request.destination =
                std::move(encoded_destination).take_value();
        }
        auto encoded = ytp1::EncodeOpen(request);
        if (!encoded.ok()) {
            remove_stream(stream_id, protocol_failure(
                "local OPEN could not be encoded canonically"));
            auto result = Result<std::shared_ptr<StreamResponder>>(Status(
                StatusCode::Internal, "local OPEN encoding failed"));
            invoke_noexcept(completion, std::move(result));
            return;
        }
        Status send = enqueue_record(
            ytp1::RecordType::Open, stream_id, as_bytes(*encoded.value), true,
            false);
        if (send.ok()) {
            send = send_stream_credit(stream_id,
                                      limits_.initial_stream_credit);
        }
        if (!send.ok()) {
            remove_stream(stream_id, send);
            auto result = Result<std::shared_ptr<StreamResponder>>(send);
            invoke_noexcept(completion, std::move(result));
            return;
        }
    } catch (const std::bad_alloc&) {
        Status failure(StatusCode::ResourceExhausted,
                       "stream OPEN construction allocation failed");
        remove_stream(stream_id, failure);
        auto result = Result<std::shared_ptr<StreamResponder>>(failure);
        invoke_noexcept(completion, std::move(result));
        return;
    } catch (...) {
        Status failure(StatusCode::Internal,
                       "stream OPEN construction failed");
        remove_stream(stream_id, failure);
        auto result = Result<std::shared_ptr<StreamResponder>>(failure);
        invoke_noexcept(completion, std::move(result));
        return;
    }
    std::shared_ptr<StreamResponder> public_responder = responder;
    auto result = Result<std::shared_ptr<StreamResponder>>(
        std::move(public_responder));
    invoke_noexcept(completion, std::move(result));
}

void SessionEngine::Impl::stream_read(
    StreamId stream_id,
    CancellationToken cancellation,
    StreamResponder::ReadCompletion completion) {
    if (!completion) {
        return;
    }
    if (cancellation.is_cancelled()) {
        auto result = Result<ReceivedRecord>(Status(
            StatusCode::Cancelled, "stream read was cancelled"));
        invoke_noexcept(completion, std::move(result));
        return;
    }
    std::optional<ReceivedRecord> ready;
    std::optional<std::uint64_t> queued_operation;
    Status status = Status::success();
    bool retire_after_read = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = streams_.find(stream_id.value());
        if (it == streams_.end() || it->second->closed) {
            status = Status(StatusCode::Closed, "stream is closed");
        } else if (it->second->pending_read.has_value()) {
            status = Status(StatusCode::FailedPrecondition,
                            "stream already has a pending read");
        } else if (!it->second->inbound.empty()) {
            ready.emplace(std::move(it->second->inbound.front()));
            it->second->inbound.pop_front();
            it->second->inbound_queued_bytes -= ready->payload().size();
            inbound_queued_bytes_ -= ready->payload().size();
            retire_after_read = it->second->peer_write_closed &&
                                it->second->local_write_closed &&
                                it->second->inbound.empty();
        } else if (it->second->peer_write_closed) {
            status = Status(
                StatusCode::Closed,
                "peer shut down the stream write side");
            retire_after_read = it->second->local_write_closed;
        } else {
            if (operation_ids_exhausted_) {
                status = Status(StatusCode::ResourceExhausted,
                                "stream operation IDs are exhausted");
            } else {
                const std::uint64_t operation_id = next_operation_id_;
                if (next_operation_id_ ==
                    std::numeric_limits<std::uint64_t>::max()) {
                    operation_ids_exhausted_ = true;
                } else {
                    ++next_operation_id_;
                }
                it->second->pending_read.emplace(
                    operation_id, std::move(completion));
                queued_operation = operation_id;
            }
        }
    }
    if (retire_after_read) {
        remove_stream(stream_id, Status(
            StatusCode::Closed, "stream is fully closed"));
    }
    if (!status.ok()) {
        auto result = Result<ReceivedRecord>(status);
        invoke_noexcept(completion, std::move(result));
        return;
    }
    if (queued_operation.has_value()) {
        const std::weak_ptr<SessionEngine> weak = weak_owner();
        auto registration = cancellation.register_callback(
            [weak, stream_id,
             operation_id = *queued_operation] {
                if (auto engine = weak.lock()) {
                    engine->impl_->cancel_pending_read(
                        stream_id, operation_id,
                        Status(StatusCode::Cancelled,
                               "stream read was cancelled"));
                }
            });
        if (!registration.ok()) {
            cancel_pending_read(stream_id, *queued_operation,
                                registration.status());
            return;
        }
        CancellationRegistration installed =
            std::move(registration).take_value();
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = streams_.find(stream_id.value());
        if (it != streams_.end() &&
            it->second->pending_read.has_value() &&
            it->second->pending_read->operation_id == *queued_operation) {
            it->second->pending_read->cancellation = std::move(installed);
        }
        return;
    }
    auto result = Result<ReceivedRecord>(std::move(*ready));
    invoke_noexcept(completion, std::move(result));
}

void SessionEngine::Impl::stream_write(
    StreamId stream_id,
    Buffer payload,
    CancellationToken cancellation,
    StreamResponder::WriteCompletion completion) {
    if (!completion) {
        return;
    }
    if (cancellation.is_cancelled()) {
        invoke_noexcept(completion, Status(
            StatusCode::Cancelled, "stream write was cancelled"), 0U);
        return;
    }
    std::shared_ptr<StreamStateData> stream;
    Status status = Status::success();
    bool can_send = false;
    std::optional<std::uint64_t> queued_operation;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = streams_.find(stream_id.value());
        if (it == streams_.end() || it->second->closed) {
            status = Status(StatusCode::Closed, "stream is closed");
        } else if (it->second->local_write_shutdown_requested) {
            status = Status(StatusCode::Closed,
                            "stream write side is shut down");
        } else if (payload.empty() ||
                   payload.size() > limits_.max_frame_payload ||
                   (it->second->kind == ServiceKind::PacketChannel &&
                    payload.size() > limits_.max_packet_size)) {
            status = Status(StatusCode::InvalidArgument,
                            "stream payload size is invalid");
        } else {
            stream = it->second;
            can_send = payload.size() <= stream->outbound_credit &&
                       payload.size() <= outbound_connection_credit_ &&
                       !outbound_rekey_pending_;
            if (!can_send) {
                const std::size_t retained = queued_wire_bytes_ +
                                             pending_write_bytes_;
                if (payload.size() > limits_.max_stream_queued_bytes -
                                         stream->outbound_queued_bytes ||
                    retained > limits_.max_queued_bytes ||
                    payload.size() > limits_.max_queued_bytes - retained) {
                    status = Status(StatusCode::ResourceExhausted,
                                    "stream write queue is full");
                } else if (operation_ids_exhausted_) {
                    status = Status(StatusCode::ResourceExhausted,
                                    "stream operation IDs are exhausted");
                } else {
                    try {
                        const std::uint64_t operation_id = next_operation_id_;
                        stream->pending_writes.emplace_back(
                            operation_id, std::move(payload),
                            std::move(completion));
                        if (next_operation_id_ ==
                            std::numeric_limits<std::uint64_t>::max()) {
                            operation_ids_exhausted_ = true;
                        } else {
                            ++next_operation_id_;
                        }
                        stream->outbound_queued_bytes +=
                            stream->pending_writes.back().payload.size();
                        pending_write_bytes_ +=
                            stream->pending_writes.back().payload.size();
                        queued_operation = operation_id;
                    } catch (const std::bad_alloc&) {
                        status = Status(StatusCode::ResourceExhausted,
                                        "stream write queue allocation failed");
                    }
                }
            } else {
                stream->outbound_credit -= payload.size();
                outbound_connection_credit_ -= payload.size();
                ++stream->outbound_publications;
            }
        }
    }
    if (!status.ok()) {
        invoke_noexcept(completion, status, 0U);
        return;
    }
    if (queued_operation.has_value()) {
        const std::weak_ptr<SessionEngine> weak = weak_owner();
        auto registration = cancellation.register_callback(
            [weak, stream_id,
             operation_id = *queued_operation] {
                if (auto engine = weak.lock()) {
                    engine->impl_->cancel_pending_write(
                        stream_id, operation_id,
                        Status(StatusCode::Cancelled,
                               "stream write was cancelled"));
                }
            });
        if (!registration.ok()) {
            cancel_pending_write(stream_id, *queued_operation,
                                 registration.status());
            return;
        }
        CancellationRegistration installed =
            std::move(registration).take_value();
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = streams_.find(stream_id.value());
        if (it != streams_.end()) {
            const auto pending = std::find_if(
                it->second->pending_writes.begin(),
                it->second->pending_writes.end(),
                [operation_id = *queued_operation](const PendingWrite& write) {
                    return write.operation_id == operation_id;
                });
            if (pending != it->second->pending_writes.end()) {
                pending->cancellation = std::move(installed);
            }
        }
        return;
    }
    if (cancellation.is_cancelled()) {
        const std::size_t payload_size = payload.size();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stream->outbound_credit += payload_size;
            outbound_connection_credit_ += payload_size;
            --stream->outbound_publications;
        }
        invoke_noexcept(completion, Status(
            StatusCode::Cancelled, "stream write was cancelled"), 0U);
        const Status shutdown = finish_stream_shutdown_if_ready(stream_id);
        if (!shutdown.ok() && shutdown.code() != StatusCode::Closed) {
            fail(shutdown);
        }
        return;
    }
    const std::size_t payload_size = payload.size();
    const ytp1::RecordType type = stream->kind == ServiceKind::ByteStream
        ? ytp1::RecordType::Data
        : ytp1::RecordType::Packet;
    std::shared_ptr<StreamResponder::WriteCompletion> completion_holder;
    try {
        completion_holder =
            std::make_shared<StreamResponder::WriteCompletion>(
                std::move(completion));
    } catch (const std::bad_alloc&) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            stream->outbound_credit += payload_size;
            outbound_connection_credit_ += payload_size;
            --stream->outbound_publications;
        }
        invoke_noexcept(completion, Status(
            StatusCode::ResourceExhausted,
            "stream write completion allocation failed"), 0U);
        const Status shutdown = finish_stream_shutdown_if_ready(stream_id);
        if (!shutdown.ok() && shutdown.code() != StatusCode::Closed) {
            fail(shutdown);
        }
        return;
    }
    status = enqueue_record(
        type, stream_id, payload.bytes(), true, false, payload_size,
        [completion_holder](Status send_status,
                            std::size_t transferred) noexcept {
            invoke_noexcept(*completion_holder, std::move(send_status),
                            transferred);
            *completion_holder = {};
        });
    {
        std::lock_guard<std::mutex> lock(mutex_);
        --stream->outbound_publications;
        if (!status.ok()) {
            stream->outbound_credit += payload_size;
            outbound_connection_credit_ += payload_size;
        }
    }
    if (!status.ok()) {
        invoke_noexcept(*completion_holder, status, 0U);
        *completion_holder = {};
    }
    const Status shutdown = finish_stream_shutdown_if_ready(stream_id);
    if (!shutdown.ok() && shutdown.code() != StatusCode::Closed) {
        fail(shutdown);
    }
}

void SessionEngine::Impl::drain_pending_writes(StreamId stream_id) noexcept {
    for (;;) {
        std::optional<PendingWrite> pending;
        std::shared_ptr<StreamStateData> stream;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            const auto it = streams_.find(stream_id.value());
            if (it == streams_.end() || it->second->closed) {
                return;
            }
            if (outbound_rekey_pending_) {
                return;
            }
            if (it->second->pending_writes.empty()) {
                break;
            }
            stream = it->second;
            const std::size_t size = stream->pending_writes.front().payload.size();
            if (size > stream->outbound_credit ||
                size > outbound_connection_credit_) {
                return;
            }
            pending.emplace(std::move(stream->pending_writes.front()));
            stream->pending_writes.pop_front();
            stream->outbound_queued_bytes -= size;
            pending_write_bytes_ -= size;
            stream->outbound_credit -= size;
            outbound_connection_credit_ -= size;
            ++stream->outbound_publications;
        }
        const std::size_t size = pending->payload.size();
        const ytp1::RecordType type = stream->kind == ServiceKind::ByteStream
            ? ytp1::RecordType::Data
            : ytp1::RecordType::Packet;
        std::shared_ptr<StreamResponder::WriteCompletion> completion_holder;
        try {
            completion_holder =
                std::make_shared<StreamResponder::WriteCompletion>(
                    std::move(pending->completion));
        } catch (const std::bad_alloc&) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                stream->outbound_credit += size;
                outbound_connection_credit_ += size;
                --stream->outbound_publications;
            }
            invoke_noexcept(pending->completion, Status(
                StatusCode::ResourceExhausted,
                "queued-write completion allocation failed"), 0U);
            break;
        }
        const Status status = enqueue_record(
            type, stream_id, pending->payload.bytes(), true, false, size,
            [completion_holder](Status send_status,
                                std::size_t transferred) noexcept {
                invoke_noexcept(*completion_holder,
                                std::move(send_status), transferred);
                *completion_holder = {};
            });
        {
            std::lock_guard<std::mutex> lock(mutex_);
            --stream->outbound_publications;
            if (!status.ok()) {
                stream->outbound_credit += size;
                outbound_connection_credit_ += size;
            }
        }
        if (!status.ok()) {
            invoke_noexcept(*completion_holder, status, 0U);
            *completion_holder = {};
            break;
        }
    }
    const Status shutdown = finish_stream_shutdown_if_ready(stream_id);
    if (!shutdown.ok() && shutdown.code() != StatusCode::Closed) {
        fail(shutdown);
    }
}

Status SessionEngine::Impl::stream_shutdown(StreamId stream_id) noexcept {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = streams_.find(stream_id.value());
        if (it == streams_.end() || it->second->closed) {
            return Status(StatusCode::Closed, "stream is closed");
        }
        if (it->second->local_write_shutdown_requested) {
            return Status::success();
        }
        it->second->local_write_shutdown_requested = true;
    }
    return finish_stream_shutdown_if_ready(stream_id);
}

void SessionEngine::Impl::stream_close(
    StreamId stream_id,
    Status reason) noexcept {
    (void)send_close(stream_id, StreamCloseCode::Aborted);
    remove_stream(stream_id, std::move(reason));
}

Status SessionEngine::Impl::send_stream_credit(
    StreamId stream_id,
    std::uint32_t increment) {
    const auto encoded = ytp1::EncodeCreditUpdate(increment);
    if (!encoded.ok()) {
        return Status(StatusCode::Internal,
                      "validated stream credit could not be encoded");
    }
    return enqueue_record(
        ytp1::RecordType::StreamCredit, stream_id,
        as_bytes(*encoded.value), true, false);
}

Status SessionEngine::Impl::send_close(
    StreamId stream_id,
    StreamCloseCode code) {
    const std::array<std::byte, kClosePayloadBytes> payload{
        static_cast<std::byte>(code)};
    return enqueue_record(ytp1::RecordType::Close, stream_id,
                          payload, true, false);
}

Status SessionEngine::Impl::finish_stream_shutdown_if_ready(
    StreamId stream_id) noexcept {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = streams_.find(stream_id.value());
        if (it == streams_.end() || it->second->closed) {
            return Status(StatusCode::Closed, "stream is closed");
        }
        if (!it->second->local_write_shutdown_requested ||
            it->second->local_write_closed ||
            !it->second->pending_writes.empty() ||
            it->second->outbound_publications != 0U) {
            return Status::success();
        }
        // Publication on the carrier is ordered after every DATA/PACKET record
        // already accepted for this stream. Mark the side closed before the
        // unlocked enqueue so concurrent writers cannot pass the FIN.
        it->second->local_write_closed = true;
    }

    const Status status = send_close(stream_id, StreamCloseCode::Normal);
    if (!status.ok()) {
        remove_stream(stream_id, status);
        return status;
    }

    bool fully_closed = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = streams_.find(stream_id.value());
        if (it != streams_.end() && !it->second->closed) {
            fully_closed = it->second->peer_write_closed &&
                           it->second->inbound.empty();
        }
    }
    if (fully_closed) {
        remove_stream(stream_id, Status(
            StatusCode::Closed, "stream is fully closed"));
    }
    return Status::success();
}

void SessionEngine::Impl::return_receive_credit(
    StreamId stream_id,
    std::size_t bytes) noexcept {
    if (bytes == 0U || bytes > ytp1::kMaxCreditIncrement) {
        fail(Status(StatusCode::Internal,
                    "application returned invalid receive credit"));
        return;
    }
    bool stream_is_live = false;
    bool valid = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (terminal_locked()) {
            return;
        }
        const auto it = streams_.find(stream_id.value());
        if (bytes <= limits_.max_connection_credit -
                         inbound_connection_credit_) {
            inbound_connection_credit_ += bytes;
            valid = true;
            if (it != streams_.end() && !it->second->closed) {
                if (bytes > limits_.max_stream_credit -
                                it->second->inbound_credit) {
                    valid = false;
                    inbound_connection_credit_ -= bytes;
                } else {
                    it->second->inbound_credit += bytes;
                    stream_is_live = true;
                }
            }
        }
    }
    if (!valid) {
        fail(protocol_failure("receive-credit accounting overflowed"));
        return;
    }
    const Status stream_credit = stream_is_live
        ? send_stream_credit(stream_id, static_cast<std::uint32_t>(bytes))
        : Status::success();
    const auto connection = ytp1::EncodeCreditUpdate(
        static_cast<std::uint32_t>(bytes));
    Status connection_status = connection.ok()
        ? enqueue_record(ytp1::RecordType::ConnectionCredit,
                         StreamId::control(),
                         as_bytes(*connection.value), true, true)
        : Status(StatusCode::Internal,
                 "returned connection credit could not be encoded");
    if (!stream_credit.ok()) {
        fail(stream_credit);
    } else if (!connection_status.ok()) {
        fail(connection_status);
    }
}

void SessionEngine::Impl::remove_stream(
    StreamId stream_id,
    Status reason) noexcept {
    std::shared_ptr<StreamStateData> stream;
    StreamResponder::ReadCompletion read;
    std::deque<PendingWrite> writes;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = streams_.find(stream_id.value());
        if (it == streams_.end()) {
            return;
        }
        stream = it->second;
        stream->closed = true;
        if (stream->pending_read.has_value()) {
            read = std::move(stream->pending_read->completion);
            stream->pending_read.reset();
        }
        writes.swap(stream->pending_writes);
        pending_write_bytes_ -= stream->outbound_queued_bytes;
        stream->outbound_queued_bytes = 0U;
        inbound_queued_bytes_ -= stream->inbound_queued_bytes;
        stream->inbound_queued_bytes = 0U;
        streams_.erase(it);
    }
    if (read) {
        auto result = Result<ReceivedRecord>(reason);
        invoke_noexcept(read, std::move(result));
    }
    for (PendingWrite& write : writes) {
        invoke_noexcept(write.completion, reason, 0U);
    }
}

void SessionEngine::Impl::cancel_pending_read(
    StreamId stream_id,
    std::uint64_t operation_id,
    Status reason) noexcept {
    StreamResponder::ReadCompletion completion;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = streams_.find(stream_id.value());
        if (it == streams_.end() ||
            !it->second->pending_read.has_value() ||
            it->second->pending_read->operation_id != operation_id) {
            return;
        }
        completion = std::move(it->second->pending_read->completion);
        it->second->pending_read.reset();
    }
    auto result = Result<ReceivedRecord>(reason);
    invoke_noexcept(completion, std::move(result));
}

void SessionEngine::Impl::cancel_pending_write(
    StreamId stream_id,
    std::uint64_t operation_id,
    Status reason) noexcept {
    StreamResponder::WriteCompletion completion;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto stream_it = streams_.find(stream_id.value());
        if (stream_it == streams_.end()) {
            return;
        }
        auto& pending = stream_it->second->pending_writes;
        const auto write_it = std::find_if(
            pending.begin(), pending.end(),
            [operation_id](const PendingWrite& write) {
                return write.operation_id == operation_id;
            });
        if (write_it == pending.end()) {
            return;
        }
        const std::size_t bytes = write_it->payload.size();
        completion = std::move(write_it->completion);
        pending.erase(write_it);
        stream_it->second->outbound_queued_bytes -= bytes;
        pending_write_bytes_ -= bytes;
    }
    invoke_noexcept(completion, std::move(reason), 0U);
    const Status shutdown = finish_stream_shutdown_if_ready(stream_id);
    if (!shutdown.ok() && shutdown.code() != StatusCode::Closed) {
        fail(shutdown);
    }
}

Status SessionEngine::Impl::initiate_rekey() {
    std::uint32_t next_epoch = 0U;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (state_ != SessionState::Active) {
            return Status(StatusCode::FailedPrecondition,
                          "session is not active");
        }
        if (outbound_rekey_pending_) {
            return Status(StatusCode::AlreadyExists,
                          "outbound rekey is already pending");
        }
        if (rekey_work_ >= limits_.max_concurrent_rekeys ||
            outbound_epoch_ == std::numeric_limits<std::uint32_t>::max()) {
            return Status(StatusCode::ResourceExhausted,
                          "directional rekey capacity is exhausted");
        }
        next_epoch = outbound_epoch_ + 1U;
        outbound_rekey_pending_ = true;
        outbound_rekey_epoch_ = next_epoch;
        ++rekey_work_;
    }

    Result<Buffer> initiation(Status(
        StatusCode::Internal, "security provider did not begin rekey"));
    try {
        std::lock_guard<std::mutex> security_lock(security_mutex_);
        initiation = security_->begin_outbound_rekey(next_epoch);
    } catch (const std::bad_alloc&) {
        initiation = Result<Buffer>(Status(
            StatusCode::ResourceExhausted,
            "security provider allocation failed during rekey"));
    } catch (...) {
        initiation = Result<Buffer>(Status(
            StatusCode::Internal,
            "security provider threw while beginning rekey"));
    }
    if (!initiation.ok() || initiation.value().empty() ||
        initiation.value().size() > limits_.max_rekey_payload ||
        initiation.value().size() > limits_.max_frame_payload -
                                      kRekeyEpochBytes) {
        const Status failure = initiation.ok()
            ? Status(StatusCode::ProviderMismatch,
                     "security provider returned an invalid rekey initiation")
            : initiation.status();
        fail(failure);
        return failure;
    }
    auto payload = Buffer::allocate(
        kRekeyEpochBytes + initiation.value().size(),
        kRekeyEpochBytes + initiation.value().size());
    if (!payload.ok()) {
        const Status failure = payload.status();
        fail(failure);
        return failure;
    }
    Buffer bytes = std::move(payload).take_value();
    write_u32(bytes.mutable_bytes(), 0U, next_epoch);
    std::memcpy(bytes.mutable_bytes().data() + kRekeyEpochBytes,
                initiation.value().bytes().data(),
                initiation.value().size());
    const Status sent = enqueue_record(
        ytp1::RecordType::RekeyInit, StreamId::control(), bytes.bytes(),
        true, true, 0U, {}, true);
    if (!sent.ok()) {
        fail(sent);
    }
    return sent;
}

Status SessionEngine::Impl::process_rekey_init(
    std::span<const std::byte> payload) {
    if (payload.size() <= kRekeyEpochBytes ||
        payload.size() > limits_.max_rekey_payload + kRekeyEpochBytes) {
        return protocol_failure("REKEY_INIT payload has an invalid size");
    }
    const std::uint32_t next_epoch = read_u32(payload, 0U);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (inbound_epoch_ == std::numeric_limits<std::uint32_t>::max() ||
            next_epoch != inbound_epoch_ + 1U ||
            rekey_work_ >= limits_.max_concurrent_rekeys) {
            return protocol_failure("inbound rekey epoch or capacity is invalid");
        }
        ++rekey_work_;
    }
    Result<Buffer> acknowledgement(Status(
        StatusCode::Internal, "security provider did not accept rekey"));
    try {
        std::lock_guard<std::mutex> security_lock(security_mutex_);
        acknowledgement = security_->accept_inbound_rekey(
            next_epoch, payload.subspan(kRekeyEpochBytes));
    } catch (const std::bad_alloc&) {
        acknowledgement = Result<Buffer>(Status(
            StatusCode::ResourceExhausted,
            "security provider allocation failed while accepting rekey"));
    } catch (...) {
        acknowledgement = Result<Buffer>(Status(
            StatusCode::Internal,
            "security provider threw while accepting rekey"));
    }
    if (!acknowledgement.ok() || acknowledgement.value().empty() ||
        acknowledgement.value().size() > limits_.max_rekey_payload ||
        acknowledgement.value().size() > limits_.max_frame_payload -
                                           kRekeyEpochBytes) {
        std::lock_guard<std::mutex> lock(mutex_);
        --rekey_work_;
        return acknowledgement.ok()
            ? Status(StatusCode::ProviderMismatch,
                     "security provider returned an invalid rekey acknowledgement")
            : acknowledgement.status();
    }

    auto encoded = Buffer::allocate(
        kRekeyEpochBytes + acknowledgement.value().size(),
        kRekeyEpochBytes + acknowledgement.value().size());
    if (!encoded.ok()) {
        std::lock_guard<std::mutex> lock(mutex_);
        --rekey_work_;
        return encoded.status();
    }
    Buffer bytes = std::move(encoded).take_value();
    write_u32(bytes.mutable_bytes(), 0U, next_epoch);
    std::memcpy(bytes.mutable_bytes().data() + kRekeyEpochBytes,
                acknowledgement.value().bytes().data(),
                acknowledgement.value().size());

    // Provider acceptance authenticates INIT under the old inbound root and
    // commits the candidate new inbound root. Mirror that epoch transition in
    // the engine before the peer can send its first protected record under the
    // new root. ACK itself travels in the explicitly authenticated raw form
    // described in process_received() and consumes no directional record key.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        inbound_epoch_ = next_epoch;
        --rekey_work_;
    }
    return enqueue_record(ytp1::RecordType::RekeyAck,
                          StreamId::control(), bytes.bytes(), false, true);
}

Status SessionEngine::Impl::process_rekey_ack(
    std::span<const std::byte> payload) {
    if (payload.size() <= kRekeyEpochBytes ||
        payload.size() > limits_.max_rekey_payload + kRekeyEpochBytes) {
        return protocol_failure("REKEY_ACK payload has an invalid size");
    }
    const std::uint32_t next_epoch = read_u32(payload, 0U);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!outbound_rekey_pending_ ||
            next_epoch != outbound_rekey_epoch_) {
            return protocol_failure("REKEY_ACK epoch is unexpected");
        }
    }
    Status finished(StatusCode::Internal,
                    "security provider did not finish rekey");
    try {
        std::lock_guard<std::mutex> security_lock(security_mutex_);
        finished = security_->finish_outbound_rekey(
            next_epoch, payload.subspan(kRekeyEpochBytes));
    } catch (const std::bad_alloc&) {
        finished = Status(StatusCode::ResourceExhausted,
                          "security provider allocation failed while finishing rekey");
    } catch (...) {
        finished = Status(StatusCode::Internal,
                          "security provider threw while finishing rekey");
    }
    if (!finished.ok()) {
        return finished;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        outbound_epoch_ = next_epoch;
        outbound_rekey_pending_ = false;
        --rekey_work_;
    }
    const Status flushed = flush_deferred_records();
    if (!flushed.ok()) {
        return flushed;
    }
    std::vector<StreamId> pending;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        pending.reserve(streams_.size());
        for (const auto& [_, stream] : streams_) {
            if (!stream->pending_writes.empty()) {
                pending.push_back(stream->id);
            }
        }
    }
    for (StreamId stream_id : pending) {
        drain_pending_writes(stream_id);
    }
    return Status::success();
}

void SessionEngine::Impl::fail(Status status) noexcept {
    if (status.ok()) {
        status = Status(StatusCode::Internal,
                        "session failed without an error status");
    }
    stop(std::move(status), true);
}

void SessionEngine::Impl::stop(Status reason, bool failed) noexcept {
    if (reason.ok()) {
        reason = Status(StatusCode::Closed, "session closed");
    }
    StartCompletion start;
    std::unordered_map<std::uint32_t, std::shared_ptr<StreamStateData>>
        retired_streams;
    std::deque<OutboundItem> retired_outbound;
    std::deque<DeferredRecord> retired_deferred;
    std::optional<ActiveSend> retired_active;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (terminal_locked()) {
            return;
        }
        state_ = SessionState::Closing;
        terminal_status_ = reason;
        start = std::move(start_completion_);
        for (auto& [_, stream] : streams_) {
            stream->closed = true;
        }
        // Stream queues own RAII receive-credit leases whose destruction may
        // re-enter return_receive_credit(). Move them out and destroy them
        // only after releasing the engine lock.
        retired_streams.swap(streams_);
        retired_outbound.swap(outbound_queue_);
        retired_deferred.swap(deferred_records_);
        retired_active = std::move(active_send_);
        active_send_.reset();
        pending_write_bytes_ = 0U;
        inbound_queued_bytes_ = 0U;
        queued_wire_bytes_ = 0U;
        queued_control_messages_ = 0U;
        state_ = failed ? SessionState::Failed : SessionState::Closed;
    }

    cancellation_.cancel();
    try {
        std::lock_guard<std::mutex> security_lock(security_mutex_);
        security_->cancel();
    } catch (...) {
        // Provider cleanup is a noexcept boundary by contract.
    }
    try {
        carrier_->cancel();
    } catch (...) {
    }
    try {
        carrier_->close();
    } catch (...) {
    }
    invoke_noexcept(start, reason);
    for (auto& [_, stream] : retired_streams) {
        if (stream->pending_read.has_value()) {
            auto result = Result<ReceivedRecord>(reason);
            invoke_noexcept(stream->pending_read->completion,
                            std::move(result));
        }
        for (PendingWrite& write : stream->pending_writes) {
            invoke_noexcept(write.completion, reason, 0U);
        }
    }
    for (OutboundItem& item : retired_outbound) {
        invoke_noexcept(item.completion, reason, 0U);
    }
    for (DeferredRecord& item : retired_deferred) {
        invoke_noexcept(item.completion, reason, 0U);
    }
    if (retired_active.has_value()) {
        invoke_noexcept(retired_active->completion, reason, 0U);
    }
}

}  // namespace yume::engine
