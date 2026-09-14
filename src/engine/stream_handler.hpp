/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include "engine/carrier.hpp"
#include "engine/route_provider.hpp"
#include "engine/stream_id.hpp"

namespace yume::engine {

class StreamOpenContext final {
public:
    static Result<StreamOpenContext> create(
        StreamId stream_id,
        std::string service_name,
        ServiceKind service_kind,
        PeerEvidence peer_evidence,
        std::optional<RouteDestination> destination = std::nullopt);

    StreamId stream_id() const noexcept { return stream_id_; }
    const std::string& service_name() const noexcept { return service_name_; }
    ServiceKind service_kind() const noexcept { return service_kind_; }
    const PeerEvidence& peer_evidence() const noexcept {
        return peer_evidence_;
    }
    const RouteDestination* destination_if() const noexcept {
        return destination_ ? &*destination_ : nullptr;
    }

private:
    StreamOpenContext(StreamId stream_id,
                      std::string service_name,
                      ServiceKind service_kind,
                      PeerEvidence peer_evidence,
                      std::optional<RouteDestination> destination) noexcept;

    StreamId stream_id_;
    std::string service_name_;
    ServiceKind service_kind_;
    PeerEvidence peer_evidence_;
    std::optional<RouteDestination> destination_;
};

// Application-facing authenticated stream. For PacketChannel services each
// read/write Buffer is one packet; for ByteStream services buffers are ordered
// byte chunks. Receive credit remains owned by ReceivedRecord until the
// application has consumed or discarded the chunk.
//
// A read fails with StatusCode::EndOfStream once the peer's authenticated FIN
// arrived and every earlier inbound record was delivered. Later reads repeat
// it until the stream or its session terminates. Any other failure is a termination
// (local close, peer refusal or abort, session end) and may have discarded
// undelivered records.
class StreamResponder {
public:
    using ReadCompletion = std::function<void(Result<ReceivedRecord>)>;
    using WriteCompletion = std::function<void(Status, std::size_t)>;

    virtual ~StreamResponder() = default;
    virtual ExecutorAffinity executor_affinity() const noexcept = 0;
    virtual ServiceKind service_kind() const noexcept = 0;
    virtual std::size_t max_write_size() const noexcept = 0;
    // Thread-safe terminal observation for adapters retaining delivered records
    // or EOF. A normal half-close is not termination; an abort, local close or
    // lost session is, even after the last read completed with EndOfStream.
    virtual bool terminated() const noexcept = 0;
    virtual void async_read(CancellationToken cancellation,
                            ReadCompletion completion) = 0;
    virtual void async_write(Buffer payload,
                             CancellationToken cancellation,
                             WriteCompletion completion) = 0;
    // Stops only the local write direction after previously accepted writes.
    // Reads remain valid until the peer independently shuts down its write
    // direction or the stream is aborted.
    virtual Status shutdown_write() noexcept = 0;
    virtual void close(Status reason) noexcept = 0;
};

class StreamHandler {
public:
    using AcceptanceCompletion = std::function<void(Status)>;
    virtual ~StreamHandler() = default;
    virtual const ProviderDescriptor& descriptor() const noexcept = 0;
    virtual ServiceKind service_kind() const noexcept = 0;

    // The dispatcher calls authorize independently for every OPEN, even when
    // the capability was advertised. It fails closed if this method throws.
    virtual Status authorize(const StreamOpenContext& context) = 0;

    // Completion accepts or refuses one incoming OPEN. Credit is withheld until
    // success. Implementations that establish an asynchronous dependency must
    // complete only after that dependency is ready. PermissionDenied sends an
    // unauthorized CLOSE, including policy refusal after DNS resolution. Other
    // failures send handler-failure CLOSE. Default adapters invoke the
    // existing synchronous handler methods below and then accept.
    virtual void async_open(StreamOpenContext context,
                            std::shared_ptr<StreamResponder> stream,
                            AcceptanceCompletion completion);
    virtual void async_route(AuthorizedRouteRequest request,
                             std::shared_ptr<RouteProvider> route_provider,
                             std::shared_ptr<StreamResponder> stream,
                             AcceptanceCompletion completion);

    // Invoked without engine locks. The engine contains handler exceptions and
    // closes the corresponding stream rather than corrupting session state.
    virtual void on_open(StreamOpenContext context,
                         std::shared_ptr<StreamResponder> stream) = 0;

    // Invoked only after authorize() succeeds for a destination-bearing OPEN
    // and only when the provider advertises the matching DirectTcp or
    // DirectUdp capability. The request is constructed by SessionEngine, so a
    // RouteProvider never receives raw, pre-policy destination metadata. The
    // dispatcher supplies the provider selected and validated by EngineGraph;
    // handlers must use that instance rather than retaining a separate route
    // provider. Runtime shutdown owns cancellation of the selected provider.
    virtual void on_route(AuthorizedRouteRequest request,
                          std::shared_ptr<RouteProvider> route_provider,
                          std::shared_ptr<StreamResponder> stream);
};

}  // namespace yume::engine
