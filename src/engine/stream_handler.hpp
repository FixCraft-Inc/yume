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
class StreamResponder {
public:
    using ReadCompletion = std::function<void(Result<ReceivedRecord>)>;
    using WriteCompletion = std::function<void(Status, std::size_t)>;

    virtual ~StreamResponder() = default;
    virtual ExecutorAffinity executor_affinity() const noexcept = 0;
    virtual ServiceKind service_kind() const noexcept = 0;
    virtual std::size_t max_write_size() const noexcept = 0;
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
    virtual ~StreamHandler() = default;
    virtual const ProviderDescriptor& descriptor() const noexcept = 0;
    virtual ServiceKind service_kind() const noexcept = 0;

    // The dispatcher calls authorize independently for every OPEN, even when
    // the capability was advertised. It fails closed if this method throws.
    virtual Status authorize(const StreamOpenContext& context) = 0;

    // Invoked without engine locks. The engine contains handler exceptions and
    // closes the corresponding stream rather than corrupting session state.
    virtual void on_open(StreamOpenContext context,
                         std::shared_ptr<StreamResponder> stream) = 0;

    // Invoked only after authorize() succeeds for a destination-bearing OPEN
    // and only when the provider advertises the matching DirectTcp or
    // DirectUdp capability. The request is constructed by SessionEngine, so a
    // RouteProvider never receives raw, pre-policy destination metadata.
    virtual void on_route(AuthorizedRouteRequest request,
                          std::shared_ptr<StreamResponder> stream);
};

}  // namespace yume::engine
