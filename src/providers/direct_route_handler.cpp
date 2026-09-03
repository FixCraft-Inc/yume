/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/direct_route_handler.hpp"

#include <algorithm>
#include <cstddef>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <string_view>
#include <utility>

namespace yume::providers {
namespace {

using engine::AuthorizedRouteRequest;
using engine::Buffer;
using engine::ByteChannel;
using engine::CancellationSource;
using engine::Capability;
using engine::CarrierCredit;
using engine::NetworkProtocol;
using engine::PacketChannel;
using engine::ReceivedRecord;
using engine::Result;
using engine::RouteConnection;
using engine::RouteProvider;
using engine::ServiceKind;
using engine::Status;
using engine::StatusCode;
using engine::StreamResponder;

Status allocation_failure(std::string_view operation) noexcept {
    try {
        return Status(StatusCode::ResourceExhausted, operation);
    } catch (...) {
        return Status(StatusCode::ResourceExhausted);
    }
}

Status provider_failure(std::string_view operation) noexcept {
    try {
        return Status(StatusCode::Internal, operation);
    } catch (...) {
        return Status(StatusCode::Internal);
    }
}

void close_connection(RouteConnection& connection) noexcept {
    if (ByteChannel* channel = connection.byte_channel_if()) {
        channel->cancel();
        channel->close();
    }
    if (PacketChannel* channel = connection.packet_channel_if()) {
        channel->cancel();
        channel->close();
    }
}

bool valid_kind(ServiceKind kind) noexcept {
    switch (kind) {
    case ServiceKind::ByteStream:
    case ServiceKind::PacketChannel:
        return true;
    }
    return false;
}

Capability route_capability(ServiceKind kind) noexcept {
    return kind == ServiceKind::ByteStream
        ? Capability::DirectTcp
        : Capability::DirectUdp;
}

class RouteBridge final : public std::enable_shared_from_this<RouteBridge> {
public:
    RouteBridge(ServiceKind kind,
                std::shared_ptr<RouteProvider> provider,
                std::shared_ptr<StreamResponder> stream) noexcept
        : kind_(kind),
          provider_(std::move(provider)),
          stream_(std::move(stream)) {}

    void start(const AuthorizedRouteRequest& request) noexcept {
        // Reading before egress establishment bounds pre-open buffering to one
        // YTP record and lets session teardown cancel a stalled route open.
        issue_stream_read();

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (terminal_) {
                return;
            }
        }

        try {
            provider_->async_open(
                request, cancellation_.token(),
                [self = shared_from_this()](
                    Result<RouteConnection> result) noexcept {
                    self->complete_open(std::move(result));
                });
        } catch (const std::bad_alloc&) {
            fail(allocation_failure(
                "route-provider open callback allocation failed"));
        } catch (...) {
            fail(provider_failure("route provider threw while opening"));
        }
    }

private:
    struct PendingStreamRecord final {
        explicit PendingStreamRecord(ReceivedRecord record) noexcept
            : payload(std::move(record.payload())),
              credit(record.take_credit()),
              total_size(payload.size()) {}

        Buffer payload;
        CarrierCredit credit;
        std::size_t total_size{0U};
        std::size_t offset{0U};
    };

    void complete_open(Result<RouteConnection> result) noexcept {
        try {
            complete_open_contained(std::move(result));
        } catch (const std::bad_alloc&) {
            fail(allocation_failure(
                "route-open completion allocation failed"));
        } catch (...) {
            fail(provider_failure("route-open completion threw"));
        }
    }

    void complete_open_contained(Result<RouteConnection> result) {
        bool discard = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (terminal_ || open_settled_) {
                discard = true;
            } else {
                open_settled_ = true;
            }
        }
        if (discard) {
            if (result.ok()) {
                RouteConnection connection =
                    std::move(result).take_value();
                close_connection(connection);
            }
            return;
        }
        if (!result.ok()) {
            fail(result.status());
            return;
        }

        RouteConnection connection = std::move(result).take_value();
        if (connection.kind() != kind_) {
            close_connection(connection);
            fail(Status(StatusCode::ProviderMismatch,
                        "route provider returned the wrong channel kind"));
            return;
        }

        ByteChannel* byte_channel = connection.byte_channel_if();
        PacketChannel* packet_channel = connection.packet_channel_if();
        const bool valid_byte =
            kind_ == ServiceKind::ByteStream && byte_channel &&
            byte_channel->executor_affinity().valid() &&
            byte_channel->max_read_size() != 0U &&
            byte_channel->max_write_size() != 0U;
        const bool valid_packet =
            kind_ == ServiceKind::PacketChannel && packet_channel &&
            packet_channel->executor_affinity().valid() &&
            packet_channel->max_packet_size() != 0U &&
            packet_channel->max_packet_size() <=
                engine::kAbsoluteMaxBufferBytes;
        if ((!valid_byte && !valid_packet) ||
            !stream_->executor_affinity().valid() ||
            stream_->service_kind() != kind_ ||
            stream_->max_write_size() == 0U) {
            close_connection(connection);
            fail(Status(StatusCode::ProviderMismatch,
                        "route or stream I/O bounds are invalid"));
            return;
        }

        bool stream_eof = false;
        bool has_pending_record = false;
        bool became_terminal = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (terminal_) {
                became_terminal = true;
            } else {
                if (kind_ == ServiceKind::ByteStream) {
                    byte_channel_ = connection.take_byte_channel();
                } else {
                    packet_channel_ = connection.take_packet_channel();
                }
                route_open_ = true;
                stream_eof = stream_input_eof_;
                has_pending_record = pending_stream_record_.has_value();
            }
        }
        if (became_terminal) {
            close_connection(connection);
            return;
        }

        issue_route_read();
        if (has_pending_record) {
            issue_route_write();
        } else if (stream_eof) {
            propagate_stream_eof();
        }
    }

    void issue_stream_read() noexcept {
        std::shared_ptr<StreamResponder> stream;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (terminal_ || stream_input_eof_ || stream_read_inflight_ ||
                pending_stream_record_.has_value()) {
                return;
            }
            stream_read_inflight_ = true;
            stream = stream_;
        }

        try {
            stream->async_read(
                cancellation_.token(),
                [self = shared_from_this()](
                    Result<ReceivedRecord> result) noexcept {
                    self->complete_stream_read(std::move(result));
                });
        } catch (const std::bad_alloc&) {
            fail(allocation_failure(
                "stream-read callback allocation failed"));
        } catch (...) {
            fail(provider_failure("stream responder threw while reading"));
        }
    }

    void complete_stream_read(Result<ReceivedRecord> result) noexcept {
        try {
            bool route_open = false;
            bool eof = false;
            Status failure = Status::success();
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (!stream_read_inflight_) {
                    return;
                }
                stream_read_inflight_ = false;
                if (terminal_) {
                    return;
                }
                if (!result.ok()) {
                    if (kind_ == ServiceKind::ByteStream &&
                        result.status().code() == StatusCode::Closed) {
                        stream_input_eof_ = true;
                        route_open = route_open_;
                        eof = true;
                    } else {
                        failure = result.status();
                    }
                } else {
                    ReceivedRecord record =
                        std::move(result).take_value();
                    if (record.payload().empty()) {
                        failure = Status(
                            StatusCode::ProviderMismatch,
                            "stream responder returned an empty payload");
                    } else {
                        pending_stream_record_.emplace(std::move(record));
                        route_open = route_open_;
                    }
                }
            }
            if (!failure.ok()) {
                fail(std::move(failure));
            } else if (eof) {
                if (route_open) {
                    propagate_stream_eof();
                }
            } else if (route_open) {
                issue_route_write();
            }
        } catch (const std::bad_alloc&) {
            fail(allocation_failure(
                "stream-read completion allocation failed"));
        } catch (...) {
            fail(provider_failure("stream-read completion threw"));
        }
    }

    void issue_route_write() noexcept {
        ByteChannel* byte_channel = nullptr;
        PacketChannel* packet_channel = nullptr;
        std::size_t chunk_size = 0U;
        std::size_t source_offset = 0U;
        bool whole_payload = false;
        Status preparation_failure = Status::success();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (terminal_ || !route_open_ || route_write_inflight_ ||
                !pending_stream_record_.has_value()) {
                return;
            }
            PendingStreamRecord& pending = *pending_stream_record_;
            if (pending.offset >= pending.total_size) {
                preparation_failure = Status(
                    StatusCode::Internal,
                    "route bridge lost stream payload state");
            } else if (kind_ == ServiceKind::ByteStream) {
                byte_channel = byte_channel_.get();
                chunk_size = std::min(
                    pending.total_size - pending.offset,
                    byte_channel->max_write_size());
            } else {
                packet_channel = packet_channel_.get();
                if (pending.total_size > packet_channel->max_packet_size()) {
                    preparation_failure = Status(
                        StatusCode::ResourceExhausted,
                        "YTP packet exceeds the route-provider packet bound");
                } else {
                    chunk_size = pending.total_size;
                }
            }
            if (preparation_failure.ok() && chunk_size == 0U) {
                preparation_failure = Status(
                    StatusCode::ProviderMismatch,
                    "route provider declared a zero write bound");
            }
            if (preparation_failure.ok()) {
                source_offset = pending.offset;
                whole_payload = source_offset == 0U &&
                                chunk_size == pending.total_size;
                route_write_inflight_ = true;
                route_write_expected_ = chunk_size;
            }
        }
        if (!preparation_failure.ok()) {
            fail(std::move(preparation_failure));
            return;
        }

        Result<Buffer> outbound(Status(
            StatusCode::Internal, "route write payload was not prepared"));
        CarrierCredit terminal_credit;
        if (whole_payload) {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!pending_stream_record_.has_value()) {
                route_write_inflight_ = false;
                return;
            }
            if (terminal_) {
                route_write_inflight_ = false;
                terminal_credit = std::move(
                    pending_stream_record_->credit);
                pending_stream_record_.reset();
            } else {
                outbound = Result<Buffer>(
                    std::move(pending_stream_record_->payload));
            }
        } else {
            try {
                std::lock_guard<std::mutex> lock(mutex_);
                if (!pending_stream_record_.has_value()) {
                    route_write_inflight_ = false;
                    return;
                }
                if (terminal_) {
                    route_write_inflight_ = false;
                    terminal_credit = std::move(
                        pending_stream_record_->credit);
                    pending_stream_record_.reset();
                } else {
                    const auto source =
                        pending_stream_record_->payload.bytes();
                    outbound = Buffer::copy_from(
                        source.subspan(source_offset, chunk_size), chunk_size);
                }
            } catch (const std::bad_alloc&) {
                outbound = Result<Buffer>(allocation_failure(
                    "route write payload allocation failed"));
            }
        }
        terminal_credit.release_now();
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (terminal_) {
                return;
            }
        }
        if (!outbound.ok()) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                route_write_inflight_ = false;
            }
            fail(outbound.status());
            return;
        }

        try {
            if (kind_ == ServiceKind::ByteStream) {
                byte_channel->async_write(
                    std::move(outbound).take_value(), cancellation_.token(),
                    [self = shared_from_this()](
                        Status status, std::size_t transferred) noexcept {
                        self->complete_route_write(
                            std::move(status), transferred);
                    });
            } else {
                packet_channel->async_send(
                    std::move(outbound).take_value(), cancellation_.token(),
                    [self = shared_from_this()](
                        Status status, std::size_t transferred) noexcept {
                        self->complete_route_write(
                            std::move(status), transferred);
                    });
            }
        } catch (const std::bad_alloc&) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                route_write_inflight_ = false;
            }
            fail(allocation_failure(
                "route-write callback allocation failed"));
        } catch (...) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                route_write_inflight_ = false;
            }
            fail(provider_failure("route channel threw while writing"));
        }
    }

    void complete_route_write(Status status,
                              std::size_t transferred) noexcept {
        try {
            CarrierCredit released_credit;
            bool continue_record = false;
            bool read_next = false;
            bool was_terminal = false;
            Status failure = Status::success();
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (!route_write_inflight_) {
                    return;
                }
                route_write_inflight_ = false;
                was_terminal = terminal_;
                if (!pending_stream_record_.has_value()) {
                    if (!was_terminal) {
                        failure = Status(
                            StatusCode::Internal,
                            "route write completed without retained credit");
                    }
                } else if (was_terminal || !status.ok() ||
                           transferred != route_write_expected_) {
                    released_credit = std::move(
                        pending_stream_record_->credit);
                    pending_stream_record_.reset();
                    if (!was_terminal) {
                        failure = status.ok()
                            ? Status(StatusCode::ProviderMismatch,
                                     "route write reported a partial completion")
                            : status;
                    }
                } else {
                    PendingStreamRecord& pending =
                        *pending_stream_record_;
                    pending.offset += route_write_expected_;
                    if (pending.offset == pending.total_size) {
                        released_credit = std::move(pending.credit);
                        pending_stream_record_.reset();
                        read_next = true;
                    } else if (pending.offset < pending.total_size) {
                        continue_record = true;
                    } else {
                        released_credit = std::move(pending.credit);
                        pending_stream_record_.reset();
                        failure = Status(
                            StatusCode::Internal,
                            "route write completion exceeded retained payload");
                    }
                }
            }
            released_credit.release_now();
            if (was_terminal) {
                return;
            }
            if (!failure.ok()) {
                fail(std::move(failure));
            } else if (continue_record) {
                issue_route_write();
            } else if (read_next) {
                issue_stream_read();
            }
        } catch (const std::bad_alloc&) {
            fail(allocation_failure(
                "route-write completion allocation failed"));
        } catch (...) {
            fail(provider_failure("route-write completion threw"));
        }
    }

    void issue_route_read() noexcept {
        ByteChannel* byte_channel = nullptr;
        PacketChannel* packet_channel = nullptr;
        std::size_t max_bytes = 0U;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (terminal_ || !route_open_ || route_input_eof_ ||
                route_read_inflight_ || stream_write_inflight_) {
                return;
            }
            route_read_inflight_ = true;
            if (kind_ == ServiceKind::ByteStream) {
                byte_channel = byte_channel_.get();
                max_bytes = std::min({
                    byte_channel->max_read_size(),
                    stream_->max_write_size(),
                    engine::kAbsoluteMaxBufferBytes});
            } else {
                packet_channel = packet_channel_.get();
            }
        }

        if (kind_ == ServiceKind::ByteStream && max_bytes == 0U) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                route_read_inflight_ = false;
            }
            fail(Status(StatusCode::ProviderMismatch,
                        "route read has no positive common bound"));
            return;
        }

        try {
            if (kind_ == ServiceKind::ByteStream) {
                byte_channel->async_read(
                    max_bytes, cancellation_.token(),
                    [self = shared_from_this()](
                        Result<Buffer> result) noexcept {
                        self->complete_route_read(std::move(result));
                    });
            } else {
                packet_channel->async_receive(
                    cancellation_.token(),
                    [self = shared_from_this()](
                        Result<Buffer> result) noexcept {
                        self->complete_route_read(std::move(result));
                    });
            }
        } catch (const std::bad_alloc&) {
            fail(allocation_failure(
                "route-read callback allocation failed"));
        } catch (...) {
            fail(provider_failure("route channel threw while reading"));
        }
    }

    void complete_route_read(Result<Buffer> result) noexcept {
        try {
            std::shared_ptr<StreamResponder> stream;
            std::optional<Buffer> payload;
            bool eof = false;
            Status failure = Status::success();
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (!route_read_inflight_) {
                    return;
                }
                route_read_inflight_ = false;
                if (terminal_) {
                    return;
                }
                if (!result.ok()) {
                    if (kind_ == ServiceKind::ByteStream &&
                        result.status().code() == StatusCode::Closed) {
                        route_input_eof_ = true;
                        eof = true;
                    } else {
                        failure = result.status();
                    }
                } else if (result.value().empty()) {
                    failure = Status(
                        StatusCode::ProviderMismatch,
                        "route provider returned an empty read");
                } else if (result.value().size() >
                           stream_->max_write_size() ||
                           (kind_ == ServiceKind::PacketChannel &&
                            result.value().size() >
                                packet_channel_->max_packet_size())) {
                    failure = Status(
                        StatusCode::ProviderMismatch,
                        "route read exceeded a declared I/O bound");
                } else {
                    stream_write_inflight_ = true;
                    stream_write_expected_ = result.value().size();
                    payload.emplace(std::move(result).take_value());
                    stream = stream_;
                }
            }
            if (!failure.ok()) {
                fail(std::move(failure));
                return;
            }
            if (eof) {
                propagate_route_eof();
                return;
            }

            try {
                stream->async_write(
                    std::move(*payload), cancellation_.token(),
                    [self = shared_from_this()](
                        Status status, std::size_t transferred) noexcept {
                        self->complete_stream_write(
                            std::move(status), transferred);
                    });
            } catch (const std::bad_alloc&) {
                fail(allocation_failure(
                    "stream-write callback allocation failed"));
            } catch (...) {
                fail(provider_failure(
                    "stream responder threw while writing"));
            }
        } catch (const std::bad_alloc&) {
            fail(allocation_failure(
                "route-read completion allocation failed"));
        } catch (...) {
            fail(provider_failure("route-read completion threw"));
        }
    }

    void complete_stream_write(Status status,
                               std::size_t transferred) noexcept {
        try {
            bool terminal = false;
            Status failure = Status::success();
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (!stream_write_inflight_) {
                    return;
                }
                stream_write_inflight_ = false;
                terminal = terminal_;
                if (!terminal &&
                    (!status.ok() || transferred != stream_write_expected_)) {
                    failure = status.ok()
                        ? Status(StatusCode::ProviderMismatch,
                                 "stream write reported a partial completion")
                        : status;
                }
            }
            if (terminal) {
                return;
            }
            if (!failure.ok()) {
                fail(std::move(failure));
            } else {
                issue_route_read();
            }
        } catch (const std::bad_alloc&) {
            fail(allocation_failure(
                "stream-write completion allocation failed"));
        } catch (...) {
            fail(provider_failure("stream-write completion threw"));
        }
    }

    void propagate_stream_eof() noexcept {
        ByteChannel* channel = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (terminal_ || kind_ != ServiceKind::ByteStream ||
                !route_open_ || route_write_shutdown_) {
                return;
            }
            channel = byte_channel_.get();
            route_write_shutdown_ = true;
        }
        Status status = channel->shutdown_write();
        if (!status.ok()) {
            fail(std::move(status));
            return;
        }
        finish_if_graceful();
    }

    void propagate_route_eof() noexcept {
        std::shared_ptr<StreamResponder> stream;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (terminal_ || kind_ != ServiceKind::ByteStream ||
                stream_write_shutdown_) {
                return;
            }
            stream_write_shutdown_ = true;
            stream = stream_;
        }
        Status status = stream->shutdown_write();
        if (!status.ok()) {
            fail(std::move(status));
            return;
        }
        finish_if_graceful();
    }

    void finish_if_graceful() noexcept {
        ByteChannel* byte_channel = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (terminal_ || !stream_input_eof_ || !route_input_eof_ ||
                !route_write_shutdown_ || !stream_write_shutdown_) {
                return;
            }
            terminal_ = true;
            if (!route_close_issued_) {
                route_close_issued_ = true;
                byte_channel = byte_channel_.get();
            }
        }
        cancellation_.cancel();
        if (byte_channel) {
            byte_channel->close();
        }
    }

    void fail(Status reason) noexcept {
        std::shared_ptr<StreamResponder> stream;
        ByteChannel* byte_channel = nullptr;
        PacketChannel* packet_channel = nullptr;
        CarrierCredit dropped_credit;
        Status close_reason(StatusCode::Internal);
        bool cleanup = false;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!terminal_) {
                if (reason.ok()) {
                    reason = provider_failure(
                        "route bridge failed without an error");
                }
                terminal_ = true;
                terminal_reason_ = std::move(reason);
                failure_needs_cleanup_ = true;
            }
            if (failure_needs_cleanup_) {
                failure_needs_cleanup_ = false;
                cleanup = true;
                stream = stream_;
                if (pending_stream_record_.has_value() &&
                    !route_write_inflight_) {
                    dropped_credit = std::move(
                        pending_stream_record_->credit);
                    pending_stream_record_.reset();
                }
                if (!route_close_issued_) {
                    route_close_issued_ = true;
                    byte_channel = byte_channel_.get();
                    packet_channel = packet_channel_.get();
                }
                close_reason = std::move(terminal_reason_);
            }
        }
        if (!cleanup) {
            return;
        }
        dropped_credit.release_now();
        cancellation_.cancel();
        if (byte_channel) {
            byte_channel->cancel();
            byte_channel->close();
        }
        if (packet_channel) {
            packet_channel->cancel();
            packet_channel->close();
        }
        stream->close(std::move(close_reason));
    }

    ServiceKind kind_;
    std::shared_ptr<RouteProvider> provider_;
    std::shared_ptr<StreamResponder> stream_;
    CancellationSource cancellation_;

    std::mutex mutex_;
    std::unique_ptr<ByteChannel> byte_channel_;
    std::unique_ptr<PacketChannel> packet_channel_;
    std::optional<PendingStreamRecord> pending_stream_record_;
    Status terminal_reason_{StatusCode::Internal,
                            "route bridge did not record a failure"};
    std::size_t route_write_expected_{0U};
    std::size_t stream_write_expected_{0U};
    bool open_settled_{false};
    bool route_open_{false};
    bool stream_read_inflight_{false};
    bool route_write_inflight_{false};
    bool route_read_inflight_{false};
    bool stream_write_inflight_{false};
    bool stream_input_eof_{false};
    bool route_input_eof_{false};
    bool route_write_shutdown_{false};
    bool stream_write_shutdown_{false};
    bool route_close_issued_{false};
    bool terminal_{false};
    bool failure_needs_cleanup_{false};
};

Status validate_composition(
    const engine::ProviderDescriptor& descriptor,
    ServiceKind service_kind,
    const std::shared_ptr<RouteProvider>& route_provider,
    const DirectRouteHandler::AuthorizationPolicy& authorization_policy) {
    if (!valid_kind(service_kind) || !route_provider ||
        !authorization_policy) {
        return Status(StatusCode::InvalidArgument,
                      "direct route handler composition is incomplete");
    }
    const Capability direct = route_capability(service_kind);
    engine::CapabilitySet required_handler =
        engine::mandatory_capabilities(engine::ProviderKind::StreamHandler)
            .with(direct);
    if (service_kind == ServiceKind::PacketChannel) {
        required_handler = required_handler.with(Capability::PacketChannels);
    }
    if (descriptor.kind() != engine::ProviderKind::StreamHandler ||
        !descriptor.capabilities().contains_all(required_handler)) {
        return Status(StatusCode::ProviderMismatch,
                      "stream-handler descriptor lacks direct-route capabilities");
    }
    const engine::ProviderDescriptor& route = route_provider->descriptor();
    if (route.kind() != engine::ProviderKind::RouteProvider ||
        !route.capabilities().contains_all(
            engine::mandatory_capabilities(
                engine::ProviderKind::RouteProvider).with(direct))) {
        return Status(StatusCode::ProviderMismatch,
                      "route provider lacks the required direct-route capability");
    }
    return Status::success();
}

}  // namespace

DirectRouteHandler::DirectRouteHandler(
    engine::ProviderDescriptor descriptor,
    engine::ServiceKind service_kind,
    std::shared_ptr<engine::RouteProvider> route_provider,
    AuthorizationPolicy authorization_policy) noexcept
    : descriptor_(std::move(descriptor)),
      service_kind_(service_kind),
      route_provider_(std::move(route_provider)),
      authorization_policy_(std::move(authorization_policy)) {}

engine::Result<std::shared_ptr<DirectRouteHandler>>
DirectRouteHandler::create(
    engine::ProviderDescriptor descriptor,
    engine::ServiceKind service_kind,
    std::shared_ptr<engine::RouteProvider> route_provider,
    AuthorizationPolicy authorization_policy) {
    const Status validation = validate_composition(
        descriptor, service_kind, route_provider, authorization_policy);
    if (!validation.ok()) {
        return engine::Result<std::shared_ptr<DirectRouteHandler>>(validation);
    }
    try {
        return engine::Result<std::shared_ptr<DirectRouteHandler>>(
            std::shared_ptr<DirectRouteHandler>(new DirectRouteHandler(
                std::move(descriptor), service_kind,
                std::move(route_provider),
                std::move(authorization_policy))));
    } catch (const std::bad_alloc&) {
        return engine::Result<std::shared_ptr<DirectRouteHandler>>(
            Status(StatusCode::ResourceExhausted,
                   "direct route handler allocation failed"));
    }
}

const engine::ProviderDescriptor&
DirectRouteHandler::descriptor() const noexcept {
    return descriptor_;
}

engine::ServiceKind DirectRouteHandler::service_kind() const noexcept {
    return service_kind_;
}

engine::Status DirectRouteHandler::authorize(
    const engine::StreamOpenContext& context) {
    if (context.service_kind() != service_kind_ ||
        !context.destination_if()) {
        return Status(StatusCode::InvalidArgument,
                      "direct route requires a matching typed destination");
    }
    const NetworkProtocol expected =
        service_kind_ == ServiceKind::ByteStream
        ? NetworkProtocol::Tcp
        : NetworkProtocol::Udp;
    if (context.destination_if()->protocol() != expected) {
        return Status(StatusCode::InvalidArgument,
                      "direct route protocol does not match service kind");
    }
    try {
        return authorization_policy_(context);
    } catch (const std::bad_alloc&) {
        return allocation_failure("route authorization allocation failed");
    } catch (...) {
        return provider_failure("route authorization policy threw");
    }
}

void DirectRouteHandler::on_open(
    engine::StreamOpenContext,
    std::shared_ptr<engine::StreamResponder> stream) {
    if (stream) {
        stream->close(Status(
            StatusCode::FailedPrecondition,
            "direct route handler requires destination metadata"));
    }
}

void DirectRouteHandler::on_route(
    engine::AuthorizedRouteRequest request,
    std::shared_ptr<engine::StreamResponder> stream) {
    if (!stream) {
        return;
    }
    const NetworkProtocol expected =
        service_kind_ == ServiceKind::ByteStream
        ? NetworkProtocol::Tcp
        : NetworkProtocol::Udp;
    if (stream->service_kind() != service_kind_ ||
        request.destination().protocol() != expected) {
        stream->close(Status(
            StatusCode::ProviderMismatch,
            "authorized route does not match the handler kind"));
        return;
    }

    try {
        auto bridge = std::make_shared<RouteBridge>(
            service_kind_, route_provider_, stream);
        bridge->start(request);
    } catch (const std::bad_alloc&) {
        stream->close(allocation_failure(
            "route bridge allocation failed"));
    } catch (...) {
        stream->close(provider_failure(
            "route bridge construction threw"));
    }
}

}  // namespace yume::providers
