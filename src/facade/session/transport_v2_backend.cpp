/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/session/endpoint_backend.hpp"

#include <chrono>
#include <filesystem>
#include <mutex>
#include <utility>

#include <nlohmann/json.hpp>

#include "facade/session/service_open_transaction.hpp"
#include "facade/session/service_open_wait.hpp"
#include "client/transport/runtime_lifetime.hpp"
#include "client/transport/tunnel.hpp"
#include "core/runtime/operation_status.hpp"
#include "core/runtime/service_stream.hpp"
#include "facade/config/config_io.hpp"
#include "facade/session/inproc_client.hpp"
#include "server/runtime/controller.hpp"

namespace yume::embed {
namespace {

// Bounded so an embedder that passes 0 still gets a start that terminates.
constexpr std::chrono::milliseconds kDefaultStartWait{30000};

std::string join_report(
    const facade::config_io::ValidationReport& report) {
    std::string joined;
    for (const std::string& error : report.errors) {
        if (!joined.empty()) joined += "; ";
        joined += error;
    }
    return joined.empty() ? std::string("configuration is not valid") : joined;
}

class ClientBackendConfig final : public BackendConfig {
public:
    explicit ClientBackendConfig(client::ClientConfig value)
        : value_(std::move(value)) {}

    bool is_server() const noexcept override { return false; }
    const client::ClientConfig& value() const noexcept { return value_; }

private:
    client::ClientConfig value_;
};

class ServerBackendConfig final : public BackendConfig {
public:
    explicit ServerBackendConfig(server::ServerConfig value)
        : value_(std::move(value)) {}

    bool is_server() const noexcept override { return true; }
    const server::ServerConfig& value() const noexcept { return value_; }

private:
    server::ServerConfig value_;
};

// Machine-readable outcomes must survive the seam. Never recover one of these
// from the human-readable diagnostic text.
BackendIo backend_io_from(runtime::OperationStatus status) noexcept {
    switch (status) {
    case runtime::OperationStatus::Success:
        return BackendIo::Ok;
    case runtime::OperationStatus::InvalidArgument:
    case runtime::OperationStatus::ParseError:
        return BackendIo::Invalid;
    case runtime::OperationStatus::NotRunning:
        return BackendIo::NotRunning;
    case runtime::OperationStatus::Timeout:
        return BackendIo::Timeout;
    case runtime::OperationStatus::WouldBlock:
        return BackendIo::WouldBlock;
    case runtime::OperationStatus::NotFound:
    case runtime::OperationStatus::PermissionDenied:
    case runtime::OperationStatus::AlreadyRunning:
    case runtime::OperationStatus::ResourceExhausted:
    case runtime::OperationStatus::InternalError:
        return BackendIo::Failed;
    }
    return BackendIo::Failed;
}

// One adapter serves both roles: ServiceStream already owns framing, credit,
// half-close, and queue bounds, so the ABI never re-implements them.
class ServiceBackendStream final : public BackendStream {
public:
    explicit ServiceBackendStream(
        std::shared_ptr<runtime::ServiceStream> stream)
        : stream_(std::move(stream)) {}

    ~ServiceBackendStream() override { close(); }

    BackendIo read(void* out,
                   std::size_t capacity,
                   std::uint32_t timeout_ms,
                   std::size_t& bytes_read,
                   std::string& error) override {
        bytes_read = 0;
        std::string reason;
        const auto result =
            stream_->read(out, capacity, timeout_ms, &bytes_read, &reason);
        switch (result) {
        case runtime::ServiceStream::ReadResult::Data:
            return BackendIo::Ok;
        case runtime::ServiceStream::ReadResult::Eof:
            return BackendIo::Eof;
        case runtime::ServiceStream::ReadResult::Timeout:
            return BackendIo::Timeout;
        case runtime::ServiceStream::ReadResult::Closed:
            error = reason;
            return BackendIo::Closed;
        }
        error = reason.empty() ? "unknown stream read result" : reason;
        return BackendIo::Failed;
    }

    BackendIo write(const void* data,
                    std::size_t size,
                    std::uint32_t timeout_ms,
                    std::string& error) override {
        const auto result = stream_->write(data, size, timeout_ms, &error);
        switch (result) {
        case runtime::ServiceStream::WriteResult::Accepted:
            return BackendIo::Ok;
        case runtime::ServiceStream::WriteResult::WouldBlock:
            return BackendIo::WouldBlock;
        case runtime::ServiceStream::WriteResult::Timeout:
            return BackendIo::Timeout;
        case runtime::ServiceStream::WriteResult::Closed:
            return BackendIo::Closed;
        case runtime::ServiceStream::WriteResult::Invalid:
            return BackendIo::Invalid;
        case runtime::ServiceStream::WriteResult::Failed:
            return BackendIo::Failed;
        }
        return BackendIo::Failed;
    }

    BackendIo shutdown_write(std::uint32_t timeout_ms,
                             std::string& error) override {
        // The FIN must follow every accepted write, so this can block and
        // therefore honours the caller's deadline.
        return stream_->shutdown_write(&error, timeout_ms) ? BackendIo::Ok
                                                           : BackendIo::Failed;
    }

    void close() noexcept override {
        try {
            stream_->close("ABI stream closed");
        } catch (...) {
        }
    }

    BackendPeerIdentity peer_identity() const override {
        const runtime::ServicePeerInfo info = stream_->peer_info();
        BackendPeerIdentity identity;
        identity.service = info.service;
        identity.peer_label = info.peer;
        identity.fingerprint_sha256 = info.auth_fingerprint_sha256;
        // The transport only publishes a fingerprint once composite
        // authentication succeeded, so its presence is the authentication
        // signal rather than a separate self-reported flag.
        identity.authenticated = !info.auth_fingerprint_sha256.empty();
        return identity;
    }

private:
    std::shared_ptr<runtime::ServiceStream> stream_;
};

struct ClientOpenRollback {
    client::Tunnel* tunnel{nullptr};
    std::shared_ptr<runtime::ServiceStream>* stream{nullptr};
    std::uint8_t stream_id{0};
};

// Restored from the 0.2 ABI unchanged in behaviour: a client OPEN crosses four
// ownership boundaries and every one of them has to be undone in the right
// order, or a late ACK can alias a later stream on the same transport.
void rollback_client_open(
        void* opaque,
        detail::ServiceOpenTransaction::Phase phase) noexcept {
    using Phase = detail::ServiceOpenTransaction::Phase;
    using RollbackAction = detail::ServiceOpenTransaction::RollbackAction;
    auto* context = static_cast<ClientOpenRollback*>(opaque);
    if (!context || !context->tunnel || context->stream_id == 0) return;

    // A ServiceStream destructor normally invokes its transport close
    // callback. Disconnect it first so this transaction stays the only owner
    // of rollback and cannot send a second CLOSE during stack unwind.
    if (context->stream && *context->stream) {
        try {
            (*context->stream)->set_callbacks({}, {}, {});
            (*context->stream)->receive_close("stream OPEN rolled back");
        } catch (...) {
        }
    }

    const auto action = detail::ServiceOpenTransaction::ActionFor(phase);
    if (action == RollbackAction::release_reservation) {
        try {
            context->tunnel->release_reserved_stream(context->stream_id);
        } catch (...) {
        }
        return;
    }
    if (action == RollbackAction::unregister) {
        try {
            context->tunnel->unregister_stream(context->stream_id);
        } catch (...) {
        }
        return;
    }
    if (action == RollbackAction::none) return;

    // Once OPEN construction starts, conservatively assume it may have been
    // queued. Retire the id even if sending CLOSE fails.
    try {
        context->tunnel->send_close(
            context->stream_id,
            phase == Phase::accepted ? "stream handle publication failed"
                                     : "stream open aborted");
    } catch (...) {
    }
    try {
        context->tunnel->retire_stream_id(context->stream_id);
    } catch (...) {
    }
}

class ClientBackend final : public EndpointBackend {
public:
    explicit ClientBackend(client::ClientConfig config)
        : config_(std::move(config)) {}

    // The worker thread must be joined before the runtime is destroyed, and a
    // caller is allowed to drop the handle without stopping first.
    ~ClientBackend() override { stop(); }

    bool start(std::uint32_t timeout_ms, std::string& error) override {
        const auto wait = timeout_ms == 0U
            ? kDefaultStartWait
            : std::chrono::milliseconds(timeout_ms);
        std::lock_guard<std::mutex> lock(mutex_);
        return client_.start(config_, &error, wait);
    }

    void stop() noexcept override {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            client_.stop(nullptr, "ABI endpoint stopping");
        } catch (...) {
            // stop() is reached from the destructor and from a noexcept ABI
            // boundary. There is nowhere to report a teardown failure.
        }
    }

    bool running() const noexcept override {
        try {
            return client_.running();
        } catch (...) {
            return false;
        }
    }

    BackendIo register_service(const std::string&, std::string& error) override {
        error = "a client endpoint does not register services";
        return BackendIo::Invalid;
    }

    BackendIo open_stream(const std::string& service,
                          std::uint32_t timeout_ms,
                          std::unique_ptr<BackendStream>& out,
                          std::string& error) override {
        out.reset();
        if (timeout_ms == 0U) {
            error = "stream OPEN requires a positive deadline";
            return BackendIo::Invalid;
        }
        auto runtime_access = client_.acquire_runtime();
        if (!runtime_access) {
            error = "client runtime is not running";
            return BackendIo::NotRunning;
        }
        const auto lifetime_gate = runtime_access->gate();
        auto tunnel = runtime_access->tunnel();
        if (!tunnel || !tunnel->is_alive()) {
            error = "client tunnel is not running";
            return BackendIo::NotRunning;
        }

        std::shared_ptr<runtime::ServiceStream> stream;
        ClientOpenRollback rollback{tunnel.get(), &stream, 0};
        const std::uint8_t stream_id = tunnel->reserve_stream_id();
        if (stream_id == 0) {
            error = "no stream ids available";
            return BackendIo::Failed;
        }
        rollback.stream_id = stream_id;
        detail::ServiceOpenTransaction open_transaction(&rollback,
                                                        rollback_client_open);

        stream = std::make_shared<runtime::ServiceStream>(service, "server");
        auto open_wait = std::make_shared<detail::ServiceOpenWait>();
        std::weak_ptr<detail::ServiceOpenWait> weak_open_wait = open_wait;
        std::weak_ptr<client::Tunnel> weak_tunnel = tunnel;

        stream->set_callbacks(
            [weak_tunnel, lifetime_gate, stream_id](
                runtime::ServiceStream::Bytes data,
                std::uint32_t write_timeout_ms,
                runtime::ServiceStream::WriteCompletion completion,
                std::string* write_error) {
                using Admission = client::TransportCore::DataWriteAdmission;
                using Result = runtime::ServiceStream::WriteResult;
                client::RuntimeLifetimeGate::Lease lease;
                if (lifetime_gate) {
                    lease = lifetime_gate->try_acquire();
                    if (!lease) {
                        if (write_error) *write_error = "client runtime is stopping";
                        return Result::Closed;
                    }
                }
                auto locked = weak_tunnel.lock();
                if (!locked || !locked->is_alive()) {
                    if (write_error) *write_error = "client tunnel is closed";
                    return Result::Closed;
                }
                const auto admission = locked->wait_send_data(
                    stream_id, std::move(data),
                    std::chrono::milliseconds(write_timeout_ms),
                    [completion = std::move(completion)](
                        bool ok, std::size_t, const std::string& reason) mutable {
                        if (completion) completion(ok, reason);
                    });
                switch (admission) {
                case Admission::accepted:
                    return Result::Accepted;
                case Admission::would_block:
                    if (write_error) *write_error = "service write would block";
                    return Result::WouldBlock;
                case Admission::timeout:
                    if (write_error) *write_error = "service write deadline expired";
                    return Result::Timeout;
                case Admission::stopped:
                    if (write_error) *write_error = "client transport stopped";
                    return Result::Closed;
                case Admission::invalid:
                    if (write_error) *write_error = "service write is too large";
                    return Result::Invalid;
                }
                if (write_error) *write_error = "unknown service write admission";
                return Result::Failed;
            },
            [weak_tunnel, lifetime_gate, stream_id](std::string reason) {
                auto lease = lifetime_gate ? lifetime_gate->try_acquire()
                                           : client::RuntimeLifetimeGate::Lease{};
                if (lifetime_gate && !lease) return;
                if (auto locked = weak_tunnel.lock()) {
                    locked->send_close(stream_id, reason);
                    locked->unregister_stream(stream_id);
                }
            },
            [weak_tunnel, lifetime_gate, stream_id](std::string reason) {
                auto lease = lifetime_gate ? lifetime_gate->try_acquire()
                                           : client::RuntimeLifetimeGate::Lease{};
                if (lifetime_gate && !lease) return;
                if (auto locked = weak_tunnel.lock()) {
                    locked->send_stream_fin(stream_id, reason);
                }
            });

        const bool registered = tunnel->register_stream(
            stream_id,
            [stream, weak_tunnel, lifetime_gate, stream_id](
                const client::Tunnel::Bytes& data,
                client::Tunnel::InboundCredit inbound_credit) {
                std::string queue_error;
                client::Tunnel::Bytes owned(data.begin(), data.end());
                if (stream->receive_data(std::move(owned),
                                         std::move(inbound_credit),
                                         &queue_error)) {
                    return;
                }
                const std::string reason = queue_error.empty()
                    ? "service inbound queue overflow"
                    : "service inbound queue overflow: " + queue_error;
                stream->receive_close(reason, true);
                auto lease = lifetime_gate ? lifetime_gate->try_acquire()
                                           : client::RuntimeLifetimeGate::Lease{};
                if (lifetime_gate && !lease) return;
                if (auto locked = weak_tunnel.lock()) {
                    locked->send_close(stream_id, reason);
                    locked->unregister_stream(stream_id);
                }
            },
            [stream, weak_tunnel, weak_open_wait, lifetime_gate, stream_id](
                const std::string& reason) {
                // Tunnel shutdown clears pending OPEN handlers but still
                // invokes registered stream-close handlers, so settling the
                // waiter here is what wakes both a stop and a disconnect.
                if (auto wait = weak_open_wait.lock()) wait->cancel(reason);
                stream->receive_close(reason);
                auto lease = lifetime_gate ? lifetime_gate->try_acquire()
                                           : client::RuntimeLifetimeGate::Lease{};
                if (lifetime_gate && !lease) return;
                if (auto locked = weak_tunnel.lock()) {
                    locked->unregister_stream(stream_id);
                }
            },
            [stream](const std::string& reason) { stream->receive_fin(reason); });
        if (!registered) {
            if (!tunnel->is_alive()) {
                error = "client tunnel stopped while registering stream";
                return BackendIo::NotRunning;
            }
            error = "reserved stream registration failed";
            return BackendIo::Failed;
        }
        open_transaction.MarkRegistered();

        open_transaction.MarkOpenStarted();
        tunnel->open_relay_stream(
            stream_id,
            nlohmann::json{{"proto", "service.v1"}, {"service", service}},
            [open_wait](bool ok, const std::string& reason) {
                open_wait->complete(ok, reason);
            });

        const auto open_result =
            open_wait->wait_for(std::chrono::milliseconds(timeout_ms));
        using Outcome = detail::ServiceOpenWait::Outcome;
        if (open_result.outcome != Outcome::accepted) {
            if (open_result.outcome == Outcome::timed_out) {
                error = "stream open timed out";
                return BackendIo::Timeout;
            }
            open_transaction.MarkRejected();
            if (open_result.outcome == Outcome::cancelled) {
                error = open_result.reason.empty()
                    ? "client tunnel closed while opening stream"
                    : open_result.reason;
                return BackendIo::NotRunning;
            }
            error = open_result.reason.empty() ? "stream open rejected"
                                               : open_result.reason;
            return BackendIo::Closed;
        }

        open_transaction.MarkAccepted();
        // Keep `stream` populated until Publish(): the rollback context points
        // at it, so an allocation failure here can still detach the
        // unpublished stream before the transport is closed and retired.
        out = std::make_unique<ServiceBackendStream>(stream);
        open_transaction.Publish();
        return BackendIo::Ok;
    }

    BackendIo accept_stream(const std::string&,
                            std::uint32_t,
                            std::unique_ptr<BackendStream>& out,
                            std::string& error) override {
        out.reset();
        error = "a client endpoint does not accept streams";
        return BackendIo::Invalid;
    }

private:
    mutable std::mutex mutex_;
    client::ClientConfig config_;
    facade::InProcClient client_;
};

// The server uses RuntimeController rather than facade::ServerSession because
// only the controller exposes service registration and stream accept.
class ServerBackend final : public EndpointBackend {
public:
    explicit ServerBackend(server::ServerConfig config)
        : config_(std::move(config)) {}

    ~ServerBackend() override { stop(); }

    bool start(std::uint32_t /*timeout_ms*/, std::string& error) override {
        // Listener setup already bounds itself and takes no caller deadline.
        std::lock_guard<std::mutex> lock(mutex_);
        return controller_.start(config_, &error);
    }

    void stop() noexcept override {
        try {
            std::lock_guard<std::mutex> lock(mutex_);
            controller_.stop();
        } catch (...) {
        }
    }

    bool running() const noexcept override {
        try {
            return controller_.running();
        } catch (...) {
            return false;
        }
    }

    BackendIo register_service(const std::string& service,
                               std::string& error) override {
        if (!controller_.running()) {
            error = "server runtime is not running";
            return BackendIo::NotRunning;
        }
        return controller_.register_service(service, &error) ? BackendIo::Ok
                                                             : BackendIo::Failed;
    }

    BackendIo open_stream(const std::string&,
                          std::uint32_t,
                          std::unique_ptr<BackendStream>& out,
                          std::string& error) override {
        out.reset();
        // A server-initiated OPEN is a separate reviewed capability, not an
        // accident of symmetry. It stays refused until that review happens.
        error = "a server endpoint does not open streams";
        return BackendIo::Invalid;
    }

    BackendIo accept_stream(const std::string& service,
                            std::uint32_t timeout_ms,
                            std::unique_ptr<BackendStream>& out,
                            std::string& error) override {
        out.reset();
        if (!controller_.running()) {
            error = "server runtime is not running";
            return BackendIo::NotRunning;
        }
        auto operation_status = runtime::OperationStatus::Success;
        auto stream = controller_.accept_service_stream(
            service, timeout_ms, &error, &operation_status);
        if (!stream) {
            return backend_io_from(operation_status);
        }
        out = std::make_unique<ServiceBackendStream>(std::move(stream));
        return BackendIo::Ok;
    }

private:
    mutable std::mutex mutex_;
    server::ServerConfig config_;
    server::RuntimeController controller_;
};

}  // namespace

std::unique_ptr<BackendConfig> parse_transport_v2_config(
    std::string_view json,
    bool is_server,
    std::string_view base_dir,
    std::string& error) {
    // The ABI receives bytes, not a file, so relative credential paths have
    // to resolve against something explicit rather than silently against
    // whatever the embedder's working directory happens to be at parse time.
    const std::filesystem::path base{std::string(base_dir)};
    try {
        if (is_server) {
            auto parsed = facade::config_io::parse_server_json(
                json, base, &error);
            if (!parsed) return nullptr;
            const auto report = facade::config_io::validate(*parsed);
            if (!report.ok()) {
                error = join_report(report);
                return nullptr;
            }
            return std::make_unique<ServerBackendConfig>(std::move(*parsed));
        }
        auto parsed = facade::config_io::parse_client_json(json, base, &error);
        if (!parsed) return nullptr;
        const auto report = facade::config_io::validate(*parsed);
        if (!report.ok()) {
            error = join_report(report);
            return nullptr;
        }
        return std::make_unique<ClientBackendConfig>(std::move(*parsed));
    } catch (const std::exception& thrown) {
        error = thrown.what();
        return nullptr;
    } catch (...) {
        error = "configuration parsing failed";
        return nullptr;
    }
}

std::unique_ptr<EndpointBackend> make_transport_v2_backend(
    const BackendConfig& config,
    std::string& error) {
    try {
        if (config.is_server()) {
            const auto* typed = dynamic_cast<const ServerBackendConfig*>(&config);
            if (typed == nullptr) {
                error = "configuration handle does not carry a server config";
                return nullptr;
            }
            return std::make_unique<ServerBackend>(typed->value());
        }
        const auto* typed = dynamic_cast<const ClientBackendConfig*>(&config);
        if (typed == nullptr) {
            error = "configuration handle does not carry a client config";
            return nullptr;
        }
        return std::make_unique<ClientBackend>(typed->value());
    } catch (const std::exception& thrown) {
        error = thrown.what();
        return nullptr;
    } catch (...) {
        error = "endpoint backend construction failed";
        return nullptr;
    }
}

}  // namespace yume::embed
