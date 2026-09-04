/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

// The embedding seam. A consumer of YUME, whether the C ABI or another
// binding, drives a transport through these interfaces and never through the
// client, server, or core headers directly.
//
// This lives in yume_embed rather than in the ABI because reaching a tunnel,
// a runtime controller, and a service stream is the embedding layer's job.
// Putting it here keeps the ABI shell free of any runtime and gives a future
// non-C binding the same entry point.
//
// Exactly one backend exists today: the runnable transport-v2 product. The
// YTP/1 replacement will add a second one behind the same interface, and the
// swap must not change one public symbol.
namespace yume::embed {

// A parsed, role-tagged transport configuration. The concrete type stays in
// the backend translation unit so no transport-v2 header reaches the shell.
class BackendConfig {
public:
    virtual ~BackendConfig() = default;
    virtual bool is_server() const noexcept = 0;
};

// Transport outcomes, kept independent of the public status enum so the seam
// stays a runtime boundary rather than a second copy of the C header.
enum class BackendIo {
    Ok,
    Eof,
    Timeout,
    WouldBlock,
    Closed,
    Invalid,
    NotRunning,
    NotFound,
    PermissionDenied,
    ResourceExhausted,
    Failed,
};

struct BackendPeerIdentity {
    std::string service;
    // Opaque transport label. It carries no application meaning.
    std::string peer_label;
    // Lowercase hex, empty when the transport did not authenticate one.
    std::string fingerprint_sha256;
    bool authenticated{false};
    bool peer_is_server{false};
};

class BackendStream {
public:
    virtual ~BackendStream() = default;

    // Reads may be partial. Eof means the peer shut down its write side after
    // every buffered byte was returned.
    virtual BackendIo read(void* out,
                           std::size_t capacity,
                           std::uint32_t timeout_ms,
                           std::size_t& bytes_read,
                           std::string& error) = 0;

    // Copies the complete input before returning Ok. Admission is all or
    // none, so a partial write is never reported.
    virtual BackendIo write(const void* data,
                            std::size_t size,
                            std::uint32_t timeout_ms,
                            std::string& error) = 0;

    // Blocks until accepted writes have drained, so it takes a deadline.
    virtual BackendIo shutdown_write(std::uint32_t timeout_ms,
                                     std::string& error) = 0;
    // A client OPEN is not externally committed until its embedding handle
    // exists. Implementations keep rollback armed until this call.
    virtual void publish() noexcept = 0;
    virtual void close() noexcept = 0;
    virtual BackendPeerIdentity peer_identity() const = 0;
};

using SocketProtector = std::function<bool(std::intptr_t)>;

class EndpointBackend {
public:
    virtual ~EndpointBackend() = default;

    // Blocking start bounded by timeout_ms, where 0 means the backend's own
    // default. Returns false with `error` populated on failure.
    virtual bool start(std::uint32_t timeout_ms, std::string& error) = 0;

    // Idempotent, must not throw, and must be safe from the destructor.
    virtual void stop() noexcept = 0;

    virtual bool running() const noexcept = 0;

    // Advertises a service the peer may open. Server roles only.
    virtual BackendIo register_service(const std::string& service,
                                       std::string& error) = 0;

    // Client roles open, server roles accept. A backend that cannot perform
    // the direction asked of it returns Invalid rather than blocking.
    virtual BackendIo open_stream(const std::string& service,
                                  std::uint32_t timeout_ms,
                                  std::unique_ptr<BackendStream>& out,
                                  std::string& error) = 0;

    virtual BackendIo accept_stream(const std::string& service,
                                    std::uint32_t timeout_ms,
                                    std::unique_ptr<BackendStream>& out,
                                    std::string& error) = 0;
};

// Parses the transport-v2 configuration dialect. Returns nullptr with `error`
// populated when the document is not valid for the requested role. Relative
// credential paths resolve against `base_dir`.
std::unique_ptr<BackendConfig> parse_transport_v2_config(
    std::string_view json,
    bool is_server,
    std::string_view base_dir,
    std::string& error);

// Creates an unstarted backend for an already-parsed configuration.
std::unique_ptr<EndpointBackend> make_transport_v2_backend(
    const BackendConfig& config,
    SocketProtector socket_protector,
    std::string& error);

}  // namespace yume::embed
