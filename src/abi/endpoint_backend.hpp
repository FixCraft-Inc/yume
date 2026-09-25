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
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace yume::config::v1 {
class Config;
}  // namespace yume::config::v1

// The embedding seam. A consumer of YUME, whether the C ABI or another
// binding, drives a transport through these interfaces and never through the
// provider or runtime headers directly.
//
// Composing the native endpoint is the embedding layer's job. Keeping it here
// leaves the ABI shell free of any runtime and gives a future non-C binding
// the same entry point.
//
// The YTP/1 backend in yume_embed_ytp1 implements it by composing the native
// endpoint, without BaseFWX. The seam and the public ABI candidate are
// unfrozen and change together with their callers and tests.
namespace yume::embed {

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
    BufferTooSmall,
    AlreadyRunning,
    // The configuration requests something this backend does not compose.
    Unsupported,
    // A provider or suite does not match the frozen composition.
    Incompatible,
    // A requested listening address belongs to another live socket.
    AddressInUse,
    Failed,
};

enum class BackendServiceKind {
    ByteStream,
    Packet,
};

// One application registration, already checked against the service-name
// grammar by the caller.
struct BackendService {
    std::string name;
    BackendServiceKind kind{BackendServiceKind::ByteStream};
};

enum class BackendAddressKind {
    Hostname,
    Ipv4,
    Ipv6,
};

// The ABI validates the address spelling before handing an owned destination
// to a backend. Hostnames are resolved and authorized by the remote endpoint.
struct BackendDestination {
    BackendAddressKind kind;
    std::string host;
    std::uint16_t port;
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

inline constexpr std::size_t kMaxPacketBatch = 256U;
inline constexpr std::size_t kMaxPacketBytes = 65535U;
inline constexpr std::size_t kMaxPacketBatchBytes = 16U * 1024U * 1024U;

struct BackendPacketView {
    const void* data;
    std::size_t size;
};

struct BackendPacketSlot {
    std::size_t offset;
    std::size_t size;
};

class BackendPacket {
public:
    virtual ~BackendPacket() = default;
    // One reader and one writer may run concurrently. Writes copy and admit
    // the whole batch or none. Received packets retain credit until copied;
    // BufferTooSmall leaves the first packet queued and reports its size.
    virtual BackendIo write(std::span<const BackendPacketView> packets,
                            std::uint32_t timeout_ms, std::string& error) = 0;
    virtual BackendIo read(void* storage, std::size_t storage_size,
                           std::span<BackendPacketSlot> slots,
                           std::uint32_t timeout_ms, std::size_t& packets_read,
                           std::size_t& required_storage, std::string& error) = 0;
    virtual void publish() noexcept = 0;
    virtual void close() noexcept = 0;
    virtual BackendPeerIdentity peer_identity() const = 0;
};

using SocketProtector = std::function<bool(std::intptr_t)>;

class EndpointBackend {
public:
    virtual ~EndpointBackend() = default;

    // Blocking start bounded by timeout_ms, where 0 means the backend's own
    // default. Anything other than Ok populates `error`. The outcome is
    // typed because a refused bind and a transient failure are different
    // answers to an embedder, and neither may be recovered from the text.
    virtual BackendIo start(std::uint32_t timeout_ms, std::string& error) = 0;

    // Idempotent, must not throw, and must be safe from the destructor.
    virtual void stop() noexcept = 0;

    virtual bool running() const noexcept = 0;

    // Client roles open, server roles accept. A backend that cannot perform
    // the direction asked of it returns Invalid rather than blocking.
    virtual BackendIo open_stream(const std::string& service,
                                  const std::optional<BackendDestination>& destination,
                                  std::uint32_t timeout_ms,
                                  std::unique_ptr<BackendStream>& out,
                                  std::string& error) = 0;

    virtual BackendIo accept_stream(const std::string& service,
                                    std::uint32_t timeout_ms,
                                    std::unique_ptr<BackendStream>& out,
                                    std::string& error) = 0;

    virtual BackendIo open_packet(const std::string& service,
                                  const std::optional<BackendDestination>& destination,
                                  std::uint32_t timeout_ms,
                                  std::unique_ptr<BackendPacket>& out,
                                  std::string& error) = 0;
    virtual BackendIo accept_packet(const std::string& service,
                                    std::uint32_t timeout_ms,
                                    std::unique_ptr<BackendPacket>& out,
                                    std::string& error) = 0;
};

// Creates an unstarted YTP/1 backend for a parsed schema-1 configuration.
// Only a server registers services, and each registration must name a
// service the configuration declares. Relative credential references resolve
// against `base_dir`. `resolver_program` is the SystemResolver helper for a
// transport host that is a name, and empty leaves such a host unresolvable.
std::unique_ptr<EndpointBackend> make_ytp1_backend(
    const config::v1::Config& config,
    std::string_view base_dir,
    std::string_view resolver_program,
    std::vector<BackendService> registered_services,
    SocketProtector socket_protector,
    BackendIo& outcome,
    std::string& error);

// Identity of the key-holding YTP/1 session-security implementation.
std::string_view ytp1_session_security_provider() noexcept;

// Identity of the cryptographic library that implementation runs on, such as
// "openssl-3.5.7".
std::string_view ytp1_crypto_backend() noexcept;

}  // namespace yume::embed
