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
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
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
// The YTP/1 backend in yume_embed implements it by composing the native
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

// Lets another thread end one start that is still in progress. The caller
// of start() makes one per attempt and keeps it reachable for the thread
// that cancels. The backend arms it once the attempt can be ended and
// disarms it before start() returns.
class StartCancellation final {
public:
    // Any thread, any number of times. The hook runs once, on the first call
    // that finds it armed.
    void cancel() noexcept {
        std::function<void()> hook;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            cancelled_ = true;
            hook = std::move(hook_);
            hook_ = nullptr;
        }
        run(hook);
    }

    bool cancelled() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return cancelled_;
    }

    // Runs hook at once when cancel() came first.
    void arm(std::function<void()> hook) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!cancelled_) {
                hook_ = std::move(hook);
                return;
            }
        }
        run(hook);
    }

    void disarm() noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        hook_ = nullptr;
    }

private:
    static void run(const std::function<void()>& hook) noexcept {
        if (!hook) return;
        try {
            hook();
        } catch (...) {
        }
    }

    mutable std::mutex mutex_;
    bool cancelled_{false};
    std::function<void()> hook_;
};

enum class BackendSession {
    None,
    Active,
    // The client's session ended while the endpoint stayed started.
    Ended,
    // A client that keeps its session up: an attempt is in flight, or it
    // waits before the next one.
    Connecting,
    Waiting,
};

struct BackendTraffic {
    std::uint64_t payload_bytes_sent{0U};
    std::uint64_t payload_bytes_received{0U};
    std::uint64_t record_bytes_sent{0U};
    std::uint64_t record_bytes_received{0U};
};

// A point-in-time view of one backend. It holds no secret material.
struct BackendStatus {
    BackendSession session{BackendSession::None};
    // Set while the session is active.
    std::uint64_t connected_ms{0U};
    std::uint32_t epoch_bytes{0U};
    // Lowercase hex of the server's verified identity, or empty.
    std::string peer_fingerprint_sha256;
    // Totals over every session this backend has had.
    BackendTraffic traffic;
    // The latest ended session or failed attempt since the backend last
    // started, or Ok when there has been none.
    BackendIo failure{BackendIo::Ok};
    std::string failure_message;
    // A client that keeps its session up: sessions authenticated since it
    // started, failed attempts since the latest of them, and the delay
    // before the next attempt while it waits.
    std::uint64_t sessions{0U};
    std::uint32_t failed_attempts{0U};
    std::uint64_t retry_ms{0U};
    // What a device bridge carries now.
    std::uint32_t device_tcp_connections{0U};
    std::uint32_t device_udp_destinations{0U};
};

// One line of a backend's message feed, or none.
struct BackendMessage {
    // Zero when no kept line is numbered above the requested point.
    std::uint64_t seq{0U};
    // Lines numbered above that point and below seq that are no longer kept.
    std::uint64_t missed{0U};
    std::int64_t time_unix_ms{0};
    std::string text;
    std::string instance;
};

// A TUN device whose traffic a client carries (docs/ABI.md, "Device
// bridge"). The descriptor stays the caller's, which keeps it open while a
// backend made with it exists.
struct BackendDevice {
    int descriptor{-1};
    std::uint32_t mtu{0U};
    std::string stream_service;
    std::string packet_service;
    // IP literals. An empty pair leaves that family out.
    std::string ipv4_address;
    std::string ipv4_peer;
    std::string ipv6_address;
    std::string ipv6_peer;
};

class EndpointBackend {
public:
    virtual ~EndpointBackend() = default;

    // Blocking start bounded by timeout_ms, where 0 means the backend's own
    // default. Anything other than Ok populates `error`. The outcome is
    // typed because a refused bind and a transient failure are different
    // answers to an embedder, and neither may be recovered from the text.
    // cancellation ends a client start early from another thread. The caller
    // tells a cancelled start from a failed one by asking cancellation.
    virtual BackendIo start(
        std::uint32_t timeout_ms,
        const std::shared_ptr<StartCancellation>& cancellation,
        std::string& error) = 0;

    // Idempotent, must not throw, and must be safe from the destructor.
    virtual void stop() noexcept = 0;

    virtual bool running() const noexcept = 0;

    // Callable from any thread, during a start included. Neither waits for
    // a lifecycle call.
    virtual BackendStatus status() const = 0;
    // The oldest kept line numbered above `after`.
    virtual BackendMessage message_after(std::uint64_t after) const = 0;
    // A client that keeps its session up and waits to retry starts that
    // attempt now. Ok when it did or had nothing to wait for, NotRunning
    // when the backend is not started, Invalid when it keeps no session.
    virtual BackendIo retry_now() noexcept = 0;

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
// With a device, a client keeps its session up as yume does and carries the
// device's traffic while it is started.
std::unique_ptr<EndpointBackend> make_native_backend(
    const config::v1::Config& config, std::string_view base_dir,
    std::string_view resolver_program,
    std::vector<BackendService> registered_services,
    SocketProtector socket_protector,
    const std::optional<BackendDevice>& device, BackendIo& outcome,
    std::string& error);

// Whether a device suits a configuration: Ok, Unsupported for a server or a
// platform without the bridge, NotFound for a service the configuration does
// not declare with the kind the bridge opens, and Invalid for anything else,
// with `error` saying what.
BackendIo check_backend_device(const config::v1::Config& config,
                               const BackendDevice& device, std::string& error);

// The files of one opened sealed kit. Destruction wipes them.
struct BackendKitFile {
    std::string_view path;
    std::span<const std::uint8_t> bytes;
    bool executable{false};
};

class BackendKit {
public:
    virtual ~BackendKit() = default;
    virtual std::size_t file_count() const noexcept = 0;
    // index is below file_count(). The views stay valid for the kit's life.
    virtual BackendKitFile file(std::size_t index) const noexcept = 0;
};

enum class BackendKitOutcome {
    Ok,
    // The code is not 25 code characters.
    BadCode,
    // Larger than a sealed kit can be.
    TooLarge,
    // The code is wrong or the bytes are not a sealed kit.
    Refused,
    // The code opened the bytes, but they do not hold a valid kit.
    Malformed,
    Exhausted,
    Failed,
};

// Opens a sealed kit (docs/protocol/SEALED_KIT_1.md) in memory. typed_code
// is the code as a user typed it. Anything but Ok returns no kit and
// populates `error`.
std::unique_ptr<BackendKit> open_sealed_kit(
    std::span<const std::uint8_t> sealed, std::string_view typed_code,
    BackendKitOutcome& outcome, std::string& error);

// Identity of the key-holding YTP/1 session-security implementation.
std::string_view security_provider_identity() noexcept;

// Identity of the cryptographic library that implementation runs on, such as
// "openssl-3.5.7".
std::string_view crypto_backend_identity() noexcept;

}  // namespace yume::embed
