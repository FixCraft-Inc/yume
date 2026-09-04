/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <deque>
#include <functional>
#include <list>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "core/runtime/inbound_credit.hpp"
#include "core/runtime/stream_queue_limits.hpp"

namespace yume::runtime {

inline constexpr std::size_t kMaxServiceWriteBytes = 256U * 1024U;
inline constexpr std::size_t kMaxServiceQueuedWriteFrames = 64U;
inline constexpr std::size_t kMaxServiceQueuedWriteBytes = 4U * 1024U * 1024U;

struct ServicePeerInfo {
    std::string service;
    std::string peer;
    std::string auth_fingerprint_sha256;
    std::string session_id;
    std::string server_session_id;
    std::string remote_addr;
};

class ServiceStream {
public:
    using Bytes = std::vector<std::uint8_t>;
    using WriteCompletion = std::function<void(bool, std::string)>;
    enum class WriteResult {
        Accepted,
        WouldBlock,
        Timeout,
        Closed,
        Invalid,
        Failed,
    };
    using WriteCallback = std::function<WriteResult(
        Bytes, std::uint32_t, WriteCompletion, std::string*)>;
    using WriteWaitAllowedCallback = std::function<bool()>;
    using CloseCallback = std::function<void(std::string)>;

    enum class ReadResult {
        Data,
        Eof,
        Timeout,
        Closed,
    };
    enum class ShutdownWriteResult {
        Sent,
        WouldBlock,
        Timeout,
        Closed,
        Failed,
    };

    ServiceStream(std::string service, std::string peer);
    ServiceStream(std::string service, std::string peer, ServicePeerInfo peer_info);
    ~ServiceStream();

    ServiceStream(const ServiceStream&) = delete;
    ServiceStream& operator=(const ServiceStream&) = delete;

    const std::string& service() const noexcept;
    const std::string& peer() const noexcept;
    ServicePeerInfo peer_info() const;

    void set_callbacks(WriteCallback write_cb,
                       CloseCallback close_cb,
                       CloseCallback shutdown_write_cb,
                       WriteWaitAllowedCallback write_wait_allowed_cb = {});

    WriteResult write(const void* data,
                      std::size_t size,
                      std::uint32_t timeout_ms,
                      std::string* error);
    // Not safe to call concurrently with write() on the same stream from
    // another thread: the drain wait releases the state lock, so a write that
    // starts in that window is not covered. The C ABI serializes both calls on
    // one handle, so an embedder is unaffected; an internal caller must not
    // interleave them.
    //
    // Sends the write-side FIN, but only after every accepted write has
    // drained. `write()` returns Accepted when the transport admits a frame,
    // not when it reaches the wire, so an unordered FIN can overtake the last
    // record and silently truncate a request/response exchange. Waits up to
    // timeout_ms for the drain; 0 means do not wait. The typed result keeps a
    // busy poll, an expired deadline, a failed accepted write, and a transport
    // callback failure distinct across embedding boundaries.
    ShutdownWriteResult shutdown_write(
        std::string* error, std::uint32_t timeout_ms = 5000);
    void close(std::string reason);

    ReadResult read(void* out,
                    std::size_t capacity,
                    std::uint32_t timeout_ms,
                    std::size_t* bytes_read,
                    std::string* reason);

    bool receive_data(Bytes data, std::string* error = nullptr);
    bool receive_data(Bytes data,
                      InboundCredit inbound_credit,
                      std::string* error = nullptr);
    void receive_fin(std::string reason);
    void receive_close(std::string reason, bool discard_buffered = false);

    bool closed() const;

private:
    std::string service_;
    std::string peer_;
    ServicePeerInfo peer_info_;

    mutable std::mutex mu_;
    std::condition_variable cv_;
    struct InboundItem {
        Bytes data;
        InboundCredit credit;
    };

    std::deque<InboundItem> incoming_;
    InboundQueueBudget inbound_budget_;
    Bytes current_;
    InboundCredit current_credit_;
    std::size_t current_offset_{0};
    bool remote_fin_{false};
    bool remote_closed_{false};
    bool local_closed_{false};
    bool local_fin_sent_{false};
    bool local_fin_sending_{false};
    std::string close_reason_;

    WriteCallback write_cb_;
    CloseCallback close_cb_;
    CloseCallback shutdown_write_cb_;
    WriteWaitAllowedCallback write_wait_allowed_cb_;

    struct OutboundState {
        std::mutex mutex;
        std::condition_variable cv;
        std::uint64_t active_write{0};
        std::uint64_t next_write{0};
        bool closed{false};
        std::string close_reason;
    };
    std::shared_ptr<OutboundState> outbound_state_{
        std::make_shared<OutboundState>()};
};

// Serializes publication of a newly-created service handle with terminal
// Session shutdown. A successful Permit holds the gate until the caller has
// made every externally-visible publication; stop() first rejects new permits
// and then waits for the current permit, if any, to leave that transaction.
class ServiceStreamAdmissionGate {
public:
    class Permit {
    public:
        Permit() = default;
        Permit(Permit&&) noexcept = default;
        Permit& operator=(Permit&&) noexcept = default;

        Permit(const Permit&) = delete;
        Permit& operator=(const Permit&) = delete;

        explicit operator bool() const noexcept {
            return lock_.owns_lock();
        }

    private:
        friend class ServiceStreamAdmissionGate;
        explicit Permit(std::mutex& mutex)
            : lock_(mutex) {}

        std::unique_lock<std::mutex> lock_;
    };

    ServiceStreamAdmissionGate() = default;
    ServiceStreamAdmissionGate(const ServiceStreamAdmissionGate&) = delete;
    ServiceStreamAdmissionGate& operator=(
        const ServiceStreamAdmissionGate&) = delete;

    Permit try_acquire();
    void stop() noexcept;
    bool stopping() const noexcept;

private:
    std::atomic<bool> stopping_{false};
    std::mutex mutex_;
};

// Per-transport admission queue for server-accepted ServiceStream writes.
// A complete payload is owned by this bounded FIFO before enqueue() reports
// Accepted, and its frame/byte reservation remains live until finish() sees
// the eventual transport disposition. The owner drains one entry at a time on
// its strand; callers may wait for capacity without ever blocking that strand.
class ServiceWriteAdmissionQueue {
public:
    using Bytes = ServiceStream::Bytes;
    using Completion = ServiceStream::WriteCompletion;
    using Cancelled = std::function<bool()>;

    enum class AdmissionResult {
        Accepted,
        WouldBlock,
        Timeout,
        Stopped,
        Invalid,
    };

    struct Entry {
        std::uint64_t sequence{0};
        std::uint8_t stream_id{0};
        Bytes payload;
        Completion completion;
    };

    explicit ServiceWriteAdmissionQueue(
        std::size_t max_frames = kMaxServiceQueuedWriteFrames,
        std::size_t max_bytes = kMaxServiceQueuedWriteBytes);

    ServiceWriteAdmissionQueue(const ServiceWriteAdmissionQueue&) = delete;
    ServiceWriteAdmissionQueue& operator=(
        const ServiceWriteAdmissionQueue&) = delete;

    AdmissionResult enqueue(
        std::uint8_t stream_id,
        Bytes&& payload,
        std::chrono::milliseconds timeout,
        Completion completion,
        const Cancelled& cancelled,
        bool* needs_dispatch,
        std::string* reason = nullptr);

    // Consumes the single scheduled wake and starts exactly one FIFO entry.
    std::optional<Entry> take_next();

    // Releases only the matching in-flight reservation. A stale/duplicate
    // completion is ignored and therefore cannot release a later write.
    bool finish(std::uint64_t sequence,
                bool* needs_dispatch = nullptr) noexcept;

    // Pending entries are completed as failed outside the queue lock. An
    // already-dispatched entry retains its transport-owned completion path.
    bool cancel_stream(std::uint8_t stream_id,
                       std::string reason) noexcept;
    void stop(std::string reason) noexcept;
    void notify_waiters() noexcept;

    std::size_t outstanding_frames() const noexcept;
    std::size_t outstanding_bytes() const noexcept;
    bool stopped() const noexcept;

private:
    bool capacity_available(std::size_t bytes) const noexcept;
    bool cancellation_requested(const Cancelled& cancelled) const noexcept;
    bool schedule_if_ready_locked() noexcept;
    static void fail_entries(std::list<Entry> entries,
                             const std::string& reason) noexcept;

    const std::size_t max_frames_;
    const std::size_t max_bytes_;
    mutable std::mutex mutex_;
    std::condition_variable capacity_cv_;
    std::list<Entry> pending_;
    std::size_t outstanding_frames_{0};
    std::size_t outstanding_bytes_{0};
    std::uint64_t next_sequence_{0};
    std::uint64_t in_flight_sequence_{0};
    std::size_t in_flight_bytes_{0};
    bool in_flight_{false};
    bool dispatch_scheduled_{false};
    bool stopped_{false};
    std::string stop_reason_;
};

}  // namespace yume::runtime
