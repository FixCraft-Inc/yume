/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yume::server::detail {

// Admission and lifetime registry for unauthenticated HTTP/2 cover requests.
//
// A slot remains held after the loopback fetch completes until the H2 stream
// closes. This bounds both active backend work and response bodies retained by
// peer flow control. A connection can retain at most four 8-MiB bodies, while
// H2Carrier's stricter 32-MiB aggregate output limit remains the final cap; the
// process limit bounds the corresponding response bodies at 256 MiB.
class H2CoverFetches {
public:
    static constexpr std::size_t kPerConnectionLimit = 4;
    static constexpr std::size_t kProcessLimit = 32;
    static constexpr std::size_t kPerConnectionOutputLimit =
        32U * 1024U * 1024U;
    static constexpr std::size_t kProcessOutputLimit =
        256U * 1024U * 1024U;

    H2CoverFetches()
        : connection_(std::make_shared<ConnectionState>()) {}

    H2CoverFetches(const H2CoverFetches&) = delete;
    H2CoverFetches& operator=(const H2CoverFetches&) = delete;

    ~H2CoverFetches() {
        const auto retained = connection_->output_bytes.exchange(
            0U, std::memory_order_relaxed);
        if (retained != 0U) {
            process_output_bytes_.fetch_sub(retained,
                                            std::memory_order_relaxed);
        }
    }

    bool admit(std::int32_t stream_id) {
        if (stream_id <= 0 || entries_.find(stream_id) != entries_.end()) {
            return false;
        }
        auto permit = Permit::TryAcquire(connection_);
        if (!permit.has_value()) {
            return false;
        }
        return entries_.try_emplace(stream_id, std::move(*permit)).second;
    }

    // Attach the cancellation action after starting the asynchronous fetch.
    // The session strand serializes attach/complete/close calls.
    bool attach_cancel(std::int32_t stream_id, std::function<void()> cancel) {
        auto it = entries_.find(stream_id);
        if (it == entries_.end() || it->second.fetch_complete ||
            it->second.cancel) {
            return false;
        }
        it->second.cancel = std::move(cancel);
        return true;
    }

    // The backend callback may race a peer reset. A missing entry means the
    // reset/connection-close path already cancelled and released the request.
    bool complete_fetch(std::int32_t stream_id) {
        auto it = entries_.find(stream_id);
        if (it == entries_.end() || it->second.fetch_complete) {
            return false;
        }
        it->second.fetch_complete = true;
        it->second.cancel = {};
        return true;
    }

    bool close_stream(std::int32_t stream_id) {
        auto it = entries_.find(stream_id);
        if (it == entries_.end()) {
            return false;
        }
        auto cancel = std::move(it->second.cancel);
        entries_.erase(it);
        if (cancel) {
            cancel();
        }
        return true;
    }

    void cancel_all() {
        std::vector<std::function<void()>> cancellations;
        cancellations.reserve(entries_.size());
        for (auto& [_, entry] : entries_) {
            if (entry.cancel) {
                cancellations.push_back(std::move(entry.cancel));
            }
        }
        entries_.clear();
        // Invoke only after erasing. A cancellation callback is allowed to
        // complete synchronously and re-enter complete_fetch().
        for (auto& cancel : cancellations) {
            cancel();
        }
    }

    std::size_t size() const noexcept { return entries_.size(); }

    // Bytes already serialized out of H2 are no longer covered by the
    // carrier's 32-MiB queue cap. Keep a second lifetime budget until the TLS
    // write actually completes so malicious WINDOW_UPDATE + RST cycling cannot
    // turn the frame-count write queue into a multi-gigabyte byte queue.
    bool reserve_output_bytes(std::size_t bytes) noexcept {
        if (bytes == 0U) {
            return true;
        }
        if (!TryAdd(connection_->output_bytes, bytes,
                    kPerConnectionOutputLimit)) {
            return false;
        }
        if (!TryAdd(process_output_bytes_, bytes, kProcessOutputLimit)) {
            connection_->output_bytes.fetch_sub(bytes,
                                                std::memory_order_relaxed);
            return false;
        }
        return true;
    }

    bool release_output_bytes(std::size_t bytes) noexcept {
        if (bytes == 0U) {
            return true;
        }
        if (!TrySubtract(process_output_bytes_, bytes)) {
            return false;
        }
        if (!TrySubtract(connection_->output_bytes, bytes)) {
            process_output_bytes_.fetch_add(bytes, std::memory_order_relaxed);
            return false;
        }
        return true;
    }

    std::size_t output_bytes() const noexcept {
        return connection_->output_bytes.load(std::memory_order_relaxed);
    }

private:
    struct ConnectionState {
        std::atomic<std::size_t> in_flight{0};
        std::atomic<std::size_t> output_bytes{0};
    };

    static bool TryAdd(std::atomic<std::size_t>& counter,
                       std::size_t add,
                       std::size_t limit) noexcept {
        if (add > limit) {
            return false;
        }
        std::size_t current = counter.load(std::memory_order_relaxed);
        while (current <= limit - add) {
            if (counter.compare_exchange_weak(
                    current, current + add, std::memory_order_relaxed,
                    std::memory_order_relaxed)) {
                return true;
            }
        }
        return false;
    }

    static bool TrySubtract(std::atomic<std::size_t>& counter,
                            std::size_t amount) noexcept {
        std::size_t current = counter.load(std::memory_order_relaxed);
        while (current >= amount) {
            if (counter.compare_exchange_weak(
                    current, current - amount, std::memory_order_relaxed,
                    std::memory_order_relaxed)) {
                return true;
            }
        }
        return false;
    }

    class Permit {
    public:
        Permit() = default;
        Permit(const Permit&) = delete;
        Permit& operator=(const Permit&) = delete;

        Permit(Permit&& other) noexcept
            : connection_(std::move(other.connection_)), held_(other.held_) {
            other.held_ = false;
        }

        Permit& operator=(Permit&& other) noexcept {
            if (this != &other) {
                release();
                connection_ = std::move(other.connection_);
                held_ = other.held_;
                other.held_ = false;
            }
            return *this;
        }

        ~Permit() { release(); }

        static std::optional<Permit> TryAcquire(
            const std::shared_ptr<ConnectionState>& connection) {
            if (!TryIncrement(connection->in_flight, kPerConnectionLimit)) {
                return std::nullopt;
            }
            if (!TryIncrement(process_in_flight_, kProcessLimit)) {
                connection->in_flight.fetch_sub(1, std::memory_order_relaxed);
                return std::nullopt;
            }
            return Permit(connection);
        }

    private:
        explicit Permit(std::shared_ptr<ConnectionState> connection)
            : connection_(std::move(connection)), held_(true) {}

        static bool TryIncrement(std::atomic<std::size_t>& counter,
                                 std::size_t limit) noexcept {
            std::size_t current = counter.load(std::memory_order_relaxed);
            while (current < limit) {
                if (counter.compare_exchange_weak(
                        current, current + 1, std::memory_order_relaxed,
                        std::memory_order_relaxed)) {
                    return true;
                }
            }
            return false;
        }

        void release() noexcept {
            if (!held_) {
                return;
            }
            held_ = false;
            connection_->in_flight.fetch_sub(1, std::memory_order_relaxed);
            process_in_flight_.fetch_sub(1, std::memory_order_relaxed);
            connection_.reset();
        }

        std::shared_ptr<ConnectionState> connection_;
        bool held_{false};
    };

    struct Entry {
        explicit Entry(Permit permit_in) : permit(std::move(permit_in)) {}

        Permit permit;
        std::function<void()> cancel;
        bool fetch_complete{false};
    };

    inline static std::atomic<std::size_t> process_in_flight_{0};
    inline static std::atomic<std::size_t> process_output_bytes_{0};

    std::shared_ptr<ConnectionState> connection_;
    std::unordered_map<std::int32_t, Entry> entries_;
};

}  // namespace yume::server::detail
