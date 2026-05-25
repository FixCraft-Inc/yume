#include "client/tunnel_pool.hpp"

#include <algorithm>
#include <limits>

namespace yume::client {

TunnelPool::TunnelPool(Policy policy) : policy_(policy) {}

void TunnelPool::add(std::shared_ptr<Tunnel> tunnel) {
    if (!tunnel) {
        return;
    }
    std::lock_guard<std::mutex> lock(mu_);
    entries_.push_back(std::make_unique<Entry>(std::move(tunnel)));
}

std::shared_ptr<Tunnel> TunnelPool::pick_for_session() {
    std::lock_guard<std::mutex> lock(mu_);
    if (entries_.empty()) {
        return nullptr;
    }
    Entry* chosen = nullptr;
    if (policy_ == Policy::RoundRobin) {
        const std::size_t idx = round_robin_cursor_.fetch_add(1) % entries_.size();
        chosen = entries_[idx].get();
    } else {
        // Least-loaded: linear scan over a small pool (N <= 16) is
        // fine; the alternative (heap / sorted index) would add
        // complexity that buys nothing at this size.
        std::size_t best_load = std::numeric_limits<std::size_t>::max();
        for (auto& entry : entries_) {
            const std::size_t load = entry->active_sessions.load();
            if (load < best_load) {
                best_load = load;
                chosen = entry.get();
            }
        }
    }
    if (chosen == nullptr) {
        return nullptr;
    }
    chosen->active_sessions.fetch_add(1);
    return chosen->tunnel;
}

void TunnelPool::release_session(const std::shared_ptr<Tunnel>& tunnel) {
    if (!tunnel) {
        return;
    }
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& entry : entries_) {
        if (entry->tunnel == tunnel) {
            // saturate at 0; a defensive guard against double-release.
            std::size_t current = entry->active_sessions.load();
            while (current > 0 &&
                   !entry->active_sessions.compare_exchange_weak(current, current - 1)) {
                // retry
            }
            return;
        }
    }
}

void TunnelPool::stop_all(const std::string& reason) {
    std::vector<std::shared_ptr<Tunnel>> to_stop;
    {
        std::lock_guard<std::mutex> lock(mu_);
        to_stop.reserve(entries_.size());
        for (auto& entry : entries_) {
            to_stop.push_back(entry->tunnel);
        }
    }
    // Stop outside the lock — Tunnel::stop runs handler callbacks
    // synchronously, and one of them might try to call back into the
    // pool (e.g. via the close_handler path).
    for (auto& tunnel : to_stop) {
        if (tunnel) {
            tunnel->stop(reason);
        }
    }
}

std::size_t TunnelPool::size() const noexcept {
    std::lock_guard<std::mutex> lock(mu_);
    return entries_.size();
}

TunnelPool::Snapshot TunnelPool::snapshot() const {
    std::lock_guard<std::mutex> lock(mu_);
    Snapshot snap;
    snap.tunnel_count = entries_.size();
    snap.sessions_per_tunnel.reserve(entries_.size());
    for (auto& entry : entries_) {
        const std::size_t load = entry->active_sessions.load();
        snap.sessions_per_tunnel.push_back(load);
        snap.total_sessions += load;
    }
    return snap;
}

}  // namespace yume::client
