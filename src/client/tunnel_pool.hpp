#pragma once

#include <atomic>
#include <cstddef>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "client/tunnel.hpp"

namespace yume::client {

// A small load-balancing pool of Tunnel instances. The first tunnel
// added is the "primary" — the existing control / relay / activity
// handlers stay wired to it. All tunnels (including the primary)
// participate in `pick_for_session()` so the SOCKS5 acceptor can spread
// new sessions across the full pool, lifting the single-tunnel
// throughput cap.
//
// Each SocksSession binds to exactly one tunnel at acceptance time and
// holds onto it for its lifetime, so stream IDs stay scoped to a
// single TLS connection (no cross-tunnel routing). When the picked
// tunnel dies, the session dies with it; new sessions pick a fresh
// live tunnel from whatever survives in the pool.
//
// Lifetime: TunnelPool itself does not own the io_context the tunnels
// run on — it only holds shared_ptrs to keep them alive while the
// SOCKS server is up. Stop the pool from the CLI top-level when
// disconnecting; this calls Tunnel::stop on every member.
class TunnelPool : public std::enable_shared_from_this<TunnelPool> {
public:
    // Picker policy. Round-robin avoids burst skew on a cold pool;
    // least-loaded prevents a long-running stream on tunnel[0] from
    // hogging while tunnel[1..3] sit idle.
    enum class Policy {
        RoundRobin,
        LeastLoaded,
    };

    explicit TunnelPool(Policy policy = Policy::LeastLoaded);

    // Add a tunnel to the pool. The first call is treated as the
    // primary (only relevant to the caller; the pool itself doesn't
    // distinguish — it's just a member of the round). Must be called
    // before sessions start; not safe to call concurrently with
    // pick_for_session().
    void add(std::shared_ptr<Tunnel> tunnel);

    // Pick a tunnel for a new session. Returns nullptr if the pool is
    // empty. Increments the chosen tunnel's session count; pair with
    // release_session() when the session closes so least-loaded stays
    // accurate.
    std::shared_ptr<Tunnel> pick_for_session();

    // Decrement the chosen tunnel's session count. Safe to call with a
    // tunnel that's no longer in the pool (e.g. it died and was
    // removed): the call is a no-op in that case.
    void release_session(const std::shared_ptr<Tunnel>& tunnel);

    // Stop every tunnel. Called from the CLI top-level on disconnect.
    void stop_all(const std::string& reason);

    // Number of tunnels currently in the pool (regardless of state).
    std::size_t size() const noexcept;

    // Diagnostic snapshot, for logging.
    struct Snapshot {
        std::size_t tunnel_count{0};
        std::size_t total_sessions{0};
        std::vector<std::size_t> sessions_per_tunnel;
    };
    Snapshot snapshot() const;

private:
    struct Entry {
        std::shared_ptr<Tunnel> tunnel;
        std::atomic<std::size_t> active_sessions{0};
        Entry() = default;
        Entry(std::shared_ptr<Tunnel> t) : tunnel(std::move(t)) {}
    };

    Policy policy_;
    mutable std::mutex mu_;
    std::vector<std::unique_ptr<Entry>> entries_;
    std::atomic<std::size_t> round_robin_cursor_{0};
};

}  // namespace yume::client
