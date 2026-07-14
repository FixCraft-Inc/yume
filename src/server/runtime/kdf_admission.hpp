/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <memory>
#include <optional>
#include <string>

namespace yume::server {

struct KdfAdmissionLimits {
    std::size_t argon2_memory_budget_kib{0};
    std::size_t argon2_max_jobs{0};
};

struct KdfAdmissionSnapshot {
    std::size_t admitted_argon2_memory_kib{0};
    std::size_t admitted_argon2_jobs{0};
};

// Server-instance-wide admission accounting for expensive KDF work.
// Admission is immediate and fail-closed so an Asio worker is never blocked
// behind an unbounded handshake queue.
class KdfAdmissionController {
private:
    struct State;

public:
    class Lease {
    public:
        Lease() = default;
        ~Lease();

        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&& other) noexcept;
        Lease& operator=(Lease&& other) noexcept;

        explicit operator bool() const noexcept { return static_cast<bool>(state_); }

    private:
        friend class KdfAdmissionController;
        Lease(std::shared_ptr<State> state, std::size_t memory_kib);
        void release() noexcept;

        std::shared_ptr<State> state_;
        std::size_t memory_kib_{0};
    };

    explicit KdfAdmissionController(KdfAdmissionLimits limits);

    std::optional<Lease> try_acquire_argon2(std::size_t memory_kib,
                                            std::string* reason = nullptr);
    KdfAdmissionSnapshot snapshot() const;
    KdfAdmissionLimits limits() const;

private:
    std::shared_ptr<State> state_;
};

}  // namespace yume::server
