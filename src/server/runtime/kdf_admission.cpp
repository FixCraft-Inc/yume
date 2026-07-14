/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/runtime/kdf_admission.hpp"

#include <mutex>
#include <stdexcept>
#include <utility>

namespace yume::server {

struct KdfAdmissionController::State {
    explicit State(KdfAdmissionLimits configured_limits)
        : limits(configured_limits) {}

    const KdfAdmissionLimits limits;
    mutable std::mutex mutex;
    std::size_t admitted_memory_kib{0};
    std::size_t admitted_jobs{0};
};

KdfAdmissionController::Lease::Lease(std::shared_ptr<State> state,
                                     std::size_t memory_kib)
    : state_(std::move(state)), memory_kib_(memory_kib) {}

KdfAdmissionController::Lease::~Lease() {
    release();
}

KdfAdmissionController::Lease::Lease(Lease&& other) noexcept
    : state_(std::move(other.state_)), memory_kib_(other.memory_kib_) {
    other.memory_kib_ = 0;
}

KdfAdmissionController::Lease& KdfAdmissionController::Lease::operator=(
    Lease&& other) noexcept {
    if (this != &other) {
        release();
        state_ = std::move(other.state_);
        memory_kib_ = other.memory_kib_;
        other.memory_kib_ = 0;
    }
    return *this;
}

void KdfAdmissionController::Lease::release() noexcept {
    if (!state_) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(state_->mutex);
        state_->admitted_memory_kib -= memory_kib_;
        --state_->admitted_jobs;
    }
    state_.reset();
    memory_kib_ = 0;
}

KdfAdmissionController::KdfAdmissionController(KdfAdmissionLimits limits)
    : state_(std::make_shared<State>(limits)) {
    if (limits.argon2_memory_budget_kib == 0 || limits.argon2_max_jobs == 0) {
        throw std::invalid_argument("Argon2 admission limits must be positive");
    }
}

std::optional<KdfAdmissionController::Lease>
KdfAdmissionController::try_acquire_argon2(std::size_t memory_kib,
                                           std::string* reason) {
    if (memory_kib == 0) {
        if (reason) *reason = "Argon2 memory reservation must be positive";
        return std::nullopt;
    }

    std::lock_guard<std::mutex> lock(state_->mutex);
    const auto memory_budget_kib = state_->limits.argon2_memory_budget_kib;
    if (memory_kib > memory_budget_kib ||
        state_->admitted_memory_kib > memory_budget_kib - memory_kib) {
        if (reason) *reason = "aggregate Argon2 memory budget exhausted";
        return std::nullopt;
    }
    if (state_->admitted_jobs >= state_->limits.argon2_max_jobs) {
        if (reason) *reason = "concurrent Argon2 job limit reached";
        return std::nullopt;
    }

    state_->admitted_memory_kib += memory_kib;
    ++state_->admitted_jobs;
    if (reason) reason->clear();
    return Lease(state_, memory_kib);
}

KdfAdmissionSnapshot KdfAdmissionController::snapshot() const {
    std::lock_guard<std::mutex> lock(state_->mutex);
    return {state_->admitted_memory_kib, state_->admitted_jobs};
}

KdfAdmissionLimits KdfAdmissionController::limits() const {
    return state_->limits;
}

}  // namespace yume::server
