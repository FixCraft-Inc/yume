/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

namespace yume::embed::detail {

// A client service OPEN crosses four ownership boundaries: a locally reserved
// id, registered callbacks, a remotely visible OPEN, and a published C handle.
// The callback is deliberately a noexcept function pointer so constructing the
// guard immediately after reservation cannot itself allocate or throw.
class ServiceOpenTransaction final {
public:
    enum class Phase {
        reserved,
        registered,
        open_started,
        accepted,
        rejected,
        published,
    };

    using Rollback = void (*)(void*, Phase) noexcept;

    enum class RollbackAction {
        release_reservation,
        unregister,
        close_and_retire,
        none,
    };

    static constexpr RollbackAction ActionFor(Phase phase) noexcept {
        switch (phase) {
        case Phase::reserved:
            return RollbackAction::release_reservation;
        case Phase::registered:
        case Phase::rejected:
            return RollbackAction::unregister;
        case Phase::open_started:
        case Phase::accepted:
            return RollbackAction::close_and_retire;
        case Phase::published:
            return RollbackAction::none;
        }
        return RollbackAction::close_and_retire;
    }

    ServiceOpenTransaction(void* context, Rollback rollback) noexcept
        : context_(context), rollback_(rollback) {}

    ServiceOpenTransaction(const ServiceOpenTransaction&) = delete;
    ServiceOpenTransaction& operator=(const ServiceOpenTransaction&) = delete;

    ~ServiceOpenTransaction() noexcept {
        if (phase_ != Phase::published && rollback_) {
            rollback_(context_, phase_);
        }
    }

    void MarkRegistered() noexcept { phase_ = Phase::registered; }
    void MarkOpenStarted() noexcept { phase_ = Phase::open_started; }
    void MarkAccepted() noexcept { phase_ = Phase::accepted; }
    void MarkRejected() noexcept { phase_ = Phase::rejected; }
    void Publish() noexcept { phase_ = Phase::published; }

private:
    void* context_{nullptr};
    Rollback rollback_{nullptr};
    Phase phase_{Phase::reserved};
};

}  // namespace yume::embed::detail
