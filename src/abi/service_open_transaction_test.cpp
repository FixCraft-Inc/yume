/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "abi/service_open_transaction.hpp"

#include <iostream>
#include <stdexcept>

namespace {

using Transaction = yume::abi::detail::ServiceOpenTransaction;

struct RollbackRecord {
    int calls{0};
    Transaction::Phase phase{Transaction::Phase::published};
    Transaction::RollbackAction action{Transaction::RollbackAction::none};
};

void RecordRollback(void* opaque, Transaction::Phase phase) noexcept {
    auto* record = static_cast<RollbackRecord*>(opaque);
    ++record->calls;
    record->phase = phase;
    record->action = Transaction::ActionFor(phase);
}

enum class InjectAfter {
    reservation,
    registration,
    open_start,
    acceptance,
    publication,
    rejection,
};

RollbackRecord InjectFailure(InjectAfter boundary) {
    RollbackRecord record;
    try {
        Transaction transaction(&record, RecordRollback);
        if (boundary == InjectAfter::reservation) {
            throw std::runtime_error("injected after reservation");
        }
        transaction.MarkRegistered();
        if (boundary == InjectAfter::registration) {
            throw std::runtime_error("injected after registration");
        }
        transaction.MarkOpenStarted();
        if (boundary == InjectAfter::open_start) {
            throw std::runtime_error("injected after OPEN start");
        }
        if (boundary == InjectAfter::rejection) {
            transaction.MarkRejected();
            throw std::runtime_error("injected after rejection");
        }
        transaction.MarkAccepted();
        if (boundary == InjectAfter::acceptance) {
            throw std::runtime_error("injected after acceptance");
        }
        transaction.Publish();
        if (boundary == InjectAfter::publication) {
            throw std::runtime_error("injected after publication");
        }
    } catch (const std::runtime_error&) {
    }
    return record;
}

}  // namespace

int main() {
    const auto require = [](bool condition, const char* message) {
        if (!condition) {
            std::cerr << "FAIL: " << message << '\n';
            return false;
        }
        return true;
    };

    const auto reserved = InjectFailure(InjectAfter::reservation);
    if (!require(reserved.calls == 1, "reservation rollback call count") ||
        !require(reserved.phase == Transaction::Phase::reserved,
                 "reservation rollback phase") ||
        !require(
            reserved.action ==
                Transaction::RollbackAction::release_reservation,
            "reservation rollback action")) {
        return 1;
    }

    const auto registered = InjectFailure(InjectAfter::registration);
    if (!require(registered.calls == 1, "registration rollback call count") ||
        !require(registered.phase == Transaction::Phase::registered,
                 "registration rollback phase") ||
        !require(registered.action == Transaction::RollbackAction::unregister,
                 "registration rollback action")) {
        return 1;
    }

    const auto opening = InjectFailure(InjectAfter::open_start);
    if (!require(opening.calls == 1, "OPEN rollback call count") ||
        !require(opening.phase == Transaction::Phase::open_started,
                 "OPEN rollback phase") ||
        !require(
            opening.action == Transaction::RollbackAction::close_and_retire,
            "OPEN rollback action")) {
        return 1;
    }

    const auto accepted = InjectFailure(InjectAfter::acceptance);
    if (!require(accepted.calls == 1, "acceptance rollback call count") ||
        !require(accepted.phase == Transaction::Phase::accepted,
                 "acceptance rollback phase") ||
        !require(
            accepted.action == Transaction::RollbackAction::close_and_retire,
            "acceptance rollback action")) {
        return 1;
    }

    const auto rejected = InjectFailure(InjectAfter::rejection);
    if (!require(rejected.calls == 1, "rejection rollback call count") ||
        !require(rejected.phase == Transaction::Phase::rejected,
                 "rejection rollback phase") ||
        !require(rejected.action == Transaction::RollbackAction::unregister,
                 "rejection rollback action")) {
        return 1;
    }

    const auto published = InjectFailure(InjectAfter::publication);
    if (!require(published.calls == 0,
                 "published handle unexpectedly rolled back")) {
        return 1;
    }
    return 0;
}
