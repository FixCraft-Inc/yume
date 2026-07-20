/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/runtime/identity_admission.hpp"

namespace yume::server {

bool IdentityAdmissionController::admit(std::uint64_t session_id,
                                        const std::string& fingerprint,
                                        std::uint32_t max_sessions,
                                        std::string* error) {
    if (session_id == 0 || fingerprint.empty() || max_sessions == 0) {
        if (error) *error = "invalid identity admission request";
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    const auto existing = session_identities_.find(session_id);
    if (existing != session_identities_.end()) {
        if (existing->second == fingerprint) {
            if (error) error->clear();
            return true;
        }
        if (error) *error = "session is already bound to another identity";
        return false;
    }

    auto& count = identity_counts_[fingerprint];
    if (count >= max_sessions) {
        if (error) *error = "authenticated key session limit reached";
        return false;
    }
    ++count;
    session_identities_.emplace(session_id, fingerprint);
    if (error) error->clear();
    return true;
}

void IdentityAdmissionController::release(std::uint64_t session_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto session = session_identities_.find(session_id);
    if (session == session_identities_.end()) {
        return;
    }
    const auto identity = identity_counts_.find(session->second);
    if (identity != identity_counts_.end()) {
        if (identity->second <= 1) {
            identity_counts_.erase(identity);
        } else {
            --identity->second;
        }
    }
    session_identities_.erase(session);
}

std::size_t IdentityAdmissionController::active_for(
    const std::string& fingerprint) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = identity_counts_.find(fingerprint);
    return it == identity_counts_.end() ? 0 : it->second;
}

std::size_t IdentityAdmissionController::active_total() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return session_identities_.size();
}

}  // namespace yume::server
