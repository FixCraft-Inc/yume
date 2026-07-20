/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace yume::server {

// Tracks post-authentication concurrency separately from the pre-auth TCP
// session cap. A bulk key may authenticate several independent sessions, but
// it never bypasses a bounded per-key count. Release is idempotent so every
// session-close path can use the same cleanup operation safely.
class IdentityAdmissionController {
public:
    bool admit(std::uint64_t session_id,
               const std::string& fingerprint,
               std::uint32_t max_sessions,
               std::string* error = nullptr);
    void release(std::uint64_t session_id);

    std::size_t active_for(const std::string& fingerprint) const;
    std::size_t active_total() const;

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::size_t> identity_counts_;
    std::unordered_map<std::uint64_t, std::string> session_identities_;
};

}  // namespace yume::server
