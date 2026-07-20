/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/runtime/identity_admission.hpp"

#include <atomic>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

void require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void test_individual_and_idempotent_release() {
    yume::server::IdentityAdmissionController admission;
    std::string error;
    require(admission.admit(1, "individual", 1, &error),
            "first individual session should be admitted");
    require(!admission.admit(2, "individual", 1, &error),
            "second individual session must be refused");
    require(admission.active_for("individual") == 1,
            "individual count must remain one");
    admission.release(1);
    admission.release(1);
    require(admission.active_total() == 0, "release must be idempotent");
}

void test_concurrent_bulk_cap() {
    yume::server::IdentityAdmissionController admission;
    constexpr std::uint32_t kLimit = 64;
    constexpr std::uint32_t kAttempts = 128;
    std::atomic<std::uint32_t> admitted{0};
    std::vector<std::thread> threads;
    threads.reserve(kAttempts);
    for (std::uint32_t i = 0; i < kAttempts; ++i) {
        threads.emplace_back([&, i] {
            if (admission.admit(1000 + i, "bulk", kLimit)) {
                admitted.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    require(admitted.load(std::memory_order_relaxed) == kLimit,
            "concurrent bulk admission exceeded or undershot its cap");
    require(admission.active_for("bulk") == kLimit,
            "bulk identity count is incorrect");
}

}  // namespace

int main() {
    test_individual_and_idempotent_release();
    test_concurrent_bulk_cap();
    return 0;
}
