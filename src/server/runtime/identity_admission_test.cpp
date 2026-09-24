/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "test_support/allocation_failure.hpp"

#include "server/runtime/identity_admission.hpp"

#include <atomic>
#include <cstdlib>
#include <new>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {
thread_local int fail_after = -1;
}

namespace {
void check_test_allocation(std::size_t) {
    if (fail_after == 0) throw std::bad_alloc();
    if (fail_after > 0) --fail_after;
}
}


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

void test_failed_admission_preserves_capacity() {
    const std::string fingerprint(64, 'a');
    for (const bool already_active : {false, true}) {
        bool reached_success = false;
        for (int allocation = 0; allocation < 32; ++allocation) {
            yume::server::IdentityAdmissionController admission;
            const std::size_t previous = already_active ? 1U : 0U;
            if (already_active) {
                require(admission.admit(1, fingerprint, 2), "fixture admission failed");
            }
            bool failed = false;
            fail_after = allocation;
            try {
                reached_success = admission.admit(2, fingerprint, 2);
            } catch (const std::bad_alloc&) {
                failed = true;
            }
            fail_after = -1;
            if (!failed) break;
            require(admission.active_total() == previous,
                    "failed admission published a session");
            require(admission.active_for(fingerprint) == previous,
                    "failed admission consumed an identity slot");
            admission.release(2);
            require(admission.admit(3, fingerprint, 2),
                    "failed admission did not return capacity");
            admission.release(3);
            require(admission.active_for(fingerprint) == previous,
                    "failed admission left an unreleaseable count");
        }
        require(reached_success, "allocation sweep never reached successful admission");
    }
}

}  // namespace

int main() {
    yume::test::before_allocate_on_any_thread.store(check_test_allocation);

    test_individual_and_idempotent_release();
    test_failed_admission_preserves_capacity();
    test_concurrent_bulk_cap();
    return 0;
}
