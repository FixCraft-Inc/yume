/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <cassert>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <thread>

#include "server/runtime/kdf_admission.hpp"

namespace {

void assert_empty(const yume::server::KdfAdmissionController& controller) {
    const auto snapshot = controller.snapshot();
    assert(snapshot.admitted_argon2_memory_kib == 0);
    assert(snapshot.admitted_argon2_jobs == 0);
}

void test_budget_and_job_limits() {
    yume::server::KdfAdmissionController controller({100, 2});
    auto first = controller.try_acquire_argon2(60);
    assert(first.has_value());

    std::string reason;
    assert(!controller.try_acquire_argon2(41, &reason).has_value());
    assert(reason.find("memory") != std::string::npos);

    auto second = controller.try_acquire_argon2(30);
    assert(second.has_value());
    assert(!controller.try_acquire_argon2(1, &reason).has_value());
    assert(reason.find("job") != std::string::npos);

    second.reset();
    first.reset();
    assert_empty(controller);
}

void test_raii_release_on_exception_and_move() {
    yume::server::KdfAdmissionController controller({64, 1});
    try {
        auto lease = controller.try_acquire_argon2(64);
        assert(lease.has_value());
        auto moved = std::move(*lease);
        assert(static_cast<bool>(moved));
        throw std::runtime_error("simulated derivation failure");
    } catch (const std::runtime_error&) {
    }
    assert_empty(controller);
}

void test_cross_thread_accounting() {
    yume::server::KdfAdmissionController controller({64, 1});
    auto held = controller.try_acquire_argon2(32);
    assert(held.has_value());

    bool admitted = true;
    std::thread contender([&]() {
        admitted = controller.try_acquire_argon2(1).has_value();
    });
    contender.join();
    assert(!admitted);

    held.reset();
    auto after_release = controller.try_acquire_argon2(64);
    assert(after_release.has_value());
    after_release.reset();
    assert_empty(controller);
}

}  // namespace

int main() {
    test_budget_and_job_limits();
    test_raii_release_on_exception_and_move();
    test_cross_thread_accounting();
    std::cout << "kdf_admission_test ok\n";
    return 0;
}
