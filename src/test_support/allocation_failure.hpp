/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <new>

// Include in exactly one translation unit of an isolated test executable.
// These hooks intercept ordinary and nothrow C++ allocations, not aligned or
// C/library allocation families. Observers must not allocate or throw during delete.
namespace yume::test {
inline std::atomic<bool> fail_allocations{false};
inline thread_local void (*before_allocate)(std::size_t) = nullptr;
inline thread_local void (*after_allocate)(void*, std::size_t) = nullptr;
inline thread_local void (*before_deallocate)(void*) noexcept = nullptr;

// Single-shot injection for sweeping one failure across every allocation an
// operation performs. Failing once rather than continuously keeps the
// assertions after the call able to allocate.
inline thread_local std::size_t allocation_countdown = 0;

inline void fail_on_allocation_countdown(std::size_t) {
    if (allocation_countdown == 0) return;
    if (--allocation_countdown == 0) throw std::bad_alloc();
}

inline void arm_allocation_failure(std::size_t nth) {
    allocation_countdown = nth;
    before_allocate = fail_on_allocation_countdown;
}

// Returns true when the armed failure actually fired.
inline bool disarm_allocation_failure() {
    before_allocate = nullptr;
    const bool fired = allocation_countdown == 0;
    allocation_countdown = 0;
    return fired;
}
}  // namespace yume::test

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmismatched-new-delete"
#endif

void* operator new(std::size_t size) {
    if (yume::test::fail_allocations.load(std::memory_order_relaxed)) {
        throw std::bad_alloc();
    }
    if (yume::test::before_allocate) yume::test::before_allocate(size);
    void* storage = std::malloc(size == 0U ? 1U : size);
    if (!storage) throw std::bad_alloc();
    if (yume::test::after_allocate) yume::test::after_allocate(storage, size);
    return storage;
}

void* operator new[](std::size_t size) { return ::operator new(size); }
// Keep nothrow allocations in the same malloc/free family as ordinary new.
// Sanitizer runtimes may otherwise supply these overloads independently.
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
    try { return ::operator new(size); } catch (...) { return nullptr; }
}
void* operator new[](std::size_t size, const std::nothrow_t&) noexcept {
    try { return ::operator new[](size); } catch (...) { return nullptr; }
}
void operator delete(void* storage) noexcept {
    if (yume::test::before_deallocate) yume::test::before_deallocate(storage);
    std::free(storage);
}
void operator delete[](void* storage) noexcept { ::operator delete(storage); }
void operator delete(void* storage, std::size_t) noexcept { ::operator delete(storage); }
void operator delete[](void* storage, std::size_t) noexcept { ::operator delete(storage); }
// Matching cleanup if a constructor throws after a nothrow allocation.
void operator delete(void* storage, const std::nothrow_t&) noexcept { ::operator delete(storage); }
void operator delete[](void* storage, const std::nothrow_t&) noexcept { ::operator delete(storage); }

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
