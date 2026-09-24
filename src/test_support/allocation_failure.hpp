/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <atomic>
#include <cstddef>
#include <cerrno>
#include <cstdlib>
#include <new>

// Include in exactly one translation unit of an isolated test executable.
// These hooks intercept ordinary and nothrow C++ allocations. POSIX provider
// tests can opt into aligned C/C++ allocation interception below. Other C/library
// families are not intercepted. Delete observers must neither allocate nor throw.
namespace yume::test {
inline std::atomic<bool> fail_allocations{false};
// Installed before worker launch by tests whose injection policy spans threads.
inline std::atomic<void (*)(std::size_t)> before_allocate_on_any_thread{nullptr};
inline thread_local void (*before_allocate)(std::size_t) = nullptr;
inline thread_local void (*after_allocate)(void*, std::size_t) = nullptr;
inline thread_local void (*before_deallocate)(void*) noexcept = nullptr;
// A secret-lifetime probe may quarantine storage to detect late wiping or a
// duplicate release. Returning true transfers eventual free() to that probe.
inline thread_local bool (*retain_deallocation)(void*) noexcept = nullptr;

inline void check_allocation(std::size_t size) {
    if (fail_allocations.load(std::memory_order_relaxed)) throw std::bad_alloc();
    if (const auto hook = before_allocate_on_any_thread.load(std::memory_order_relaxed)) hook(size);
    if (before_allocate) before_allocate(size);
}

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

// Optimized GCC 11 builds inlined these replacements into callers and then
// reported the malloc/free pair as mismatched outside this pragma. Keeping
// them out of line leaves each caller with an ordinary new/delete pair.
#if defined(__GNUC__) && !defined(__clang__)
#define YUME_TEST_ALLOCATION_FUNCTION [[gnu::noipa]]
#elif defined(__clang__)
#define YUME_TEST_ALLOCATION_FUNCTION [[gnu::noinline]]
#else
#define YUME_TEST_ALLOCATION_FUNCTION
#endif

YUME_TEST_ALLOCATION_FUNCTION void* operator new(std::size_t size) {
    yume::test::check_allocation(size);
    void* storage = std::malloc(size == 0U ? 1U : size);
    if (!storage) throw std::bad_alloc();
    if (yume::test::after_allocate) yume::test::after_allocate(storage, size);
    return storage;
}

YUME_TEST_ALLOCATION_FUNCTION void* operator new[](std::size_t size) { return ::operator new(size); }
// Keep nothrow allocations in the same malloc/free family as ordinary new.
// Sanitizer runtimes may otherwise supply these overloads independently.
YUME_TEST_ALLOCATION_FUNCTION void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
    try { return ::operator new(size); } catch (...) { return nullptr; }
}
YUME_TEST_ALLOCATION_FUNCTION void* operator new[](std::size_t size, const std::nothrow_t&) noexcept {
    try { return ::operator new[](size); } catch (...) { return nullptr; }
}
YUME_TEST_ALLOCATION_FUNCTION void operator delete(void* storage) noexcept {
    if (yume::test::before_deallocate) yume::test::before_deallocate(storage);
    if (yume::test::retain_deallocation && yume::test::retain_deallocation(storage)) return;
    std::free(storage);
}
YUME_TEST_ALLOCATION_FUNCTION void operator delete[](void* storage) noexcept { ::operator delete(storage); }
YUME_TEST_ALLOCATION_FUNCTION void operator delete(void* storage, std::size_t) noexcept { ::operator delete(storage); }
YUME_TEST_ALLOCATION_FUNCTION void operator delete[](void* storage, std::size_t) noexcept { ::operator delete(storage); }
// Matching cleanup if a constructor throws after a nothrow allocation.
YUME_TEST_ALLOCATION_FUNCTION void operator delete(void* storage, const std::nothrow_t&) noexcept { ::operator delete(storage); }
YUME_TEST_ALLOCATION_FUNCTION void operator delete[](void* storage, const std::nothrow_t&) noexcept { ::operator delete(storage); }

// Opt in only for POSIX provider tests that also intercept Asio's C allocation
// route. Preserve that route's failure policy and malloc/free storage family.
#if defined(YUME_TEST_ALIGNED_ALLOCATIONS) && !defined(_WIN32)
extern "C" YUME_TEST_ALLOCATION_FUNCTION void* aligned_alloc(std::size_t alignment, std::size_t size) noexcept {
    try { yume::test::check_allocation(size); } catch (...) { errno = ENOMEM; return nullptr; }
    void* storage = nullptr;
    const int error = ::posix_memalign(&storage, alignment, size == 0U ? 1U : size);
    if (error != 0) errno = error;
    return storage;
}
YUME_TEST_ALLOCATION_FUNCTION void* operator new(std::size_t size, std::align_val_t alignment) {
    if (void* storage = ::aligned_alloc(static_cast<std::size_t>(alignment), size)) return storage;
    throw std::bad_alloc();
}
YUME_TEST_ALLOCATION_FUNCTION void* operator new[](std::size_t size, std::align_val_t alignment) {
    return ::operator new(size, alignment);
}
YUME_TEST_ALLOCATION_FUNCTION void operator delete(void* storage, std::align_val_t) noexcept { std::free(storage); }
YUME_TEST_ALLOCATION_FUNCTION void operator delete[](void* storage, std::align_val_t alignment) noexcept { ::operator delete(storage, alignment); }
YUME_TEST_ALLOCATION_FUNCTION void operator delete(void* storage, std::size_t, std::align_val_t alignment) noexcept { ::operator delete(storage, alignment); }
YUME_TEST_ALLOCATION_FUNCTION void operator delete[](void* storage, std::size_t, std::align_val_t alignment) noexcept { ::operator delete(storage, alignment); }
YUME_TEST_ALLOCATION_FUNCTION void* operator new(std::size_t size, std::align_val_t alignment, const std::nothrow_t&) noexcept {
    try { return ::operator new(size, alignment); } catch (...) { return nullptr; }
}
YUME_TEST_ALLOCATION_FUNCTION void* operator new[](std::size_t size, std::align_val_t alignment, const std::nothrow_t&) noexcept {
    try { return ::operator new[](size, alignment); } catch (...) { return nullptr; }
}
YUME_TEST_ALLOCATION_FUNCTION void operator delete(void* storage, std::align_val_t alignment, const std::nothrow_t&) noexcept { ::operator delete(storage, alignment); }
YUME_TEST_ALLOCATION_FUNCTION void operator delete[](void* storage, std::align_val_t alignment, const std::nothrow_t&) noexcept { ::operator delete(storage, alignment); }
#endif

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
#undef YUME_TEST_ALLOCATION_FUNCTION
