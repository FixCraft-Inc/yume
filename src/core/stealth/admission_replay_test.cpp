/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/stealth/obfs_signal.hpp"

#include <cstdlib>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>

namespace {
thread_local int fail_after = -1;
}

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmismatched-new-delete"
#endif
void* operator new(std::size_t size) {
    if (fail_after == 0) throw std::bad_alloc();
    if (fail_after > 0) --fail_after;
    if (void* storage = std::malloc(size == 0U ? 1U : size)) return storage;
    throw std::bad_alloc();
}
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void* storage) noexcept { std::free(storage); }
void operator delete[](void* storage) noexcept { ::operator delete(storage); }
void operator delete(void* storage, std::size_t) noexcept { ::operator delete(storage); }
void operator delete[](void* storage, std::size_t) noexcept { ::operator delete(storage); }
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

namespace {
void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

std::string path_for(char digit) {
    // HMAC/authority verification belongs to the caller and obfs_test. This
    // fixture supplies a shape-valid path to the replay-state boundary only.
    return "/" + std::string(yume::obfs::kH2TokenHexLen, 'a') + "/" +
           std::string(yume::obfs::kH2NonceHexLen, digit);
}

void test_saturation_and_expiry() {
    yume::obfs::AdmissionReplayCache cache(2, 7200);
    const auto first = path_for('1');
    const auto second = path_for('2');
    const auto third = path_for('3');
    require(!cache.AcceptPathAt("/invalid", 100), "invalid path was accepted");
    require(cache.AcceptPathAt(first, 100), "first admission failed");
    require(cache.AcceptPathAt(second, 101), "second admission failed");
    require(!cache.AcceptPathAt(third, 102), "saturation displaced a live nonce");
    require(cache.size() == 2, "cache exceeded its cap");
    require(!cache.AcceptPathAt(first, 102) && !cache.AcceptPathAt(second, 102),
            "saturation allowed a replay");
    auto changed_token = first;
    changed_token[1] = 'b';
    require(!cache.AcceptPathAt(changed_token, 103), "another token reused a live nonce");
    require(cache.AcceptPathAt(third, 7300), "expired entry did not return capacity");
    require(!cache.AcceptPathAt(second, 7300), "entry expired early");
    require(cache.AcceptPathAt(first, 7301), "second expiry did not return capacity");
    require(cache.size() == 2, "expiry changed the capacity bound");
    require(!cache.AcceptPathAt(path_for('4'), std::numeric_limits<std::uint64_t>::max()),
            "expiry arithmetic overflow was accepted");
}

void test_failed_insert_preserves_capacity() {
    const auto first = path_for('1');
    const auto second = path_for('2');
    bool reached_success = false;
    for (int allocation = 0; allocation < 32; ++allocation) {
        yume::obfs::AdmissionReplayCache cache(1, 7200);
        fail_after = allocation;
        reached_success = cache.AcceptPathAt(first, 100);
        fail_after = -1;
        if (reached_success) break;
        require(cache.size() == 0, "failed insertion retained a nonce");
        require(cache.AcceptPathAt(second, 101), "failed insertion consumed capacity");
        require(!cache.AcceptPathAt(second, 102), "failed insertion broke replay refusal");
        require(cache.AcceptPathAt(first, 7301), "failed insertion broke expiry recovery");
        require(cache.size() == 1, "failed insertion broke the cache bound");
    }
    require(reached_success, "allocation sweep never reached successful insertion");
}
}  // namespace

int main() {
    test_saturation_and_expiry();
    test_failed_insert_preserves_capacity();
}
