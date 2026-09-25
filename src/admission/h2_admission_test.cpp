/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "test_support/allocation_failure.hpp"

#include "admission/h2_admission.hpp"

#include <openssl/evp.h>

#include <array>
#include <atomic>
#include <cstdlib>
#include <limits>
#include <new>
#include <stdexcept>
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
using namespace yume::admission;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

Nonce nonce_for(unsigned char value) {
    Nonce nonce{};
    nonce[0] = static_cast<std::byte>(value);
    return nonce;
}

void test_path_boundaries() {
    Token token{};
    token.fill(std::byte{0xab});
    Nonce nonce{};
    for (std::size_t i = 0; i < nonce.size(); ++i) {
        nonce[i] = static_cast<std::byte>(i);
    }
    const auto path = build_path(token, nonce);
    const auto parsed = parse_path(path);
    require(parsed && parsed->token == token && parsed->nonce == nonce,
            "canonical path did not roundtrip");
    require(token_hex(token) ==
        "abababababababababababababababababababababababababababababababab",
        "token hex changed");
    require(nonce_hex(nonce) ==
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "nonce encoding changed");
    require(!parse_path("") && !parse_path(path + "x") &&
            !parse_path(path.substr(1)), "malformed path length was accepted");
    for (std::size_t i = 0; i < path.size(); ++i) {
        auto mutated = path;
        mutated[i] = i == 0U || i == 65U ? '0' : 'G';
        require(!parse_path(mutated), "noncanonical path was accepted");
    }
    require(!parse_token_hex(std::string(64U, 'A')) &&
            !parse_nonce_hex(std::string(63U, '0')),
            "noncanonical hex was accepted");
}

void test_authority_boundaries() {
    require(authority_matches_tls_sni("Example.COM:443", "example.com", 443),
            "authority case normalization failed");
    require(authority_matches_tls_sni("example.com.", "example.com", 443),
            "transport-v2 root-dot normalization changed");
    require(authority_matches_tls_sni("[0:0:0:0:0:0:0:1]:443", "::1", 443),
            "IPv6 normalization changed");
    for (const auto authority : {"", "evil.example", "user@example.com",
             "example.com:0", "example.com:65536", "example.com:444",
             "example.com:443:extra", "example.com/path", "example.com\n",
             "[::1]extra", "::1"}) {
        require(!authority_matches_tls_sni(authority, "example.com", 443),
                "invalid authority matched");
    }
}

void test_hmac_vector_and_private_provider() {
    require(EVP_set_default_properties(nullptr, "provider=not-installed") == 1,
            "could not isolate process-global provider fixture");
    std::array<std::byte, 20> key{};
    key.fill(std::byte{0x0b});
    constexpr std::string_view input = "Hi There";
    const auto token = hmac_sha256(key, std::as_bytes(std::span(input)));
    require(token && token_hex(*token) ==
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
        "HMAC-SHA256 known answer failed");
    require(!hmac_sha256({}, {}), "empty admission key was accepted");
    require(constant_time_equal(*token, *token), "equal token rejected");
    for (std::size_t i = 0; i < token->size(); ++i) {
        auto changed = *token;
        changed[i] ^= std::byte{1};
        require(!constant_time_equal(*token, changed), "mutated token matched");
    }
    const auto first = random_nonce();
    const auto second = random_nonce();
    require(first && second && *first != *second, "fresh nonce generation failed");
    require(EVP_set_default_properties(nullptr, "") == 1,
            "could not restore process-global provider fixture");
}

void test_replay_saturation_expiry_and_clock() {
    ReplayCache cache(2, 10);
    require(cache.reserve(nonce_for(1), 100) == ReplayDecision::Accepted,
            "first reservation failed");
    require(cache.reserve(nonce_for(2), 101) == ReplayDecision::Accepted,
            "second reservation failed");
    require(cache.reserve(nonce_for(3), 102) == ReplayDecision::Rejected &&
            cache.reserve(nonce_for(1), 103) == ReplayDecision::Rejected,
            "saturation displaced a live nonce");
    require(cache.reserve(nonce_for(3), 99) == ReplayDecision::Rejected,
            "clock regression was accepted");
    require(cache.reserve(nonce_for(3), 110) == ReplayDecision::Accepted &&
            cache.reserve(nonce_for(2), 110) == ReplayDecision::Rejected,
            "expiry did not preserve live reservations");
    require(cache.reserve(nonce_for(1), 111) == ReplayDecision::Accepted &&
            cache.size() == 2U, "expired capacity was not recovered");
    require(cache.reserve(nonce_for(4), std::numeric_limits<std::uint64_t>::max()) ==
                ReplayDecision::Rejected,
            "expiry overflow was accepted");
    require(cache.reserve(nonce_for(4), 121) == ReplayDecision::Accepted,
            "overflow refusal poisoned the clock");
}

void test_allocation_rollback() {
    // Exercise both initial map growth and later deque block/map growth. Each
    // failed allocation must leave a reservation usable by the next request.
    std::size_t failures = 0U;
    for (unsigned char prefix = 0; prefix < 32; ++prefix) {
        bool reached_success = false;
        for (int allocation = 0; allocation < 16; ++allocation) {
            ReplayCache cache(static_cast<std::size_t>(prefix) + 1U, 10);
            for (unsigned char n = 0; n < prefix; ++n) {
                require(cache.reserve(nonce_for(n), 100) == ReplayDecision::Accepted,
                        "rollback fixture reservation failed");
            }
            fail_after = allocation;
            const auto result = cache.reserve(nonce_for(100), 101);
            fail_after = -1;
            if (result == ReplayDecision::Accepted) {
                reached_success = true;
                break;
            }
            ++failures;
            require(cache.size() == prefix, "failed insertion retained state");
            require(cache.reserve(nonce_for(101), 102) == ReplayDecision::Accepted,
                    "failed insertion consumed capacity");
            require(cache.reserve(nonce_for(101), 103) == ReplayDecision::Rejected,
                    "failed insertion broke duplicate refusal");
            require(cache.reserve(nonce_for(100), 112) == ReplayDecision::Accepted,
                    "failed insertion broke expiry recovery");
            require(cache.size() == 1U, "failed insertion retained expiry state");
        }
        require(reached_success, "allocation sweep never completed");
    }
    require(failures > 32U, "allocation sweep missed container growth");
}

void test_concurrent_reservations() {
    ReplayCache shared(8U, 10U);
    std::atomic<unsigned int> admitted{0U};
    std::vector<std::thread> workers;
    for (unsigned int i = 0; i < 16U; ++i) {
        workers.emplace_back([&] {
            if (shared.reserve(nonce_for(1), 100) == ReplayDecision::Accepted) {
                admitted.fetch_add(1U, std::memory_order_relaxed);
            }
        });
    }
    for (auto& worker : workers) worker.join();
    require(admitted == 1U && shared.size() == 1U,
            "concurrent replay admitted more than once");
    workers.clear();
    for (unsigned char i = 2; i < 18; ++i) {
        workers.emplace_back([&, i] {
            if (shared.reserve(nonce_for(i), 100) == ReplayDecision::Accepted) {
                admitted.fetch_add(1U, std::memory_order_relaxed);
            }
        });
    }
    for (auto& worker : workers) worker.join();
    require(admitted == 8U && shared.size() == 8U,
            "concurrent admission exceeded capacity");
}
}  // namespace

int main() {
    yume::test::before_allocate_on_any_thread.store(check_test_allocation);

    test_path_boundaries();
    test_authority_boundaries();
    test_hmac_vector_and_private_provider();
    test_replay_saturation_expiry_and_clock();
    test_allocation_rollback();
    test_concurrent_reservations();
}
