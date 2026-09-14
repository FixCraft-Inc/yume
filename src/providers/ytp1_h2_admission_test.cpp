/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/ytp1_h2_admission.hpp"

#include <array>
#include <cstdlib>
#include <new>
#include <stdexcept>

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
using namespace yume;
using namespace yume::providers;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

std::array<std::byte, 32> sequence(unsigned int start) {
    std::array<std::byte, 32> bytes{};
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        bytes[i] = static_cast<std::byte>(start + i);
    }
    return bytes;
}

const auto kKey = sequence(0U);
const auto kExporter = sequence(32U);
const auto kNonce = sequence(64U);
constexpr std::string_view kServerName = "carrier.example";

std::string bytes_hex(std::span<const std::byte> input) {
    constexpr std::string_view digits = "0123456789abcdef";
    std::string output;
    for (auto value : input) {
        const auto byte = std::to_integer<unsigned int>(value);
        output.push_back(digits[byte >> 4U]);
        output.push_back(digits[byte & 0xfU]);
    }
    return output;
}

void test_canonical_vector() {
    const auto encoded = encode_ytp1_h2_admission_input(kServerName, kExporter, kNonce);
    require(encoded && bytes_hex(*encoded) ==
        "001e79756d652f7974702f312f68322d7765622f61646d697373696f6e2f7631"
        "000f636172726965722e6578616d706c65"
        "0020202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
        "YTP admission canonical input changed");
    const auto token = derive_ytp1_h2_admission_token(kKey, kServerName, kExporter, kNonce);
    require(token && admission::token_hex(*token) ==
        "5cce6d59ef5999bc862090608b5d3867eed659b2a1ff9c8e8d45397af3d31a6c",
        "YTP admission HMAC vector changed");
    const auto path = build_ytp1_h2_admission_path(kKey, kServerName, kExporter, kNonce);
    require(path && *path ==
        "/5cce6d59ef5999bc862090608b5d3867eed659b2a1ff9c8e8d45397af3d31a6c/"
        "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
        "YTP admission path vector changed");
    require(verify_ytp1_h2_admission_path(kKey, "CARRIER.EXAMPLE:443",
                "Carrier.Example", kExporter, *path, 443),
            "valid admission proof refused");
}

void test_binding_mutations() {
    const auto path = build_ytp1_h2_admission_path(kKey, kServerName, kExporter, kNonce);
    require(path.has_value(), "binding fixture failed");
    for (std::size_t i = 0; i < kKey.size(); ++i) {
        auto key = kKey;
        key[i] ^= std::byte{1};
        require(!verify_ytp1_h2_admission_path(key, kServerName, kServerName,
                                              kExporter, *path),
                "different admission key accepted");
        auto exporter = kExporter;
        exporter[i] ^= std::byte{1};
        require(!verify_ytp1_h2_admission_path(kKey, kServerName, kServerName,
                                              exporter, *path),
                "proof transferred to another TLS channel");
    }
    for (std::size_t i = 1; i < path->size(); ++i) {
        if (i == 65U) continue;
        auto changed = *path;
        changed[i] = changed[i] == '0' ? '1' : '0';
        require(!verify_ytp1_h2_admission_path(kKey, kServerName, kServerName,
                                              kExporter, changed),
                "mutated token or nonce accepted");
    }
    require(!verify_ytp1_h2_admission_path(kKey, "other.example", "other.example",
                                          kExporter, *path),
            "proof transferred to another server name");
    const std::string v2_path =
        "/58dc98878665b2edcd9130f1d556011ca6222547c816c09e74cc8f53cc61d2a0/"
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    require(!verify_ytp1_h2_admission_path(kKey, kServerName, kServerName,
                                          kExporter, v2_path),
            "transport-v2 proof accepted as YTP");
}

void test_input_and_authority_boundaries() {
    for (const std::string name : {"", ".example", "example.", "bad..example",
             "-bad.example", "bad-.example", "bad_name.example", "host:443",
             "user@host", "bad/name", "bad name", "bad\nname", "host\xc3\xa9"}) {
        require(!canonicalize_ytp1_h2_server_name(name), "invalid DNS name accepted");
        require(!encode_ytp1_h2_admission_input(name, kExporter, kNonce),
                "invalid DNS name encoded");
    }
    require(!canonicalize_ytp1_h2_server_name(std::string(64U, 'a') + ".example"),
            "oversized DNS label accepted");
    const auto maximum = std::string(63U, 'a') + "." + std::string(63U, 'b') +
        "." + std::string(63U, 'c') + "." + std::string(61U, 'd');
    require(canonicalize_ytp1_h2_server_name(maximum).has_value() &&
            !canonicalize_ytp1_h2_server_name(maximum + "e"),
            "DNS name length bound changed");
    const auto path = build_ytp1_h2_admission_path(kKey, kServerName, kExporter, kNonce);
    require(path.has_value(), "authority fixture failed");
    for (const auto authority : {"other.example", "carrier.example:444",
             "carrier.example:0", "carrier.example:65536", "carrier.example:443/",
             "user@carrier.example", "carrier.example:443:extra"}) {
        require(!verify_ytp1_h2_admission_path(kKey, authority, kServerName,
                                              kExporter, *path, 443),
                "invalid authority admitted");
    }
    std::array<std::byte, 33> oversized{};
    for (const std::span<const std::byte> key :
         {std::span<const std::byte>{}, std::span<const std::byte>{kKey}.first(31U),
          std::span<const std::byte>{oversized}}) {
        require(!build_ytp1_h2_admission_path(key, kServerName, kExporter, kNonce),
                "invalid key length accepted");
    }
    for (const std::span<const std::byte> exporter :
         {std::span<const std::byte>{}, std::span<const std::byte>{kExporter}.first(31U),
          std::span<const std::byte>{oversized}}) {
        require(!build_ytp1_h2_admission_path(kKey, kServerName, exporter, kNonce),
                "absent or invalid exporter accepted");
    }
}

void test_allocation_failure_is_refusal() {
    // Warm provider initialization outside the allocation sweep. C++ failure
    // injection covers the hostname, encoded input and final path allocations.
    const auto initial = build_ytp1_h2_admission_path(kKey, kServerName, kExporter, kNonce);
    require(initial.has_value(), "allocation fixture failed");
    bool succeeded = false;
    std::size_t failures = 0U;
    for (int allocation = 0; allocation < 16; ++allocation) {
        fail_after = allocation;
        const auto result = build_ytp1_h2_admission_path(kKey,
            "longer.carrier.example", kExporter, kNonce);
        fail_after = -1;
        if (result) {
            succeeded = true;
            break;
        }
        ++failures;
    }
    require(succeeded && failures >= 3U, "allocation sweep missed refusal paths");
    fail_after = 0;
    const bool admitted = verify_ytp1_h2_admission_path(kKey,
        "longer.carrier.example", "longer.carrier.example", kExporter, *initial);
    fail_after = -1;
    require(!admitted, "allocation failure admitted a request");
}
}  // namespace

int main() {
    test_canonical_vector();
    test_binding_mutations();
    test_input_and_authority_boundaries();
    test_allocation_failure_is_refusal();
}
