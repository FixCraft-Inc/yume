/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/transfer/share_file.hpp"
#include "test_support/allocation_failure.hpp"

#include <algorithm>
#include <cstdio>

namespace {
constexpr std::size_t kSecretBytes = 4096;
void* secret_copy = nullptr;
bool fail_next = false;
bool failed = false;
bool released = false;
bool wiped = false;

void before_allocation(std::size_t) {
    if (fail_next) {
        fail_next = false;
        failed = true;
        throw std::bad_alloc();
    }
}
void after_allocation(void* data, std::size_t size) {
    if (!secret_copy && !released && size == kSecretBytes + 1U) {
        secret_copy = data;
        fail_next = true;
    }
}
void before_release(void* data) noexcept {
    if (!data || data != secret_copy) return;
    released = true;
    const auto* bytes = static_cast<const unsigned char*>(data);
    wiped = std::all_of(bytes, bytes + kSecretBytes,
                        [](unsigned char byte) { return byte == 0; });
    secret_copy = nullptr;
}
}  // namespace

int main() {
    yume::share::ShareBundle bundle;
    bundle.server_host = "example.invalid";
    bundle.auth_private_key_pem.assign(kSecretBytes, 'S');
    const std::string password = "synthetic password only";
    yume::test::before_allocate = before_allocation;
    yume::test::after_allocate = after_allocation;
    yume::test::before_deallocate = before_release;
    bool refused = false;
    try { refused = yume::share::encode_share(bundle, password, nullptr).empty(); }
    catch (const std::bad_alloc&) { refused = true; }
    yume::test::before_allocate = nullptr;
    yume::test::after_allocate = nullptr;
    yume::test::before_deallocate = nullptr;
    if (!failed || !refused || !released || !wiped ||
        bundle.auth_private_key_pem != std::string(kSecretBytes, 'S')) {
        std::fputs("share serialization: partial JSON secret was not wiped before delete\n", stderr);
        return 1;
    }
    std::puts("share serialization: allocation failure wiped partial JSON before delete");
}
