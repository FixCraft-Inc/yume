/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "modules/share/bundle_file.hpp"
#include "test_support/allocation_failure.hpp"

#include <algorithm>
#include <cstdio>
#include <string>

namespace {

// {"key":"SSS..."} serialises to the secret plus ten bytes.
constexpr std::size_t kSecretBytes = 4096;
constexpr std::size_t kSerialisedBytes = kSecretBytes + 10U;

void* serialised_buffer = nullptr;
bool failed = false;
bool released = false;
bool wiped = false;

// seal_share copies the finished serialisation into a vector of exactly its
// size. Failing that copy leaves the serialisation as the only full copy, and
// it must be wiped before its storage is freed. The serialisation lives in the
// most recent larger allocation, because a string outgrows smaller buffers.
void after_allocation(void* data, std::size_t size) {
    if (!failed && size > kSerialisedBytes) serialised_buffer = data;
}
void before_allocation(std::size_t size) {
    if (!failed && serialised_buffer && size == kSerialisedBytes) {
        failed = true;
        throw std::bad_alloc();
    }
}
void before_release(void* data) noexcept {
    if (!data || data != serialised_buffer) return;
    if (!failed) {
        serialised_buffer = nullptr;
        return;
    }
    released = true;
    const auto* bytes = static_cast<const unsigned char*>(data);
    wiped = std::all_of(bytes, bytes + kSerialisedBytes,
                        [](unsigned char byte) { return byte == 0; });
    serialised_buffer = nullptr;
}

}  // namespace

int main() {
    const nlohmann::json document{{"key", std::string(kSecretBytes, 'S')}};
    if (document.dump().size() != kSerialisedBytes) {
        std::fputs("share lifetime: unexpected serialised size\n", stderr);
        return 1;
    }
    const std::string password(yume::share::kPasswordMin, 'p');
    yume::test::after_allocate = after_allocation;
    yume::test::before_allocate = before_allocation;
    yume::test::before_deallocate = before_release;
    bool refused = false;
    try {
        refused = yume::share::seal_share(document, yume::share::BundleType::Backup, password,
                                          nullptr)
                      .empty();
    } catch (const std::bad_alloc&) {
        refused = true;
    }
    yume::test::after_allocate = nullptr;
    yume::test::before_allocate = nullptr;
    yume::test::before_deallocate = nullptr;
    if (!failed || !refused || !released || !wiped ||
        document.at("key") != std::string(kSecretBytes, 'S')) {
        std::fputs("share lifetime: the serialised document was not wiped before release\n",
                   stderr);
        return 1;
    }
    std::puts("share lifetime: allocation failure wiped the serialised document");
    return 0;
}
