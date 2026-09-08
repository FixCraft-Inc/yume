/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/security/crypto.hpp"
#include "core/security/secure_erase.hpp"
#include "test_support/allocation_failure.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <string_view>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/buffer.h>

#ifndef _WIN32
#include <unistd.h>
#endif

namespace {
void check(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "memory lifetime: %s\n", message);
        std::exit(1);
    }
}

void* watched = nullptr;
std::size_t watched_bytes = 0;
bool released = false;
bool wiped = false;

void observe_release(void* data) noexcept {
    if (!data || data != watched) return;
    // Observe at delete entry, while the allocation is still live. A wipe
    // after delete or an inspection of newly initialized storage cannot pass.
    released = true;
    const auto* bytes = static_cast<const unsigned char*>(data);
    wiped = std::all_of(bytes, bytes + watched_bytes,
                        [](unsigned char value) { return value == 0; });
    watched = nullptr;
}

void test_erase() {
    yume::test::before_deallocate = observe_release;
    {
        yume::crypto::Bytes bytes(4096, 0xA5);
        watched = bytes.data();
        watched_bytes = bytes.size();
        bytes.resize(7);
        yume::test::fail_allocations = true;
        yume::security::secure_erase(bytes);
        yume::test::fail_allocations = false;
        check(bytes.empty(), "vector erase retained its length");
    }
    check(released && wiped, "shrunk vector retained secret bytes at delete");
    released = wiped = false;
    {
        std::string value(4096, 'S');
        watched = value.data();
        watched_bytes = value.size();
        value.resize(7);
        yume::test::fail_allocations = true;
        yume::security::secure_erase(value);
        yume::test::fail_allocations = false;
    }
    check(released && wiped, "shrunk string retained secret bytes at delete");
    std::string short_value = "short-secret";
    const auto length = short_value.size();
    short_value.resize(1);
    yume::security::secure_erase(short_value);
    // Inspect the existing storage without a resize that could overwrite the
    // tail and hide a failed erase.
    const volatile char* bytes = short_value.data();
    for (std::size_t i = 0; i < length; ++i) {
        check(bytes[i] == 0, "short string retained secret bytes");
    }
}

bool watch_c = false;
void* c_context = nullptr;
bool c_context_freed = false;
bool fail_c_once = false;

void* openssl_malloc(std::size_t size, const char*, int) {
    if (fail_c_once) {
        fail_c_once = false;
        return nullptr;
    }
    void* data = std::malloc(size);
    if (watch_c && !c_context) c_context = data;
    return data;
}
void* openssl_realloc(void* old, std::size_t size, const char*, int) {
    // OpenSSL owns this allocation family. Preserve realloc failure semantics:
    // a null result for a nonzero size leaves the old allocation owned/live.
    return std::realloc(old, size);
}
void openssl_free(void* data, const char*, int) {
    observe_release(data);
    if (data && data == c_context) c_context_freed = true;
    std::free(data);
}

void test_bio_growth() {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    check(bio != nullptr, "BIO creation failed");
    const std::string secret(64, 'S');
    check(BIO_write(bio.get(), secret.data(), static_cast<int>(secret.size())) == 64,
          "BIO fixture write failed");
    BUF_MEM* buffer = nullptr;
    BIO_get_mem_ptr(bio.get(), &buffer);
    check(buffer && buffer->data, "BIO buffer missing");
    watched = buffer->data;
    watched_bytes = buffer->max;
    const auto original_length = buffer->length;
    const std::array<char, 4096> extra{};
    fail_c_once = true;
    check(BIO_write(bio.get(), extra.data(), static_cast<int>(extra.size())) <= 0 &&
              !fail_c_once, "BIO growth did not reach C allocation failure");
    check(buffer->data == watched && buffer->length == original_length &&
              buffer->max == watched_bytes &&
              std::memcmp(buffer->data, secret.data(), secret.size()) == 0,
          "failed clear-realloc lost or mutated the owned BIO buffer");
    bio.reset();
    check(released && wiped, "BIO did not wipe retained storage before C free");
    ERR_clear_error();
}

void test_sign() {
    yume::crypto::EVP_PKEY_ptr key(
        EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"), EVP_PKEY_free);
    check(key != nullptr, "Ed25519 keygen failed");
    const yume::crypto::Bytes message{1, 2, 3};
    const auto signature = yume::crypto::sign_message(key.get(), message);
    check(yume::crypto::verify_key(key.get(), message, signature),
          "ordinary signing failed");
    // Warm provider caches first. The first C allocation in sign_message is
    // its EVP_MD_CTX. Failing C++ new then hits the signature vector.
    watch_c = true;
    bool caught = false;
    yume::test::fail_allocations = true;
    try {
        (void)yume::crypto::sign_message(key.get(), message);
    } catch (const std::bad_alloc&) {
        caught = true;
    }
    yume::test::fail_allocations = false;
    watch_c = false;
    check(caught && c_context, "signature allocation failure was not reached");
    check(c_context_freed, "signing leaked its OpenSSL context on bad_alloc");
    c_context = nullptr;
    check(yume::crypto::verify_key(key.get(), message,
              yume::crypto::sign_message(key.get(), message)),
          "signing did not recover");
}

struct Allocation { void* data{}; std::size_t size{}; };
std::array<Allocation, 256> allocations{};
bool released_pem = false;
void track_allocation(void* data, std::size_t size) {
    for (auto& slot : allocations) {
        if (!slot.data) { slot = {data, size}; return; }
    }
    std::abort();
}
void observe_pem_release(void* data) noexcept {
    if (!data) return;
    for (auto& slot : allocations) {
        if (slot.data != data) continue;
        constexpr std::string_view prefix = "-----BEGIN PRIVATE KEY-----";
        if (slot.size >= prefix.size() &&
            std::memcmp(data, prefix.data(), prefix.size()) == 0) {
            released_pem = true;
        }
        slot = {};
        return;
    }
}
void test_pem_export(bool missing_half) {
    auto keys = yume::crypto::generate_composite_keypair();
    if (missing_half) keys.pq.private_key.reset();
    yume::test::after_allocate = track_allocation;
    yume::test::before_deallocate = observe_pem_release;
    bool caught = false;
    try {
        auto pem = yume::crypto::encode_composite_private_pem(keys);
        check(!pem.empty(), "private PEM export was empty");
        yume::security::secure_erase(pem);
    } catch (const std::runtime_error&) {
        caught = true;
    }
    yume::test::after_allocate = nullptr;
    yume::test::before_deallocate = nullptr;
    check(caught == missing_half, "unexpected private PEM export result");
    check(!released_pem, "private PEM survived vector release/growth");
}

#ifndef _WIN32
void fail_after_file_allocation(void* data, std::size_t size) {
    if (size == 4096) {
        watched = data;
        watched_bytes = size;
        yume::test::fail_allocations = true;
    }
}
void test_pem_load() {
    char path[] = "/tmp/yume-memory-key-XXXXXX";
    const int fd = ::mkstemp(path);
    check(fd >= 0, "private fixture creation failed");
    std::array<char, 4096> contents{};
    contents.fill('S');
    check(::write(fd, contents.data(), contents.size()) ==
              static_cast<ssize_t>(contents.size()), "fixture write failed");
    check(::close(fd) == 0, "fixture close failed");
    const std::string filename(path);
    yume::test::after_allocate = fail_after_file_allocation;
    yume::test::before_deallocate = observe_release;
    bool caught = false;
    try {
        (void)yume::crypto::load_composite_keypair(filename);
    } catch (const std::bad_alloc&) {
        caught = true;
    }
    yume::test::fail_allocations = false;
    yume::test::after_allocate = nullptr;
    yume::test::before_deallocate = nullptr;
    check(::unlink(path) == 0, "fixture removal failed");
    check(caught && released, "PEM parse allocation failure was not reached");
    check(wiped, "private file buffer survived failed PEM validation");
}
#endif
}  // namespace

int main(int argc, char** argv) {
    check(CRYPTO_set_mem_functions(openssl_malloc, openssl_realloc, openssl_free) == 1,
          "OpenSSL allocation hooks were installed too late");
    check(argc == 2, "one test case is required");
    const std::string_view name(argv[1]);
    if (name == "erase") test_erase();
    else if (name == "sign") test_sign();
    else if (name == "bio-growth") test_bio_growth();
    else if (name == "pem-export") test_pem_export(false);
    else if (name == "pem-partial") test_pem_export(true);
#ifndef _WIN32
    else if (name == "pem-load") test_pem_load();
#endif
    else check(false, "unknown case");
    yume::test::before_deallocate = nullptr;
    std::puts("memory lifetime: passed");
}
