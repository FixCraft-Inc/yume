/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/transfer/share_file.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <string>
#include <utility>

namespace {

// Large synthetic strings force allocation without relying on an SSO size or
// a library's exact capacity growth. No other bundle field allocates this much
// before the three secrets; one later public field exercises copy rollback.
constexpr std::size_t kSecretBytes = 4096;

struct Allocation {
    void* data{nullptr};
    bool released{false};
    bool wiped_before_release{false};
};

struct AllocationProbe {
    std::array<Allocation, 3> secrets{};
    std::size_t attempts{0};
    std::size_t fail_at{0};
    bool enabled{false};
    bool failed{false};
    bool double_release{false};

    ~AllocationProbe() {
        for (const auto& allocation : secrets) {
            if (allocation.released) std::free(allocation.data);
        }
    }
};

thread_local AllocationProbe* active_probe = nullptr;

class ProbeScope {
public:
    explicit ProbeScope(AllocationProbe& probe) noexcept {
        active_probe = &probe;
        probe.enabled = true;
    }
    ~ProbeScope() { active_probe = nullptr; }
    ProbeScope(const ProbeScope&) = delete;
    ProbeScope& operator=(const ProbeScope&) = delete;
};

void check(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "share bundle lifetime: %s\n", message);
        std::exit(EXIT_FAILURE);
    }
}

bool contains_secret(const std::string& value, char byte) {
    return value.size() == kSecretBytes &&
           std::all_of(value.begin(), value.end(), [byte](char c) { return c == byte; });
}

void check_secrets(const yume::share::ShareBundle& bundle) {
    check(contains_secret(bundle.auth_private_key_pem, 'A'), "private key changed");
    check(contains_secret(bundle.obfs_secret, 'B'), "admission secret changed");
    check(contains_secret(bundle.inner_psk, 'C'), "PSK changed");
}

void test_construction(bool move, std::size_t fail_at) {
    yume::share::ShareBundle source;
    source.auth_private_key_pem.assign(kSecretBytes, 'A');
    source.obfs_secret.assign(kSecretBytes, 'B');
    source.inner_psk.assign(kSecretBytes, 'C');
    source.tls_ca_cert_pem.assign(kSecretBytes, 'D');

    AllocationProbe probe;
    probe.fail_at = fail_at;
    bool caught = false;
    {
        ProbeScope scope(probe);
        try {
            // Conditional prvalues are constructed directly into the result;
            // no extra copy/move may obscure which constructor is exercised.
            auto destination = move ? yume::share::ShareBundle(std::move(source))
                                    : yume::share::ShareBundle(source);
            probe.enabled = false;
            check(fail_at == 0, "allocation failure was not reached");
            check_secrets(destination);
            check(contains_secret(destination.tls_ca_cert_pem, 'D'), "public field changed");
        } catch (const std::bad_alloc&) {
            probe.enabled = false;
            caught = true;
        }
    }

    check(caught == (fail_at != 0) && probe.failed == caught,
          "construction did not propagate the injected failure");
    check(probe.attempts == (fail_at != 0 ? fail_at : (move ? 3U : 4U)),
          "unexpected allocation sequence; review the fixture");
    check(!probe.double_release, "copied secret released twice");
    const std::size_t copied = fail_at != 0 ? std::min<std::size_t>(fail_at - 1U, 3U) : 3U;
    for (std::size_t i = 0; i < probe.secrets.size(); ++i) {
        const auto& allocation = probe.secrets[i];
        check((allocation.data != nullptr) == (i < copied), "copied buffer was not observed");
        if (i < copied) {
            check(allocation.released, "copied secret allocation leaked");
            check(allocation.wiped_before_release, "secret bytes survived deallocation");
        }
    }
    if (!move || caught) {
        check_secrets(source);
    } else {
        check(source.auth_private_key_pem.empty() && source.obfs_secret.empty() &&
                  source.inner_psk.empty(), "successful move retained source secrets");
    }
}

}  // namespace

// Isolate allocation interception in this executable. Quarantine copied
// buffers after checking them at delete entry: a regressed constructor's late
// cleanup cannot make the observation pass by wiping already-released storage.
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmismatched-new-delete"
#endif

void* operator new(std::size_t size) {
    auto* probe = active_probe;
    const bool tracked = probe && probe->enabled && size > kSecretBytes;
    if (tracked) {
        ++probe->attempts;
        if (probe->attempts == probe->fail_at) {
            probe->enabled = false;
            probe->failed = true;
            throw std::bad_alloc();
        }
    }
    void* data = std::malloc(size == 0 ? 1 : size);
    if (!data) throw std::bad_alloc();
    if (tracked && probe->attempts <= probe->secrets.size()) {
        probe->secrets[probe->attempts - 1U].data = data;
    }
    return data;
}

void* operator new[](std::size_t size) { return ::operator new(size); }

void operator delete(void* data) noexcept {
    if (data && active_probe) {
        for (auto& allocation : active_probe->secrets) {
            if (allocation.data != data) continue;
            if (allocation.released) {
                active_probe->double_release = true;
                return;
            }
            const auto* bytes = static_cast<const unsigned char*>(data);
            allocation.wiped_before_release =
                std::all_of(bytes, bytes + kSecretBytes, [](unsigned char c) { return c == 0; });
            allocation.released = true;
            return;
        }
    }
    std::free(data);
}

void operator delete[](void* data) noexcept { ::operator delete(data); }
void operator delete(void* data, std::size_t) noexcept { ::operator delete(data); }
void operator delete[](void* data, std::size_t) noexcept { ::operator delete(data); }

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

int main() {
    for (std::size_t fail_at = 0; fail_at <= 4; ++fail_at) {
        test_construction(false, fail_at);
        if (fail_at <= 3) test_construction(true, fail_at);
    }
    std::puts("share bundle lifetime: 9 copy/move success and allocation-failure cases passed");
}
