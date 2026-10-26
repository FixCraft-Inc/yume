/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <string_view>

#include <unistd.h>

// Exercise the private transaction owner without generating a whole cluster
// for every allocation. The linked archive supplies the other setup units.
#include "setup/cluster.cpp"
#include "test_support/allocation_failure.hpp"

namespace {
namespace fs = std::filesystem;
using namespace yume::setup;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

const char* close_target = nullptr;
bool close_seen = false;
const char* chmod_target = nullptr;

template <typename Operation>
void rollback_sweep(const fs::path& root, const char* name,
                    Operation operation) {
    bool completed = false;
    std::size_t failures = 0;
    for (std::size_t nth = 1; nth <= 256; ++nth) {
        bool threw = false;
        {
            Changes changes;
            yume::test::arm_allocation_failure(nth);
            try {
                operation(changes);
            } catch (const std::bad_alloc&) {
                threw = true;
            }
            const bool fired = yume::test::disarm_allocation_failure();
            require(fired == threw, "unexpected transaction sweep outcome");
            completed = !fired;
        }
        require(fs::is_empty(root),
                "transaction rollback left a created object");
        if (completed) break;
        ++failures;
    }
    require(completed && failures > 0, "transaction sweep did not complete");
    std::printf("%s: %zu allocation failures and success rolled back\n", name,
                failures);
}

void test_changes(const fs::path& scratch) {
    const auto root = scratch / "transaction";
    make_private_directory(root);
    const auto directory = root / "nested" / "directory";
    const auto file = root / "created-file";
    const auto source = scratch / "copy-source";
    const auto target = root / "replacement";
    const auto bytes = as_bytes("transaction contents");
    write_new_file(source, bytes);
    const Owner owner = owner_of(root);
    rollback_sweep(root, "directory", [&](Changes& changes) {
        changes.directory(directory, owner);
    });
    rollback_sweep(root, "create", [&](Changes& changes) {
        changes.create(file, bytes, owner);
    });
    rollback_sweep(root, "copy", [&](Changes& changes) {
        changes.copy(source, file, owner);
    });
    rollback_sweep(root, "replace", [&](Changes& changes) {
        changes.replace(target, "replacement contents", owner);
    });
    write_new_file(file, bytes);
    bool refused = false;
    try {
        Changes changes;
        changes.create(file, as_bytes("overwrite"), owner);
    } catch (const SetupError&) {
        refused = true;
    }
    require(refused && read_ascii(file) == "transaction contents",
            "exclusive-create refusal deleted an existing file");
}

void test_directory_protection_failure(const fs::path& scratch) {
    const auto path = scratch / "unprotected";
    chmod_target = path.c_str();
    bool refused = false;
    try {
        make_private_directory(path);
    } catch (const SetupError&) {
        refused = true;
    }
    chmod_target = nullptr;
    require(refused && !fs::exists(path),
            "directory protection failure left a created directory");
}

void test_add_client(const fs::path& scratch) {
    InitOptions init;
    init.host = "setup.example.test";
    init.output = scratch / "kit";
    init.preset = default_preset();
    const auto kit = init_kit(init);
    const auto authorized = kit / "server/credentials/authorized";
    const auto store_path = kit / "server/credentials/authorized-keys.json";
    const auto original_store = read_ascii(store_path);
    for (const auto* suffix : {"-composite.pub.pem", "-access.psk"}) {
        AddClientOptions add;
        add.server = kit / "server";
        add.host = init.host;
        add.client_name = "additional";
        add.output = scratch / "additional";
        const auto public_path = authorized / "additional-composite.pub.pem";
        const auto psk_path = authorized / "additional-access.psk";
        const auto inject_path = authorized / (add.client_name + suffix);
        close_seen = false;
        close_target = inject_path.c_str();
        bool threw = false;
        try {
            static_cast<void>(add_client(add));
        } catch (const std::bad_alloc&) {
            threw = true;
        }
        close_target = nullptr;
        const bool fired = yume::test::disarm_allocation_failure();
        require(close_seen && fired && threw,
                "add-client injection did not fire");
        require(!fs::exists(public_path) && !fs::exists(psk_path) &&
                    !fs::exists(add.output),
                "add-client rollback orphaned authorization or client files");
        require(read_ascii(store_path) == original_store,
                "failed add-client changed the authorization store");
    }
    std::puts(
        "add-client: post-public-key and post-PSK allocation failures rolled "
        "back");
}
}  // namespace

extern "C" int __real_chmod(const char* path, mode_t mode);
extern "C" int __wrap_chmod(const char* path, mode_t mode) {
    if (chmod_target && std::strcmp(path, chmod_target) == 0) {
        errno = EACCES;
        return -1;
    }
    return __real_chmod(path, mode);
}

extern "C" int __real_close(int fd);
extern "C" int __wrap_close(int fd) {
    bool matched = false;
    if (close_target) {
        char descriptor[64];
        char target[4096];
        const int length = std::snprintf(descriptor, sizeof(descriptor),
                                         "/proc/self/fd/%d", fd);
        if (length > 0 &&
            static_cast<std::size_t>(length) < sizeof(descriptor)) {
            const auto count = ::readlink(descriptor, target, sizeof(target));
            matched =
                count >= 0 &&
                static_cast<std::size_t>(count) == std::strlen(close_target) &&
                std::memcmp(target, close_target,
                            static_cast<std::size_t>(count)) == 0;
        }
    }
    const int result = __real_close(fd);
    if (matched && result == 0) {
        close_target = nullptr;
        close_seen = true;
        yume::test::arm_allocation_failure(1U);
    }
    return result;
}

int main() {
    char pattern[] = "/tmp/yume-transaction-test-XXXXXX";
    if (!::mkdtemp(pattern)) return 1;
    const fs::path scratch(pattern);
    int result = 0;
    try {
        test_changes(scratch);
        test_directory_protection_failure(scratch);
        test_add_client(scratch);
        std::puts("setup transaction tests passed");
    } catch (const std::exception& error) {
        static_cast<void>(yume::test::disarm_allocation_failure());
        std::fprintf(stderr, "FAILED: %s\n", error.what());
        result = 1;
    }
    remove_tree(scratch);
    return result;
}
