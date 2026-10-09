/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// yume-setup and yume-doctor keep secrets in wiped storage on every path.
// Each case sweeps one allocation failure across every allocation an
// operation makes, each in a child process, then lets it complete, and
// checks every heap buffer as it is released: none may still hold a private
// key's PEM text or a known secret. A child may end in std::terminate when
// the failure lands in nlohmann's destructors, which allocate. A kit
// directory must stay unpublished, and its staging directory removed, either
// way. tests/test_yume_setup.py and tests/test_yume_doctor.py hold the
// programs' behavior.

#include <array>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <new>
#include <string>
#include <string_view>
#include <optional>
#include <system_error>

#include <sys/wait.h>
#include <unistd.h>

#include "setup/actions.hpp"
#include "setup/doctor.hpp"
#include "setup/files.hpp"
#include "setup/material.hpp"
#include "setup/provision.hpp"
#include "test_support/allocation_failure.hpp"

namespace {

namespace fs = std::filesystem;
using namespace yume::setup;

int failures = 0;

void expect(bool condition, const char* what) {
    if (condition) return;
    std::fprintf(stderr, "FAILED: %s\n", what);
    ++failures;
}

// Live allocations and their sizes, in fixed storage, so the hooks never
// allocate.
struct Allocation final {
    void* storage;
    std::size_t size;
};
std::array<Allocation, 1U << 16U> live{};
// What no released buffer may hold.
constexpr std::string_view kPrivatePem = "PRIVATE KEY-----";
std::array<unsigned char, 32> secret{};
bool secret_armed = false;
bool leaked = false;
bool table_full = false;

std::size_t slot(void* storage) noexcept {
    return (reinterpret_cast<std::uintptr_t>(storage) >> 4U) &
           (live.size() - 1U);
}

void record(void* storage, std::size_t size) noexcept {
    for (std::size_t probe = 0, index = slot(storage); probe < live.size();
         ++probe, index = (index + 1U) & (live.size() - 1U)) {
        if (live[index].storage == nullptr) {
            live[index] = {storage, size};
            return;
        }
    }
    table_full = true;
}

bool holds(const unsigned char* bytes, std::size_t size, const void* needle,
           std::size_t length) noexcept {
    if (length == 0U || size < length) return false;
    for (std::size_t offset = 0; offset + length <= size; ++offset) {
        if (std::memcmp(bytes + offset, needle, length) == 0) return true;
    }
    return false;
}

void inspect(void* storage) noexcept {
    if (storage == nullptr) return;
    for (std::size_t probe = 0, index = slot(storage); probe < live.size();
         ++probe, index = (index + 1U) & (live.size() - 1U)) {
        if (live[index].storage == nullptr) return;
        if (live[index].storage != storage) continue;
        const auto* bytes = static_cast<const unsigned char*>(storage);
        const auto size = live[index].size;
        if (holds(bytes, size, kPrivatePem.data(), kPrivatePem.size()) ||
            (secret_armed &&
             holds(bytes, size, secret.data(), secret.size()))) {
            leaked = true;
        }
        // Remove the entry and reinsert the run after it, which keeps the
        // open-addressed table without tombstones.
        live[index] = {};
        for (auto next = (index + 1U) & (live.size() - 1U);
             live[next].storage != nullptr;
             next = (next + 1U) & (live.size() - 1U)) {
            const auto moved = live[next];
            live[next] = {};
            record(moved.storage, moved.size);
        }
        return;
    }
}

fs::path scratch;

bool empty_directory(const fs::path& directory) {
    std::error_code error;
    if (fs::is_empty(directory, error) && !error) return true;
    for (const auto& entry : fs::directory_iterator(directory, error)) {
        std::fprintf(stderr, "left behind: %s\n", entry.path().c_str());
    }
    return false;
}

// How one child run of an operation ended.
enum class Outcome {
    // The armed allocation never came, and the operation completed.
    Completed,
    // The armed allocation failed, and the operation threw.
    Failed,
    // A library destructor failed to allocate and ended the process through
    // std::terminate. nlohmann's destructors allocate a work stack.
    Terminated,
};

// The child's exit codes besides Completed and Failed.
constexpr int kExitLeaked = 3;
constexpr int kExitUnexpected = 4;

[[noreturn]] void leaked_exit() noexcept {
    std::_Exit(kExitLeaked);
}

void inspect_and_exit(void* storage) noexcept {
    inspect(storage);
    if (leaked || table_full) leaked_exit();
}

// Runs operation in a child with the nth allocation failing. A released
// buffer that still holds a secret ends the child at once.
int last_status = 0;

template <typename Operation>
std::optional<Outcome> run_child(std::size_t nth, Operation& operation) {
    std::fflush(nullptr);
    const pid_t child = ::fork();
    if (child < 0) return std::nullopt;
    if (child == 0) {
        remove_staging_on_terminate();
        live.fill({});
        yume::test::after_allocate = record;
        yume::test::before_deallocate = inspect_and_exit;
        yume::test::arm_allocation_failure(nth);
        int code = kExitUnexpected;
        bool threw = false;
        try {
            operation();
        } catch (const std::bad_alloc&) {
            threw = true;
        } catch (const SetupError&) {
            // A reader that reports any failure in its own words.
            threw = true;
        } catch (...) {
            std::_Exit(kExitUnexpected);
        }
        const bool fired = yume::test::disarm_allocation_failure();
        if (fired && threw) code = 1;
        if (!fired && !threw) code = 0;
        std::_Exit(code);
    }
    int status = 0;
    if (::waitpid(child, &status, 0) != child) return std::nullopt;
    last_status = status;
    if (WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT)
        return Outcome::Terminated;
    if (!WIFEXITED(status)) return std::nullopt;
    switch (WEXITSTATUS(status)) {
        case 0:
            return Outcome::Completed;
        case 1:
            return Outcome::Failed;
        default:
            return std::nullopt;
    }
}

// Runs operation once per allocation it makes, failing that allocation, and
// then once more without a failure. after sees each outcome.
template <typename Operation, typename After>
void sweep(const char* name, Operation&& operation, After&& after) {
    std::size_t failed = 0;
    std::size_t terminated = 0;
    for (std::size_t nth = 1;; ++nth) {
        const auto outcome = run_child(nth, operation);
        if (!outcome) {
            std::fprintf(stderr,
                         "FAILED: %s leaked a secret or failed unexpectedly at "
                         "allocation %zu "
                         "(wait status %#x)\n",
                         name, nth, static_cast<unsigned>(last_status));
            ++failures;
            return;
        }
        after(*outcome);
        if (*outcome == Outcome::Completed) break;
        ++(*outcome == Outcome::Failed ? failed : terminated);
    }
    std::printf("%s: %zu allocation failures handled, %zu ended in terminate\n",
                name, failed, terminated);
    expect(failed > 0U, name);
}

void test_generated_keys() {
    const Material material;
    sweep(
        "key generation",
        [&] {
            auto identity = material.composite();
            auto kem = material.mlkem();
            auto tls = material.tls("setup.example.test");
            yume::test::keep_contents(identity.private_pem.data());
            yume::test::keep_contents(kem.private_pem.data());
            yume::test::keep_contents(tls.key_pem.data());
        },
        [](Outcome outcome) {
            expect(outcome != Outcome::Terminated,
                   "key generation never terminates");
        });
}

void test_init_publishes_nothing_on_failure() {
    const auto parent = scratch / "init";
    fs::create_directory(parent);
    // The arguments exist before the sweep arms, so it measures init alone.
    InitOptions options;
    options.host = "setup.example.test";
    options.output = parent / "kit";
    options.preset = default_preset();
    sweep(
        "init", [&] { static_cast<void>(init_kit(options)); },
        [&](Outcome outcome) {
            if (outcome == Outcome::Completed) {
                expect(fs::is_directory(parent / "kit/server/credentials"),
                       "init writes a kit");
            } else {
                expect(empty_directory(parent),
                       "an init that fails leaves nothing behind");
            }
        });
}

void test_secret_copy_is_wiped() {
    const auto source = scratch / "secret.key";
    for (std::size_t index = 0; index < secret.size(); ++index) {
        secret[index] = static_cast<unsigned char>(0xA5U ^ (index * 7U));
    }
    write_new_file(source, secret);
    secret_armed = true;
    const auto destination = scratch / "copied.key";
    sweep(
        "secret copy", [&] { copy_private_file(source, destination); },
        [&](Outcome outcome) {
            expect(outcome != Outcome::Terminated,
                   "a secret copy never terminates");
            if (outcome == Outcome::Completed) {
                expect(read_secret(destination, 64).size() == secret.size(),
                       "the copy is whole");
            } else {
                expect(!fs::exists(destination),
                       "a failed copy leaves no file");
            }
            remove_file(destination);
        });
    secret_armed = false;
}

void test_doctor_wipes_what_it_reads() {
    const auto kit = scratch / "init/kit";
    const auto psk = read_secret(kit / "server/credentials/admission.key", 32);
    expect(psk.size() == secret.size(), "the kit has an admission key");
    std::memcpy(secret.data(), psk.bytes().data(), secret.size());
    secret_armed = true;
    for (const auto* config : {"server/yumed.json", "client/yume.json"}) {
        const auto path = kit / config;
        sweep(
            "doctor",
            [&] {
                const auto report = diagnose(path);
                if (!report.diagnostics.empty())
                    throw SetupError(report.diagnostics[0].detail);
            },
            [](Outcome) {});
    }
    secret_armed = false;
}

}  // namespace

int main() {
    std::string pattern =
        (fs::temp_directory_path() / "yume-setup-test-XXXXXX").string();
    if (::mkdtemp(pattern.data()) == nullptr) {
        std::perror("mkdtemp");
        return 1;
    }
    scratch = pattern;
    try {
        test_generated_keys();
        test_init_publishes_nothing_on_failure();
        test_secret_copy_is_wiped();
        test_doctor_wipes_what_it_reads();
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAILED: unexpected %s\n", error.what());
        ++failures;
    }
    std::error_code ignored;
    fs::remove_all(scratch, ignored);
    if (failures != 0) return 1;
    std::puts("yume setup allocation-failure tests passed");
    return 0;
}
