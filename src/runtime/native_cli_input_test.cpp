/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Exercise the private input boundary without exposing terminal or allocator
// controls in the CLI interface. The archive's native_cli object is not linked.
#include "runtime/native_cli.cpp"
#include "test_support/allocation_failure.hpp"

#include <array>
#include <cstring>
#include <cstdlib>

namespace {
// A synthetic, valid code with extra permitted separators exceeds a string's
// first heap capacity on libstdc++, unlike the usual five-group display.
constexpr std::string_view kInput = "ABCDE - FGHJK - MNPQR - STVWX - YZ012\n";
std::size_t position = 0U;
std::size_t fail_read_at = std::string_view::npos;
bool terminal = false;
bool refuse_silence = false;
bool echo = true;
std::size_t echo_changes = 0U;
struct Allocation final {
    void* data{nullptr};
    std::size_t size{0U};
};
std::array<Allocation, 64U> allocations{};
std::size_t allocation_count = 0U;
std::size_t unwiped = 0U;

void check(bool condition, const char* message = "CLI input check failed") {
    if (!condition) {
        std::fputs(message, stderr);
        std::fputs("\n", stderr);
        std::abort();
    }
}

void allocated(void* data, std::size_t size) {
    check(allocation_count < allocations.size());
    allocations[allocation_count++] = {data, size};
}

void deallocating(void* data) noexcept {
    for (auto& allocation : allocations) {
        if (allocation.data != data) continue;
        if (allocation.size >= 16U &&
            std::memcmp(data, kInput.data(), 16U) == 0)
            ++unwiped;
        allocation.data = nullptr;
    }
}

void reset() {
    position = 0U;
    fail_read_at = std::string_view::npos;
    terminal = false;
    refuse_silence = false;
    echo = true;
    echo_changes = 0U;
}

void test_secret_storage() {
    reset();
    terminal = true;
    yume::test::after_allocate = allocated;
    yume::test::before_deallocate = deallocating;
    {
        auto code =
            yume::runtime::read_code_line(yume::runtime::NativeCliRole::Client);
        check(code && *code == kInput.substr(0U, kInput.size() - 1U));
        check(echo && echo_changes == 2U);
        const yume::security::ScopedErase guard(*code);
    }
    yume::test::after_allocate = nullptr;
    yume::test::before_deallocate = nullptr;
    check(unwiped == 0U, "released kit-code storage was not wiped");
}

void test_failure_before_input() {
    reset();
    terminal = true;
    yume::test::arm_allocation_failure(1U);
    bool refused = false;
    try {
        (void)yume::runtime::read_code_line(
            yume::runtime::NativeCliRole::Client);
    } catch (const std::bad_alloc&) {
        refused = true;
    }
    check(yume::test::disarm_allocation_failure());
    check(refused && position == 0U && echo && echo_changes == 0U);

    reset();
    terminal = true;
    refuse_silence = true;
    check(!yume::runtime::read_code_line(yume::runtime::NativeCliRole::Client));
    check(position == 0U && echo);
}

void test_read_failure() {
    reset();
    terminal = true;
    fail_read_at = 20U;
    check(!yume::runtime::read_code_line(yume::runtime::NativeCliRole::Client));
    check(position == fail_read_at && echo && echo_changes == 2U);
}
}  // namespace

extern "C" ssize_t __real_read(int fd, void* storage, size_t size);
extern "C" ssize_t __wrap_read(int fd, void* storage, size_t size) {
    if (fd != STDIN_FILENO) return __real_read(fd, storage, size);
    check(!terminal || !echo);
    if (position == fail_read_at) {
        errno = EIO;
        return -1;
    }
    if (position == kInput.size()) return 0;
    check(size > 0U);
    *static_cast<char*>(storage) = kInput[position++];
    return 1;
}

extern "C" int __wrap_isatty(int) noexcept {
    return terminal ? 1 : 0;
}
extern "C" int __wrap_tcgetattr(int, termios* settings) noexcept {
    *settings = {};
    settings->c_lflag = echo ? ECHO : 0;
    return 0;
}
extern "C" int __wrap_tcsetattr(int, int, const termios* settings) noexcept {
    const bool enabled = (settings->c_lflag & ECHO) != 0;
    if (!enabled && refuse_silence) {
        errno = EIO;
        return -1;
    }
    echo = enabled;
    ++echo_changes;
    return 0;
}

int main() {
    test_secret_storage();
    test_failure_before_input();
    test_read_failure();
    return EXIT_SUCCESS;
}
