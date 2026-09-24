/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include <sys/types.h>

#include "engine/status.hpp"

namespace yume::providers {

// Owns one file descriptor and closes it on destruction.
class Descriptor final {
public:
    explicit Descriptor(int value = -1) noexcept : value_(value) {}
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    Descriptor(Descriptor&& other) noexcept : value_(other.release()) {}
    Descriptor& operator=(Descriptor&& other) noexcept {
        if (this != &other) {
            reset();
            value_ = other.release();
        }
        return *this;
    }
    ~Descriptor() { reset(); }

    int get() const noexcept { return value_; }
    int release() noexcept { return std::exchange(value_, -1); }
    void reset() noexcept;

private:
    int value_;
};

// The descriptor number at which a spawned child receives its passed descriptor.
inline constexpr int kPassedDescriptor = 3;

// Checks a program this process is about to run: the running executable
// itself as /proc/self/exe, or an absolute path to a regular executable file
// owned by root or this user, not writable by group or others, and neither
// set-ID nor carrying file capabilities. name begins the diagnostics, as in
// "resolver helper".
engine::Status validate_program(const std::filesystem::path& program,
                                std::string_view name) noexcept;

// A child started with posix_spawn. Its descriptor 0 is /dev/null, 1 and 2 are
// inherited, the passed descriptor becomes kPassedDescriptor and every other
// descriptor is closed. It inherits this process's environment and starts with
// default signal handling, an empty signal mask and its own process group, so
// terminal signals reach only the parent. A pidfd names it for signals, so a
// signal never reaches an unrelated process that reused the PID after a host
// reaped the child itself, for example by ignoring SIGCHLD.
class ChildProcess final {
public:
    // arguments[0] becomes the child's argv[0]. Spawning needs glibc 2.34 for
    // its descriptor-closing action, and fails closed without it.
    static engine::Result<ChildProcess> spawn(const std::filesystem::path& program,
                                              std::span<const std::string> arguments,
                                              int passed_descriptor);

    ChildProcess() noexcept = default;
    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;
    ChildProcess(ChildProcess&& other) noexcept;
    ChildProcess& operator=(ChildProcess&& other) noexcept;
    // Kills and reaps a child that is still running.
    ~ChildProcess();

    bool running() const noexcept { return pid_ > 0; }
    pid_t pid() const noexcept { return pid_; }
    // Readable once the child has exited. -1 where the kernel has no pidfd.
    int pidfd() const noexcept { return pidfd_; }
    void signal(int number) noexcept;
    // Reaps the child if it has exited, without waiting, and returns its wait
    // status. The PID and pidfd are released then.
    std::optional<int> try_reap() noexcept;
    // Sends SIGKILL and waits for the child to exit.
    void kill_and_reap() noexcept;

private:
    void release() noexcept;

    pid_t pid_{-1};
    int pidfd_{-1};
};

}  // namespace yume::providers
