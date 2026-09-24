/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/child_process.hpp"

#include <cerrno>
#include <csignal>
#include <new>
#include <string>
#include <vector>

#include <fcntl.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/xattr.h>
#endif

extern char** environ;

namespace yume::providers {
namespace {
using engine::Result;
using engine::Status;
using engine::StatusCode;

// glibc 2.34 added the descriptor-closing spawn action. Without it a child
// would inherit every descriptor lacking FD_CLOEXEC, including accepted
// connections, and keep them open after this process closes them.
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 34))
constexpr bool kSpawnSupported = true;
#else
constexpr bool kSpawnSupported = false;
#endif

constexpr std::string_view kSelfProgram = "/proc/self/exe";

Status diagnostic(StatusCode code, std::string_view name, std::string_view detail) noexcept {
    try {
        std::string message(name);
        message += detail;
        return Status(code, message);
    } catch (...) {
        return Status(code);
    }
}

class SpawnSetup final {
public:
    SpawnSetup() noexcept {
        actions_ready_ = ::posix_spawn_file_actions_init(&actions_) == 0;
        attributes_ready_ = ::posix_spawnattr_init(&attributes_) == 0;
    }
    SpawnSetup(const SpawnSetup&) = delete;
    SpawnSetup& operator=(const SpawnSetup&) = delete;
    ~SpawnSetup() {
        if (actions_ready_) (void)::posix_spawn_file_actions_destroy(&actions_);
        if (attributes_ready_) (void)::posix_spawnattr_destroy(&attributes_);
    }

    bool prepare(int passed) noexcept {
        if (!actions_ready_ || !attributes_ready_) return false;
        sigset_t empty;
        sigset_t all;
        sigemptyset(&empty);
        sigfillset(&all);
        bool ok = ::posix_spawn_file_actions_addopen(
                      &actions_, 0, "/dev/null", O_RDONLY, 0) == 0 &&
                  ::posix_spawn_file_actions_adddup2(&actions_, passed, kPassedDescriptor) == 0;
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 34))
        ok = ok && ::posix_spawn_file_actions_addclosefrom_np(
                       &actions_, kPassedDescriptor + 1) == 0;
#else
        ok = false;
#endif
        return ok &&
               ::posix_spawnattr_setflags(&attributes_,
                   POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETPGROUP) == 0 &&
               ::posix_spawnattr_setsigmask(&attributes_, &empty) == 0 &&
               ::posix_spawnattr_setsigdefault(&attributes_, &all) == 0 &&
               ::posix_spawnattr_setpgroup(&attributes_, 0) == 0;
    }

    const posix_spawn_file_actions_t* actions() const noexcept { return &actions_; }
    const posix_spawnattr_t* attributes() const noexcept { return &attributes_; }

private:
    posix_spawn_file_actions_t actions_{};
    posix_spawnattr_t attributes_{};
    bool actions_ready_{false};
    bool attributes_ready_{false};
};

}  // namespace

void Descriptor::reset() noexcept {
    if (value_ >= 0) ::close(value_);
    value_ = -1;
}

Status validate_program(const std::filesystem::path& program, std::string_view name) noexcept {
    if (program.native() == kSelfProgram) return Status::success();
    if (!program.is_absolute()) return diagnostic(StatusCode::InvalidArgument, name, " path must be absolute");
    struct stat status {};
    if (::lstat(program.c_str(), &status) != 0)
        return diagnostic(StatusCode::FailedPrecondition, name, " is missing");
    if (!S_ISREG(status.st_mode))
        return diagnostic(StatusCode::FailedPrecondition, name, " is not a regular file");
    if ((status.st_mode & (S_IWGRP | S_IWOTH)) != 0U ||
        (status.st_uid != 0U && status.st_uid != ::geteuid()))
        return diagnostic(StatusCode::PermissionDenied, name,
                          " must be owned by root or this user and not writable by others");
    if (::access(program.c_str(), X_OK) != 0)
        return diagnostic(StatusCode::PermissionDenied, name, " is not executable");
    // Running a set-ID program, or one with file capabilities, is a privileged
    // exec even under no_new_privs, which gains nothing yet still clears
    // settings such as a module's parent-death signal.
    if ((status.st_mode & (S_ISUID | S_ISGID)) != 0U)
        return diagnostic(StatusCode::PermissionDenied, name, " must not be set-user-ID or set-group-ID");
#if defined(__linux__)
    if (::lgetxattr(program.c_str(), "security.capability", nullptr, 0U) >= 0)
        return diagnostic(StatusCode::PermissionDenied, name, " must not have file capabilities");
    if (errno != ENODATA && errno != ENOTSUP)
        return diagnostic(StatusCode::PermissionDenied, name, " file capabilities could not be read");
#endif
    return Status::success();
}

Result<ChildProcess> ChildProcess::spawn(const std::filesystem::path& program,
                                         std::span<const std::string> arguments,
                                         int passed_descriptor) {
    using Spawned = Result<ChildProcess>;
    if (!kSpawnSupported)
        return Spawned(diagnostic(StatusCode::FailedPrecondition, "process spawning",
                                  " needs glibc 2.34 or newer"));
    if (arguments.empty() || passed_descriptor < 0) return Spawned(Status(StatusCode::InvalidArgument));
    try {
        // dup2 onto an equal descriptor would keep FD_CLOEXEC set. A copy
        // above the target makes the spawn action always clear it.
        Descriptor copy(::fcntl(passed_descriptor, F_DUPFD_CLOEXEC, kPassedDescriptor + 1));
        if (copy.get() < 0) return Spawned(Status(StatusCode::ResourceExhausted));
        SpawnSetup setup;
        if (!setup.prepare(copy.get())) return Spawned(Status(StatusCode::ResourceExhausted));
        std::string path = program.string();
        std::vector<std::string> owned(arguments.begin(), arguments.end());
        std::vector<char*> argv;
        argv.reserve(owned.size() + 1U);
        for (auto& argument : owned) argv.push_back(argument.data());
        argv.push_back(nullptr);
        pid_t pid = -1;
        const int error = ::posix_spawn(&pid, path.c_str(), setup.actions(), setup.attributes(),
                                        argv.data(), environ);
        if (error != 0)
            return Spawned(Status(error == ENOMEM || error == EAGAIN ? StatusCode::ResourceExhausted
                                                                     : StatusCode::FailedPrecondition));
        ChildProcess child;
        child.pid_ = pid;
#if defined(SYS_pidfd_open)
        child.pidfd_ = static_cast<int>(::syscall(SYS_pidfd_open, pid, 0));
#endif
        return Spawned(std::move(child));
    } catch (const std::bad_alloc&) {
        return Spawned(Status(StatusCode::ResourceExhausted));
    }
}

ChildProcess::ChildProcess(ChildProcess&& other) noexcept
    : pid_(std::exchange(other.pid_, -1)), pidfd_(std::exchange(other.pidfd_, -1)) {}

ChildProcess& ChildProcess::operator=(ChildProcess&& other) noexcept {
    if (this != &other) {
        kill_and_reap();
        pid_ = std::exchange(other.pid_, -1);
        pidfd_ = std::exchange(other.pidfd_, -1);
    }
    return *this;
}

ChildProcess::~ChildProcess() { kill_and_reap(); }

void ChildProcess::signal(int number) noexcept {
    if (pid_ <= 0) return;
#if defined(SYS_pidfd_send_signal)
    if (pidfd_ >= 0) {
        (void)::syscall(SYS_pidfd_send_signal, pidfd_, number, nullptr, 0U);
        return;
    }
#endif
    (void)::kill(pid_, number);
}

std::optional<int> ChildProcess::try_reap() noexcept {
    if (pid_ <= 0) return std::nullopt;
    int status = 0;
    pid_t reaped = -1;
    do {
        reaped = ::waitpid(pid_, &status, WNOHANG);
    } while (reaped < 0 && errno == EINTR);
    if (reaped == 0) return std::nullopt;
    // Also after ECHILD, when a host reaped the child itself.
    const bool own = reaped == pid_;
    release();
    return own ? status : 0;
}

void ChildProcess::kill_and_reap() noexcept {
    if (pid_ <= 0) return;
    signal(SIGKILL);
    int status = 0;
    while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {
    }
    release();
}

void ChildProcess::release() noexcept {
    if (pidfd_ >= 0) ::close(pidfd_);
    pidfd_ = -1;
    pid_ = -1;
}

}  // namespace yume::providers
