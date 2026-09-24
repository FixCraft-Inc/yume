/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/child_process.hpp"

#include <array>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {
using yume::engine::StatusCode;
using yume::providers::ChildProcess;
using yume::providers::Descriptor;
using yume::providers::validate_program;

void check(bool condition, const char* description) {
    if (!condition) throw std::runtime_error(description);
}

struct Pipe final {
    Pipe() {
        int ends[2] = {-1, -1};
        check(::pipe2(ends, O_CLOEXEC) == 0, "pipe failed");
        read = Descriptor(ends[0]);
        write = Descriptor(ends[1]);
    }
    Descriptor read;
    Descriptor write;
};

ChildProcess spawn_shell(const std::string& script, int passed) {
    const std::vector<std::string> arguments{"sh", "-c", script};
    auto spawned = ChildProcess::spawn("/bin/sh", arguments, passed);
    check(spawned.ok(), "spawning the shell failed");
    return std::move(spawned).take_value();
}

// Waits for the pidfd to report the exit, then reaps.
int wait_status(ChildProcess& child) {
    check(child.pidfd() >= 0, "no pidfd for the child");
    pollfd ready{child.pidfd(), POLLIN, 0};
    check(::poll(&ready, 1, 10'000) == 1, "the child did not exit in time");
    const auto status = child.try_reap();
    check(status.has_value() && !child.running(), "an exited child was not reaped");
    return *status;
}

void test_exit_status_and_passed_descriptor() {
    Pipe pipe;
    auto child = spawn_shell(
        "[ -e /proc/self/fd/3 ] && [ ! -e /proc/self/fd/4 ] && printf ready >&3 && exit 7",
        pipe.write.get());
    check(child.running() && child.pid() > 0, "the child is not running");
    const int status = wait_status(child);
    check(WIFEXITED(status) && WEXITSTATUS(status) == 7,
          "descriptor 3 was missing or another descriptor leaked");
    pipe.write.reset();
    std::array<char, 8> text{};
    check(::read(pipe.read.get(), text.data(), text.size()) == 5 &&
              std::string(text.data(), 5) == "ready",
          "the passed descriptor was not descriptor 3");
    check(!child.try_reap(), "a reaped child was reaped again");
}

void test_signals_and_kill() {
    Pipe pipe;
    auto terminated = spawn_shell("exec sleep 30", pipe.write.get());
    check(!terminated.try_reap(), "a running child was reaped");
    terminated.signal(SIGTERM);
    const int status = wait_status(terminated);
    check(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM, "SIGTERM did not end the child");

    auto killed = spawn_shell("trap '' TERM; exec sleep 30", pipe.write.get());
    const auto started = std::chrono::steady_clock::now();
    killed.kill_and_reap();
    check(!killed.running() && killed.pidfd() < 0, "kill_and_reap left the child");
    check(std::chrono::steady_clock::now() - started < std::chrono::seconds(5),
          "kill_and_reap waited for the child to finish");

    auto owner = spawn_shell("exec sleep 30", pipe.write.get());
    const pid_t pid = owner.pid();
    ChildProcess moved = std::move(owner);
    check(!owner.running() && moved.running() && moved.pid() == pid,
          "moving did not transfer the child");
    {
        ChildProcess scoped = std::move(moved);
    }
    check(::kill(pid, 0) != 0, "destruction left a moved child running");
}

void test_spawn_failures() {
    Pipe pipe;
    const std::vector<std::string> arguments{"missing"};
    check(!ChildProcess::spawn("/nonexistent/program", arguments, pipe.write.get()).ok(),
          "a missing program started");
    check(ChildProcess::spawn("/bin/sh", {}, pipe.write.get()).status().code() ==
              StatusCode::InvalidArgument,
          "a spawn without argv[0] was accepted");
    check(ChildProcess::spawn("/bin/sh", arguments, -1).status().code() ==
              StatusCode::InvalidArgument,
          "a spawn without a passed descriptor was accepted");
}

void test_program_validation() {
    check(validate_program("/proc/self/exe", "helper").ok(), "the running program was refused");
    const auto shell = std::filesystem::canonical("/bin/sh");
    check(validate_program(shell, "helper").ok(), "a root-owned program was refused");
    if (std::filesystem::is_symlink("/bin/sh"))
        check(validate_program("/bin/sh", "helper").code() == StatusCode::FailedPrecondition,
              "a symbolic link was accepted as the program");
    check(validate_program("bin/sh", "helper").code() == StatusCode::InvalidArgument,
          "a relative path was accepted");
    check(validate_program("/nonexistent/program", "helper").code() == StatusCode::FailedPrecondition,
          "a missing program was accepted");
    check(validate_program("/tmp", "helper").code() == StatusCode::FailedPrecondition,
          "a directory was accepted");
    std::string directory = "/tmp/yume-child-XXXXXX";
    check(::mkdtemp(directory.data()) != nullptr, "mkdtemp failed");
    const auto program = std::filesystem::path(directory) / "program";
    std::ofstream(program) << "#!/bin/sh\n";
    ::chmod(program.c_str(), 0620);
    check(validate_program(program, "helper").code() == StatusCode::PermissionDenied,
          "a group-writable program was accepted");
    ::chmod(program.c_str(), 0600);
    check(validate_program(program, "helper").code() == StatusCode::PermissionDenied,
          "a program without execute permission was accepted");
    ::chmod(program.c_str(), 0700);
    check(validate_program(program, "helper").ok(), "a private executable was refused");
    for (const mode_t set_id : {S_ISUID, S_ISGID}) {
        struct stat status {};
        ::chmod(program.c_str(), 0700 | set_id);
        // An unprivileged chmod drops S_ISGID silently outside the file's group.
        if (::stat(program.c_str(), &status) == 0 && (status.st_mode & set_id) != 0U)
            check(validate_program(program, "helper").code() == StatusCode::PermissionDenied,
                  "a set-ID program was accepted");
    }
    ::chmod(program.c_str(), 0700);
    const auto message = validate_program("relative", "module program").message();
    check(message.rfind("module program", 0) == 0, "diagnostics did not name the program");
    std::filesystem::remove_all(directory);
}

}  // namespace

int main() {
    try {
        test_exit_status_and_passed_descriptor();
        test_signals_and_kill();
        test_spawn_failures();
        test_program_validation();
        std::cout << "child process tests passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "child process test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
