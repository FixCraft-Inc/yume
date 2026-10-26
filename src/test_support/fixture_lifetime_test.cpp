/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <stdexcept>
#include <string_view>

#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test_support/allocation_failure.hpp"
#include "test_support/circuit_fixtures.hpp"
#include "test_support/socket_activated_module.hpp"

namespace {
enum class Failure { None, PathAllocation, Socket, Bind, Chmod, Listen };
Failure failure = Failure::None;
char created_directory[128]{};

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void test_module_construction() {
    for (const auto point :
         {Failure::PathAllocation, Failure::Socket, Failure::Bind,
          Failure::Chmod, Failure::Listen, Failure::None}) {
        failure = point;
        created_directory[0] = '\0';
        bool threw = false;
        try {
            yume::test::SocketActivatedModule module;
            require(std::filesystem::is_socket(module.socket),
                    "successful fixture has no socket");
        } catch (const std::bad_alloc&) {
            require(point == Failure::PathAllocation,
                    "unexpected allocation failure");
            threw = true;
        } catch (const std::runtime_error&) {
            threw = true;
        }
        static_cast<void>(yume::test::disarm_allocation_failure());
        failure = Failure::None;
        require(threw == (point != Failure::None), "fixture injection missed");
        require(created_directory[0] != '\0', "fixture never made a directory");
        const bool removed = !std::filesystem::exists(created_directory);
        // Keep even a failing removed-fix control from leaving /tmp debris.
        if (!removed) std::filesystem::remove_all(created_directory);
        require(removed,
                "failed fixture construction leaked its directory/socket");
    }
    std::puts(
        "module fixture: allocation/socket/bind/chmod/listen failures cleaned");
}

void test_handler_exception() {
    const pid_t child = ::fork();
    require(child >= 0, "fork failed");
    if (child == 0) {
        const rlimit no_core{0, 0};
        static_cast<void>(::setrlimit(RLIMIT_CORE, &no_core));
        yume::test::IoRuntime io;
        boost::asio::post(io.context()->executor(), [] {
            throw std::runtime_error("intentional uncaught handler failure");
        });
        io.sync([] {});
        std::_Exit(0);
    }
    int status = 0;
    require(::waitpid(child, &status, 0) == child, "waitpid failed");
    require(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT,
            "unexpected handler exception was swallowed by fixture");
    yume::test::IoRuntime io;
    bool caught = false;
    try {
        io.sync([] { throw std::runtime_error("expected task failure"); });
    } catch (const std::runtime_error&) {
        caught = true;
    }
    require(caught && io.sync([] { return 42; }) == 42,
            "packaged-task exception did not reach its caller");
    std::puts(
        "circuit fixture: handler failure aborts, task exception reaches "
        "caller");
}
}  // namespace

extern "C" char* __real_mkdtemp(char* pattern);
extern "C" char* __wrap_mkdtemp(char* pattern) {
    char* result = __real_mkdtemp(pattern);
    if (result) {
        std::snprintf(created_directory, sizeof(created_directory), "%s",
                      result);
        if (failure == Failure::PathAllocation)
            yume::test::arm_allocation_failure(1U);
    }
    return result;
}
extern "C" int __real_socket(int domain, int type, int protocol);
extern "C" int __wrap_socket(int domain, int type, int protocol) {
    if (failure == Failure::Socket) {
        errno = EMFILE;
        return -1;
    }
    return __real_socket(domain, type, protocol);
}
extern "C" int __real_bind(int fd, const sockaddr* address, socklen_t size);
extern "C" int __wrap_bind(int fd, const sockaddr* address, socklen_t size) {
    if (failure == Failure::Bind) {
        errno = EACCES;
        return -1;
    }
    return __real_bind(fd, address, size);
}
extern "C" int __real_chmod(const char* path, mode_t mode);
extern "C" int __wrap_chmod(const char* path, mode_t mode) {
    if (failure == Failure::Chmod) {
        errno = EACCES;
        return -1;
    }
    return __real_chmod(path, mode);
}
extern "C" int __real_listen(int fd, int backlog);
extern "C" int __wrap_listen(int fd, int backlog) {
    if (failure == Failure::Listen) {
        errno = EIO;
        return -1;
    }
    return __real_listen(fd, backlog);
}

int main(int argc, char** argv) {
    try {
        const std::string_view selected = argc == 2 ? argv[1] : "all";
        if (selected == "all" || selected == "module")
            test_module_construction();
        if (selected == "all" || selected == "handler")
            test_handler_exception();
        std::puts("fixture lifetime tests passed");
        return 0;
    } catch (const std::exception& error) {
        std::fprintf(stderr, "FAILED: %s\n", error.what());
        return 1;
    }
}
