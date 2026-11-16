/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Model refused privilege drops and read-back outcomes without root or real
// capability changes. The existing resolver test checks the real helper's
// kernel state. This test checks refusal before its first protocol message.
#include <array>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

#include <fcntl.h>
#include <linux/capability.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "providers/system_resolver_helper.hpp"
#include "providers/system_resolver_protocol.hpp"

extern char** environ;

namespace {

enum class Outcome {
    Empty,
    Effective,
    Permitted,
    Inheritable,
    NoNewPrivilegesMissing,
    CapgetDenied,
    NoNewPrivilegesQueryDenied
};
Outcome outcome = Outcome::Empty;

void require(bool condition, const char* message) {
    if (condition) return;
    std::fprintf(stderr, "%s (outcome %d)\n", message,
                 static_cast<int>(outcome));
    std::abort();
}

class Descriptor final {
public:
    explicit Descriptor(int descriptor) noexcept : descriptor_(descriptor) {}
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    ~Descriptor() {
        if (descriptor_ >= 0) ::close(descriptor_);
    }
    int get() const noexcept { return descriptor_; }

private:
    int descriptor_;
};

class Child final {
public:
    explicit Child(pid_t pid) noexcept : pid_(pid) {}
    Child(const Child&) = delete;
    Child& operator=(const Child&) = delete;
    ~Child() {
        if (pid_ <= 0) return;
        (void)::kill(pid_, SIGKILL);
        while (::waitpid(pid_, nullptr, 0) < 0 && errno == EINTR) {
        }
    }
    int wait() {
        int status = 0;
        pid_t result;
        do {
            result = ::waitpid(pid_, &status, 0);
        } while (result < 0 && errno == EINTR);
        require(result == pid_, "cannot reap helper");
        pid_ = -1;
        return status;
    }

private:
    pid_t pid_;
};

void check_helper(Outcome expected) {
    namespace protocol = yume::providers::resolver_protocol;
    outcome = expected;
    std::array<int, 2> pair{-1, -1};
    require(::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
                         pair.data()) == 0,
            "cannot create helper socketpair");
    Descriptor parent(pair[0]);
    pid_t pid = -1;
    {
        Descriptor source(pair[1]);
        Descriptor passed(::fcntl(source.get(), F_DUPFD_CLOEXEC, 4));
        require(passed.get() >= 0, "cannot prepare helper descriptor");
        posix_spawn_file_actions_t actions{};
        require(::posix_spawn_file_actions_init(&actions) == 0,
                "cannot prepare helper actions");
        const int prepared = ::posix_spawn_file_actions_adddup2(
            &actions, passed.get(), protocol::kHelperDescriptor);
        std::string mode = std::to_string(static_cast<int>(expected));
        char image[] = "/proc/self/exe";
        char role[] = "--helper";
        char* arguments[]{image, role, mode.data(), nullptr};
        const int started = prepared == 0
                                ? ::posix_spawn(&pid, image, &actions, nullptr,
                                                arguments, environ)
                                : prepared;
        (void)::posix_spawn_file_actions_destroy(&actions);
        require(started == 0, "cannot start helper");
    }
    Child child(pid);
    pollfd ready{parent.get(), POLLIN, 0};
    int polled;
    do {
        polled = ::poll(&ready, 1, 2000);
    } while (polled < 0 && errno == EINTR);
    require(polled > 0, "helper neither exited nor became ready");
    std::array<std::uint8_t, protocol::kHelloBytes + 1U> message{};
    const auto count =
        ::recv(parent.get(), message.data(), message.size(), MSG_DONTWAIT);
    if (expected == Outcome::Empty) {
        require(
            count > 0 && protocol::valid_hello(std::span(
                             message.data(), static_cast<std::size_t>(count))),
            "already unprivileged helper was refused");
    } else {
        require(count == 0,
                "helper announced readiness without verified privilege drop");
        const int status = child.wait();
        require(WIFEXITED(status) && WEXITSTATUS(status) == 1,
                "helper privilege failure did not exit with failure");
    }
}

}  // namespace

extern "C" int __wrap_prctl(int option, ...) noexcept {
    if (option == PR_GET_NO_NEW_PRIVS) {
        if (outcome == Outcome::NoNewPrivilegesQueryDenied) {
            errno = EPERM;
            return -1;
        }
        return outcome == Outcome::NoNewPrivilegesMissing ? 0 : 1;
    }
    if (option == PR_CAP_AMBIENT) {
        va_list arguments;
        va_start(arguments, option);
        const int action = va_arg(arguments, int);
        va_end(arguments);
        require(action == PR_CAP_AMBIENT_CLEAR_ALL,
                "unexpected ambient operation");
    } else {
        require(option == PR_SET_NO_NEW_PRIVS, "unexpected prctl operation");
    }
    errno = EPERM;
    return -1;
}

extern "C" long __wrap_syscall(long number, ...) noexcept {
    require(number == SYS_capset || number == SYS_capget, "unexpected syscall");
    if (number == SYS_capset || outcome == Outcome::CapgetDenied) {
        errno = EPERM;
        return -1;
    }
    va_list arguments;
    va_start(arguments, number);
    (void)va_arg(arguments, __user_cap_header_struct*);
    auto* data = va_arg(arguments, __user_cap_data_struct*);
    va_end(arguments);
    for (std::size_t index = 0U; index < _LINUX_CAPABILITY_U32S_3; ++index)
        data[index] = {};
    data[0].effective = outcome == Outcome::Effective ? 1U : 0U;
    data[0].permitted = outcome == Outcome::Permitted ? 1U : 0U;
    data[0].inheritable = outcome == Outcome::Inheritable ? 1U : 0U;
    return 0;
}

int main(int argc, char** argv) {
    if (argc == 3 && std::strcmp(argv[1], "--helper") == 0) {
        outcome = static_cast<Outcome>(std::atoi(argv[2]));
        return yume::providers::run_system_resolver_helper();
    }
    require(argc == 1, "unexpected test arguments");
    for (const auto expected :
         {Outcome::Empty, Outcome::Effective, Outcome::Permitted,
          Outcome::Inheritable, Outcome::NoNewPrivilegesMissing,
          Outcome::CapgetDenied, Outcome::NoNewPrivilegesQueryDenied}) {
        check_helper(expected);
    }
    std::puts("resolver privilege outcomes: 7 passed");
}
