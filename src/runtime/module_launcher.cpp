/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/module_launcher.hpp"

#include <csignal>
#include <cstdio>

#include <sys/prctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include "providers/process_privileges.hpp"

namespace yume::runtime {
namespace {

constexpr int kModuleDescriptor = 3;
constexpr int kLaunchFailed = 127;

bool listening_unix_socket(int descriptor) noexcept {
    int value = 0;
    socklen_t length = sizeof(value);
    if (::getsockopt(descriptor, SOL_SOCKET, SO_DOMAIN, &value, &length) != 0 || value != AF_UNIX)
        return false;
    length = sizeof(value);
    if (::getsockopt(descriptor, SOL_SOCKET, SO_TYPE, &value, &length) != 0 || value != SOCK_STREAM)
        return false;
    length = sizeof(value);
    return ::getsockopt(descriptor, SOL_SOCKET, SO_ACCEPTCONN, &value, &length) == 0 &&
           value == 1;
}

// The process that called listen() on a listening socket, which SO_PEERCRED
// reports for it. Zero when unknown.
pid_t listener_process(int descriptor) noexcept {
    ucred credentials{};
    socklen_t length = sizeof(credentials);
    if (::getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
        length != sizeof(credentials))
        return 0;
    return credentials.pid;
}

}  // namespace

bool is_module_launcher(int argc, const char* const* argv) noexcept {
    return argc >= 2 && argv != nullptr && argv[0] != nullptr && argv[1] != nullptr &&
           std::string_view(argv[0]) == kModuleLauncherArgv0;
}

int run_module_launcher(int argc, char** argv) noexcept {
    if (!is_module_launcher(argc, argv) || !listening_unix_socket(kModuleDescriptor)) {
        std::fputs("yume-module: started without a module socket\n", stderr);
        return kLaunchFailed;
    }
    // The module ends with the daemon that supervises it, even when the daemon
    // is killed without a chance to stop it. The parent check after arming the
    // signal catches a daemon that died first. SIGKILL survives the execv
    // below, because no_new_privs keeps it from gaining privileges.
    const pid_t daemon = listener_process(kModuleDescriptor);
    if (daemon <= 0 || ::prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || ::getppid() != daemon) {
        std::fputs("yume-module: the supervising daemon is gone\n", stderr);
        return kLaunchFailed;
    }
    providers::drop_process_privileges();
    ::execv(argv[1], argv + 1);
    std::fprintf(stderr, "yume-module: cannot run %s\n", argv[1]);
    return kLaunchFailed;
}

}  // namespace yume::runtime
