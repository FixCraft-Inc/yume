/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/process_privileges.hpp"

#if defined(__linux__)
#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace yume::providers {

void drop_process_privileges() noexcept {
#if defined(__linux__)
    (void)::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
#if defined(PR_CAP_AMBIENT)
    (void)::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
#endif
    __user_cap_header_struct header{};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;
    __user_cap_data_struct data[_LINUX_CAPABILITY_U32S_3]{};
    (void)::syscall(SYS_capset, &header, data);
#endif
}

}  // namespace yume::providers
