/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "yume/yume.h"

int main() {
    if (yume_abi_version() != YUME_ABI_VERSION) {
        return 1;
    }
    if (!yume_version() || !yume_basefwx_version()) {
        return 2;
    }
    if ((yume_feature_flags() & YUME_FEATURE_PBKDF2_HKDF) == 0) {
        return 3;
    }
    if (yume_get_build_info(nullptr, sizeof(yume_build_info)) != YUME_STATUS_INVALID_ARGUMENT) {
        return 4;
    }

    yume_build_info info{};
    if (yume_get_build_info(&info, sizeof(info) - 1) != YUME_STATUS_BUFFER_TOO_SMALL) {
        return 5;
    }
    if (yume_get_build_info(&info, sizeof(info)) != YUME_STATUS_OK) {
        return 6;
    }
    if (info.struct_size != sizeof(info) || info.abi_version != YUME_ABI_VERSION) {
        return 7;
    }
    if (!info.yume_version || !info.basefwx_version || !info.pq_backend || !info.argon2_backend) {
        return 8;
    }
    return 0;
}
