/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/security/inner_crypto.hpp"

#include <cassert>
#include <cstdlib>
#include <string>

int main() {
    yume::inner::KdfParams params;
    params.name = "pbkdf2";
    params.pbkdf2_iters = 4000000;
    std::string reason;
    assert(!yume::inner::pbkdf2_params_exceed_limits(params, 4000000, &reason));
    assert(reason.empty());

    params.pbkdf2_iters = 4000001;
    assert(yume::inner::pbkdf2_params_exceed_limits(params, 4000000, &reason));
    assert(!reason.empty());

#if !defined(_WIN32)
    setenv("YUME_PBKDF2_ITERS_MAX", "not-a-number", 1);
    assert(yume::inner::pbkdf2_env_iters_max() == 4000000);
    setenv("YUME_PBKDF2_ITERS_MAX", "1", 1);
    assert(yume::inner::pbkdf2_env_iters_max() == 4000000);
    setenv("YUME_PBKDF2_ITERS_MAX", "5000000", 1);
    assert(yume::inner::pbkdf2_env_iters_max() == 5000000);
    unsetenv("YUME_PBKDF2_ITERS_MAX");

    unsetenv("YUME_ARGON2_MEM_MAX");
    assert(yume::inner::argon2_env_limits().memory_max == (1u << 19));
    setenv("YUME_ARGON2_MEM_MAX", "65536", 1);
    assert(yume::inner::argon2_env_limits().memory_max == 65536);
    setenv("YUME_ARGON2_MEM_MAX", "1048576", 1);
    assert(yume::inner::argon2_env_limits().memory_max == 1048576);
    setenv("YUME_ARGON2_MEM_MAX", "0", 1);
    assert(yume::inner::argon2_env_limits().memory_max == (1u << 19));
    setenv("YUME_ARGON2_MEM_MAX", "invalid", 1);
    assert(yume::inner::argon2_env_limits().memory_max == (1u << 19));
    unsetenv("YUME_ARGON2_MEM_MAX");
#endif

    yume::inner::Config cfg;
    yume::inner::KdfParams zero_argon2;
    zero_argon2.name = "argon2";
    const auto resolved = yume::inner::resolve_server_kdf_params(
        cfg, true, zero_argon2);
    assert(resolved.name == "argon2");
    assert(resolved.argon2_time > 0);
    assert(resolved.argon2_memory > 0);
    assert(resolved.argon2_parallelism > 0);

    return 0;
}
