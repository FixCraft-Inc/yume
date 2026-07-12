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
#endif

    return 0;
}
