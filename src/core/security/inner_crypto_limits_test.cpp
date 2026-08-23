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

    // These resolvers pin the retired legacy KDF policy values. AUTH v2 does
    // not accept these parameters from a peer.
    const auto light = yume::inner::resolve_client_kdf_params(cfg, false);
    assert(light.name == "hkdf");
    assert(light.argon2_memory == 0);

    const auto heavy = yume::inner::resolve_client_kdf_params(cfg, true);
    assert(heavy.name == "argon2");
    assert(heavy.argon2_time > 0);
    assert(heavy.argon2_memory > 0);
    assert(heavy.argon2_parallelism > 0);

    // A configured ceiling still clamps the reported legacy policy value.
    yume::inner::Config capped;
    capped.argon2_limits.memory_max = heavy.argon2_memory / 2;
    capped.argon2_limits.time_max = heavy.argon2_time;
    capped.argon2_limits.parallelism_max = heavy.argon2_parallelism;
    const auto clamped = yume::inner::resolve_client_kdf_params(capped, true);
    assert(clamped.name == "argon2");
    assert(clamped.argon2_memory <= capped.argon2_limits.memory_max);
    assert(clamped.argon2_memory > 0);

    // Hop-key trial decryption was removed with the unreachable hop surface.
    // Keep focused negatives on the remaining legacy AEAD primitive: a wrong
    // key, wrong AAD field, or modified ciphertext must fail closed.
#if YUME_USE_BASEFWX
    {
        const yume::inner::Bytes key(32, 0x3C);
        const yume::inner::Bytes plaintext{1, 2, 3, 4, 5};
        const auto sealed = yume::inner::encrypt_payload(key, 7, 3, plaintext);
        assert(yume::inner::decrypt_payload(key, 7, 3, sealed) == plaintext);

        auto rejected = [&](const yume::inner::Bytes& candidate_key,
                            std::uint8_t frame_type,
                            std::uint8_t stream_id,
                            yume::inner::Bytes blob) {
            try {
                (void)yume::inner::decrypt_payload(
                    candidate_key, frame_type, stream_id, blob);
                return false;
            } catch (...) {
                return true;
            }
        };
        assert(rejected(yume::inner::Bytes(32, 0x5E), 7, 3, sealed));
        assert(rejected(key, 8, 3, sealed));
        assert(rejected(key, 7, 4, sealed));
        auto tampered = sealed;
        tampered.back() ^= 0x01;
        assert(rejected(key, 7, 3, std::move(tampered)));
    }
#endif

    return 0;
}
