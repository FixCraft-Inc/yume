/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/security/inner_crypto.hpp"
#include "core/runtime/system_profile.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <mutex>
#include <system_error>
#include <stdexcept>
#include <string>

#if !defined(_WIN32)
#include <sys/stat.h>
#endif

#if YUME_USE_BASEFWX
#include <basefwx/crypto.hpp>
#include <basefwx/pq.hpp>
#include <basefwx/constants.hpp>
#if defined(BASEFWX_HAS_OQS) && BASEFWX_HAS_OQS
#include <oqs/oqs.h>
#endif
#if defined(BASEFWX_HAS_ARGON2) && BASEFWX_HAS_ARGON2
#include <argon2.h>
#endif
#endif

namespace yume::inner {

namespace {
constexpr const char kHkdfInfo[] = "yume-inner-v1";
constexpr const char kHopInfoPrefix[] = "yume-hop-v1:";

Bytes read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open key file: " + path);
    }
    in.seekg(0, std::ios::end);
    std::streamoff size = in.tellg();
    if (size < 0) {
        throw std::runtime_error("failed to read key file size: " + path);
    }
    in.seekg(0, std::ios::beg);
    Bytes data(static_cast<std::size_t>(size));
    if (!data.empty()) {
        in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!in) {
            throw std::runtime_error("failed to read key file: " + path);
        }
    }
    return data;
}

Bytes load_pq_public_key(const std::string& path, bool allow_embedded_master) {
#if !YUME_USE_BASEFWX
    (void)path;
    (void)allow_embedded_master;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    struct Cache {
        std::string path;
        Bytes bytes;
        bool valid{false};
    };
    static std::mutex cache_mutex;
    static Cache cache;
    const std::string cache_key = (path.empty() ? std::string("<default>") : path) +
                                  (allow_embedded_master ? "|embedded=1" : "|embedded=0");
    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        if (cache.valid && cache.path == cache_key) {
            return cache.bytes;
        }
    }

    Bytes loaded;
    if (!path.empty()) {
        loaded = basefwx::pq::DecodeKeyBytes(read_file(path));
    } else if (allow_embedded_master) {
        auto pub = basefwx::pq::LoadMasterPublicKey();
        if (!pub.has_value()) {
            throw std::runtime_error("PQ public key not configured");
        }
        loaded = *pub;
    } else {
        throw std::runtime_error(
            "PQ public key not configured (set --pq-pub or enable --use-embedded-master)");
    }
    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        cache.path = cache_key;
        cache.bytes = loaded;
        cache.valid = true;
    }
    return loaded;
#endif
}

Bytes load_pq_private_key(const std::string& path, bool allow_embedded_master) {
#if !YUME_USE_BASEFWX
    (void)path;
    (void)allow_embedded_master;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    struct Cache {
        std::string path;
        Bytes bytes;
        bool valid{false};
    };
    static std::mutex cache_mutex;
    static Cache cache;
    const std::string cache_key = (path.empty() ? std::string("<default>") : path) +
                                  (allow_embedded_master ? "|embedded=1" : "|embedded=0");
    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        if (cache.valid && cache.path == cache_key) {
            return cache.bytes;
        }
    }

    Bytes loaded;
    if (!path.empty()) {
        loaded = basefwx::pq::DecodeKeyBytes(read_file(path));
    } else if (allow_embedded_master) {
        loaded = basefwx::pq::LoadMasterPrivateKey();
        if (loaded.empty()) {
            throw std::runtime_error("PQ private key not configured");
        }
    } else {
        throw std::runtime_error(
            "PQ private key not configured (set --pq-key or enable --use-embedded-master)");
    }
    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        cache.path = cache_key;
        basefwx::crypto::SecureClear(cache.bytes);
        cache.bytes = loaded;
        cache.valid = true;
    }
    return loaded;
#endif
}

bool write_file_bytes(const std::string& path, const Bytes& data, std::string* err) {
    try {
        std::filesystem::path p(path);
        if (p.has_parent_path()) {
            std::error_code ec;
            std::filesystem::create_directories(p.parent_path(), ec);
        }
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            if (err) *err = "failed to open file: " + path;
            return false;
        }
        if (!data.empty()) {
            out.write(reinterpret_cast<const char*>(data.data()),
                      static_cast<std::streamsize>(data.size()));
            if (!out) {
                if (err) *err = "failed to write file: " + path;
                return false;
            }
        }
        out.close();
        if (!out) {
            if (err) *err = "failed to flush file: " + path;
            return false;
        }
#if !defined(_WIN32)
        if (path.find(".key") != std::string::npos) {
            ::chmod(path.c_str(), 0600);
        } else {
            ::chmod(path.c_str(), 0644);
        }
#endif
        return true;
    } catch (const std::exception& ex) {
        if (err) *err = ex.what();
        return false;
    }
}

std::uint32_t read_env_u32(const char* name, std::uint32_t fallback) {
    const char* raw = std::getenv(name);
    if (!raw || !*raw) {
        return fallback;
    }
    try {
        unsigned long long parsed = std::stoull(raw);
        if (parsed == 0) {
            return fallback;
        }
        if (parsed > std::numeric_limits<std::uint32_t>::max()) {
            return std::numeric_limits<std::uint32_t>::max();
        }
        return static_cast<std::uint32_t>(parsed);
    } catch (...) {
        return fallback;
    }
}

bool read_env_u32_optional(const char* name, std::uint32_t* out) {
    const char* raw = std::getenv(name);
    if (!raw || !*raw) {
        return false;
    }
    try {
        unsigned long long parsed = std::stoull(raw);
        if (parsed == 0) {
            return false;
        }
        if (parsed > std::numeric_limits<std::uint32_t>::max()) {
            *out = std::numeric_limits<std::uint32_t>::max();
        } else {
            *out = static_cast<std::uint32_t>(parsed);
        }
        return true;
    } catch (...) {
        return false;
    }
}

double resource_cap_ratio() {
    return yume::runtime::resource_cap_ratio_from_env();
}

std::uint32_t argon2_time_cost() {
#if !YUME_USE_BASEFWX
    constexpr std::uint32_t kDefaultArgon2TimeCost = 4;
    return read_env_u32("YUME_ARGON2_TIME", kDefaultArgon2TimeCost);
#else
    return read_env_u32("YUME_ARGON2_TIME", basefwx::constants::kArgon2TimeCost);
#endif
}

std::uint32_t argon2_parallelism() {
    std::uint32_t env_val = 0;
    if (read_env_u32_optional("YUME_ARGON2_PAR", &env_val)) {
        return env_val;
    }
    // YUME heavy handshakes carry the selected Argon2 lane count in the
    // auth payload. This host-tuned fallback is only for locally selected
    // transport params, including the speculative heavy key in dual-mode
    // light sessions; it is not a portable file-format default.
#if !YUME_USE_BASEFWX
    constexpr unsigned fallback = 4;
#else
    const unsigned fallback = basefwx::constants::DefaultHeavyArgon2Parallelism();
#endif
    return static_cast<std::uint32_t>(
        yume::runtime::scaled_thread_count(yume::runtime::detect_system_profile(),
                                           resource_cap_ratio(),
                                           fallback,
                                           1,
                                           std::numeric_limits<std::uint32_t>::max()));
}

void apply_argon2_limits_to_values(std::uint32_t* time_cost,
                                   std::uint32_t* mem_cost,
                                   std::uint32_t* par_cost,
                                   const Argon2Limits& limits) {
    if (time_cost && limits.time_max > 0 && *time_cost > limits.time_max) {
        *time_cost = limits.time_max;
    }
    if (mem_cost && limits.memory_max > 0 && *mem_cost > limits.memory_max) {
        *mem_cost = limits.memory_max;
    }
    if (par_cost && limits.parallelism_max > 0 && *par_cost > limits.parallelism_max) {
        *par_cost = limits.parallelism_max;
    }

    if (par_cost && *par_cost == 0) {
        *par_cost = 1;
    }
    if (!mem_cost || !par_cost) {
        return;
    }

    std::uint64_t min_mem = static_cast<std::uint64_t>(*par_cost) * 8u;
    if (*mem_cost > 0 && *mem_cost < min_mem) {
        std::uint32_t max_par_for_mem = static_cast<std::uint32_t>(*mem_cost / 8u);
        *par_cost = max_par_for_mem > 0 ? max_par_for_mem : 1u;
    }
    min_mem = static_cast<std::uint64_t>(*par_cost) * 8u;
    if (*mem_cost < min_mem) {
        *mem_cost = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(min_mem, std::numeric_limits<std::uint32_t>::max()));
    }
}

KdfParams select_argon2_params(const Argon2Limits& remote_limits = Argon2Limits{}) {
    KdfParams params;
    params.name = "argon2";
    params.argon2_time = argon2_time_cost();
    params.argon2_parallelism = argon2_parallelism();
#if !YUME_USE_BASEFWX
    params.pbkdf2_iters = 2000000;
    constexpr std::uint32_t kDefaultHeavyArgon2MemoryCost = 1u << 18;
#else
    params.pbkdf2_iters = basefwx::constants::HeavyPbkdf2Iterations();
    constexpr std::uint32_t kDefaultHeavyArgon2MemoryCost = basefwx::constants::kHeavyArgon2MemoryCost;
#endif

    std::uint32_t default_mem = kDefaultHeavyArgon2MemoryCost;
    const bool default_mem_env = read_env_u32_optional("YUME_ARGON2_HEAVY_MEM_DEFAULT", &default_mem);
    std::uint32_t mem = 0;
    const bool mem_env = read_env_u32_optional("YUME_ARGON2_MEM", &mem);
    if (!mem_env) {
        mem = default_mem;
    }
    const auto profile = yume::runtime::detect_system_profile();
    const std::uint64_t max_budget_mib =
        std::numeric_limits<std::uint32_t>::max() / 1024ull;
    const std::uint64_t budget_kib =
        yume::runtime::memory_budget_mib(profile,
                                         resource_cap_ratio(),
                                         static_cast<std::uint64_t>(default_mem) / 1024ull,
                                         max_budget_mib) * 1024ull;
    if (!mem_env && !default_mem_env && budget_kib > mem) {
        mem = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(budget_kib, std::numeric_limits<std::uint32_t>::max()));
    }
    if (budget_kib > 0 && mem > budget_kib) {
        mem = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(budget_kib, std::numeric_limits<std::uint32_t>::max()));
    } else if (mem == 0) {
        mem = default_mem;
    }

    params.argon2_memory = mem;
    apply_argon2_limits_to_values(&params.argon2_time,
                                  &params.argon2_memory,
                                  &params.argon2_parallelism,
                                  argon2_env_limits());
    apply_argon2_limits_to_values(&params.argon2_time,
                                  &params.argon2_memory,
                                  &params.argon2_parallelism,
                                  remote_limits);
    return params;
}

Bytes derive_key(const Bytes& shared) {
#if !YUME_USE_BASEFWX
    (void)shared;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    return basefwx::crypto::HkdfSha256(shared, kHkdfInfo, 32);
#endif
}

DerivedKey derive_key_heavy(const Bytes& shared,
                            const Bytes& salt,
                            const KdfParams& kdf_params,
                            bool allow_fallback) {
#if !YUME_USE_BASEFWX
    (void)shared;
    (void)salt;
    (void)kdf_params;
    (void)allow_fallback;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    auto is_oom = [](const std::string& msg) {
        std::string lowered;
        lowered.reserve(msg.size());
        for (unsigned char c : msg) {
            lowered.push_back(static_cast<char>(std::tolower(c)));
        }
        if (lowered.find("out of memory") != std::string::npos) {
            return true;
        }
        if (lowered.find("insufficient memory") != std::string::npos) {
            return true;
        }
        if (lowered.find("memory allocation") != std::string::npos) {
            return true;
        }
        if (lowered.find("memory cost is too large") != std::string::npos) {
            return true;
        }
        return false;
    };

    std::string password(reinterpret_cast<const char*>(shared.data()), shared.size());
    // password is a std::string copy of the KEM shared secret — it
    // holds key material and must be wiped before this function returns
    // (crypto-conventions Rule 2). SecretGuard handles every return
    // path, including the three exception-rethrow paths below.
    basefwx::crypto::SecretGuard pwd_guard;
    pwd_guard.Add(password);
    KdfParams params = kdf_params;
    if (params.name.empty()) {
        params = select_argon2_params();
    }
    if (params.pbkdf2_iters == 0) {
        params.pbkdf2_iters = basefwx::constants::HeavyPbkdf2Iterations();
    }

    if (params.name == "pbkdf2") {
        DerivedKey out;
        out.kdf = "pbkdf2";
        out.key = basefwx::crypto::Pbkdf2HmacSha256(password, salt, params.pbkdf2_iters, 32);
        return out;
    }

    if (params.name == "argon2") {
#if defined(BASEFWX_HAS_ARGON2) && BASEFWX_HAS_ARGON2
        std::uint32_t time_cost = params.argon2_time ? params.argon2_time : argon2_time_cost();
        std::uint32_t mem_cost = params.argon2_memory ? params.argon2_memory : basefwx::constants::kHeavyArgon2MemoryCost;
        std::uint32_t par_cost = params.argon2_parallelism ? params.argon2_parallelism : argon2_parallelism();
        if (par_cost == 0) {
            par_cost = 1;
        }
        std::uint64_t min_mem = static_cast<std::uint64_t>(par_cost) * 8u;
        if (mem_cost < min_mem) {
            mem_cost = static_cast<std::uint32_t>(
                std::min<std::uint64_t>(min_mem, std::numeric_limits<std::uint32_t>::max()));
        }
        try {
            DerivedKey out;
            out.kdf = "argon2";
            out.key = basefwx::crypto::Argon2idHashRaw(password,
                                                       salt,
                                                       time_cost,
                                                       mem_cost,
                                                       par_cost,
                                                       32);
            return out;
        } catch (const std::exception& ex) {
            if (!is_oom(ex.what()) || !allow_fallback) {
                throw;
            }
            DerivedKey out;
            out.kdf = "pbkdf2";
            out.key = basefwx::crypto::Pbkdf2HmacSha256(password,
                                                        salt,
                                                        params.pbkdf2_iters,
                                                        32);
            return out;
        }
#else
        if (!allow_fallback) {
            throw std::runtime_error("argon2 not supported");
        }
        DerivedKey out;
        out.kdf = "pbkdf2";
        out.key = basefwx::crypto::Pbkdf2HmacSha256(password,
                                                    salt,
                                                    params.pbkdf2_iters,
                                                    32);
        return out;
#endif
    }

    if (params.name == "hkdf") {
        DerivedKey out;
        out.kdf = "hkdf";
        out.key = derive_key(shared);
        return out;
    }

    throw std::runtime_error("invalid kdf request");
#endif
}

Bytes build_aad(std::uint8_t frame_type, std::uint8_t stream_id) {
    Bytes aad(6);
    aad[0] = static_cast<std::uint8_t>('Y');
    aad[1] = static_cast<std::uint8_t>('U');
    aad[2] = static_cast<std::uint8_t>('M');
    aad[3] = static_cast<std::uint8_t>('E');
    aad[4] = frame_type;
    aad[5] = stream_id;
    return aad;
}
}  // namespace

// Safe-by-default Argon2 caps. The server-side guard at
// server/session/auth.cpp calls argon2_params_exceed_limits with
// the value returned here — and prior to 1.0.x this function returned
// {0,0,0} when no env var was set, which the guard interpreted as
// "no cap". That made the daemon vulnerable to a remote pre-auth
// resource-exhaustion: a hostile client could request
// argon2_memory = UINT32_MAX KiB and the server would attempt to
// allocate it before the AUTH frame had succeeded.
//
// The defaults below are deliberately generous (2× the existing HEAVY
// mode constants in basefwx::constants — kHeavyArgon2TimeCost=6,
// kHeavyArgon2MemoryCost=1<<18 KiB, kHeavyArgon2Parallelism=4) so any
// legitimate client request, including the heaviest documented mode,
// passes the guard untouched. They only block obvious abuse.
//
// Operators who genuinely need to allow heavier params can raise the
// caps via env vars; setting an env var to a value LARGER than the
// default wins. Setting an env var to 0 keeps the field at the
// default — there's no way to disable the cap entirely from the env,
// which is the safe direction.
inline constexpr std::uint32_t kDefaultArgon2TimeMax        = 12;
inline constexpr std::uint32_t kDefaultArgon2MemoryMaxKib   = 1u << 19;   // 512 MiB
inline constexpr std::uint32_t kDefaultArgon2ParallelismMax = 8;

Argon2Limits argon2_env_limits() {
    Argon2Limits limits;
    limits.time_max        = kDefaultArgon2TimeMax;
    limits.memory_max      = kDefaultArgon2MemoryMaxKib;
    limits.parallelism_max = kDefaultArgon2ParallelismMax;
    // Env vars can only raise the defaults. A too-small value is ignored
    // so operators cannot accidentally lock out legitimate default-heavy
    // clients by setting, for example, YUME_ARGON2_MEM_MAX=1024.
    auto raise_from_env = [](const char* name, std::uint32_t& cap) {
        std::uint32_t parsed = 0;
        if (read_env_u32_optional(name, &parsed)) {
            cap = std::max(cap, parsed);
        }
    };
    raise_from_env("YUME_ARGON2_TIME_MAX", limits.time_max);
    raise_from_env("YUME_ARGON2_MEM_MAX", limits.memory_max);
    raise_from_env("YUME_ARGON2_PAR_MAX", limits.parallelism_max);
    return limits;
}

bool argon2_params_exceed_limits(const KdfParams& params,
                                 const Argon2Limits& limits,
                                 std::string* reason) {
    auto fail = [&](const std::string& msg) {
        if (reason) {
            *reason = msg;
        }
        return true;
    };
    if (limits.time_max > 0 && params.argon2_time > limits.time_max) {
        return fail("time=" + std::to_string(params.argon2_time) +
                    " > max=" + std::to_string(limits.time_max));
    }
    if (limits.memory_max > 0 && params.argon2_memory > limits.memory_max) {
        return fail("mem=" + std::to_string(params.argon2_memory) +
                    " > max=" + std::to_string(limits.memory_max));
    }
    if (limits.parallelism_max > 0 && params.argon2_parallelism > limits.parallelism_max) {
        return fail("par=" + std::to_string(params.argon2_parallelism) +
                    " > max=" + std::to_string(limits.parallelism_max));
    }
    if (reason) {
        reason->clear();
    }
    return false;
}

bool generate_pq_keypair(const std::string& private_path,
                         const std::string& public_path,
                         std::string* err) {
#if !YUME_USE_BASEFWX
    if (err) *err = "inner crypto not available: BaseFWX disabled";
    return false;
#else
#if !defined(BASEFWX_HAS_OQS) || !BASEFWX_HAS_OQS
    if (err) *err = "PQ not available (liboqs not enabled in BaseFWX)";
    return false;
#else
    std::string algo_str(basefwx::constants::kMasterPqAlg);
    const char* algo = algo_str.c_str();
    OQS_KEM* kem = OQS_KEM_new(algo);
    if (!kem) {
        if (err) *err = "OQS_KEM_new failed";
        return false;
    }
    Bytes pub(kem->length_public_key);
    Bytes priv(kem->length_secret_key);
    if (OQS_KEM_keypair(kem, pub.data(), priv.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        if (err) *err = "OQS_KEM_keypair failed";
        return false;
    }
    OQS_KEM_free(kem);
    if (!write_file_bytes(private_path, priv, err)) {
        return false;
    }
    if (!write_file_bytes(public_path, pub, err)) {
        return false;
    }
    return true;
#endif
#endif
}

bool validate_pq_keypair(const std::string& private_path,
                         const std::string& public_path,
                         std::string* err) {
#if !YUME_USE_BASEFWX
    (void)private_path;
    (void)public_path;
    if (err) *err = "inner crypto not available: BaseFWX disabled";
    return false;
#else
    try {
        if (private_path.empty() || public_path.empty()) {
            if (err) *err = "missing pq key path";
            return false;
        }
        Bytes pub = basefwx::pq::DecodeKeyBytes(read_file(public_path));
        // priv and shared2 are key material — SecureBytes wraps each
        // so wipe-on-destruction is automatic, in correct order, with
        // no SecretGuard raw-pointer lifetime trap.
        basefwx::crypto::SecureBytes priv{
            basefwx::pq::DecodeKeyBytes(read_file(private_path))};
        auto kem = basefwx::pq::KemEncrypt(pub);
        basefwx::crypto::SecureBytes shared2{
            basefwx::pq::KemDecrypt(priv.bytes(), kem.ciphertext)};
        if (shared2.bytes() != kem.shared) {
            if (err) *err = "pq keypair mismatch";
            return false;
        }
        return true;
    } catch (const std::exception& ex) {
        if (err) *err = ex.what();
        return false;
    }
#endif
}

ClientHandshake client_prepare(const Config& cfg, bool heavy) {
    ClientHandshake result;
    if (!cfg.enabled) {
        return result;
    }
#if !YUME_USE_BASEFWX
    (void)cfg;
    (void)heavy;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    Bytes pub = load_pq_public_key(cfg.pq_public_key, cfg.allow_embedded_master);
    auto kem = basefwx::pq::KemEncrypt(pub);
    basefwx::crypto::SecureBytes kem_shared{std::move(kem.shared)};
    result.enabled = true;
    result.pq_ciphertext = std::move(kem.ciphertext);
    result.salt = basefwx::crypto::RandomBytes(basefwx::constants::kUserKdfSaltSize);
    if (heavy) {
        KdfParams params = select_argon2_params(cfg.argon2_limits);
        DerivedKey derived = derive_key_heavy(kem_shared.bytes(), result.salt, params, true);
        result.key = derived.key;
        result.kdf = derived.kdf;
        result.pbkdf2_iters = params.pbkdf2_iters;
        if (derived.kdf == "argon2") {
            result.argon2_time = params.argon2_time;
            result.argon2_memory = params.argon2_memory;
            result.argon2_parallelism = params.argon2_parallelism;
        }
    } else {
        result.key = derive_key(kem_shared.bytes());
        result.kdf = "hkdf";
    }
    return result;
#endif
}

std::optional<DerivedKey> server_derive_key(const Config& cfg,
                                            const Bytes& pq_ciphertext,
                                            const Bytes& salt,
                                            bool heavy,
                                            const std::optional<KdfParams>& kdf_params) {
    if (!cfg.enabled) {
        return std::nullopt;
    }
#if !YUME_USE_BASEFWX
    (void)cfg;
    (void)pq_ciphertext;
    (void)salt;
    (void)heavy;
    (void)kdf_params;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    // priv (PQ private key) and shared (KEM secret) are key material;
    // SecureBytes wraps each so the destructor wipes them on scope
    // exit, in reverse construction order, with the wrap holding the
    // bytes (no SecretGuard raw-pointer lifetime trap).
    basefwx::crypto::SecureBytes priv{
        load_pq_private_key(cfg.pq_private_key, cfg.allow_embedded_master)};
    basefwx::crypto::SecureBytes shared{
        basefwx::pq::KemDecrypt(priv.bytes(), pq_ciphertext)};
    if (!heavy) {
        DerivedKey out;
        out.kdf = "hkdf";
        out.key = derive_key(shared.bytes());
        return out;
    }
    KdfParams params = kdf_params.value_or(KdfParams{});
    std::string effective_kdf = params.name;
    if (effective_kdf.empty()) {
        effective_kdf = select_argon2_params(cfg.argon2_limits).name;
    }
    if (effective_kdf == "argon2"
        && argon2_params_exceed_limits(params, argon2_env_limits(), nullptr)) {
        return std::nullopt;
    }
    bool allow_fallback = params.name.empty();
    return derive_key_heavy(shared.bytes(), salt, params, allow_fallback);
#endif
}

bool pq_supported() {
#if YUME_USE_BASEFWX && defined(BASEFWX_HAS_OQS) && BASEFWX_HAS_OQS
    return true;
#else
    return false;
#endif
}

bool argon2_supported() {
#if YUME_USE_BASEFWX && defined(BASEFWX_HAS_ARGON2) && BASEFWX_HAS_ARGON2
    return true;
#else
    return false;
#endif
}

bool pbkdf2_supported() {
    return true;
}

std::string pq_backend_version() {
#if YUME_USE_BASEFWX && defined(BASEFWX_HAS_OQS) && BASEFWX_HAS_OQS
    std::string out = "available (";
#if defined(OQS_VERSION_TEXT)
    out += "liboqs ";
    out += OQS_VERSION_TEXT;
#else
    out += "liboqs";
#endif
    out += ", ";
    out.append(basefwx::constants::kMasterPqAlg.data(), basefwx::constants::kMasterPqAlg.size());
    out += ")";
    return out;
#else
    return "unavailable";
#endif
}

std::string argon2_backend_version() {
#if YUME_USE_BASEFWX && defined(BASEFWX_HAS_ARGON2) && BASEFWX_HAS_ARGON2
    std::string out = "available (libargon2";
#if defined(ARGON2_VERSION_NUMBER)
    out += ", Argon2 v=";
    out += std::to_string(ARGON2_VERSION_NUMBER);
#endif
    out += ")";
    return out;
#else
    return "unavailable";
#endif
}

std::uint64_t hop_id_from_time_ms(std::int64_t now_ms, std::uint32_t interval_ms, std::int64_t offset_ms) {
    if (interval_ms == 0) {
        return 0;
    }
    std::int64_t adjusted = now_ms + offset_ms;
    if (adjusted < 0) {
        adjusted = 0;
    }
    return static_cast<std::uint64_t>(adjusted / static_cast<std::int64_t>(interval_ms));
}

Bytes derive_hop_key(const Bytes& base_key, std::uint64_t hop_id) {
#if !YUME_USE_BASEFWX
    (void)base_key;
    (void)hop_id;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    std::array<char, 64> info{};
    constexpr std::string_view prefix(kHopInfoPrefix);
    std::memcpy(info.data(), prefix.data(), prefix.size());
    auto [ptr, ec] = std::to_chars(info.data() + prefix.size(),
                                   info.data() + info.size(),
                                   hop_id);
    std::size_t len = prefix.size();
    if (ec == std::errc()) {
        len = static_cast<std::size_t>(ptr - info.data());
    }
    return basefwx::crypto::HkdfSha256(base_key, std::string_view(info.data(), len), 32);
#endif
}

Bytes encrypt_payload(const Bytes& key, std::uint8_t frame_type, std::uint8_t stream_id, const Bytes& plaintext) {
#if !YUME_USE_BASEFWX
    (void)key;
    (void)frame_type;
    (void)stream_id;
    (void)plaintext;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    return basefwx::crypto::AeadEncrypt(key, plaintext, build_aad(frame_type, stream_id));
#endif
}

Bytes decrypt_payload(const Bytes& key, std::uint8_t frame_type, std::uint8_t stream_id, const Bytes& blob) {
#if !YUME_USE_BASEFWX
    (void)key;
    (void)frame_type;
    (void)stream_id;
    (void)blob;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    return basefwx::crypto::AeadDecrypt(key, blob, build_aad(frame_type, stream_id));
#endif
}

}  // namespace yume::inner
