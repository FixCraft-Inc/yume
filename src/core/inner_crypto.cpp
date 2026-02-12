/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "core/inner_crypto.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <mutex>
#include <system_error>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>

#if !defined(_WIN32)
#include <sys/stat.h>
#endif
#if defined(__APPLE__)
#include <sys/sysctl.h>
#endif
#if defined(_WIN32)
#include <windows.h>
#endif

#if YUME_USE_BASEFWX
#include <basefwx/crypto.hpp>
#include <basefwx/pq.hpp>
#include <basefwx/constants.hpp>
#if defined(BASEFWX_HAS_OQS) && BASEFWX_HAS_OQS
#include <oqs/oqs.h>
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

Bytes load_pq_public_key(const std::string& path) {
#if !YUME_USE_BASEFWX
    (void)path;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    struct Cache {
        std::string path;
        Bytes bytes;
        bool valid{false};
    };
    static std::mutex cache_mutex;
    static Cache cache;
    const std::string cache_key = path.empty() ? std::string("<default>") : path;
    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        if (cache.valid && cache.path == cache_key) {
            return cache.bytes;
        }
    }

    Bytes loaded;
    if (!path.empty()) {
        loaded = basefwx::pq::DecodeKeyBytes(read_file(path));
    } else {
        auto pub = basefwx::pq::LoadMasterPublicKey();
        if (!pub.has_value()) {
            throw std::runtime_error("PQ public key not configured");
        }
        loaded = *pub;
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

Bytes load_pq_private_key(const std::string& path) {
#if !YUME_USE_BASEFWX
    (void)path;
    throw std::runtime_error("inner crypto not available: BaseFWX disabled");
#else
    struct Cache {
        std::string path;
        Bytes bytes;
        bool valid{false};
    };
    static std::mutex cache_mutex;
    static Cache cache;
    const std::string cache_key = path.empty() ? std::string("<default>") : path;
    {
        std::lock_guard<std::mutex> lock(cache_mutex);
        if (cache.valid && cache.path == cache_key) {
            return cache.bytes;
        }
    }

    Bytes loaded;
    if (!path.empty()) {
        loaded = basefwx::pq::DecodeKeyBytes(read_file(path));
    } else {
        loaded = basefwx::pq::LoadMasterPrivateKey();
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

double read_env_ratio(const char* name, double fallback) {
    const char* raw = std::getenv(name);
    if (!raw || !*raw) {
        return fallback;
    }
    try {
        double parsed = std::stod(raw);
        if (parsed <= 0.0) {
            return fallback;
        }
        if (parsed > 1.0) {
            parsed /= 100.0;
        }
        if (parsed <= 0.0) {
            return fallback;
        }
        if (parsed > 1.0) {
            parsed = 1.0;
        }
        return parsed;
    } catch (...) {
        return fallback;
    }
}

double resource_cap_ratio() {
    return read_env_ratio("YUME_RESOURCE_CAP", 0.84);
}

std::uint64_t read_meminfo_kib(const char* key) {
#if defined(_WIN32) || defined(__APPLE__)
    (void)key;
    return 0;
#else
    std::ifstream meminfo("/proc/meminfo");
    if (!meminfo) {
        return 0;
    }
    std::string line;
    while (std::getline(meminfo, line)) {
        if (line.rfind(key, 0) != 0) {
            continue;
        }
        std::istringstream iss(line);
        std::string label;
        std::uint64_t value = 0;
        std::string unit;
        if (iss >> label >> value >> unit) {
            return value;
        }
    }
    return 0;
#endif
}

std::uint64_t available_memory_kib() {
#if defined(_WIN32)
    MEMORYSTATUSEX status{};
    status.dwLength = sizeof(status);
    if (!GlobalMemoryStatusEx(&status)) {
        return 0;
    }
    return static_cast<std::uint64_t>(status.ullAvailPhys / 1024);
#elif defined(__APPLE__)
    std::uint64_t mem = 0;
    size_t len = sizeof(mem);
    if (sysctlbyname("hw.memsize", &mem, &len, nullptr, 0) != 0) {
        return 0;
    }
    return static_cast<std::uint64_t>(mem / 1024);
#else
    std::uint64_t avail = read_meminfo_kib("MemAvailable:");
    if (avail == 0) {
        avail = read_meminfo_kib("MemTotal:");
    }
    return avail;
#endif
}

std::uint32_t argon2_time_cost() {
    return read_env_u32("YUME_ARGON2_TIME", basefwx::constants::kArgon2TimeCost);
}

std::uint32_t argon2_parallelism() {
    std::uint32_t env_val = 0;
    if (read_env_u32_optional("YUME_ARGON2_PAR", &env_val)) {
        return env_val;
    }
    const double cap = resource_cap_ratio();
    auto count = std::thread::hardware_concurrency();
    if (count == 0) {
        return basefwx::constants::DefaultHeavyArgon2Parallelism();
    }
    std::uint32_t scaled = static_cast<std::uint32_t>(std::floor(static_cast<double>(count) * cap));
    return scaled > 0 ? scaled : 1u;
}

KdfParams select_argon2_params() {
    KdfParams params;
    params.name = "argon2";
    params.argon2_time = argon2_time_cost();
    params.argon2_parallelism = argon2_parallelism();
    params.pbkdf2_iters = basefwx::constants::HeavyPbkdf2Iterations();

    std::uint32_t mem = 0;
    const bool mem_env = read_env_u32_optional("YUME_ARGON2_MEM", &mem);
    std::uint64_t avail = available_memory_kib();
    if (avail > 0) {
        const double cap = resource_cap_ratio();
        std::uint64_t cap_mem = static_cast<std::uint64_t>(
            std::floor(static_cast<double>(avail) * cap));
        if (cap_mem == 0) {
            cap_mem = avail;
        }
        if (!mem_env) {
            mem = static_cast<std::uint32_t>(
                std::min<std::uint64_t>(cap_mem, std::numeric_limits<std::uint32_t>::max()));
        } else if (mem > avail) {
            mem = static_cast<std::uint32_t>(
                std::min<std::uint64_t>(avail, std::numeric_limits<std::uint32_t>::max()));
        }
    } else if (!mem_env) {
        mem = basefwx::constants::kHeavyArgon2MemoryCost;
    }

    if (params.argon2_parallelism == 0) {
        params.argon2_parallelism = 1;
    }
    std::uint64_t min_mem = static_cast<std::uint64_t>(params.argon2_parallelism) * 8u;
    if (mem < min_mem && mem > 0) {
        std::uint32_t max_par = static_cast<std::uint32_t>(mem / 8u);
        params.argon2_parallelism = max_par > 0 ? max_par : 1;
    }
    min_mem = static_cast<std::uint64_t>(params.argon2_parallelism) * 8u;
    if (mem < min_mem) {
        mem = static_cast<std::uint32_t>(
            std::min<std::uint64_t>(min_mem, std::numeric_limits<std::uint32_t>::max()));
    }
    params.argon2_memory = mem;
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
        if (lowered.find("allocation") != std::string::npos) {
            return true;
        }
        if (lowered.find("memory cost is too large") != std::string::npos) {
            return true;
        }
        return false;
    };

    std::string password(reinterpret_cast<const char*>(shared.data()), shared.size());
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
        Bytes priv = basefwx::pq::DecodeKeyBytes(read_file(private_path));
        auto kem = basefwx::pq::KemEncrypt(pub);
        Bytes shared2 = basefwx::pq::KemDecrypt(priv, kem.ciphertext);
        if (shared2 != kem.shared) {
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
    Bytes pub = load_pq_public_key(cfg.pq_public_key);
    auto kem = basefwx::pq::KemEncrypt(pub);
    result.enabled = true;
    result.pq_ciphertext = std::move(kem.ciphertext);
    result.salt = basefwx::crypto::RandomBytes(basefwx::constants::kUserKdfSaltSize);
    if (heavy) {
        KdfParams params = select_argon2_params();
        DerivedKey derived = derive_key_heavy(kem.shared, result.salt, params, true);
        result.key = derived.key;
        result.kdf = derived.kdf;
        result.pbkdf2_iters = params.pbkdf2_iters;
        if (derived.kdf == "argon2") {
            result.argon2_time = params.argon2_time;
            result.argon2_memory = params.argon2_memory;
            result.argon2_parallelism = params.argon2_parallelism;
        }
    } else {
        result.key = derive_key(kem.shared);
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
    Bytes priv = load_pq_private_key(cfg.pq_private_key);
    Bytes shared = basefwx::pq::KemDecrypt(priv, pq_ciphertext);
    if (!heavy) {
        DerivedKey out;
        out.kdf = "hkdf";
        out.key = derive_key(shared);
        return out;
    }
    KdfParams params = kdf_params.value_or(KdfParams{});
    bool allow_fallback = params.name.empty();
    return derive_key_heavy(shared, salt, params, allow_fallback);
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
