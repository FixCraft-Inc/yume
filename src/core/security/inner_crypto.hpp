#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace yume::inner {

using Bytes = std::vector<std::uint8_t>;

struct Argon2Limits {
    std::uint32_t time_max{0};
    std::uint32_t memory_max{0};
    std::uint32_t parallelism_max{0};
};

struct Config {
#if YUME_USE_BASEFWX
    bool enabled{false};
    std::string pq_public_key;
    std::string pq_private_key;
    bool allow_embedded_master{false};
    Argon2Limits argon2_limits;
#else
    bool enabled{false};
    std::string pq_public_key;
    std::string pq_private_key;
    bool allow_embedded_master{false};
    Argon2Limits argon2_limits;
#endif
};

struct ClientHandshake {
    bool enabled{false};
    Bytes pq_ciphertext;
    Bytes salt;
    Bytes key;
    std::string kdf;
    std::uint32_t argon2_time{0};
    std::uint32_t argon2_memory{0};
    std::uint32_t argon2_parallelism{0};
    std::uint32_t pbkdf2_iters{0};
};

ClientHandshake client_prepare(const Config& cfg, bool heavy);
struct DerivedKey {
    Bytes key;
    std::string kdf;
};

struct KdfParams {
    std::string name;
    std::uint32_t argon2_time{0};
    std::uint32_t argon2_memory{0};
    std::uint32_t argon2_parallelism{0};
    std::uint32_t pbkdf2_iters{0};
};

std::optional<DerivedKey> server_derive_key(const Config& cfg,
                                            const Bytes& pq_ciphertext,
                                            const Bytes& salt,
                                            bool heavy,
                                            const std::optional<KdfParams>& kdf_params);

bool pq_supported();
bool argon2_supported();
bool pbkdf2_supported();
std::string pq_backend_version();
std::string argon2_backend_version();
Argon2Limits argon2_env_limits();
bool argon2_params_exceed_limits(const KdfParams& params,
                                 const Argon2Limits& limits,
                                 std::string* reason);

std::uint64_t hop_id_from_time_ms(std::int64_t now_ms, std::uint32_t interval_ms, std::int64_t offset_ms);
Bytes derive_hop_key(const Bytes& base_key, std::uint64_t hop_id);

bool generate_pq_keypair(const std::string& private_path,
                         const std::string& public_path,
                         std::string* err);

bool validate_pq_keypair(const std::string& private_path,
                         const std::string& public_path,
                         std::string* err);

Bytes encrypt_payload(const Bytes& key, std::uint8_t frame_type, std::uint8_t stream_id, const Bytes& plaintext);
Bytes decrypt_payload(const Bytes& key, std::uint8_t frame_type, std::uint8_t stream_id, const Bytes& blob);

}  // namespace yume::inner
