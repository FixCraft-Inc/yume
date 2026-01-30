#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace yume::inner {

using Bytes = std::vector<std::uint8_t>;

struct Config {
#if YUME_USE_BASEFWX
    bool enabled{false};
    std::string pq_public_key;
    std::string pq_private_key;
#else
    bool enabled{false};
    std::string pq_public_key;
    std::string pq_private_key;
#endif
};

struct ClientHandshake {
    bool enabled{false};
    Bytes pq_ciphertext;
    Bytes key;
};

ClientHandshake client_prepare(const Config& cfg);
std::optional<Bytes> server_derive_key(const Config& cfg, const Bytes& pq_ciphertext);

Bytes encrypt_payload(const Bytes& key, std::uint8_t frame_type, std::uint8_t stream_id, const Bytes& plaintext);
Bytes decrypt_payload(const Bytes& key, std::uint8_t frame_type, std::uint8_t stream_id, const Bytes& blob);

}  // namespace yume::inner
