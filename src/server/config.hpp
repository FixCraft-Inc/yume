#pragma once

#include <string>

namespace yume::server {

struct ServerConfig {
    int listen_port{443};
    std::string tls_cert;
    std::string tls_key;
    std::string auth_keys;
    int threads{4};
    bool obfuscation{false};
    bool inner_crypto{false};
    bool inner_heavy{true};
    std::string pq_private_key;
    bool allow_exec{false};
    bool real_http{false};
    std::string real_index_path;
    std::string real_secret;
    std::string real_secret_file;
    bool anonym{false};
    std::string anonym_api;
    std::string anonym_token;
    std::string anonym_hash;
    std::string anonym_sig;
    std::string anonym_ts;
    std::string anonym_nonce;
    std::string auth_keys_meta;
};

}  // namespace yume::server
