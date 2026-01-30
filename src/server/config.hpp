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
    std::string pq_private_key;
    bool allow_exec{false};
};

}  // namespace yume::server
