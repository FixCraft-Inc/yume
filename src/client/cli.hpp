#pragma once

#include <string>

namespace yume::client {

struct ClientConfig {
    std::string server;
    int port{443};
    std::string identity;
    int socks_port{0};
    bool obfuscation{false};
    bool inner_crypto{true};
    bool inner_heavy{true};
    std::string pq_public_key;
    std::string anonym_pubkey;
    std::string anonym_ca_cert;
    std::string tls_ca_cert;
    std::string tls_pin_sha256;
    bool require_anonym{false};
};

class Cli {
public:
    int run(int argc, char** argv);
};

}  // namespace yume::client
