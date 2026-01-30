#pragma once

#include <string>

namespace yume::client {

struct ClientConfig {
    std::string server;
    int port{443};
    std::string identity;
    int socks_port{0};
    bool obfuscation{false};
    bool inner_crypto{false};
    std::string pq_public_key;
};

class Cli {
public:
    int run(int argc, char** argv);
};

}  // namespace yume::client
