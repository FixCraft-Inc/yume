#pragma once

#include <cstdint>
#include <string>

namespace yume::client {

struct ClientConfig {
    std::string server;
    int port{443};
    std::string identity;
    int socks_port{0};
    int io_threads{0};
    bool obfuscation{false};
    bool inner_crypto{true};
    bool inner_heavy{true};
    bool inner_hop{true};
    std::uint32_t hop_interval_ms{500};
    bool allow_udp{false};
    bool allow_local_ip{false};
    bool server_in_charge{false};
    bool allow_exec{false};
    std::string pq_public_key;
    std::string anonym_pubkey;
    std::string anonym_ca_cert;
    std::string tls_ca_cert;
    std::string tls_pin_sha256;
    bool require_anonym{false};
    bool boring{false};
    bool non_interactive{false};
};

class Cli {
public:
    int run(int argc, char** argv);
};

}  // namespace yume::client
