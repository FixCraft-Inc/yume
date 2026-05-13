#pragma once

#include <cstdint>
#include <filesystem>
#include <string>

namespace yume::client {

struct ClientConfig {
    std::string server;
    int port{443};
    std::string identity;
    int socks_port{0};
    int io_threads{0};
    bool obfuscation{true};
    std::string obfs_secret;
    bool inner_crypto{true};
    bool inner_heavy{true};
    bool inner_hop{true};
    std::uint32_t hop_interval_ms{500};
    bool allow_udp{false};
    bool allow_local_ip{false};
    bool server_in_charge{false};
    int server_in_charge_port{0};
    bool allow_exec{false};
    std::string pq_public_key;
    bool allow_embedded_master{false};
    std::string anonym_pubkey;
    std::string anonym_ca_cert;
    std::string anonym_ca_material_id{"embedded-anonym-ca"};
    std::string auth_key_material_id;
    std::string tls_ca_cert;
    std::string tls_pin_sha256;
    bool require_anonym{false};
    bool boring{false};
    bool non_interactive{false};
    std::string instance_name;
    std::string preferred_name;
    std::string preferred_id;
    std::string relay_mode{"untrusted"};
    bool allow_inbound_admin{false};
    bool allow_outbound_admin{false};
    bool allow_chat{true};
    bool allow_file{true};
    bool allow_bytes{true};
    bool history_enabled{true};
    std::string history_dir;
    std::string relay_key_file;
    bool auto_attach_local{true};
    
    // TLS Stealth Mode settings
    bool tls_stealth_enabled{true};  // ON by default
    std::string tls_stealth_profile{"chrome"};  // chrome, firefox, safari
    bool tls_stealth_rotate{false};
    std::uint32_t tls_stealth_rotation_interval{100};
    bool tls_fingerprint_log{false};
    std::string tls_fingerprint_log_path{"./logs/fingerprints"};
    bool tls_fingerprint_verify{false};
    std::string tls_fingerprint_test_endpoint{"tls.peet.ws"};
};

class Cli {
public:
    int run(int argc, char** argv);
};

}  // namespace yume::client
