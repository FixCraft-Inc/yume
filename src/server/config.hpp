#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "core/runtime_policy.hpp"

namespace yume::server {

struct ServerConfig {
    int listen_port{443};
    std::string tls_cert;
    std::string tls_key;
    std::string auth_keys;
    int threads{0};
    bool obfuscation{false};
    bool inner_crypto{true};
    bool inner_heavy{true};
    bool inner_dual{false};
    bool inner_required{false};
    bool inner_hop{true};
    std::uint32_t hop_interval_ms{500};
    int reverse_port_min{yume::policy::kReversePortMinDefault};
    int reverse_port_max{yume::policy::kReversePortMaxDefault};
    std::string dns_server;
    std::string pq_private_key;
    bool pq_auto_generate{false};
    bool allow_embedded_master{false};
    bool allow_exec{false};
    bool allow_local_ip{false};
    bool control_full{false};
    bool real_http{false};
    std::string real_index_path;
    std::string real_secret;
    std::string real_secret_file;
    std::string obfs_secret;
    bool anonym{false};
    std::string anonym_proof_mode{std::string(yume::policy::kAnonymProofModeAuto)};
    std::string anonym_api;
    std::string anonym_token;
    std::string anonym_hash;
    std::string anonym_sig;
    std::string anonym_ts;
    std::string anonym_nonce;
    std::string anonym_certfp;
    std::string anonym_ca_key;
    std::string anonym_ca_cert;
    std::string anonym_ca_sig;
    std::string anonym_ca_alg;
    std::string anonym_sub_key;
    std::string anonym_sub_cert;
    std::string anonym_sub_cert_b64;
    std::string anonym_sub_sig;
    std::string anonym_sub_alg;
    std::vector<std::string> anonym_proof_sources;
    std::string pq_pub_b64;
    std::string pq_sig;
    std::string pq_alg;
    std::string auth_keys_meta;
    std::string server_name;
    std::string server_id;
    std::string outbound_proxy_url;
    bool relay_enable{true};
    bool directory_enable{true};
    bool ipc_enable{true};
    std::string ipc_path;
    bool federation_enable{false};
    // True when the operator passed --cluster-bootstrap: the daemon is
    // an entry point into a federated cluster, expects peers to dial
    // it but has no outgoing dial-out list of its own. Relaxes the
    // "federation requires at least one --peer" startup check.
    bool cluster_bootstrap{false};
    std::vector<std::string> federation_peers;
    std::string federation_auth_key;
    std::string federation_anonym_ca;
    std::string operator_keys;
    std::string operator_keys_meta;
    bool boring{false};
};

}  // namespace yume::server
