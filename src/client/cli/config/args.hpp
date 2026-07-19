/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace yume::client {

struct ParsedArgs {
    std::string config_path{"config/yume.json"};
    bool config_specified{false};
    bool completion{false};
    std::string completion_shell;
    std::string server;
    int port{0};
    std::string identity;
    std::string socks_bind_host;
    int socks_port{0};
    bool socks_port_override{false};
    int io_threads{0};
    int tunnel_count{0};
    bool tunnel_count_override{false};
    bool obfuscation{true};
    bool obfuscation_override{false};
    std::string obfs_secret;
    bool obfs_secret_override{false};
    std::string obfs_secret_file;
    bool obfs_secret_file_override{false};
    std::string inner_psk_file;
    bool inner_psk_file_override{false};
    std::uint16_t obfs_pad_multiple{0};
    bool obfs_pad_multiple_override{false};
    std::uint32_t obfs_jitter_ms{0};
    bool obfs_jitter_ms_override{false};
    int lport{0};
    std::string lbind_host;
    std::string rhost;
    int rport{0};
    std::string run_cmd;
    bool run_ipv4{false};
    bool proxycmd{false};
    std::string dest_host;
    int dest_port{0};
    bool inner_crypto{false};
    bool inner_crypto_override{false};
    bool inner_heavy{true};
    bool inner_hop{true};
    bool inner_hop_override{false};
    std::uint32_t hop_interval_ms{0};
    bool hop_interval_override{false};
    bool use_udp{false};
    bool udp_override{false};
    bool allow_local_ip{false};
    bool allow_local_ip_override{false};
    std::string pq_public_key;
    bool allow_embedded_master{false};
    bool allow_embedded_master_override{false};
    std::string anonym_ca_cert;
    std::string tls_ca_cert;
    std::string tls_server_name;
    std::string tls_pin_sha256;
    // socks5://[user[:pass]@]host:port; see ClientConfig::outbound_proxy_url.
    std::string outbound_proxy_url;
    bool outbound_proxy_override{false};
    bool tls_stealth{true};
    bool tls_stealth_override{false};
    std::string tls_stealth_profile{"chrome"};
    // Empty means derive the HTTP-layer profile from tls_stealth_profile.
    std::string http_profile;
    bool tls_stealth_rotate{false};
    std::uint32_t tls_stealth_rotation_interval{100};
    bool tls_fingerprint_log{false};
    std::string tls_fingerprint_log_path{"./logs/fingerprints"};
    bool tls_fingerprint_verify{false};
    std::string tls_fingerprint_test_endpoint{"tls.peet.ws"};
    bool self_dpi{false};
    bool self_dpi_override{false};
    bool local_benchmark{false};
    bool local_benchmark_full{false};
    std::vector<std::string> local_benchmark_args;
    bool bench{false};
    bool bench_full{false};
    int bench_mib{256};
    int bench_chunk_kib{256};
    int bench_streams{1};
    std::string bench_direction{"both"};
    bool bench_mib_override{false};
    bool bench_chunk_kib_override{false};
    bool bench_streams_override{false};
    bool bench_direction_override{false};
    bool help{false};
    bool version{false};
    bool credits{false};
    bool accept_monitoring{false};
    bool service_streams_only{false};
    bool save_server{false};
    bool share_export{false};
    bool share_import{false};
    std::string share_path;
    bool share_password_stdin{false};
    bool require_anonym{false};
    bool boring{false};
    bool boring_override{false};
    bool non_interactive{false};
    bool live_status{false};
    bool timing{false};
    bool io_threads_override{false};
    bool server_in_charge{false};
    bool server_in_charge_override{false};
    int server_in_charge_port{0};
    bool server_in_charge_port_override{false};
    int server_in_charge_min_port{0};
    int server_in_charge_max_port{0};
    bool allow_exec{false};
    bool allow_exec_override{false};
    bool control_mode{false};
    bool list_controlled{false};
    std::string control_id;
    std::string preferred_name;
    std::string preferred_id;
    std::string relay_mode{"untrusted"};
    bool allow_inbound_admin{false};
    bool allow_inbound_admin_override{false};
    bool allow_outbound_admin{false};
    bool allow_outbound_admin_override{false};
    bool keep_root{false};
    bool allow_chat{true};
    bool allow_chat_override{false};
    bool allow_file{true};
    bool allow_file_override{false};
    bool allow_bytes{true};
    bool allow_bytes_override{false};
    std::string history_dir;
    bool history_enabled{true};
    bool history_override{false};
    std::string relay_key_file;
    std::string instance_name;
    bool attach_local{false};
    std::string app_codec;
    bool app_codec_override{false};
    std::string app_codec_listen;
    bool app_codec_listen_override{false};
    std::string chat_target;
    std::string chat_password;
    std::string file_target;
    std::string file_path;
    std::string bytes_target;
    std::string bytes_path;
    bool directory_mode{false};
    std::string admin_target;
    std::string exec_cmd;
    std::string ssh_L;
    std::string ssh_R;
    std::string parse_error;
};

ParsedArgs parse_args(int argc, char** argv);

}  // namespace yume::client
