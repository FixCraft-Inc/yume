/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "client/cli/config/args.hpp"
#include "client/cli/entry.hpp"
#include "client/proxy/outbound_proxy.hpp"
#include "core/security/crypto.hpp"
#include "core/security/inner_crypto.hpp"

namespace yume::client {

class RelayRuntime;
class Tunnel;

struct ConnectedSessionOptions {
    using RuntimeReadyCallback = Cli::RuntimeReadyCallback;
    using RuntimeReadyProvider = std::function<RuntimeReadyCallback()>;
    using SetActiveRuntimeCallback = std::function<void(
        boost::asio::io_context*,
        const std::shared_ptr<Tunnel>&,
        const std::shared_ptr<RelayRuntime>&,
        std::function<void(const std::string&)>)>;

    const ParsedArgs* args{nullptr};
    const ClientConfig* cfg{nullptr};
    std::string local_runtime_path;
    std::string argv0;

    bool use_reverse{false};
    bool reverse_server_in_charge_auto{false};
    bool reverse_server_in_charge_manual{false};
    int reverse_listen_port{0};
    std::string reverse_host;
    int reverse_port{0};
    int reverse_auto_min_port{0};
    int reverse_auto_max_port{0};

    bool live_status_enabled{false};
    bool silent{false};
    bool have_inner_caps{false};
    bool server_inner_dual{false};
    bool server_inner_active{false};
    bool hop_enabled{false};
    std::uint32_t hop_interval_ms{0};
    std::int64_t hop_offset_ms{0};
    std::optional<inner::KdfParams> inner_kdf;
    std::optional<crypto::Bytes> inner_key;
    std::string server_tls_fingerprint_sha256;
    std::function<std::string()> status_block_builder;

    std::function<void()> announce_stopping;
    SetActiveRuntimeCallback set_active_runtime;
    RuntimeReadyProvider take_runtime_ready_callback;
};

using ClientTlsStream = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;

int run_connected_session(boost::asio::io_context& io,
                          boost::asio::ssl::context& ctx,
                          ClientTlsStream&& stream,
                          const outbound_proxy::Config& proxy_cfg,
                          ConnectedSessionOptions options,
                          std::atomic<bool>& stop_requested);

}  // namespace yume::client
