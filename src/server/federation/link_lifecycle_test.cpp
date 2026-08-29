/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/federation/link.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio/io_context.hpp>

#include "core/security/secret_file.hpp"
#include "server/federation/manager.hpp"

#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace yume::server {

struct FederationLinkLifecycleTestPeer {
    static void InstallTunnel(
        FederationLink& link,
        const std::shared_ptr<client::Tunnel>& tunnel) {
        std::lock_guard<std::mutex> lock(link.mutex_);
        link.tunnel_ = tunnel;
        link.ready_ = false;
        link.state_ = "hello";
        link.remote_namespace_for_local_.clear();
    }

    static void HandleControl(FederationLink& link,
                              const nlohmann::json& json,
                              const std::shared_ptr<client::Tunnel>& tunnel) {
        link.handle_control(json, tunnel);
    }

    static void AddChannel(FederationLink& link,
                           std::uint8_t stream_id,
                           std::string channel_id,
                           bool open_pending) {
        std::lock_guard<std::mutex> lock(link.mutex_);
        link.channels_[stream_id] = FederationLink::LinkChannel{
            {}, 0, stream_id, std::move(channel_id), open_pending};
        link.channels_active_ =
            static_cast<std::uint32_t>(link.channels_.size());
        link.ready_ = true;
        link.state_ = "ready";
    }

    static void CompleteOpen(FederationLink& link,
                             std::uint8_t stream_id,
                             const std::string& channel_id,
                             bool ok) {
        link.complete_channel_open(stream_id, channel_id, ok,
                                   ok ? "accepted" : "rejected");
    }

    static std::size_t ChannelCount(const FederationLink& link) {
        std::lock_guard<std::mutex> lock(link.mutex_);
        return link.channels_.size();
    }

    static std::string PeerPskFile(const FederationLink& link) {
        return link.peer_.psk_file;
    }

    static void SetLastError(FederationLink& link, std::string error) {
        std::lock_guard<std::mutex> lock(link.mutex_);
        link.last_error_ = std::move(error);
    }
};

}  // namespace yume::server

namespace {

void Require(bool condition, const char* message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

std::shared_ptr<yume::client::Tunnel> MakeTestTunnel(
    boost::asio::io_context& io,
    boost::asio::ssl::context& ssl_context) {
    yume::client::ClientTransportStream::OpenSslStream stream(
        boost::asio::ip::tcp::socket(io), ssl_context);
    return std::make_shared<yume::client::Tunnel>(
        yume::client::ClientTransportStream(std::move(stream)));
}

void CheckHelloAndChannelLifecycle() {
    boost::asio::io_context server_io;
    boost::asio::io_context tunnel_io;
    boost::asio::ssl::context ssl_context(
        boost::asio::ssl::context::tls_client);
    yume::server::ServerConfig config;
    config.server_id = "local-server";
    config.server_name = "Local server";
    yume::server::FederationPeer peer;
    peer.id = "remote-server";
    auto link = std::make_shared<yume::server::FederationLink>(
        server_io, config, peer, nullptr);
    auto tunnel = MakeTestTunnel(tunnel_io, ssl_context);
    yume::server::FederationLinkLifecycleTestPeer::InstallTunnel(
        *link, tunnel);

    Require(!link->is_ready(),
            "link became ready before an accepted hello");
    const nlohmann::json hello{
        {"cmd", "federation.hello"},
        {"ok", true},
        {"peer_id", "local-at-remote"},
        {"your_peer_id", "local-at-remote"},
        {"server_id", "remote-server"},
        {"server_name", "Remote server"},
    };
    yume::server::FederationLinkLifecycleTestPeer::HandleControl(
        *link, hello, tunnel);
    Require(link->is_ready(),
            "valid hello did not publish application readiness");
    Require(link->remote_namespace_for_local() == "local-at-remote",
            "valid hello namespace was not retained");

    auto changed_hello = hello;
    changed_hello["peer_id"] = "changed";
    changed_hello["your_peer_id"] = "changed";
    yume::server::FederationLinkLifecycleTestPeer::HandleControl(
        *link, changed_hello, tunnel);
    Require(!link->is_ready(),
            "changed duplicate hello kept the link ready");

    // Reinstall the same in-memory transport for isolated stream lifecycle
    // checks; it need not perform network I/O.
    yume::server::FederationLinkLifecycleTestPeer::InstallTunnel(
        *link, tunnel);
    const std::uint8_t rejected_stream = tunnel->reserve_stream_id();
    Require(rejected_stream != 0, "test stream reservation failed");
    tunnel->register_stream(
        rejected_stream,
        [](const yume::client::Tunnel::Bytes&,
           yume::client::Tunnel::InboundCredit) {},
        [](const std::string&) {});
    yume::server::FederationLinkLifecycleTestPeer::AddChannel(
        *link, rejected_stream, "rejected-open", true);
    yume::server::FederationLinkLifecycleTestPeer::CompleteOpen(
        *link, rejected_stream, "rejected-open", false);
    Require(
        yume::server::FederationLinkLifecycleTestPeer::ChannelCount(*link) ==
            0U,
        "negative OPEN left a link channel registered");

    bool rejected_stream_reusable = false;
    std::vector<std::uint8_t> reservations;
    for (std::size_t index = 0; index < 255U; ++index) {
        const std::uint8_t candidate = tunnel->reserve_stream_id();
        if (candidate == 0) break;
        reservations.push_back(candidate);
        if (candidate == rejected_stream) {
            rejected_stream_reusable = true;
            break;
        }
    }
    Require(rejected_stream_reusable,
            "negative OPEN did not unregister its remote stream");
    for (const auto stream_id : reservations) {
        tunnel->release_reserved_stream(stream_id);
    }

    const std::uint8_t data_stream = tunnel->reserve_stream_id();
    Require(data_stream != 0, "DATA test stream reservation failed");
    tunnel->register_stream(
        data_stream,
        [](const yume::client::Tunnel::Bytes&,
           yume::client::Tunnel::InboundCredit) {},
        [](const std::string&) {});
    yume::server::FederationLinkLifecycleTestPeer::AddChannel(
        *link, data_stream, "bounded-data", false);
    std::size_t released_bytes = 0;
    constexpr std::size_t kRejectedPayloadBytes =
        16U * 1024U * 1024U + 1U;
    link->send_data(
        data_stream, "bounded-data",
        yume::client::Tunnel::Bytes(kRejectedPayloadBytes, 0x5a),
        yume::client::Tunnel::InboundCredit(
            17U, [&released_bytes](std::size_t bytes) {
                released_bytes += bytes;
            }));
    Require(released_bytes == 17U,
            "rejected federation DATA did not release credit exactly once");
    Require(
        yume::server::FederationLinkLifecycleTestPeer::ChannelCount(*link) ==
            0U,
        "rejected federation DATA did not close only its channel");

    link->close();
    tunnel->cancel_runtime_operations("test complete");
}

void CheckDuplicatePeerIds(const std::filesystem::path& root) {
    boost::asio::io_context io;
    yume::server::ServerConfig config;
    const auto first_psk = root / "first-missing.psk";
    const auto second_psk = root / "second-missing.psk";
    const auto first_carrier = root / "first-missing.carrier";
    const auto second_carrier = root / "second-missing.carrier";
    config.federation_peers = {
        nlohmann::json({
            {"id", "duplicate-peer"},
            {"url", "yume://127.0.0.1:1"},
            {"psk_file", first_psk.string()},
            {"carrier_secret_file", first_carrier.string()},
        }).dump(),
        nlohmann::json({
            {"id", "duplicate-peer"},
            {"url", "yume://127.0.0.1:2"},
            {"psk_file", second_psk.string()},
            {"carrier_secret_file", second_carrier.string()},
        }).dump(),
    };

    yume::server::FederationManager manager(io, config, nullptr);
    const auto configured = manager.configured_peers();
    Require(configured.peers.size() == 1U &&
                configured.invalid_entries == 1U,
            "status did not count the rejected duplicate peer id");
    Require(configured.peers[0].port == 1,
            "status did not retain the first duplicate peer target");
    const auto pre_manager =
        yume::server::FederationManager::configured_peers(config);
    Require(pre_manager.peers.size() == 1U &&
                pre_manager.invalid_entries == 1U,
            "static configuration status drifted from manager status");
    manager.start();
    const auto first_link = manager.find("duplicate-peer");
    Require(first_link != nullptr,
            "duplicate peer test did not retain the first link");
    Require(manager.statuses().size() == 1U,
            "duplicate peer id created more than one tracked link");
    Require(yume::server::FederationLinkLifecycleTestPeer::PeerPskFile(
                *first_link) == first_psk.string(),
            "duplicate peer id replaced the first configured link");

    // start() may be called defensively by lifecycle code. It must not replace
    // a previously published link or orphan its worker.
    manager.start();
    Require(manager.find("duplicate-peer") == first_link,
            "repeated manager start replaced the tracked federation link");
    manager.stop();
}

void CheckStrictPeerConfiguration() {
    const auto peer_json = [](const std::string& id,
                              const std::string& url,
                              const std::string& pin) {
        nlohmann::json peer{
            {"id", id},
            {"url", url},
            {"psk_file", "/run/yume/test.psk"},
            {"carrier_secret_file", "/run/yume/test.carrier"},
        };
        if (!pin.empty()) {
            peer["tls_pin"] = pin;
        }
        return peer.dump();
    };

    yume::server::ServerConfig config;
    const std::string valid_pin(64U, 'a');
    config.federation_peers = {
        peer_json("valid-v6", "yume://[2001:db8::1]:9443", valid_pin),
        peer_json("port-prefix", "yume://peer.invalid:443junk", ""),
        peer_json("uppercase-pin", "yume://peer.invalid:443",
                  std::string(64U, 'A')),
        peer_json("short-pin", "yume://peer.invalid:443",
                  std::string(63U, 'a')),
        peer_json("bare-v6", "yume://2001:db8::2:443", ""),
        peer_json("url-path", "yume://peer.invalid:443/ignored", ""),
    };
    auto unknown_field = nlohmann::json::parse(
        peer_json("unknown-field", "yume://peer.invalid:443", ""));
    unknown_field["legacy"] = true;
    config.federation_peers.push_back(unknown_field.dump());
    config.federation_peers.push_back(
        nlohmann::json(peer_json(
            "string-wrapper", "yume://peer.invalid:443", "")).dump());

    const auto configured =
        yume::server::FederationManager::configured_peers(config);
    Require(configured.peers.size() == 1U,
            "strict federation parsing rejected the valid IPv6 peer");
    Require(configured.invalid_entries == 7U,
            "strict federation parsing accepted malformed ports, pins, IPv6, "
            "URL suffixes, unknown fields, or string-wrapped objects");
    Require(configured.peers[0].host == "2001:db8::1" &&
                configured.peers[0].port == 9443 &&
                configured.peers[0].tls_pin_present,
            "valid bracketed IPv6 configuration was not normalized");
}

void CheckRemoteSnapshotUsesFederatedCacheBudget() {
    boost::asio::io_context io;
    yume::server::ServerConfig config;
    yume::server::FederationManager manager(io, config, nullptr);

    yume::control::EndpointInfo endpoint;
    endpoint.display_name = "cached endpoint";
    endpoint.client_platform = "linux";
    endpoint.client_variant = "cli";
    // Canonical base64 for exactly 256 zero bytes, the minimum accepted
    // relay identity size at the directory trust boundary.
    endpoint.auth_pubkey_b64.assign(340U, 'A');
    endpoint.auth_pubkey_b64.append("AA==");

    constexpr std::size_t kSnapshotRows =
        yume::control::kMaxDirectoryEndpoints + 1U;
    for (std::size_t index = 0; index < kSnapshotRows; ++index) {
        const std::string suffix = std::to_string(index);
        endpoint.endpoint_id = "endpoint-" + suffix;
        manager.update_directory(
            "peer-" + suffix, "server-" + suffix, "server", {endpoint});
    }

    Require(manager.remote_endpoints().size() == kSnapshotRows,
            "federation-only snapshot reused the smaller client directory "
            "response budget");
    Require(manager.remote_endpoints(
                yume::control::kMaxDirectoryEndpoints).size() ==
                yume::control::kMaxDirectoryEndpoints,
            "explicit federation snapshot limit was not honored");
}

void CheckPublicErrorRedaction() {
    boost::asio::io_context io;
    yume::server::ServerConfig config;
    config.federation_identity = "/private/federation/identity.pem";
    config.federation_operator_ca = "/private/federation/operator-ca.pem";
    yume::server::FederationPeer peer;
    peer.id = "redaction-peer";
    peer.psk_file = "/private/federation/peer.psk";
    peer.carrier_secret_file = "/private/federation/carrier.hex";

    yume::server::FederationLink link(io, config, peer, nullptr);
    std::string error = "failed " + config.federation_identity + " and " +
                        config.federation_operator_ca + " and " + peer.psk_file +
                        " and " + peer.carrier_secret_file;
    error.push_back('\n');
    error.push_back('\x1b');
    error.append(700U, 'x');
    yume::server::FederationLinkLifecycleTestPeer::SetLastError(
        link, std::move(error));

    const auto status = link.status();
    Require(status.last_error.size() <=
                yume::server::kMaxFederationPublicErrorBytes,
            "public federation error exceeded its size bound");
    Require(status.last_error.find("/private/federation") ==
                std::string::npos,
            "public federation error leaked a configured path");
    Require(status.last_error.find('\n') == std::string::npos &&
                status.last_error.find('\x1b') == std::string::npos,
            "public federation error retained terminal control characters");
    Require(status.last_error.find("[redacted-path]") != std::string::npos,
            "public federation error did not mark redacted paths");
}

class ScopedDirectory {
public:
    explicit ScopedDirectory(std::filesystem::path path)
        : path_(std::move(path)) {}
    ~ScopedDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

private:
    std::filesystem::path path_;
};

}  // namespace

int main() {
#if defined(_WIN32)
    // Protected Secret32 loading intentionally fails closed on Windows until
    // its identity/secret ACL policy is implemented.
    return 0;
#else
    CheckHelloAndChannelLifecycle();
    using namespace std::chrono_literals;
    const auto root = std::filesystem::temp_directory_path() /
        ("yume-federation-close-" + std::to_string(::getpid()));
    std::error_code directory_error;
    assert(std::filesystem::create_directory(root, directory_error));
    ScopedDirectory cleanup(root);

    CheckDuplicatePeerIds(root);
    CheckStrictPeerConfiguration();
    CheckRemoteSnapshotUsesFederatedCacheBudget();
    CheckPublicErrorRedaction();

    const std::vector<std::uint8_t> encoded_secret(64, '0');
    const auto psk_path = root / "peer.psk";
    const auto carrier_path = root / "peer.carrier";
    std::string write_error;
    assert(yume::security::WriteFileExclusive0600(
        psk_path, encoded_secret, &write_error));
    assert(yume::security::WriteFileExclusive0600(
        carrier_path, encoded_secret, &write_error));

    boost::asio::io_context server_io;
    boost::asio::io_context peer_io;
    boost::asio::ip::tcp::acceptor peer_acceptor(
        peer_io, {boost::asio::ip::tcp::v4(), 0});
    const int peer_port = peer_acceptor.local_endpoint().port();
    std::thread close_after_accept([&] {
        boost::asio::ip::tcp::socket socket(peer_io);
        boost::system::error_code ignored;
        peer_acceptor.accept(socket, ignored);
        socket.close(ignored);
    });

    yume::server::ServerConfig config;
    yume::server::FederationPeer peer;
    peer.id = "unreachable-test-peer";
    peer.host = "127.0.0.1";
    // The local peer accepts once and closes before TLS, putting the worker
    // deterministically into its one-second reconnect backoff.
    peer.port = peer_port;
    peer.psk_file = psk_path.string();
    peer.carrier_secret_file = carrier_path.string();

    auto link = std::make_shared<yume::server::FederationLink>(
        server_io, config, peer, nullptr);
    link->start();

    const auto failure_deadline = std::chrono::steady_clock::now() + 3s;
    while (link->status().last_error.empty() &&
           std::chrono::steady_clock::now() < failure_deadline) {
        std::this_thread::sleep_for(5ms);
    }
    close_after_accept.join();
    assert(!link->status().last_error.empty());

    const auto close_started = std::chrono::steady_clock::now();
    link->close();
    const auto close_elapsed = std::chrono::steady_clock::now() - close_started;
    // The old uninterruptible reconnect sleep makes this approximately one
    // second. Leave ample sanitizer/CI scheduling margin while still pinning
    // prompt notification-driven shutdown.
    assert(close_elapsed < 750ms);
    return 0;
#endif
}
