/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/relay/runtime.hpp"

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <atomic>
#include <cassert>
#include <chrono>
#include <filesystem>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>

#include <boost/asio/io_context.hpp>
#include <boost/asio/local/connect_pair.hpp>
#include <boost/asio/local/stream_protocol.hpp>

#include "client/transport/client_stream.hpp"
#include "core/security/crypto.hpp"
#include "core/security/secret_file.hpp"
#include "core/security/secure_erase.hpp"
#include "util.hpp"

namespace yume::client {

namespace {

class TempRuntimeFiles {
public:
    TempRuntimeFiles() {
        const std::string suffix = yume::util::random_hex(12);
        identity_path_ = std::filesystem::temp_directory_path() /
            ("yume-relay-runtime-" + suffix + ".pem");
        trust_path_ = std::filesystem::temp_directory_path() /
            ("yume-relay-runtime-trust-" + suffix);

        auto identity = yume::crypto::generate_composite_keypair();
        auto encoded = yume::crypto::encode_composite_private_pem(identity);
        std::string write_error;
        const bool written = yume::security::WriteFileExclusive0600(
            identity_path_, encoded, &write_error);
        yume::security::secure_erase(encoded);
        if (!written) {
            throw std::runtime_error(
                "failed to create relay runtime test identity: " +
                write_error);
        }
    }

    ~TempRuntimeFiles() {
        std::error_code ignored;
        std::filesystem::remove(identity_path_, ignored);
        std::filesystem::remove_all(trust_path_, ignored);
    }

    RelayRuntime::Options options() const {
        RelayRuntime::Options value;
        value.identity_path = identity_path_.string();
        value.history_enabled = false;
        value.allow_file = false;
        value.allow_bytes = false;
        value.peer_trust.directory = trust_path_;
        return value;
    }

    const std::filesystem::path& identity_path() const noexcept {
        return identity_path_;
    }

private:
    std::filesystem::path identity_path_;
    std::filesystem::path trust_path_;
};

class RuntimeHarness {
public:
    RuntimeHarness(const TempRuntimeFiles& files, bool connected)
        : peer_socket(io) {
        boost::asio::local::stream_protocol::socket runtime_socket(io);
        if (connected) {
            boost::asio::local::connect_pair(runtime_socket, peer_socket);
        }
        ClientTransportStream transport(
            std::move(runtime_socket), TlsConnectionMetadata{}, nullptr);
        tunnel = std::make_shared<Tunnel>(std::move(transport));
        runtime = std::make_shared<RelayRuntime>(
            tunnel, ClientConfig{}, files.options());
    }

    boost::asio::io_context io;
    boost::asio::local::stream_protocol::socket peer_socket;
    std::shared_ptr<Tunnel> tunnel;
    std::shared_ptr<RelayRuntime> runtime;
};

}  // namespace

struct RelayRuntimeTestPeer {
    static RelayRuntime::ChannelState MakeReadyChannel(
            std::uint8_t stream_id) {
        RelayRuntime::ChannelState channel;
        channel.channel_id = "ready";
        channel.stream_id = stream_id;
        channel.ratchet = std::make_unique<ratchet::SessionRatchet>(
            ratchet::EndpointRole::Client,
            ratchet::Bytes(32, 0x17), ratchet::Bytes(32, 0x28),
            ratchet::kMinRekeyWindow, ratchet::kMinRekeyWindow,
            ratchet::kExtremePolicy, ratchet::kExtremePolicy);
        return channel;
    }

    static RelayRuntime::ChannelState MakeBlockedRekeyChannel(
            RelayRuntime& runtime, std::uint8_t stream_id) {
        (void)runtime;
        const ratchet::RatchetPolicy one_frame_policy{
            ratchet::kMaxProtectedPayload,
            1,
            std::chrono::milliseconds(500),
        };
        auto channel_ratchet = std::make_unique<ratchet::SessionRatchet>(
            ratchet::EndpointRole::Client,
            ratchet::Bytes(32, 0x31), ratchet::Bytes(32, 0x52),
            ratchet::kMinRekeyWindow, ratchet::kMinRekeyWindow,
            one_frame_policy, one_frame_policy);
        const auto now = std::chrono::steady_clock::now();
        protocol::Frame first{{1, protocol::DATA, 0, 0}, {0x41}};
        (void)channel_ratchet->Seal(first, now);
        (void)channel_ratchet->BeginOutboundRekey(now);

        RelayRuntime::ChannelState channel;
        channel.channel_id = "blocked-rekey";
        channel.stream_id = stream_id;
        channel.ratchet = std::move(channel_ratchet);
        return channel;
    }

    static void CheckBoundedRekeyQueue(RelayRuntime& runtime) {
        {
            auto channel = MakeBlockedRekeyChannel(runtime, 7);
            std::string error;
            for (std::size_t index = 0; index < 8; ++index) {
                assert(runtime.send_channel_payload_locked(
                    channel, "queued-" + std::to_string(index), {},
                    &error));
            }
            assert(channel.pending_applications.size() == 8);
            assert(!runtime.send_channel_payload_locked(
                channel, "queue-overflow", {}, &error));
            assert(error.find("pending application queue is full") !=
                   std::string::npos);
        }
        {
            auto channel = MakeBlockedRekeyChannel(runtime, 8);
            std::string error;
            const std::string maximum_record(
                relay_v2::record::kMaxPlaintextPayloadBytes, 'x');
            for (std::size_t index = 0; index < 4; ++index) {
                assert(runtime.send_channel_payload_locked(
                    channel, maximum_record, {}, &error));
            }
            assert(channel.pending_application_bytes == 256U * 1024U);
            assert(!runtime.send_channel_payload_locked(
                channel, "byte-overflow", {}, &error));
            assert(error.find("pending application queue is full") !=
                   std::string::npos);
        }
    }

    static void CheckRekeyAckFlush(RelayRuntime& runtime) {
        const ratchet::RatchetPolicy one_frame_policy{
            ratchet::kMaxProtectedPayload,
            1,
            std::chrono::milliseconds(500),
        };
        const ratchet::Bytes root(32, 0x63);
        const ratchet::Bytes psk(32, 0x74);
        auto sender = std::make_unique<ratchet::SessionRatchet>(
            ratchet::EndpointRole::Client, root, psk,
            ratchet::kMinRekeyWindow, ratchet::kMinRekeyWindow,
            one_frame_policy, one_frame_policy);
        ratchet::SessionRatchet receiver(
            ratchet::EndpointRole::Server, root, psk,
            ratchet::kMinRekeyWindow, ratchet::kMinRekeyWindow,
            one_frame_policy, one_frame_policy);
        const auto now = std::chrono::steady_clock::now();
        protocol::Frame first{{1, protocol::DATA, 0, 0}, {0x41}};
        const auto first_sealed = sender->Seal(first, now);
        assert(receiver.Open(first_sealed, now).application_frame.has_value());
        const auto init = sender->BeginOutboundRekey(now);
        auto init_result = receiver.Open(init, now);
        assert(init_result.control_response.has_value());

        RelayRuntime::ChannelState channel;
        channel.channel_id = "ack-flush";
        channel.stream_id = 9;
        channel.ratchet = std::move(sender);
        std::string error;
        assert(runtime.send_channel_payload_locked(
            channel, "wait-for-ack", {}, &error));
        assert(channel.pending_applications.size() == 1);

        const auto ack = receiver.Seal(
            *init_result.control_response, now);
        const auto ack_result = channel.ratchet->Open(ack, now);
        assert(ack_result.outbound_rekey_completed);
        runtime.flush_pending_applications_locked(channel);
        assert(channel.pending_applications.empty());
        assert(channel.pending_application_bytes == 0);
    }

    static void CheckRejectedWriteOwnership(
            RelayRuntime& runtime,
            Tunnel& tunnel,
            boost::asio::io_context& io) {
        std::size_t admitted = 0;
        while (tunnel.try_send_data(
                   41, Tunnel::Bytes{static_cast<std::uint8_t>(admitted)})) {
            ++admitted;
            assert(admitted < 1024);
        }
        assert(admitted > 0);

        std::atomic<int> rejected_callbacks{0};
        const RelayRuntime::ChannelWriteCompletion rejected_completion =
            [&rejected_callbacks](bool, const std::string&) {
                rejected_callbacks.fetch_add(1, std::memory_order_relaxed);
            };
        auto direct = MakeReadyChannel(42);
        std::string direct_error;
        {
            std::lock_guard<std::mutex> lock(runtime.mutex_);
            assert(!runtime.send_channel_payload_locked(
                direct, "queue-full", rejected_completion,
                &direct_error));
        }
        assert(direct_error.find("queue is full") != std::string::npos);
        // A rejected admission never transfers callback ownership to the
        // transport and therefore never invokes it.
        assert(rejected_callbacks.load(std::memory_order_relaxed) == 0);

        std::atomic<int> flush_callbacks{0};
        auto pending = MakeReadyChannel(43);
        pending.pending_application_bytes = 1;
        pending.pending_applications.emplace_back(
            relay_v2::Bytes{0x51},
            [&flush_callbacks](bool ok, const std::string&) {
                assert(!ok);
                flush_callbacks.fetch_add(1, std::memory_order_relaxed);
            });
        bool flush_failed = false;
        {
            std::lock_guard<std::mutex> lock(runtime.mutex_);
            try {
                runtime.flush_pending_applications_locked(pending);
            } catch (const std::exception&) {
                flush_failed = true;
            }
        }
        assert(flush_failed);
        assert(flush_callbacks.load(std::memory_order_relaxed) == 0);
        io.run();
        assert(flush_callbacks.load(std::memory_order_relaxed) == 1);
    }

    static void CheckAcceptedWriteAndRemoteStopArePosted(
            RelayRuntime& runtime,
            boost::asio::io_context& io) {
        std::atomic<int> write_callbacks{0};
        auto channel = MakeReadyChannel(51);
        std::string write_error;
        {
            std::lock_guard<std::mutex> lock(runtime.mutex_);
            assert(runtime.send_channel_payload_locked(
                channel, "accepted",
                [&write_callbacks](bool ok, const std::string& reason) {
                    assert(ok);
                    assert(reason.empty());
                    write_callbacks.fetch_add(
                        1, std::memory_order_relaxed);
                },
                &write_error));
            assert(write_callbacks.load(std::memory_order_relaxed) == 0);
        }
        assert(write_error.empty());
        assert(write_callbacks.load(std::memory_order_relaxed) == 0);
        io.run();
        assert(write_callbacks.load(std::memory_order_relaxed) == 1);

        io.restart();
        std::atomic<int> stop_callbacks{0};
        runtime.set_stop_callback([&runtime, &stop_callbacks]() {
            // Re-entering the runtime proves the embedder callback does not
            // run under RelayRuntime::mutex_.
            (void)runtime.status_json();
            stop_callbacks.fetch_add(1, std::memory_order_relaxed);
        });
        bool stop_after_response = false;
        {
            std::lock_guard<std::mutex> lock(runtime.mutex_);
            const auto response = runtime.handle_admin_request(
                {{"op", "runtime.stop"}, {"request_id", "stop-1"}},
                &stop_after_response);
            assert(stop_after_response);
            assert(stop_callbacks.load(std::memory_order_relaxed) == 0);
            runtime.send_admin_response(
                channel, response, stop_after_response);
            assert(stop_callbacks.load(std::memory_order_relaxed) == 0);
        }
        io.run();
        assert(stop_callbacks.load(std::memory_order_relaxed) == 1);
    }

    static void CheckFailedAdminResponseDoesNotStop(
            RelayRuntime& runtime,
            boost::asio::io_context& io) {
        std::atomic<int> stop_callbacks{0};
        runtime.set_stop_callback([&stop_callbacks]() {
            stop_callbacks.fetch_add(1, std::memory_order_relaxed);
        });
        auto channel = MakeReadyChannel(52);
        bool stop_after_response = false;
        {
            std::lock_guard<std::mutex> lock(runtime.mutex_);
            const auto response = runtime.handle_admin_request(
                {{"op", "runtime.stop"}, {"request_id", "stop-failed"}},
                &stop_after_response);
            assert(stop_after_response);
            runtime.send_admin_response(
                channel, response, stop_after_response);
        }
        assert(stop_callbacks.load(std::memory_order_relaxed) == 0);
        io.run();
        assert(stop_callbacks.load(std::memory_order_relaxed) == 0);
    }

    static void CheckControlSendExceptionCleanup(RelayRuntime& runtime) {
        nlohmann::json request{{"cmd", "test.invalid-utf8"}};
        request["invalid"] = std::string(1, static_cast<char>(0xff));
        std::string error;
        const auto response = runtime.send_control_request(
            std::move(request), &error, 1);
        assert(response.empty());
        assert(error.find("failed to send control request") !=
               std::string::npos);
        std::lock_guard<std::mutex> lock(runtime.mutex_);
        assert(runtime.control_responses_.empty());
    }

    static void CheckAmbiguousDisplayNames(RelayRuntime& runtime) {
        control::EndpointInfo first;
        first.endpoint_id = "first";
        first.display_name = "duplicate";
        control::EndpointInfo second;
        second.endpoint_id = "second";
        second.display_name = "duplicate";
        std::lock_guard<std::mutex> lock(runtime.mutex_);
        runtime.update_directory_locked({first, second});
        assert(runtime.resolve_peer_locked("first").has_value());
        assert(runtime.resolve_peer_locked("second").has_value());
        assert(!runtime.resolve_peer_locked("duplicate").has_value());
    }

    static void CheckSourceTrustNamespaces() {
        control::PendingInvite direct;
        direct.from_endpoint_id = "alice";
        direct.to_endpoint_id = "bob";
        std::string error;
        const auto direct_id = RelayRuntime::source_trust_id_from_notification(
            nlohmann::json::object(), direct, &error);
        assert(direct_id && *direct_id == "alice");
        assert(error.empty());

        control::PendingInvite federated = direct;
        federated.to_endpoint_id = "server-b:bob";
        const nlohmann::json valid{
            {"local_target_id", "bob"},
            {"source_trust_id", "server-a:alice"},
        };
        const auto federated_id = RelayRuntime::source_trust_id_from_notification(
            valid, federated, &error);
        assert(federated_id && *federated_id == "server-a:alice");
        assert(*federated_id != federated.from_endpoint_id);

        auto missing = valid;
        missing.erase("source_trust_id");
        assert(!RelayRuntime::source_trust_id_from_notification(
            missing, federated, &error));
        assert(!error.empty());

        auto mismatched = valid;
        mismatched["source_trust_id"] = "server-a:mallory";
        assert(!RelayRuntime::source_trust_id_from_notification(
            mismatched, federated, &error));

        auto malformed = valid;
        malformed["source_trust_id"] = "server-a:other:alice";
        assert(!RelayRuntime::source_trust_id_from_notification(
            malformed, federated, &error));

        nlohmann::json caller_ambiguous{
            {"source_trust_id", "server-a:alice"},
        };
        assert(!RelayRuntime::source_trust_id_from_notification(
            caller_ambiguous, direct, &error));
    }

    static bool AddIncoming(RelayRuntime& runtime,
                            const std::string& invite_id,
                            bool accepted = false) {
        std::lock_guard<std::mutex> lock(runtime.mutex_);
        RelayRuntime::PendingIncomingInvite pending;
        pending.invite.invite_id = invite_id;
        if (accepted) {
            pending.invite.accepted = true;
        }
        return runtime.admit_incoming_invite_locked(std::move(pending));
    }

    static bool AddOutgoing(RelayRuntime& runtime,
                            const std::string& invite_id,
                            std::string* error) {
        std::lock_guard<std::mutex> lock(runtime.mutex_);
        RelayRuntime::PendingOutgoingInvite pending;
        pending.invite.invite_id = invite_id;
        return runtime.admit_outgoing_invite_locked(
            std::move(pending), error);
    }

    static std::size_t IncomingSize(RelayRuntime& runtime) {
        std::lock_guard<std::mutex> lock(runtime.mutex_);
        return runtime.incoming_invites_.size();
    }

    static std::size_t OutgoingSize(RelayRuntime& runtime) {
        std::lock_guard<std::mutex> lock(runtime.mutex_);
        return runtime.outgoing_invites_.size();
    }

    static void ExpireAllViaTimer(RelayRuntime& runtime) {
        std::lock_guard<std::mutex> lock(runtime.mutex_);
        const auto expired = std::chrono::steady_clock::now() -
            std::chrono::seconds(1);
        for (auto& [id, pending] : runtime.incoming_invites_) {
            (void)id;
            pending.expires_at = expired;
        }
        for (auto& [id, pending] : runtime.outgoing_invites_) {
            (void)id;
            pending.expires_at = expired;
        }
        runtime.schedule_pending_invite_expiry_locked();
    }

    static void CheckChatIdentityRouting(RelayRuntime& runtime) {
        constexpr std::uint8_t stream_id = 19;
        {
            std::lock_guard<std::mutex> lock(runtime.mutex_);
            auto channel = MakeReadyChannel(stream_id);
            channel.channel_id = "chat-channel-a";
            channel.channel_kind = control::ChannelKind::chat;
            channel.peer_id = "peer-a";
            channel.peer_name = "Peer A";
            assert(runtime.channels_.emplace(
                stream_id, std::move(channel)).second);
            runtime.active_chat_stream_ = stream_id;
        }

        const auto status = runtime.status_json();
        assert(status.at("active_chat").at("channel_id") ==
               "chat-channel-a");
        assert(status.at("active_chat").at("peer_id") == "peer-a");

        std::string error;
        assert(!runtime.send_chat("chat-channel-b", "wrong channel", &error));
        assert(error == "requested chat channel is not active");
        error.clear();
        assert(!runtime.close_chat("chat-channel-b", &error));
        assert(error == "requested chat channel is not active");

        std::lock_guard<std::mutex> lock(runtime.mutex_);
        runtime.active_chat_stream_.reset();
        runtime.channels_.erase(stream_id);
    }
};

}  // namespace yume::client

int main() {
    using namespace yume::client;

    TempRuntimeFiles files;
    RelayRuntimeTestPeer::CheckSourceTrustNamespaces();

    {
        boost::asio::io_context identity_io;
        boost::asio::local::stream_protocol::socket identity_socket(
            identity_io);
        ClientTransportStream identity_transport(
            std::move(identity_socket), TlsConnectionMetadata{}, nullptr);
        auto identity_tunnel = std::make_shared<Tunnel>(
            std::move(identity_transport));
        auto invalid_options = files.options();
        invalid_options.identity_path =
            files.identity_path().string() + ".missing";
        bool identity_failed = false;
        try {
            (void)std::make_shared<RelayRuntime>(
                identity_tunnel, ClientConfig{},
                std::move(invalid_options));
        } catch (const std::exception&) {
            identity_failed = true;
        }
        assert(identity_failed);
    }

    {
        RuntimeHarness connected(files, true);
        RelayRuntimeTestPeer::CheckAcceptedWriteAndRemoteStopArePosted(
            *connected.runtime, connected.io);
        RelayRuntimeTestPeer::CheckControlSendExceptionCleanup(
            *connected.runtime);
        RelayRuntimeTestPeer::CheckAmbiguousDisplayNames(
            *connected.runtime);
    }

    {
        RuntimeHarness saturated(files, false);
        RelayRuntimeTestPeer::CheckRejectedWriteOwnership(
            *saturated.runtime, *saturated.tunnel, saturated.io);
    }

    {
        RuntimeHarness failed_stop(files, false);
        RelayRuntimeTestPeer::CheckFailedAdminResponseDoesNotStop(
            *failed_stop.runtime, failed_stop.io);
    }

    boost::asio::io_context io;
    boost::asio::local::stream_protocol::socket socket(io);
    ClientTransportStream transport(
        std::move(socket), TlsConnectionMetadata{}, nullptr);
    auto tunnel = std::make_shared<Tunnel>(std::move(transport));
    auto runtime = std::make_shared<RelayRuntime>(
        tunnel, ClientConfig{}, files.options());

    RelayRuntimeTestPeer::CheckBoundedRekeyQueue(*runtime);
    RelayRuntimeTestPeer::CheckRekeyAckFlush(*runtime);
    RelayRuntimeTestPeer::CheckChatIdentityRouting(*runtime);

    assert(RelayRuntimeTestPeer::AddIncoming(
        *runtime, "incoming-secret", true));
    for (std::size_t i = 1;
         i < yume::control::kMaxPendingRelayInvitesPerEndpoint; ++i) {
        assert(RelayRuntimeTestPeer::AddIncoming(
            *runtime, "incoming-" + std::to_string(i)));
    }
    assert(RelayRuntimeTestPeer::IncomingSize(*runtime) ==
           yume::control::kMaxPendingRelayInvitesPerEndpoint);
    assert(!RelayRuntimeTestPeer::AddIncoming(*runtime, "incoming-overflow"));
    assert(!RelayRuntimeTestPeer::AddIncoming(*runtime, "incoming-1"));

    std::string error;
    for (std::size_t i = 0;
         i < yume::control::kMaxPendingRelayInvitesPerEndpoint; ++i) {
        assert(RelayRuntimeTestPeer::AddOutgoing(
            *runtime, "outgoing-" + std::to_string(i), &error));
    }
    assert(RelayRuntimeTestPeer::OutgoingSize(*runtime) ==
           yume::control::kMaxPendingRelayInvitesPerEndpoint);
    assert(!RelayRuntimeTestPeer::AddOutgoing(
        *runtime, "outgoing-overflow", &error));
    assert(error.find("too many pending") != std::string::npos);

    RelayRuntimeTestPeer::ExpireAllViaTimer(*runtime);
    io.run();
    assert(RelayRuntimeTestPeer::IncomingSize(*runtime) == 0);
    assert(RelayRuntimeTestPeer::OutgoingSize(*runtime) == 0);

    io.restart();
    assert(RelayRuntimeTestPeer::AddIncoming(
        *runtime, "recovered-incoming", true));
    assert(RelayRuntimeTestPeer::AddOutgoing(
        *runtime, "recovered-outgoing", &error));
    RelayRuntimeTestPeer::ExpireAllViaTimer(*runtime);
    io.run();
    assert(RelayRuntimeTestPeer::IncomingSize(*runtime) == 0);
    assert(RelayRuntimeTestPeer::OutgoingSize(*runtime) == 0);

    io.restart();
    assert(RelayRuntimeTestPeer::AddOutgoing(
        *runtime, "destroy-with-pending-secret", &error));
    std::weak_ptr<RelayRuntime> weak_runtime = runtime;
    runtime.reset();
    io.run();
    assert(weak_runtime.expired());
    return 0;
}
