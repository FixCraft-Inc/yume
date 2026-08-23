/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#ifdef NDEBUG
#undef NDEBUG
#endif

#include "server/session/session.hpp"

#include <cstdint>
#include <mutex>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>

#include "core/app_codec/codec.hpp"
#include "core/protocol/control_command_policy.hpp"

namespace yume::server {

struct SessionControlSurvivalTestPeer {
    static void HandleControl(Session& session, const protocol::Frame& frame) {
        static_assert(noexcept(session.handle_control(frame)));
        session.handle_control(frame);
    }

    static void HandleOpen(Session& session, const protocol::Frame& frame) {
        session.handle_open(frame);
    }

    static bool IsOpen(const Session& session) {
        return session.close_state_ == Session::CloseState::Open;
    }

    static const std::string& Hostname(const Session& session) {
        return session.client_hostname_;
    }

    static const std::string& WanIp(const Session& session) {
        return session.client_wan_ip_;
    }

    static bool ServerInCharge(const Session& session) {
        return session.client_server_in_charge_;
    }

    static bool AllowsExec(const Session& session) {
        return session.client_allow_exec_;
    }

    static std::size_t GenericStreamCount(Session& session) {
        std::lock_guard<std::mutex> lock(session.streams_mutex_);
        return session.streams_.size() + session.udp_streams_.size();
    }
};

}  // namespace yume::server

namespace {

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

yume::protocol::Frame JsonFrame(yume::protocol::FrameType type,
                                std::uint8_t stream_id,
                                const nlohmann::json& json) {
    const std::string encoded = json.dump();
    yume::crypto::Bytes payload(encoded.begin(), encoded.end());
    return {{static_cast<std::uint32_t>(payload.size()), type, stream_id, 0},
            std::move(payload)};
}

std::shared_ptr<yume::server::Session> MakeSession(
    boost::asio::io_context& io,
    boost::asio::ssl::context& tls_context) {
    auto authorized_keys = std::make_shared<
        const std::vector<yume::crypto::Bytes>>();
    auto auth_policies =
        std::make_shared<const yume::server::AuthKeyPolicyMap>();
    auto operator_keys = std::make_shared<
        const std::vector<yume::crypto::Bytes>>();
    auto operator_policies =
        std::make_shared<const yume::server::AuthKeyPolicyMap>();
    auto admin_keys = std::make_shared<
        const std::vector<yume::crypto::Bytes>>();
    auto replay_cache =
        std::make_shared<yume::obfs::AdmissionReplayCache>();
    yume::server::ServerConfig config;
    return std::make_shared<yume::server::Session>(
        boost::asio::ip::tcp::socket(io), tls_context, config,
        std::move(authorized_keys), std::move(auth_policies),
        std::move(operator_keys), std::move(operator_policies),
        std::move(admin_keys), std::move(replay_cache), 7U, nullptr);
}

void CheckControlSurvival(yume::server::Session& session) {
    using yume::server::SessionControlSurvivalTestPeer;

    const auto malformed_registration = JsonFrame(
        yume::protocol::CONTROL, 0,
        {{"cmd", "register"},
         {"hostname", 1},
         {"wan_ip", true},
         {"server_in_charge", "yes"},
         {"allow_exec", 1}});
    SessionControlSurvivalTestPeer::HandleControl(
        session, malformed_registration);
    Check(SessionControlSurvivalTestPeer::IsOpen(session),
          "malformed registration closed the session");
    Check(SessionControlSurvivalTestPeer::Hostname(session).empty(),
          "malformed registration mutated hostname");
    Check(SessionControlSurvivalTestPeer::WanIp(session).empty(),
          "malformed registration mutated WAN IP");

    auto oversized_registration = nlohmann::json{
        {"cmd", "register"},
        {"hostname", std::string(
             yume::control::kMaxLegacyHostnameBytes + 1U, 'h')},
        {"wan_ip", "203.0.113.7"},
        {"server_in_charge", true},
        {"allow_exec", true},
    };
    SessionControlSurvivalTestPeer::HandleControl(
        session, JsonFrame(yume::protocol::CONTROL, 0,
                           oversized_registration));
    Check(SessionControlSurvivalTestPeer::IsOpen(session),
          "oversized registration closed the session");
    Check(SessionControlSurvivalTestPeer::Hostname(session).empty(),
          "oversized registration mutated hostname");

    const auto valid_registration = JsonFrame(
        yume::protocol::CONTROL, 0,
        {{"cmd", "register"},
         {"hostname", "workstation.local"},
         {"wan_ip", "203.0.113.7"},
         {"server_in_charge", true},
         {"allow_exec", true}});
    SessionControlSurvivalTestPeer::HandleControl(session, valid_registration);
    Check(SessionControlSurvivalTestPeer::IsOpen(session),
          "valid registration closed the session");
    Check(SessionControlSurvivalTestPeer::Hostname(session) ==
              "workstation.local",
          "valid registration did not publish hostname");
    Check(SessionControlSurvivalTestPeer::WanIp(session) == "203.0.113.7",
          "valid registration did not publish WAN IP");
    Check(SessionControlSurvivalTestPeer::ServerInCharge(session),
          "valid registration lost server-in-charge");
    Check(!SessionControlSurvivalTestPeer::AllowsExec(session),
          "legacy registration bypassed the disabled EXEC policy");

    // This was the original remote exception: json.value<string>() on an
    // integer state.  It must produce a bounded rejection and leave the same
    // session available for the next command.
    SessionControlSurvivalTestPeer::HandleControl(
        session,
        JsonFrame(yume::protocol::CONTROL, 0,
                  {{"cmd", "client.lifecycle"},
                   {"request_id", "malformed-lifecycle"},
                   {"state", 1},
                   {"message", "still connected"}}));
    Check(SessionControlSurvivalTestPeer::IsOpen(session),
          "malformed lifecycle closed the session");

    SessionControlSurvivalTestPeer::HandleControl(
        session,
        JsonFrame(yume::protocol::CONTROL, 0,
                  {{"cmd", "directory.lookup"}, {"query", 1}}));
    Check(SessionControlSurvivalTestPeer::IsOpen(session),
          "malformed neighboring CONTROL command closed the session");

    SessionControlSurvivalTestPeer::HandleControl(
        session,
        JsonFrame(yume::protocol::CONTROL, 0,
                  {{"cmd", "register"},
                   {"hostname", "survived.local"},
                   {"wan_ip", "2001:db8::7"},
                   {"server_in_charge", false},
                   {"allow_exec", false}}));
    Check(SessionControlSurvivalTestPeer::Hostname(session) ==
              "survived.local",
          "session did not accept a command after malformed CONTROL input");
    Check(SessionControlSurvivalTestPeer::WanIp(session) == "2001:db8::7",
          "session did not update after malformed CONTROL input");
}

void CheckCodecOpenSurvival(yume::server::Session& session) {
    using yume::server::SessionControlSurvivalTestPeer;

    // OPEN parsing previously ended its exception boundary before dispatching
    // app-codec-v1.  A numeric codec then escaped json.value<string>() through
    // the io_context worker.
    SessionControlSurvivalTestPeer::HandleOpen(
        session,
        JsonFrame(yume::protocol::OPEN, 23,
                  {{"proto", std::string(yume::app_codec::kOpenProto)},
                   {"codec", 1}}));
    Check(SessionControlSurvivalTestPeer::IsOpen(session),
          "numeric application codec id closed the session");

    SessionControlSurvivalTestPeer::HandleOpen(
        session,
        JsonFrame(yume::protocol::OPEN, 24,
                  {{"proto", std::string(yume::app_codec::kOpenProto)},
                   {"codec", std::string(65U, 'c')}}));
    Check(SessionControlSurvivalTestPeer::IsOpen(session),
          "oversized application codec id closed the session");

    SessionControlSurvivalTestPeer::HandleControl(
        session,
        JsonFrame(yume::protocol::CONTROL, 0,
                  {{"cmd", "register"},
                   {"hostname", "codec-survived.local"},
                   {"wan_ip", "198.51.100.9"},
                   {"server_in_charge", false},
                   {"allow_exec", false}}));
    Check(SessionControlSurvivalTestPeer::Hostname(session) ==
              "codec-survived.local",
          "session did not accept CONTROL after malformed codec OPEN");
}

void CheckGenericOpenBounds(yume::server::Session& session) {
    using yume::server::SessionControlSurvivalTestPeer;

    const std::vector<nlohmann::json> invalid_targets{
        {{"host", std::string(256U, 'h')}, {"port", 443}, {"proto", "tcp"}},
        {{"host", std::string(1024U * 1024U, 'h')},
         {"port", 443},
         {"proto", "tcp"}},
        {{"host", "line\nbreak"}, {"port", 443}, {"proto", "tcp"}},
        {{"host", "example.test"}, {"port", "443"}, {"proto", "tcp"}},
        {{"host", "example.test"}, {"port", 0}, {"proto", "tcp"}},
        {{"host", "example.test"}, {"port", 65536}, {"proto", "tcp"}},
        {{"host", "example.test"}, {"port", 443.5}, {"proto", "tcp"}},
        {{"host", "example.test"}, {"port", 443}, {"proto", 1}},
        {{"host", "example.test"}, {"port", 443}, {"proto", "quic"}},
        {{"host", "example.test"},
         {"port", 443},
         {"proto", "tcp"},
         {"unexpected", true}},
    };

    std::uint8_t stream_id = 40U;
    for (const auto& target : invalid_targets) {
        SessionControlSurvivalTestPeer::HandleOpen(
            session,
            JsonFrame(yume::protocol::OPEN, stream_id++, target));
        Check(SessionControlSurvivalTestPeer::IsOpen(session),
              "invalid generic OPEN closed the session");
        Check(SessionControlSurvivalTestPeer::GenericStreamCount(session) ==
                  0U,
              "invalid generic OPEN allocated a destination stream");
    }

    SessionControlSurvivalTestPeer::HandleControl(
        session,
        JsonFrame(yume::protocol::CONTROL, 0,
                  {{"cmd", "register"},
                   {"hostname", "open-survived.local"},
                   {"wan_ip", "192.0.2.44"},
                   {"server_in_charge", false},
                   {"allow_exec", false}}));
    Check(SessionControlSurvivalTestPeer::Hostname(session) ==
              "open-survived.local",
          "session did not accept CONTROL after invalid generic OPEN");
}

}  // namespace

int main() {
    boost::asio::ssl::context tls_context(
        boost::asio::ssl::context::tls_server);
    boost::asio::io_context io;
    auto session = MakeSession(io, tls_context);
    CheckControlSurvival(*session);
    CheckCodecOpenSurvival(*session);
    CheckGenericOpenBounds(*session);

    // Do not run the io_context: rejection replies are intentionally queued on
    // the strand, while this focused regression observes synchronous command
    // admission and session state.  Destroying io releases those posted
    // handlers without touching an unopened test socket.  The TLS context was
    // constructed first so it outlives both io and the handler-owned session.
    return 0;
}
