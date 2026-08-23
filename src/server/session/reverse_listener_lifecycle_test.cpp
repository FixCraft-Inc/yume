/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/session.hpp"

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <cassert>
#include <memory>
#include <string>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>

namespace yume::server {

struct SessionReverseListenerTestPeer {
    static void Install(
        Session& session,
        uint8_t listen_id,
        const std::shared_ptr<boost::asio::ip::tcp::acceptor>& acceptor) {
        {
            std::lock_guard<std::mutex> lock(session.streams_mutex_);
            const bool inserted =
                session.reverse_listeners_.emplace(listen_id, acceptor).second;
            assert(inserted);
        }
        session.arm_reverse_accept(listen_id, acceptor);
    }

    static void Close(Session& session, uint8_t listen_id) {
        session.handle_close(listen_id, "test listener close");
    }

    static bool HasListener(Session& session, uint8_t listen_id) {
        std::lock_guard<std::mutex> lock(session.streams_mutex_);
        return session.reverse_listeners_.find(listen_id) !=
               session.reverse_listeners_.end();
    }
};

}  // namespace yume::server

int main() {
    using yume::server::Session;
    using yume::server::SessionReverseListenerTestPeer;

    boost::asio::ssl::context tls_context(
        boost::asio::ssl::context::tls_server);
    const auto authorized_keys =
        std::make_shared<const std::vector<yume::crypto::Bytes>>();
    const auto policies =
        std::make_shared<const yume::server::AuthKeyPolicyMap>();
    const auto operator_keys =
        std::make_shared<const std::vector<yume::crypto::Bytes>>();
    const auto operator_policies =
        std::make_shared<const yume::server::AuthKeyPolicyMap>();
    const auto admin_keys =
        std::make_shared<const std::vector<yume::crypto::Bytes>>();

    for (std::uint64_t iteration = 1; iteration <= 250; ++iteration) {
        boost::asio::io_context io;
        boost::asio::ip::tcp::socket socket(io);
        auto session = std::make_shared<Session>(
            std::move(socket), tls_context, yume::server::ServerConfig{},
            authorized_keys, policies, operator_keys, operator_policies,
            admin_keys, nullptr, iteration, nullptr);
        std::weak_ptr<Session> weak_session = session;
        auto acceptor = std::make_shared<boost::asio::ip::tcp::acceptor>(
            io, boost::asio::ip::tcp::endpoint(
                    boost::asio::ip::tcp::v4(), 0));

        SessionReverseListenerTestPeer::Install(*session, 7, acceptor);
        assert(SessionReverseListenerTestPeer::HasListener(*session, 7));
        SessionReverseListenerTestPeer::Close(*session, 7);
        assert(!SessionReverseListenerTestPeer::HasListener(*session, 7));

        session.reset();
        // The pending accept callback owns only a weak Session reference. The
        // old self-capturing std::function cycle kept this alive forever.
        assert(weak_session.expired());
        io.run();
        io.restart();
        // A closed acceptor completion must not re-arm bad_descriptor work.
        assert(io.poll() == 0U);
    }
    return 0;
}
