/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/session.hpp"
#include "core/protocol/frame_limits.hpp"

#include <cstdio>
#include <stdexcept>

namespace yume::server {
struct SessionFrameBudgetTestPeer {
    static void feed_header(Session& session, uint8_t type, uint16_t flags,
                            std::size_t length) {
        session.header_buf_ = {
            static_cast<uint8_t>(length >> 24), static_cast<uint8_t>(length >> 16),
            static_cast<uint8_t>(length >> 8), static_cast<uint8_t>(length),
            type, 0, static_cast<uint8_t>(flags >> 8), static_cast<uint8_t>(flags)};
        session.on_read_header({}, session.header_buf_.size());
    }

    static bool rejected_before_payload(const Session& session,
                                         const char* reason) {
        return session.close_state_ != Session::CloseState::Open &&
            session.close_reason_ == reason && session.payload_buf_.capacity() == 0;
    }
};
}  // namespace yume::server

int main() {
    using namespace yume;
    using Peer = server::SessionFrameBudgetTestPeer;
    for (const uint8_t type : {protocol::AUTH, protocol::DATA}) {
        for (const bool padded : {false, true}) {
            boost::asio::io_context io;
            boost::asio::ssl::context tls(boost::asio::ssl::context::tls);
            const server::ServerConfig config;
            auto session = std::make_shared<server::Session>(
                boost::asio::ip::tcp::socket(io), tls, config,
                nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, 7, nullptr);
            const uint16_t flags = padded ? protocol::kFlagPadded : 0;
            const auto length = protocol::frame_payload_limit(protocol::AUTH, flags) + 1U;
            Peer::feed_header(*session, type, flags, length);
            if (!Peer::rejected_before_payload(*session,
                    type == protocol::AUTH ? "AUTH frame too large" : "expected AUTH")) {
                throw std::runtime_error("Session buffered invalid pre-authentication payload");
            }
            io.poll();
        }
    }
    std::puts("Session frame budget: passed");
}
