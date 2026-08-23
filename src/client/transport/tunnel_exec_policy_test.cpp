/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/transport/tunnel.hpp"

#include <cassert>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl/context.hpp>

namespace yume::client {

struct TunnelExecPolicyTestPeer {
    static std::vector<protocol::Frame> deliver_exec(
            Tunnel& tunnel, bool* exec_handler_called) {
        std::vector<protocol::Frame> replies;
        tunnel.core_.set_write_handler(
            [&replies](std::shared_ptr<TransportCore::Bytes> wire,
                       TransportCore::WriteCompletion completion) {
                replies.push_back(protocol::decode_frame(*wire));
                if (completion) completion(true, wire->size(), {});
            });
        tunnel.core_.set_exec_handler(
            [exec_handler_called](std::uint8_t, const std::string&) {
                *exec_handler_called = true;
            });
        tunnel.core_.start();
        const std::string command = "must-not-run";
        const Tunnel::Bytes payload(command.begin(), command.end());
        tunnel.core_.feed_tls_bytes(protocol::encode_frame(
            protocol::EXEC, 17, 0, payload));
        return replies;
    }
};

}  // namespace yume::client

int main() {
    boost::asio::io_context io;
    boost::asio::ssl::context tls_context(
        boost::asio::ssl::context::tls_client);
    yume::client::ClientTransportStream::OpenSslStream tls_stream(
        io, tls_context);
    yume::client::ClientTransportStream stream(std::move(tls_stream));
    auto tunnel = std::make_shared<yume::client::Tunnel>(std::move(stream));

    // Even a caller that bypasses CLI validation cannot enable inbound EXEC.
    tunnel->set_allow_exec(true);
    bool exec_handler_called = false;
    const auto replies = yume::client::TunnelExecPolicyTestPeer::deliver_exec(
        *tunnel, &exec_handler_called);

    assert(!exec_handler_called);
    assert(replies.size() == 2);
    assert(replies[0].header.type == yume::protocol::DATA);
    assert(std::string(replies[0].payload.begin(), replies[0].payload.end()) ==
           "EXEC denied");
    assert(replies[1].header.type == yume::protocol::CLOSE);
    assert(std::string(replies[1].payload.begin(), replies[1].payload.end()) ==
           "exec denied");
    return 0;
}
