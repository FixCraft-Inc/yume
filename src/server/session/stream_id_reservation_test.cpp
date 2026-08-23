/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/session.hpp"

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <algorithm>
#include <array>
#include <cassert>
#include <memory>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>

namespace yume::server {

struct SessionStreamReservationTestPeer {
    static uint8_t PublishInbound(Session& target, std::string marker) {
        auto reservation = target.reserve_stream_id();
        if (!reservation) return 0;
        const uint8_t stream_id = reservation.stream_id();
        Session::ControlLink link;
        link.channel_id = std::move(marker);
        std::lock_guard<std::mutex> lock(target.control_mutex_);
        const bool inserted =
            target.control_inbound_.try_emplace(stream_id,
                                                std::move(link)).second;
        assert(inserted);
        return stream_id;
    }

    static bool PublishReciprocal(Session& source,
                                  Session& target,
                                  uint8_t source_stream,
                                  std::string marker) {
        std::unique_lock<std::recursive_mutex> source_allocation(
            Session::stream_id_allocation_mutex_);
        if (!source.open_stream_id_available(source_stream)) return false;
        auto target_reservation = target.reserve_stream_id();
        if (!target_reservation) return false;

        Session::ControlLink outbound;
        outbound.channel_id = marker;
        outbound.peer_stream_id = target_reservation.stream_id();
        {
            std::lock_guard<std::mutex> lock(source.control_mutex_);
            if (!source.control_outbound_
                     .try_emplace(source_stream, std::move(outbound))
                     .second) {
                return false;
            }
        }

        Session::ControlLink inbound;
        inbound.channel_id = std::move(marker);
        inbound.peer_stream_id = source_stream;
        {
            std::lock_guard<std::mutex> lock(target.control_mutex_);
            if (!target.control_inbound_
                     .try_emplace(target_reservation.stream_id(),
                                  std::move(inbound))
                     .second) {
                std::lock_guard<std::mutex> source_lock(
                    source.control_mutex_);
                source.control_outbound_.erase(source_stream);
                return false;
            }
        }
        return true;
    }

    static std::vector<std::pair<uint8_t, std::string>> InboundLinks(
        Session& target) {
        std::vector<std::pair<uint8_t, std::string>> result;
        std::lock_guard<std::mutex> lock(target.control_mutex_);
        result.reserve(target.control_inbound_.size());
        for (const auto& [stream_id, link] : target.control_inbound_) {
            result.emplace_back(stream_id, link.channel_id);
        }
        return result;
    }
};

}  // namespace yume::server

namespace {

std::shared_ptr<yume::server::Session> MakeSession(
    boost::asio::io_context& io,
    boost::asio::ssl::context& tls_context,
    std::uint64_t session_id) {
    return std::make_shared<yume::server::Session>(
        boost::asio::ip::tcp::socket(io), tls_context,
        yume::server::ServerConfig{},
        std::make_shared<const std::vector<yume::crypto::Bytes>>(),
        std::make_shared<const yume::server::AuthKeyPolicyMap>(),
        std::make_shared<const std::vector<yume::crypto::Bytes>>(),
        std::make_shared<const yume::server::AuthKeyPolicyMap>(),
        std::make_shared<const std::vector<yume::crypto::Bytes>>(),
        nullptr, session_id, nullptr);
}

}  // namespace

int main() {
    using yume::server::SessionStreamReservationTestPeer;

    boost::asio::io_context io;
    boost::asio::ssl::context tls_context(
        boost::asio::ssl::context::tls_server);
    auto target = MakeSession(io, tls_context, 1);

    constexpr std::size_t kFanIn = 128;
    std::array<uint8_t, kFanIn> stream_ids{};
    std::vector<std::thread> workers;
    workers.reserve(kFanIn);
    for (std::size_t index = 0; index < kFanIn; ++index) {
        workers.emplace_back([&, index] {
            stream_ids[index] =
                SessionStreamReservationTestPeer::PublishInbound(
                    *target, "origin-" + std::to_string(index));
        });
    }
    for (auto& worker : workers) worker.join();

    std::unordered_set<uint8_t> unique_ids;
    for (const uint8_t stream_id : stream_ids) {
        assert(stream_id != 0);
        assert(unique_ids.insert(stream_id).second);
    }
    const auto links =
        SessionStreamReservationTestPeer::InboundLinks(*target);
    assert(links.size() == kFanIn);
    for (std::size_t index = 0; index < kFanIn; ++index) {
        const auto expected = "origin-" + std::to_string(index);
        assert(std::find(links.begin(), links.end(),
                         std::pair<uint8_t, std::string>{
                             stream_ids[index], expected}) != links.end());
    }

    // Simultaneous A->B and B->A setup used to deadlock when each session had
    // its own allocation mutex. The class-wide recursive setup lock permits
    // the same-thread target reservation without creating a cross-lock cycle.
    auto left = MakeSession(io, tls_context, 2);
    auto right = MakeSession(io, tls_context, 3);
    std::array<bool, 2> reciprocal_ok{false, false};
    std::thread left_to_right([&] {
        reciprocal_ok[0] =
            SessionStreamReservationTestPeer::PublishReciprocal(
                *left, *right, 200, "left-right");
    });
    std::thread right_to_left([&] {
        reciprocal_ok[1] =
            SessionStreamReservationTestPeer::PublishReciprocal(
                *right, *left, 201, "right-left");
    });
    left_to_right.join();
    right_to_left.join();
    assert(reciprocal_ok[0]);
    assert(reciprocal_ok[1]);
    return 0;
}
