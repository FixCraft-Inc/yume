/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/fair_frame_budget.hpp"

#include "core/security/session_ratchet.hpp"

#include <cassert>
#include <chrono>
#include <cstddef>
#include <vector>

namespace {

void exercise_stream_count(std::size_t streams) {
    using namespace std::chrono_literals;
    using yume::protocol::DATA;

    yume::server::FairFrameBudget budget(64);
    std::vector<std::size_t> turns(streams + 1, 0);
    const yume::ratchet::Bytes root(32, 0x51);
    const yume::ratchet::Bytes psk(32, 0x62);
    yume::ratchet::SessionRatchet server(
        yume::ratchet::EndpointRole::Server, root, psk);
    yume::ratchet::SessionRatchet client(
        yume::ratchet::EndpointRole::Client, root, psk);
    auto now = std::chrono::steady_clock::time_point{} + 1s;
    std::size_t rekeys = 0;

    for (std::size_t i = 0; i < streams; ++i) {
        budget.activate(static_cast<std::uint8_t>(i + 1));
    }

    auto reserve_and_send = [&] {
        const auto source = budget.pop_ready();
        assert(source.has_value());
        assert(budget.reserve());
        ++turns[*source];

        yume::protocol::Frame plain{
            {64U * 1024U, DATA, *source, 0},
            std::vector<std::uint8_t>(64U * 1024U, *source)};
        if (server.ShouldStartRekey(plain, now)) {
            const auto init = server.BeginOutboundRekey(now);
            const auto opened_init = client.Open(init, now + 1ms);
            assert(opened_init.control_response.has_value());
            const auto opened_ack = server.Open(
                *opened_init.control_response, now + 2ms);
            assert(opened_ack.outbound_rekey_completed);
            ++rekeys;
            now += 3ms;
        }
        const auto opened = client.Open(server.Seal(plain, now), now + 1ms);
        assert(opened.application_frame.has_value());
        assert(opened.application_frame->header.stream_id == *source);
        now += 2ms;
        budget.activate(*source);
    };

    for (std::size_t i = 0; i < 64; ++i) reserve_and_send();
    assert(budget.full());
    assert(!budget.reserve());
    assert(budget.peak_reserved() == 64);

    // Complete several carrier/TLS waves while the real session ratchet above
    // repeatedly crosses its 256 KiB epoch boundary.
    for (int wave = 0; wave < 8; ++wave) {
        for (std::size_t i = 0; i < 64; ++i) budget.release();
        for (std::size_t i = 0; i < 64; ++i) reserve_and_send();
        assert(budget.reserved() == 64);
    }
    assert(rekeys > 2);
    assert(server.outbound_epoch() == rekeys);
    assert(client.inbound_epoch() == rekeys);
    for (std::size_t i = 1; i <= streams; ++i) {
        assert(turns[i] == (64U * 9U) / streams);
    }
}

}  // namespace

int main() {
    exercise_stream_count(16);
    exercise_stream_count(64);
    return 0;
}
