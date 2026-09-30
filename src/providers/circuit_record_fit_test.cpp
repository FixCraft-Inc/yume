/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// A full cell of either direction leaves the client's session and every link
// as exactly one TLS record (docs/protocol/CIRCUIT_1.md, Cells). The test adds
// what YTP/1 and the carrier envelope put around a cell, then runs the record
// through the carrier's real WebSocket and HTTP/2 encoding in the role that
// sends that direction, and counts the bytes of the TLS write it becomes.

#include <chrono>
#include <cstddef>
#include <iostream>
#include <string>
#include <tuple>
#include <vector>

#include "circuit/protocol.hpp"
#include "engine/session_engine.hpp"
#include "providers/h2_duplex_carrier.hpp"
#include "providers/ytp1_crypto.hpp"
#include "stealth/h2_carrier.hpp"
#include "ytp/protocol.hpp"

namespace {

using yume::obfs::H2Bytes;
using yume::obfs::H2Carrier;
using yume::obfs::H2CarrierRole;
namespace c1 = yume::circuit1;

// RFC 8446, section 5.1: a TLS record carries at most 2^14 bytes.
constexpr std::size_t kTlsRecordPlaintext = 16384U;

int g_failures = 0;

#define CHECK(condition)                                        \
    do {                                                        \
        if (!(condition)) {                                     \
            std::cerr << __FILE__ << ':' << __LINE__            \
                      << ": check failed: " #condition << '\n'; \
            ++g_failures;                                       \
        }                                                       \
    } while (false)

// A clock that never moves, so no idle rule adds a PING to the writes.
std::chrono::steady_clock::time_point Frozen() noexcept {
    return {};
}

bool Pump(H2Carrier& from, H2Carrier& to) {
    for (int round = 0; round < 16; ++round) {
        const auto bytes = from.TakeOutbound();
        if (bytes.empty()) return true;
        to.Feed(bytes);
        if (to.failed()) return false;
    }
    return false;
}

// Opens the carrier as production does: the priming page and its assets,
// the extended CONNECT and the admitted receive windows on both sides.
bool Open(H2Carrier& client, H2Carrier& server) {
    if (!client.StartClient("cover.example")) return false;
    for (int round = 0; round < 8 && !client.priming_complete(); ++round) {
        if (!Pump(client, server)) return false;
        for (const auto& request : server.TakeRequests()) {
            if (!server.RespondHttp(request.stream_id, 200,
                                    {{"content-type", "text/html"}},
                                    H2Bytes{'o', 'k'})) {
                return false;
            }
        }
        if (!Pump(server, client)) return false;
    }
    if (!client.priming_complete() ||
        !client.SubmitExtendedConnect("/carrier") || !Pump(client, server)) {
        return false;
    }
    const auto requests = server.TakeRequests();
    if (requests.size() != 1U || !server.AcceptCarrier(requests[0].stream_id) ||
        !server.EnableAdmittedReceiveWindow(
            yume::obfs::kAdmittedH2ReceiveWindowBytes) ||
        !Pump(server, client) ||
        !client.EnableAdmittedReceiveWindow(
            yume::obfs::kAdmittedH2ReceiveWindowBytes) ||
        !Pump(client, server) || !Pump(server, client)) {
        return false;
    }
    return client.carrier_active() && server.carrier_active();
}

// The bytes of one TLS write that carry one full cell of the bucket, sent by
// the carrier role that sends its direction.
std::vector<std::size_t> CellWrites(H2CarrierRole sender, std::size_t cell) {
    H2Carrier client(H2CarrierRole::Client, {}, &Frozen);
    H2Carrier server(H2CarrierRole::Server, {}, &Frozen);
    if (!Open(client, server)) {
        std::cerr << "the carrier did not open\n";
        ++g_failures;
        return {};
    }
    auto& from = sender == H2CarrierRole::Client ? client : server;
    const std::size_t record = yume::ytp1::kFrameHeaderSize + cell +
                               yume::engine::kProtectedEnvelopeBytes +
                               yume::providers::ytp1_crypto::kAesGcmTagBytes;
    const H2Bytes framed(yume::providers::kH2DuplexEnvelopeBytes + record,
                         0x5a);
    CHECK(from.SendBinary(framed));
    std::vector<std::size_t> sizes;
    for (const auto& write : from.TakeOutboundWrites())
        sizes.push_back(write.size());
    return sizes;
}

void TestFullCellsFillOneRecord() {
    // Forward cells leave the side that dialed, backward cells the other.
    const std::vector<std::size_t> one_record{kTlsRecordPlaintext};
    for (const auto& [role, cell, name] :
         {std::tuple{H2CarrierRole::Client, c1::kForwardBuckets[2], "forward"},
          std::tuple{H2CarrierRole::Server, c1::kBackwardBuckets[2],
                     "backward"}}) {
        const auto writes = CellWrites(role, cell);
        CHECK(writes == one_record);
        if (writes == one_record) continue;
        std::cerr << "  a full " << name << " cell became writes of";
        for (const auto size : writes) std::cerr << ' ' << size;
        std::cerr << " bytes\n";
    }
}

}  // namespace

int main() {
    TestFullCellsFillOneRecord();
    if (g_failures != 0) {
        std::cerr << g_failures << " circuit record check(s) failed\n";
        return 1;
    }
    std::cout << "circuit record fit tests passed\n";
    return 0;
}
