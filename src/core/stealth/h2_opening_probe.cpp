/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/stealth/h2_carrier.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

namespace {

using Bytes = yume::obfs::H2Bytes;
using Json = nlohmann::json;

constexpr std::string_view kClientPreface =
    "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
constexpr std::uint8_t kFrameHeaders = 0x01;
constexpr std::uint8_t kFramePriority = 0x02;
constexpr std::uint8_t kFrameSettings = 0x04;
constexpr std::uint8_t kFrameWindowUpdate = 0x08;
constexpr std::uint8_t kFlagAck = 0x01;
constexpr std::uint8_t kFlagPadded = 0x08;
constexpr std::uint8_t kFlagPriority = 0x20;

std::uint32_t ReadBe24(const std::uint8_t* data) {
    return (static_cast<std::uint32_t>(data[0]) << 16U) |
           (static_cast<std::uint32_t>(data[1]) << 8U) |
           static_cast<std::uint32_t>(data[2]);
}

std::uint32_t ReadBe32(const std::uint8_t* data) {
    return (static_cast<std::uint32_t>(data[0]) << 24U) |
           (static_cast<std::uint32_t>(data[1]) << 16U) |
           (static_cast<std::uint32_t>(data[2]) << 8U) |
           static_cast<std::uint32_t>(data[3]);
}

Json DecodePriority(const std::uint8_t* payload,
                    std::size_t size,
                    std::int32_t stream_id) {
    if (size < 5) {
        throw std::runtime_error("truncated HTTP/2 priority fields");
    }
    const std::uint32_t dependency = ReadBe32(payload);
    return {
        {"stream_id", stream_id},
        {"parent_stream_id", dependency & 0x7fffffffU},
        {"exclusive", (dependency & 0x80000000U) != 0},
        {"weight", static_cast<unsigned>(payload[4]) + 1U},
    };
}

Json InspectOpening(const Bytes& wire) {
    if (wire.size() < kClientPreface.size() ||
        !std::equal(kClientPreface.begin(), kClientPreface.end(),
                    wire.begin())) {
        throw std::runtime_error(
            "production carrier did not emit the HTTP/2 client preface");
    }

    Json settings = Json::array();
    Json window_updates = Json::array();
    Json priority_frames = Json::array();
    Json priming_priority;
    std::size_t offset = kClientPreface.size();

    while (offset < wire.size()) {
        if (wire.size() - offset < 9) {
            throw std::runtime_error("truncated HTTP/2 frame header");
        }
        const auto* header = wire.data() + offset;
        const std::size_t length = ReadBe24(header);
        const std::uint8_t type = header[3];
        const std::uint8_t flags = header[4];
        const std::int32_t stream_id =
            static_cast<std::int32_t>(ReadBe32(header + 5) & 0x7fffffffU);
        offset += 9;
        if (length > wire.size() - offset) {
            throw std::runtime_error("truncated HTTP/2 frame payload");
        }
        const auto* payload = wire.data() + offset;

        if (type == kFrameSettings && (flags & kFlagAck) == 0) {
            if (stream_id != 0 || length % 6 != 0) {
                throw std::runtime_error("malformed opening SETTINGS frame");
            }
            for (std::size_t pos = 0; pos < length; pos += 6) {
                const auto id = static_cast<std::uint16_t>(
                    (static_cast<std::uint16_t>(payload[pos]) << 8U) |
                    payload[pos + 1]);
                settings.push_back(
                    Json::array({id, ReadBe32(payload + pos + 2)}));
            }
        } else if (type == kFrameWindowUpdate && stream_id == 0) {
            if (length != 4) {
                throw std::runtime_error(
                    "malformed opening WINDOW_UPDATE frame");
            }
            window_updates.push_back(ReadBe32(payload) & 0x7fffffffU);
        } else if (type == kFramePriority) {
            priority_frames.push_back(
                DecodePriority(payload, length, stream_id));
        } else if (type == kFrameHeaders && stream_id == 1) {
            std::size_t pos = 0;
            std::size_t padding = 0;
            if ((flags & kFlagPadded) != 0) {
                if (length == 0) {
                    throw std::runtime_error(
                        "truncated padded opening HEADERS frame");
                }
                padding = payload[pos++];
            }
            if ((flags & kFlagPriority) == 0) {
                throw std::runtime_error(
                    "opening HEADERS omitted captured priority fields");
            }
            priming_priority =
                DecodePriority(payload + pos, length - pos, stream_id);
            pos += 5;
            if (padding > length - pos) {
                throw std::runtime_error(
                    "opening HEADERS padding exceeds payload");
            }
        }
        offset += length;
    }

    if (settings.empty() || window_updates.size() != 1 ||
        priming_priority.is_null()) {
        throw std::runtime_error(
            "production opening omitted SETTINGS, WINDOW_UPDATE, or priority");
    }

    yume::obfs::H2Carrier server(yume::obfs::H2CarrierRole::Server);
    server.Feed(wire);
    if (server.failed()) {
        throw std::runtime_error(
            "production server failed to decode client opening: " +
            server.error());
    }
    auto requests = server.TakeRequests();
    if (requests.size() != 1 || requests[0].stream_id != 1) {
        throw std::runtime_error(
            "production opening did not decode to one stream-1 request");
    }

    Json headers = Json::array();
    for (const auto& [name, value] : requests[0].headers) {
        headers.push_back(Json::array(
            {name, name == ":authority" ? "<cover-authority>" : value}));
    }
    priming_priority["headers_in_order"] = std::move(headers);

    return {
        {"settings_in_order", std::move(settings)},
        {"connection_window_updates", std::move(window_updates)},
        {"priority_frames", std::move(priority_frames)},
        {"priming_get", std::move(priming_priority)},
    };
}

}  // namespace

int main() {
    try {
        yume::obfs::H2Carrier client(yume::obfs::H2CarrierRole::Client);
        if (!client.StartClient("cover.example")) {
            throw std::runtime_error(
                "failed to start production carrier: " + client.error());
        }
        std::cout << InspectOpening(client.TakeOutbound()).dump(2) << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "yume_h2_opening_probe: " << error.what() << '\n';
        return 1;
    }
}
