/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Characterization of the carrier's wire output once the WebSocket is open.
// A fixed sequence of records crosses a client and a server carrier, and the
// test writes down everything an observer of the TLS plaintext could see: each
// socket write, the HTTP/2 frames in it (type, flags, stream, length, and the
// payload of every frame but DATA), each WebSocket frame header without its
// masking key, and a digest of the unmasked payloads, with runs of equal
// lines folded into one. The result must equal
// testdata/h2_carrier_wire_trace.txt byte for byte. Separately the payloads
// must reassemble to the records sent, every client frame must carry a mask
// of its own and no server frame may be masked. A change to the carrier, its
// wire profile or the WebSocket codec that moves a byte or a boundary fails
// here, so performance work on those files keeps the wire as it is.

#include "stealth/h2_carrier.hpp"

#include <array>
#include <cassert>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "stealth/cover_profile.hpp"

namespace {

using yume::obfs::H2Bytes;
using yume::obfs::H2Carrier;
using yume::obfs::H2CarrierRole;

#define CHECK(condition)                                                      \
    do {                                                                      \
        if (!(condition)) {                                                   \
            std::cerr << __FILE__ << ':' << __LINE__ << ": " #condition "\n"; \
            std::exit(1);                                                     \
        }                                                                     \
    } while (false)

std::chrono::steady_clock::time_point manual_now{};

std::chrono::steady_clock::time_point ManualClock() noexcept {
    return manual_now;
}

std::uint32_t ReadU24(const std::uint8_t* data) {
    return (static_cast<std::uint32_t>(data[0]) << 16U) |
           (static_cast<std::uint32_t>(data[1]) << 8U) | data[2];
}

std::uint32_t ReadU31(const std::uint8_t* data) {
    return (static_cast<std::uint32_t>(data[0] & 0x7fU) << 24U) |
           (static_cast<std::uint32_t>(data[1]) << 16U) |
           (static_cast<std::uint32_t>(data[2]) << 8U) | data[3];
}

std::string Hex(const std::uint8_t* data, std::size_t size) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(size * 2U);
    for (std::size_t i = 0; i < size; ++i) {
        out.push_back(kDigits[data[i] >> 4U]);
        out.push_back(kDigits[data[i] & 0x0fU]);
    }
    return out;
}

// FNV-1a, enough to tell payloads apart in a trace a reviewer reads.
class Digest {
public:
    void add(const std::uint8_t* data, std::size_t size) noexcept {
        for (std::size_t i = 0; i < size; ++i) {
            hash_ ^= data[i];
            hash_ *= 0x100000001b3ULL;
        }
    }
    std::string text() const {
        std::array<std::uint8_t, 8> bytes{};
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            bytes[i] = static_cast<std::uint8_t>(hash_ >> (56U - 8U * i));
        }
        return Hex(bytes.data(), bytes.size());
    }

private:
    std::uint64_t hash_{0xcbf29ce484222325ULL};
};

// Writes lines, folding a run of equal lines into one with its count, and a
// run of WebSocket frames with equal headers into one with the digest of
// their payloads together.
class Lines {
public:
    explicit Lines(std::ostringstream& out) : out_(out) {}
    ~Lines() { flush(); }
    Lines(const Lines&) = delete;
    Lines& operator=(const Lines&) = delete;

    void add(const std::string& line, const std::uint8_t* payload = nullptr,
             std::size_t payload_size = 0) {
        if (count_ != 0U && line != line_) flush();
        line_ = line;
        ++count_;
        if (payload != nullptr) {
            has_payload_ = true;
            digest_.add(payload, payload_size);
        }
    }

private:
    void flush() {
        if (count_ == 0U) return;
        out_ << line_;
        if (count_ > 1U) out_ << " x" << count_;
        if (has_payload_) out_ << " payload=" << digest_.text();
        out_ << '\n';
        count_ = 0;
        has_payload_ = false;
        digest_ = Digest{};
    }

    std::ostringstream& out_;
    std::string line_;
    std::size_t count_{0};
    bool has_payload_{false};
    Digest digest_;
};

const char* FrameName(std::uint8_t type) {
    switch (type) {
        case 0x0:
            return "DATA";
        case 0x1:
            return "HEADERS";
        case 0x2:
            return "PRIORITY";
        case 0x3:
            return "RST_STREAM";
        case 0x4:
            return "SETTINGS";
        case 0x6:
            return "PING";
        case 0x7:
            return "GOAWAY";
        case 0x8:
            return "WINDOW_UPDATE";
        default:
            return "OTHER";
    }
}

// One direction of the carrier: the WebSocket bytes seen so far on the
// carrier stream, the payload they decode to and every masking key.
struct Direction {
    const char* name;
    bool masked;
    H2Bytes websocket;
    std::size_t parsed{0};
    H2Bytes payload;
    std::vector<std::array<std::uint8_t, 4>> masks;
};

class Recorder {
public:
    explicit Recorder(std::int32_t carrier_stream)
        : carrier_stream_(static_cast<std::uint32_t>(carrier_stream)) {}

    Direction up{"up", true, {}, 0, {}, {}};
    Direction down{"down", false, {}, 0, {}, {}};

    void Note(const std::string& line) { trace_ << line << '\n'; }

    // Records one socket write and every complete WebSocket frame it ends.
    void Write(Direction& direction, const H2Bytes& write) {
        trace_ << direction.name << " write " << write.size() << '\n';
        Lines lines(trace_);
        std::size_t offset = 0;
        while (offset < write.size()) {
            CHECK(write.size() - offset >= 9U);
            const std::uint32_t length = ReadU24(write.data() + offset);
            const std::uint8_t type = write[offset + 3U];
            const std::uint8_t flags = write[offset + 4U];
            const std::uint32_t stream = ReadU31(write.data() + offset + 5U);
            CHECK(write.size() - offset - 9U >= length);
            const std::uint8_t* body = write.data() + offset + 9U;
            std::string line = std::string("  ") + FrameName(type) +
                               " flags=" + Hex(&flags, 1) +
                               " stream=" + std::to_string(stream) +
                               " length=" + std::to_string(length);
            if (type != 0x0) {
                line += " body=" + Hex(body, length);
            } else if (stream == carrier_stream_) {
                direction.websocket.insert(direction.websocket.end(), body,
                                           body + length);
            }
            lines.add(line);
            offset += 9U + length;
        }
        ParseWebSocket(direction, lines);
    }

    std::string text() const { return trace_.str(); }

private:
    void ParseWebSocket(Direction& direction, Lines& lines) {
        const H2Bytes& bytes = direction.websocket;
        while (bytes.size() - direction.parsed >= 2U) {
            const std::uint8_t* frame = bytes.data() + direction.parsed;
            const std::size_t available = bytes.size() - direction.parsed;
            const bool masked = (frame[1] & 0x80U) != 0;
            std::uint64_t length = frame[1] & 0x7fU;
            std::size_t header = 2U;
            if (length == 126U) {
                if (available < 4U) return;
                length =
                    (static_cast<std::uint64_t>(frame[2]) << 8U) | frame[3];
                header = 4U;
            } else if (length == 127U) {
                if (available < 10U) return;
                length = 0;
                for (std::size_t i = 0; i < 8U; ++i) {
                    length = (length << 8U) | frame[2U + i];
                }
                header = 10U;
            }
            const std::size_t key_bytes = masked ? 4U : 0U;
            if (available < header + key_bytes + length) return;
            CHECK(masked == direction.masked);
            std::array<std::uint8_t, 4> key{};
            if (masked) {
                for (std::size_t i = 0; i < 4U; ++i) key[i] = frame[header + i];
                direction.masks.push_back(key);
            }
            const std::uint8_t* masked_payload = frame + header + key_bytes;
            H2Bytes unmasked(static_cast<std::size_t>(length));
            for (std::size_t i = 0; i < unmasked.size(); ++i) {
                unmasked[i] =
                    static_cast<std::uint8_t>(masked_payload[i] ^ key[i & 3U]);
            }
            const std::uint8_t opcode = frame[0] & 0x0fU;
            lines.add("  websocket header=" + Hex(frame, header) +
                          (masked ? "+mask" : "") +
                          " length=" + std::to_string(length),
                      unmasked.data(), unmasked.size());
            if (opcode == 0x0 || opcode == 0x2) {
                direction.payload.insert(direction.payload.end(),
                                         unmasked.begin(), unmasked.end());
            }
            direction.parsed += header + key_bytes + unmasked.size();
        }
    }

    std::uint32_t carrier_stream_;
    std::ostringstream trace_;
};

// Moves every pending write from one carrier to the other and returns the
// decoded bytes' credit at once, as a sink that drains immediately would.
bool Transfer(H2Carrier& from, H2Carrier& to, Direction& direction,
              Recorder& recorder) {
    const auto writes = from.TakeOutboundWrites();
    CHECK(!from.failed());
    for (const auto& write : writes) {
        recorder.Write(direction, write);
        to.Feed(write);
        if (to.failed()) std::cerr << to.error() << '\n';
        CHECK(!to.failed());
        const auto tunnel = to.TakeTunnelBytes();
        CHECK(to.ConsumeTunnelBytes(tunnel.size()));
    }
    return !writes.empty();
}

void Settle(H2Carrier& client, H2Carrier& server, Recorder& recorder) {
    for (int round = 0; round < 64; ++round) {
        const bool up = Transfer(client, server, recorder.up, recorder);
        const bool down = Transfer(server, client, recorder.down, recorder);
        if (!up && !down) return;
    }
    CHECK(false && "carrier exchange did not quiesce");
}

void Pump(H2Carrier& from, H2Carrier& to) {
    for (int i = 0; i < 16; ++i) {
        auto bytes = from.TakeOutbound();
        if (bytes.empty()) return;
        to.Feed(bytes);
        CHECK(!to.failed());
    }
    CHECK(false && "HTTP/2 pump did not quiesce");
}

void OpenCarrier(H2Carrier& client, H2Carrier& server) {
    const auto& profile = yume::cover_profile::active();
    CHECK(client.StartClient("cover.example"));
    Pump(client, server);
    Pump(server, client);
    auto requests = server.TakeRequests();
    CHECK(requests.size() == 1U);
    CHECK(server.RespondHttp(requests[0].stream_id, 200,
                             {{"content-type", "text/html"}},
                             H2Bytes{'o', 'k'}));
    Pump(server, client);
    Pump(client, server);
    requests = server.TakeRequests();
    CHECK(requests.size() == profile.assets.size());
    CHECK(server.RespondHttp(requests[0].stream_id, 200,
                             {{"content-type", "text/css"}}, H2Bytes{'c'}));
    CHECK(server.RespondHttp(requests[1].stream_id, 200,
                             {{"content-type", "text/javascript"}},
                             H2Bytes{'j'}));
    Pump(server, client);
    Pump(client, server);
    CHECK(client.priming_complete());
    CHECK(client.SubmitExtendedConnect("/carrier"));
    Pump(client, server);
    requests = server.TakeRequests();
    CHECK(requests.size() == 1U);
    CHECK(server.AcceptCarrier(requests[0].stream_id));
    Pump(server, client);
    Pump(client, server);
    CHECK(client.carrier_active() && server.carrier_active());
}

H2Bytes Record(std::size_t size, std::size_t index) {
    H2Bytes record(size);
    for (std::size_t i = 0; i < size; ++i) {
        record[i] = static_cast<std::uint8_t>(
            (i * 31U + index * 7U + i / 251U) & 0xffU);
    }
    return record;
}

}  // namespace

int main(int argc, char** argv) {
    CHECK(argc == 2);
    std::ifstream expected_file(argv[1], std::ios::binary);
    const std::string expected((std::istreambuf_iterator<char>(expected_file)),
                               std::istreambuf_iterator<char>());

    manual_now =
        std::chrono::steady_clock::time_point{} + std::chrono::hours(1);
    H2Carrier client(H2CarrierRole::Client, {}, &ManualClock);
    H2Carrier server(H2CarrierRole::Server, {}, &ManualClock);
    OpenCarrier(client, server);
    Recorder recorder(client.carrier_stream_id());
    CHECK(server.carrier_stream_id() == client.carrier_stream_id());

    // Admission widens both receive windows as the duplex provider does.
    CHECK(server.EnableAdmittedReceiveWindow(
        yume::obfs::kAdmittedH2ReceiveWindowBytes));
    CHECK(client.EnableAdmittedReceiveWindow(
        yume::obfs::kAdmittedH2ReceiveWindowBytes));
    recorder.Note("admitted windows");
    Settle(client, server, recorder);

    H2Bytes sent_up;
    H2Bytes sent_down;
    std::size_t index = 0;
    const auto send = [&](H2Carrier& carrier, H2Bytes& sent, std::size_t size) {
        const H2Bytes record = Record(size, index++);
        CHECK(carrier.SendBinary(record));
        sent.insert(sent.end(), record.begin(), record.end());
    };

    // Uploads, one settled exchange each: the empty message, every WebSocket
    // length encoding and its edges, and records of several 16-KiB messages.
    for (const std::size_t size :
         {0U, 1U, 125U, 126U, 16384U, 65535U, 65536U, 200000U, 5242880U}) {
        recorder.Note("up record " + std::to_string(size));
        send(client, sent_up, size);
        Settle(client, server, recorder);
    }
    // Downloads: the first full message is the fixture's 8 + 8 KiB split.
    // The last records of each list pass half of the admitted window, so the
    // receiver returns credit in WINDOW_UPDATE frames.
    for (const std::size_t size : {16384U, 16384U, 1U, 70000U, 5242880U}) {
        recorder.Note("down record " + std::to_string(size));
        send(server, sent_down, size);
        Settle(client, server, recorder);
    }
    // Records queued in both directions before either side writes, and two
    // queued back to back, as the session does with a control record.
    recorder.Note("both directions queued");
    send(client, sent_up, 40000U);
    send(server, sent_down, 40000U);
    send(server, sent_down, 1662U);
    Settle(client, server, recorder);
    // After a quiet interval the client writes its preface PING alone.
    manual_now += yume::obfs::kH2PrefacePingIdle + std::chrono::seconds(1);
    recorder.Note("up record 300 after idle");
    send(client, sent_up, 300U);
    Settle(client, server, recorder);
    recorder.Note("graceful close");
    CHECK(client.GracefulClose());
    Settle(client, server, recorder);
    CHECK(client.websocket_close_received());
    CHECK(server.carrier_closed());

    CHECK(recorder.up.payload == sent_up);
    CHECK(recorder.down.payload == sent_down);
    CHECK(recorder.down.masks.empty());
    CHECK(!recorder.up.masks.empty());
    // A fresh random key per client frame: 32-bit keys of this many frames
    // collide by chance far less than once in a million runs.
    const std::set<std::array<std::uint8_t, 4>> distinct(
        recorder.up.masks.begin(), recorder.up.masks.end());
    CHECK(distinct.size() == recorder.up.masks.size());

    const std::string actual = recorder.text();
    if (actual != expected) {
        std::size_t line = 1;
        std::size_t at = 0;
        while (at < actual.size() && at < expected.size() &&
               actual[at] == expected[at]) {
            if (actual[at] == '\n') ++line;
            ++at;
        }
        std::cerr << "wire trace differs from " << argv[1] << " at line "
                  << line << "\n--- actual trace ---\n"
                  << actual;
        return 1;
    }
    return 0;
}
