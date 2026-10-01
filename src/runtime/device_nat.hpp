/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <unordered_map>

// The packet half of the device bridge (docs/ABI.md, "Device bridge"). It
// reads nothing and opens nothing: it classifies one IP packet from a TUN
// device and rewrites TCP in place, so the host's own kernel terminates each
// connection on a listener the bridge owns.
//
// An application's segment from the device's address to a destination leaves
// as a segment from the peer address, on a port that names the connection, to
// the listener. The kernel answers from the listener to that peer port, and
// the answer goes back to the application as if the destination had sent it.
// Checksums are updated for the changed words only, so every other byte of a
// segment stays as the kernel wrote it.
namespace yume::runtime {

// An address of either family. IPv4 uses the first four bytes and the rest
// stay zero.
using DeviceAddress = std::array<std::uint8_t, 16U>;

struct DeviceAddressPair final {
    // The device's own address, which applications' packets come from.
    DeviceAddress device{};
    // A second address that routes to the device and nothing else uses.
    DeviceAddress peer{};
};

// Where a translated TCP connection was going.
struct DeviceTcpOrigin final {
    bool ipv6{false};
    DeviceAddress destination{};
    std::uint16_t destination_port{0U};
    std::uint16_t source_port{0U};
};

// One UDP datagram an application sent. payload points into the packet.
struct DeviceDatagram final {
    bool ipv6{false};
    std::uint16_t source_port{0U};
    DeviceAddress destination{};
    std::uint16_t destination_port{0U};
    std::span<const std::uint8_t> payload;
};

enum class DevicePacket : std::uint8_t {
    // Not carried: another protocol, a fragment, a malformed packet, a
    // source that is not the device's address, or a full connection table.
    Drop,
    // TCP, rewritten in place. Write the returned bytes back to the device.
    Write,
    // UDP for the caller to carry.
    Datagram,
};

struct DeviceNatLimits final {
    // Translated TCP connections of one family, lingering ones included.
    std::size_t max_connections{4096U};
    // How long a connection the listener has not accepted keeps its port.
    std::chrono::milliseconds pending{60'000};
    // How long a closed connection keeps translating its last segments.
    std::chrono::milliseconds linger{15'000};
};

// The translator's tables. They sit outside the class so its members can
// hold them by value.
namespace device_nat_detail {

enum class Phase : std::uint8_t { Pending, Accepted, Lingering };

struct Key final {
    std::uint16_t source_port{0U};
    std::uint16_t destination_port{0U};
    DeviceAddress destination{};
    friend bool operator==(const Key&, const Key&) = default;
};

struct KeyHash final {
    std::size_t operator()(const Key& key) const noexcept;
};

struct Entry final {
    Key key;
    Phase phase{Phase::Pending};
    std::chrono::steady_clock::time_point expires{};
};

// One address family's connections, by translated peer port and by the
// application's own endpoints.
struct Family final {
    bool ipv6{false};
    DeviceAddressPair addresses;
    std::uint16_t listener_port{0U};
    std::uint16_t next_port{1024U};
    std::unordered_map<Key, std::uint16_t, KeyHash> ports;
    std::unordered_map<std::uint16_t, Entry> entries;
};

}  // namespace device_nat_detail

class DeviceNat final {
public:
    using Clock = std::chrono::steady_clock;

    // A family without addresses is dropped. The listener ports are set once
    // the listeners are bound.
    DeviceNat(std::optional<DeviceAddressPair> ipv4,
              std::optional<DeviceAddressPair> ipv6,
              DeviceNatLimits limits = {});

    void set_listener_ports(std::uint16_t ipv4, std::uint16_t ipv6) noexcept;

    // Classifies packet. For Write, written is the rewritten packet inside
    // the same storage, which may be shorter than packet. For Datagram,
    // datagram describes it. An application's segment for a connection the
    // table does not know is answered with a reset, so a connection from
    // before the bridge started ends instead of waiting.
    DevicePacket translate(std::span<std::uint8_t> packet,
                           Clock::time_point now,
                           std::span<std::uint8_t>& written,
                           DeviceDatagram& datagram);

    // The connection behind a peer port the listener accepted, which keeps
    // its port until release(). Nothing for a port the bridge did not
    // translate, such as another local process connecting to the listener.
    std::optional<DeviceTcpOrigin> accept(bool ipv6, std::uint16_t peer_port);
    // The accepted connection closed. Its port lingers for the last segments.
    void release(bool ipv6, std::uint16_t peer_port,
                 Clock::time_point now) noexcept;
    // Frees ports whose pending or lingering time has passed.
    void sweep(Clock::time_point now) noexcept;

    std::size_t connections(bool ipv6) noexcept;

    // Builds a UDP datagram from a destination back to an application's port
    // on the device into out. Returns its size, or zero when it does not fit
    // out or mtu, or the family has no address.
    std::size_t build_reply(bool ipv6, const DeviceAddress& source,
                            std::uint16_t source_port,
                            std::uint16_t destination_port,
                            std::span<const std::uint8_t> payload,
                            std::size_t mtu, std::span<std::uint8_t> out);

private:
    using Phase = device_nat_detail::Phase;
    using Key = device_nat_detail::Key;
    using Entry = device_nat_detail::Entry;
    using Family = device_nat_detail::Family;

    DevicePacket translate_tcp(Family& family, std::span<std::uint8_t> packet,
                               std::size_t header, Clock::time_point now,
                               std::span<std::uint8_t>& written);
    std::optional<std::uint16_t> allocate(Family& family, const Key& key,
                                          Clock::time_point now);
    Family* family(bool ipv6) noexcept;

    std::optional<Family> ipv4_;
    std::optional<Family> ipv6_;
    DeviceNatLimits limits_;
    std::uint16_t next_identification_{1U};
};

}  // namespace yume::runtime
