/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Public-header consumer. The Python fixture provisions identities and owns
// the native daemon and bounded UDP echo targets.
#include <yume/yume.h>

#include <array>
#include <charconv>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <memory>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {
using Runtime = std::unique_ptr<yume_runtime, decltype(&yume_runtime_destroy)>;
using Config = std::unique_ptr<yume_config, decltype(&yume_config_destroy)>;
using Endpoint = std::unique_ptr<yume_endpoint, decltype(&yume_endpoint_destroy)>;
using Packet = std::unique_ptr<yume_packet, decltype(&yume_packet_destroy)>;
using Stream = std::unique_ptr<yume_stream, decltype(&yume_stream_destroy)>;
constexpr std::uint32_t kDeadline = 5000U;

void check(bool value, std::string_view message) {
    if (!value) throw std::runtime_error(std::string(message));
}

void expect(yume_status actual, yume_status wanted, std::string_view operation) {
    if (actual != wanted) {
        throw std::runtime_error(std::string(operation) + ": status " +
                                 std::to_string(actual) + ", expected " + std::to_string(wanted));
    }
}

struct Peer final {
    explicit Peer(const std::filesystem::path& directory, bool server)
        : runtime(nullptr, yume_runtime_destroy), endpoint(nullptr, yume_endpoint_destroy) {
        const auto base = directory.string();
        yume_runtime_options options{};
        options.struct_size = sizeof(options);
        options.abi_version = YUME_ABI_VERSION;
        options.config_base_dir = base.c_str();
        yume_runtime* raw_runtime = nullptr;
        expect(yume_runtime_create(&options, &raw_runtime), YUME_STATUS_OK, "runtime create");
        runtime.reset(raw_runtime);
        std::ifstream file(directory / (server ? "yumed.json" : "yume.json"), std::ios::binary);
        std::string json(1024U * 1024U + 1U, '\0');
        file.read(json.data(), static_cast<std::streamsize>(json.size()));
        check(file.eof() && file.gcount() > 0 && file.gcount() <= 1024 * 1024,
              "test configuration cannot be read within its bound");
        json.resize(static_cast<std::size_t>(file.gcount()));
        yume_config* raw_config = nullptr;
        expect(yume_config_parse_json(runtime.get(), json.data(), json.size(), &raw_config),
               YUME_STATUS_OK, "config parse");
        Config config(raw_config, yume_config_destroy);
        yume_endpoint* raw_endpoint = nullptr;
        expect(yume_endpoint_create(runtime.get(), config.get(), &raw_endpoint),
               YUME_STATUS_OK, "endpoint create");
        endpoint.reset(raw_endpoint);
    }
    void start(bool server) {
        expect(yume_endpoint_start(endpoint.get(), server ? 0U : 10000U),
               YUME_STATUS_OK, "endpoint start");
    }
    void stop() { expect(yume_endpoint_stop(endpoint.get(), 0U), YUME_STATUS_OK, "endpoint stop"); }
    Runtime runtime;
    Endpoint endpoint;
};

void register_service(yume_endpoint* endpoint, std::string_view name, std::uint32_t kind) {
    yume_service_descriptor descriptor{};
    descriptor.struct_size = sizeof(descriptor);
    descriptor.abi_version = YUME_ABI_VERSION;
    descriptor.name = {name.data(), name.size()};
    descriptor.kind = kind;
    expect(yume_endpoint_register_service(endpoint, &descriptor), YUME_STATUS_OK, "register service");
}

yume_open_options named_options(std::string_view service) {
    yume_open_options options{};
    options.struct_size = YUME_OPEN_OPTIONS_MIN_SIZE;
    options.abi_version = YUME_ABI_VERSION;
    options.kind = YUME_SERVICE_PACKET;
    options.service = {service.data(), service.size()};
    return options;
}

yume_open_options routed_options(std::uint32_t kind, std::string_view host, std::uint16_t port) {
    auto options = named_options("udp");
    options.struct_size = sizeof(options);
    options.destination.struct_size = sizeof(options.destination);
    options.destination.abi_version = YUME_ABI_VERSION;
    options.destination.kind = kind;
    options.destination.host = {host.data(), host.size()};
    options.destination.port = port;
    return options;
}

Packet open(yume_endpoint* endpoint, yume_open_options options,
            yume_status wanted = YUME_STATUS_OK, std::uint32_t timeout = kDeadline) {
    yume_packet* raw = nullptr;
    const auto status = yume_endpoint_open_packet(endpoint, &options, timeout, &raw);
    Packet packet(raw, yume_packet_destroy);
    expect(status, wanted, "packet OPEN");
    check(static_cast<bool>(packet) == (wanted == YUME_STATUS_OK), "OPEN output handle differs");
    return packet;
}

Packet accept(yume_endpoint* endpoint, std::string_view service = "echo",
              yume_status wanted = YUME_STATUS_OK, std::uint32_t timeout = kDeadline) {
    yume_accept_options options{};
    options.struct_size = sizeof(options);
    options.abi_version = YUME_ABI_VERSION;
    options.kind = YUME_SERVICE_PACKET;
    options.service = {service.data(), service.size()};
    yume_packet* raw = nullptr;
    const auto status = yume_endpoint_accept_packet(endpoint, &options, timeout, &raw);
    Packet packet(raw, yume_packet_destroy);
    expect(status, wanted, "packet accept");
    check(static_cast<bool>(packet) == (wanted == YUME_STATUS_OK), "accept output handle differs");
    return packet;
}

void identity(yume_packet* packet, std::uint32_t role, std::string_view service,
              std::string_view fingerprint) {
    yume_peer_identity peer{};
    peer.struct_size = sizeof(peer);
    peer.abi_version = YUME_ABI_VERSION;
    expect(yume_packet_get_peer_identity(packet, &peer, sizeof(peer)), YUME_STATUS_OK, "peer identity");
    check(peer.authenticated == 1U && peer.role == role && peer.service == service &&
          peer.peer_label[0] != '\0' && fingerprint.size() == 64U, "peer identity fields differ");
    for (std::size_t i = 0U; i < 32U; ++i) {
        unsigned value = 0U;
        const auto parsed = std::from_chars(fingerprint.data() + 2U * i,
                                          fingerprint.data() + 2U * i + 2U, value, 16);
        check(parsed.ec == std::errc{} && parsed.ptr == fingerprint.data() + 2U * i + 2U &&
              peer.composite_fingerprint_sha256[i] == value, "authenticated fingerprint differs");
    }
}

void write(yume_packet* packet, std::span<const std::string_view> payloads) {
    std::vector<yume_packet_view> views;
    views.reserve(payloads.size());
    for (const auto payload : payloads) views.push_back({payload.data(), payload.size()});
    std::size_t count = 99U;
    expect(yume_packet_write_batch(packet, views.data(), views.size(), &count, kDeadline),
           YUME_STATUS_OK, "packet write");
    check(count == views.size(), "write admitted a partial batch");
}

void receive(yume_packet* packet, std::span<const std::string_view> expected) {
    std::size_t total = 0U;
    while (total < expected.size()) {
        std::array<char, 16384U> storage{};
        std::array<yume_packet_slot, 16U> slots{};
        for (auto& slot : slots) slot = {99U, 99U};
        std::size_t count = 99U;
        std::size_t required = 99U;
        expect(yume_packet_read_batch(packet, storage.data(), storage.size(), slots.data(),
                                      slots.size(), &count, &required, kDeadline),
               YUME_STATUS_OK, "packet read");
        check(count > 0U && count <= slots.size() && count <= expected.size() - total && required == 0U,
              "packet read counts differ");
        std::size_t offset = 0U;
        for (std::size_t i = 0U; i < count; ++i) {
            check(slots[i].offset == offset && slots[i].size <= storage.size() - offset,
                  "packet slot is out of bounds");
            check(std::string_view(storage.data() + offset, slots[i].size) == expected[total + i],
                  "packet boundary, order or contents differ");
            offset += slots[i].size;
        }
        for (std::size_t i = count; i < slots.size(); ++i) {
            check(slots[i].offset == 99U && slots[i].size == 99U, "unused slot changed");
        }
        total += count;
    }
}

yume_status read_one(yume_packet* packet, std::uint32_t timeout) {
    char storage{};
    yume_packet_slot slot{99U, 99U};
    std::size_t count = 99U;
    std::size_t required = 99U;
    const auto status = yume_packet_read_batch(packet, &storage, 1U, &slot, 1U,
                                              &count, &required, timeout);
    check(count == 0U && required == 0U && slot.offset == 99U && slot.size == 99U,
          "failed read changed outputs");
    return status;
}

void input_validation(yume_packet* packet) {
    std::size_t count = 99U;
    const std::array<yume_packet_view, 2U> bad{{{"valid", 5U}, {nullptr, 1U}}};
    expect(yume_packet_write_batch(packet, bad.data(), bad.size(), &count, 0U),
           YUME_STATUS_INVALID_ARGUMENT, "invalid second packet");
    check(count == 0U, "invalid batch was partly admitted");
    expect(yume_packet_write_batch(packet, bad.data(), 0U, &count, 0U),
           YUME_STATUS_INVALID_ARGUMENT, "empty batch");
    const yume_packet_view empty{"", 0U};
    expect(yume_packet_write_batch(packet, &empty, 1U, &count, 0U),
           YUME_STATUS_INVALID_ARGUMENT, "empty packet");
    expect(yume_packet_write_batch(packet, bad.data(), 257U, &count, 0U),
           YUME_STATUS_RESOURCE_EXHAUSTED, "batch count bound");
    // Count validation must happen before indexing the two-element input.
    const yume_packet_view oversized{"x", 65536U};
    expect(yume_packet_write_batch(packet, &oversized, 1U, &count, 0U),
           YUME_STATUS_INVALID_ARGUMENT, "packet size bound");
    check(count == 0U, "invalid write count differs");
    const std::array<yume_packet_view, 5U> above_config{{
        {"1", 1U}, {"2", 1U}, {"3", 1U}, {"4", 1U}, {"5", 1U}}};
    expect(yume_packet_write_batch(packet, above_config.data(), above_config.size(), &count, 0U),
           YUME_STATUS_RESOURCE_EXHAUSTED, "configured batch bound");
    check(count == 0U, "configured bound admitted a partial batch");
    expect(yume_packet_close(packet, 1U), YUME_STATUS_INVALID_ARGUMENT, "reserved close timeout");
}

void retained_first_packet(yume_packet* packet, std::size_t first_size) {
    yume_packet_slot slot{99U, 99U};
    std::size_t count = 99U;
    std::size_t required = 99U;
    expect(yume_packet_read_batch(packet, nullptr, 0U, &slot, 1U, &count, &required, kDeadline),
           YUME_STATUS_BUFFER_TOO_SMALL, "first packet size query");
    check(count == 0U && required == first_size && slot.offset == 99U && slot.size == 99U,
          "buffer-too-small outputs differ");
}

void named(const std::filesystem::path& server_dir, const std::filesystem::path& client_dir,
           std::string_view client_fingerprint, std::string_view server_fingerprint) {
    Peer server(server_dir, true);
    Peer client(client_dir, false);
    register_service(server.endpoint.get(), "echo", YUME_SERVICE_BYTE_STREAM);
    register_service(server.endpoint.get(), "echo", YUME_SERVICE_PACKET);
    register_service(server.endpoint.get(), "denied", YUME_SERVICE_PACKET);
    server.start(true);
    client.start(false);
    open(client.endpoint.get(), named_options("echo"), YUME_STATUS_WOULD_BLOCK, 0U);
    accept(server.endpoint.get(), "echo", YUME_STATUS_WOULD_BLOCK, 0U);
    accept(server.endpoint.get(), "echo", YUME_STATUS_TIMEOUT, 20U);
    open(client.endpoint.get(), named_options("missing"), YUME_STATUS_NOT_FOUND);
    open(client.endpoint.get(), named_options("stream-only"), YUME_STATUS_NOT_FOUND);
    open(client.endpoint.get(), named_options("unregistered"), YUME_STATUS_PERMISSION_DENIED);
    open(client.endpoint.get(), named_options("denied"), YUME_STATUS_PERMISSION_DENIED);
    open(server.endpoint.get(), named_options("echo"), YUME_STATUS_INVALID_ARGUMENT);
    accept(client.endpoint.get(), "echo", YUME_STATUS_INVALID_ARGUMENT);
    auto wrong_kind = named_options("echo");
    wrong_kind.kind = YUME_SERVICE_BYTE_STREAM;
    open(client.endpoint.get(), wrong_kind, YUME_STATUS_INVALID_ARGUMENT);

    auto opening = std::async(std::launch::async, [&] {
        return open(client.endpoint.get(), named_options("echo"));
    });
    auto incoming = accept(server.endpoint.get());
    auto outgoing = opening.get();
    identity(incoming.get(), YUME_ROLE_CLIENT, "echo", client_fingerprint);
    identity(outgoing.get(), YUME_ROLE_SERVER, "echo", server_fingerprint);
    input_validation(outgoing.get());
    expect(read_one(incoming.get(), 0U), YUME_STATUS_WOULD_BLOCK, "bad batch admitted nothing");
    expect(read_one(incoming.get(), 20U), YUME_STATUS_TIMEOUT, "read deadline");

    const std::array<std::string_view, 4U> payloads{{"first packet", "x", "third", "fourth payload"}};
    write(outgoing.get(), payloads);
    retained_first_packet(incoming.get(), payloads[0].size());
    receive(incoming.get(), payloads);
    // The client may write while its reader is blocked on the other direction.
    auto reader = std::async(std::launch::async, [&] { receive(outgoing.get(), payloads); });
    check(reader.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout,
          "reader settled before reply");
    write(outgoing.get(), payloads);
    receive(incoming.get(), payloads);
    write(incoming.get(), payloads);
    reader.get();

    // Both kinds with the same name must also traverse real OPEN acceptance.
    auto stream_opening = std::async(std::launch::async, [&] {
        auto options = named_options("echo");
        options.kind = YUME_SERVICE_BYTE_STREAM;
        yume_stream* raw = nullptr;
        const auto status = yume_endpoint_open_stream(client.endpoint.get(), &options, kDeadline, &raw);
        Stream stream(raw, yume_stream_destroy);
        expect(status, YUME_STATUS_OK, "same-name stream OPEN");
        return stream;
    });
    yume_accept_options stream_options{};
    stream_options.struct_size = sizeof(stream_options);
    stream_options.abi_version = YUME_ABI_VERSION;
    stream_options.kind = YUME_SERVICE_BYTE_STREAM;
    stream_options.service = {"echo", 4U};
    yume_stream* raw_stream = nullptr;
    const auto stream_status = yume_endpoint_accept_stream(server.endpoint.get(), &stream_options,
                                                           kDeadline, &raw_stream);
    Stream incoming_stream(raw_stream, yume_stream_destroy);
    expect(stream_status, YUME_STATUS_OK, "same-name stream accept");
    auto outgoing_stream = stream_opening.get();
    std::size_t count = 0U;
    expect(yume_stream_write(outgoing_stream.get(), "bytes", 5U, &count, kDeadline),
           YUME_STATUS_OK, "same-name stream write");
    check(count == 5U, "same-name stream write length differs");
    std::array<char, 5U> bytes{};
    std::size_t offset = 0U;
    while (offset < bytes.size()) {
        expect(yume_stream_read(incoming_stream.get(), bytes.data() + offset, bytes.size() - offset,
                                &count, kDeadline), YUME_STATUS_OK, "same-name stream read");
        check(count > 0U && count <= bytes.size() - offset, "stream read length differs");
        offset += count;
    }
    check(std::string_view(bytes.data(), bytes.size()) == "bytes", "same-name stream contents differ");

    auto blocked = std::async(std::launch::async, [&] { return read_one(outgoing.get(), 30000U); });
    check(blocked.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout,
          "read settled before close");
    expect(yume_packet_close(outgoing.get(), 0U), YUME_STATUS_OK, "packet close");
    expect(blocked.get(), YUME_STATUS_CLOSED, "close cancels reader");
    expect(yume_packet_close(outgoing.get(), 0U), YUME_STATUS_OK, "repeat packet close");

    auto held_opening = std::async(std::launch::async, [&] {
        return open(client.endpoint.get(), named_options("echo"));
    });
    auto held_incoming = accept(server.endpoint.get());
    auto held = held_opening.get();
    auto pending = std::async(std::launch::async, [&] { return read_one(held.get(), 30000U); });
    check(pending.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout,
          "read settled before endpoint stop");
    client.stop();
    expect(pending.get(), YUME_STATUS_CLOSED, "endpoint stop cancels reader");
    client.endpoint.reset();
    expect(read_one(held.get(), 0U), YUME_STATUS_CLOSED, "retained packet read");
    identity(held.get(), YUME_ROLE_SERVER, "echo", server_fingerprint);
    const yume_packet_view view{"x", 1U};
    expect(yume_packet_write_batch(held.get(), &view, 1U, &count, 0U),
           YUME_STATUS_CLOSED, "retained packet write");
    check(count == 0U, "stopped packet admitted data");
    server.stop();
}

std::uint16_t port(std::string_view text) {
    unsigned value = 0U;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    check(parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() &&
          value > 0U && value <= 65535U, "invalid UDP target port");
    return static_cast<std::uint16_t>(value);
}

void routed(const std::filesystem::path& directory, std::uint16_t v4, std::uint16_t v6) {
    Peer client(directory, false);
    client.start(false);
    open(client.endpoint.get(), routed_options(YUME_DESTINATION_IPV4, "127.0.0.1", v4),
         YUME_STATUS_WOULD_BLOCK, 0U);
    open(client.endpoint.get(), routed_options(YUME_DESTINATION_IPV4, "127.0.0.2", v4),
         YUME_STATUS_PERMISSION_DENIED);
    open(client.endpoint.get(), routed_options(YUME_DESTINATION_IPV6, "127.0.0.1", v4),
         YUME_STATUS_INVALID_ARGUMENT);
    std::string binary(2048U, '\0');
    for (std::size_t i = 0U; i < binary.size(); ++i) binary[i] = static_cast<char>(i % 251U);
    const std::array<std::string_view, 4U> payloads{{"first UDP datagram", "x", binary, "last"}};
    const std::array<yume_open_options, 3U> routes{{
        routed_options(YUME_DESTINATION_IPV4, "127.0.0.1", v4),
        routed_options(YUME_DESTINATION_HOSTNAME, "localhost", v4),
        routed_options(YUME_DESTINATION_IPV6, "::1", v6)}};
    for (const auto& options : routes) {
        auto packet = open(client.endpoint.get(), options);
        for (unsigned batch = 0U; batch < 8U; ++batch) {
            write(packet.get(), payloads);
            retained_first_packet(packet.get(), payloads[0].size());
            receive(packet.get(), payloads);
        }
    }
    auto held = open(client.endpoint.get(), routes[0]);
    auto pending = std::async(std::launch::async, [&] { return read_one(held.get(), 30000U); });
    check(pending.wait_for(std::chrono::milliseconds(20)) == std::future_status::timeout,
          "UDP read settled before stop");
    client.stop();
    expect(pending.get(), YUME_STATUS_CLOSED, "UDP endpoint stop");
    client.endpoint.reset();
    expect(read_one(held.get(), 0U), YUME_STATUS_CLOSED, "retained UDP handle");
}
}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 6 && std::string_view(argv[1]) == "named") {
            named(argv[2], argv[3], argv[4], argv[5]);
        } else if (argc == 5 && std::string_view(argv[1]) == "route") {
            routed(argv[2], port(argv[3]), port(argv[4]));
        } else {
            throw std::runtime_error("usage: probe named SERVER CLIENT CLIENT_FP SERVER_FP | "
                                     "probe route CLIENT IPV4_PORT IPV6_PORT");
        }
        std::cout << "public packet ABI " << argv[1] << " checks passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "packet ABI probe: " << error.what() << '\n';
        return 1;
    }
}
