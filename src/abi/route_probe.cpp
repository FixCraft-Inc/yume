/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// A consumer of the public header only. The Python fixture owns credentials,
// the native daemon and loopback echo targets.
#include <yume/yume.h>

#include <array>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {
using Runtime = std::unique_ptr<yume_runtime, decltype(&yume_runtime_destroy)>;
using Config = std::unique_ptr<yume_config, decltype(&yume_config_destroy)>;
using Endpoint = std::unique_ptr<yume_endpoint, decltype(&yume_endpoint_destroy)>;
using Stream = std::unique_ptr<yume_stream, decltype(&yume_stream_destroy)>;

void expect(yume_status actual, yume_status wanted, std::string_view operation) {
    if (actual != wanted) {
        throw std::runtime_error(std::string(operation) + ": status " +
                                 std::to_string(actual) + ", expected " +
                                 std::to_string(wanted));
    }
}

void check(bool value, const char* message) {
    if (!value) throw std::runtime_error(message);
}

std::uint16_t port(std::string_view text) {
    unsigned value = 0U;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    check(parsed.ec == std::errc{} && parsed.ptr == text.data() + text.size() &&
          value > 0U && value <= 65535U, "invalid target port");
    return static_cast<std::uint16_t>(value);
}

yume_open_options open_options(std::string_view service, std::uint32_t kind,
                               std::string_view host, std::uint16_t target) {
    yume_open_options options{};
    options.struct_size = sizeof(options);
    options.abi_version = YUME_ABI_VERSION;
    options.service = {service.data(), service.size()};
    options.kind = YUME_SERVICE_BYTE_STREAM;
    options.destination.struct_size = sizeof(options.destination);
    options.destination.abi_version = YUME_ABI_VERSION;
    options.destination.kind = kind;
    options.destination.host = {host.data(), host.size()};
    options.destination.port = target;
    return options;
}

Stream open(yume_endpoint* endpoint, yume_open_options options,
            yume_status expected = YUME_STATUS_OK, std::uint32_t timeout = 5000U) {
    yume_stream* raw = nullptr;
    const auto status = yume_endpoint_open_stream(endpoint, &options, timeout, &raw);
    Stream stream(raw, yume_stream_destroy);
    expect(status, expected, "destination OPEN");
    check(static_cast<bool>(stream) == (expected == YUME_STATUS_OK),
          "OPEN published an incorrect output handle");
    return stream;
}

void round_trip(yume_endpoint* endpoint, std::uint32_t kind, std::string_view host,
                std::uint16_t target) {
    const auto stream = open(endpoint, open_options("tcp", kind, host, target));
    // More than one epoch in each direction. The target replies only after
    // write shutdown, so an early full close loses the entire response.
    std::array<char, 64U * 1024U> payload{};
    for (std::size_t i = 0U; i < payload.size(); ++i) payload[i] = static_cast<char>(i % 251U);
    for (unsigned i = 0U; i < 20U; ++i) {
        std::size_t written = 0U;
        expect(yume_stream_write(stream.get(), payload.data(), payload.size(), &written, 5000U),
               YUME_STATUS_OK, "write");
        check(written == payload.size(), "write admitted a partial buffer");
    }
    expect(yume_stream_shutdown_write(stream.get(), 5000U), YUME_STATUS_OK, "half-close");
    std::size_t total = 0U;
    std::array<char, 8192U> received{};
    for (;;) {
        std::size_t count = 0U;
        const auto status = yume_stream_read(stream.get(), received.data(), received.size(),
                                              &count, 5000U);
        if (status == YUME_STATUS_EOF) break;
        expect(status, YUME_STATUS_OK, "read");
        check(count > 0U && count <= received.size(), "invalid read length");
        for (std::size_t i = 0U; i < count; ++i) {
            check(received[i] == payload[(total + i) % payload.size()], "routed bytes differ");
        }
        total += count;
        check(total <= payload.size() * 20U, "routed bytes duplicated");
    }
    check(total == payload.size() * 20U, "routed bytes lost");
}

void run(const std::filesystem::path& directory, std::uint16_t v4, std::uint16_t v6) {
    const auto base = directory.string();
    yume_runtime_options options{};
    options.struct_size = sizeof(options);
    options.abi_version = YUME_ABI_VERSION;
    options.config_base_dir = base.c_str();
    yume_runtime* raw_runtime = nullptr;
    expect(yume_runtime_create(&options, &raw_runtime), YUME_STATUS_OK, "runtime create");
    Runtime runtime(raw_runtime, yume_runtime_destroy);
    std::ifstream file(directory / "yume.json", std::ios::binary);
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
    Endpoint endpoint(raw_endpoint, yume_endpoint_destroy);
    expect(yume_endpoint_start(endpoint.get(), 10000U), YUME_STATUS_OK, "endpoint start");

    open(endpoint.get(), open_options("tcp", YUME_DESTINATION_IPV4, "127.0.0.1", v4),
         YUME_STATUS_WOULD_BLOCK, 0U);
    open(endpoint.get(), open_options("tcp", YUME_DESTINATION_IPV4, "127.0.0.2", v4),
         YUME_STATUS_PERMISSION_DENIED);
    auto malformed = open_options("tcp", YUME_DESTINATION_IPV6, "127.0.0.1", v4);
    open(endpoint.get(), malformed, YUME_STATUS_INVALID_ARGUMENT);
    malformed = open_options("tcp", YUME_DESTINATION_HOSTNAME, "localhost", v4);
    malformed.destination.struct_size = offsetof(yume_destination, host) +
                                        sizeof(yume_string_view) - 1U;
    open(endpoint.get(), malformed, YUME_STATUS_INVALID_ARGUMENT);
    open(endpoint.get(), open_options("missing", YUME_DESTINATION_IPV4, "127.0.0.1", v4),
         YUME_STATUS_NOT_FOUND);

    round_trip(endpoint.get(), YUME_DESTINATION_IPV4, "127.0.0.1", v4);
    round_trip(endpoint.get(), YUME_DESTINATION_HOSTNAME, "localhost", v4);
    round_trip(endpoint.get(), YUME_DESTINATION_IPV6, "::1", v6);

    // A blocking read and an open handle must both settle when the endpoint
    // stops. The stream storage stays valid after endpoint destruction.
    auto held = open(endpoint.get(), open_options("tcp", YUME_DESTINATION_IPV4, "127.0.0.1", v4));
    auto reader = std::async(std::launch::async, [&] {
        char byte{};
        std::size_t count = 0U;
        return yume_stream_read(held.get(), &byte, 1U, &count, 30000U);
    });
    check(reader.wait_for(std::chrono::milliseconds(100)) == std::future_status::timeout,
          "read settled before endpoint stop");
    expect(yume_endpoint_stop(endpoint.get(), 0U), YUME_STATUS_OK, "endpoint stop");
    expect(reader.get(), YUME_STATUS_CLOSED, "pending read after stop");
    endpoint.reset();
    std::size_t written = 0U;
    expect(yume_stream_write(held.get(), "x", 1U, &written, 0U), YUME_STATUS_CLOSED, "retained handle");
    check(written == 0U, "stopped stream admitted bytes");
}
}  // namespace

int main(int argc, char** argv) {
    try {
        check(argc == 4, "usage: probe CLIENT_DIRECTORY IPV4_PORT IPV6_PORT");
        run(argv[1], port(argv[2]), port(argv[3]));
        std::cout << "public ABI routed IPv4, hostname and IPv6 streams; refusal and stop passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "ABI route probe: " << error.what() << '\n';
        return 1;
    }
}
