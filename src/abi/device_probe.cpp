/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Public-header consumer for the device bridge. It owns a TUN device as an
// Android VpnService would, hands it to a client endpoint and then follows
// commands on standard input. The Python fixture provisions the kit, owns the
// daemon and the destinations, configures the device's addresses and routes,
// and sends the traffic.
#include <yume/yume.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>

#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace {
using Runtime = std::unique_ptr<yume_runtime, decltype(&yume_runtime_destroy)>;
using Config = std::unique_ptr<yume_config, decltype(&yume_config_destroy)>;
using Endpoint =
    std::unique_ptr<yume_endpoint, decltype(&yume_endpoint_destroy)>;

constexpr char kDeviceName[] = "ydev0";
constexpr std::uint32_t kMtu = 9000U;
constexpr std::uint32_t kStartDeadline = 15000U;

void check(bool value, std::string_view message) {
    if (!value) throw std::runtime_error(std::string(message));
}

std::string diagnostic_of(const void* handle) {
    yume_diagnostic diagnostic{};
    diagnostic.struct_size = sizeof(diagnostic);
    diagnostic.abi_version = YUME_ABI_VERSION;
    (void)yume_handle_get_diagnostic(handle, &diagnostic, sizeof(diagnostic));
    return diagnostic.message;
}

void expect(yume_status actual, yume_status wanted, std::string_view operation,
            const void* handle = nullptr) {
    if (actual == wanted) return;
    std::string text(operation);
    text += ": status " + std::to_string(actual) + ", expected " +
            std::to_string(wanted);
    if (handle != nullptr) text += " (" + diagnostic_of(handle) + ")";
    throw std::runtime_error(text);
}

struct Peer final {
    Peer(const std::filesystem::path& directory,
         const std::filesystem::path& file)
        : runtime(nullptr, yume_runtime_destroy),
          endpoint(nullptr, yume_endpoint_destroy) {
        const auto base = directory.string();
        yume_runtime_options options{};
        options.struct_size = sizeof(options);
        options.abi_version = YUME_ABI_VERSION;
        options.config_base_dir = base.c_str();
        yume_runtime* raw_runtime = nullptr;
        expect(yume_runtime_create(&options, &raw_runtime), YUME_STATUS_OK,
               "runtime create");
        runtime.reset(raw_runtime);
        std::ifstream input(file, std::ios::binary);
        std::string json(1024U * 1024U + 1U, '\0');
        input.read(json.data(), static_cast<std::streamsize>(json.size()));
        check(
            input.eof() && input.gcount() > 0 && input.gcount() <= 1024 * 1024,
            "test configuration cannot be read within its bound");
        json.resize(static_cast<std::size_t>(input.gcount()));
        yume_config* raw_config = nullptr;
        expect(yume_config_parse_json(runtime.get(), json.data(), json.size(),
                                      &raw_config),
               YUME_STATUS_OK, "config parse", runtime.get());
        const Config config(raw_config, yume_config_destroy);
        yume_endpoint* raw_endpoint = nullptr;
        expect(yume_endpoint_create(runtime.get(), config.get(), &raw_endpoint),
               YUME_STATUS_OK, "endpoint create", runtime.get());
        endpoint.reset(raw_endpoint);
    }

    Runtime runtime;
    Endpoint endpoint;
};

yume_string_view view(std::string_view text) {
    return yume_string_view{text.data(), text.size()};
}

// The device the fixture configures: 10.71.0.1 and fd71::1 on the device,
// with 10.71.0.2 and fd71::2 routed to it for the bridge.
yume_device_options device_options(int descriptor, bool ipv6) {
    yume_device_options options{};
    options.struct_size = sizeof(options);
    options.abi_version = YUME_ABI_VERSION;
    options.descriptor = descriptor;
    options.mtu = kMtu;
    options.stream_service = view("tcp");
    options.packet_service = view("udp");
    options.ipv4_address = view("10.71.0.1");
    options.ipv4_peer = view("10.71.0.2");
    if (ipv6) {
        options.ipv6_address = view("fd71::1");
        options.ipv6_peer = view("fd71::2");
    }
    return options;
}

int open_device() {
    const int descriptor = ::open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    check(descriptor >= 0, "cannot open /dev/net/tun");
    ifreq request{};
    request.ifr_flags = IFF_TUN | IFF_NO_PI;
    std::strncpy(request.ifr_name, kDeviceName, IFNAMSIZ - 1);
    if (::ioctl(descriptor, TUNSETIFF, &request) != 0) {
        ::close(descriptor);
        throw std::runtime_error("cannot create the TUN device");
    }
    return descriptor;
}

yume_endpoint_status status_of(const yume_endpoint* endpoint) {
    yume_endpoint_status status{};
    status.struct_size = sizeof(status);
    status.abi_version = YUME_ABI_VERSION;
    expect(yume_endpoint_get_status(endpoint, &status, sizeof(status)),
           YUME_STATUS_OK, "status");
    return status;
}

// What the bridge refuses before it has a device.
void check_refusals(Peer& client, Peer& server, int descriptor) {
    yume_endpoint* const endpoint = client.endpoint.get();
    auto options = device_options(descriptor, false);
    expect(yume_endpoint_set_device(server.endpoint.get(), &options),
           YUME_STATUS_UNSUPPORTED, "device on a server");

    options = device_options(descriptor, false);
    options.stream_service = view("absent");
    expect(yume_endpoint_set_device(endpoint, &options), YUME_STATUS_NOT_FOUND,
           "undeclared stream service");
    options = device_options(descriptor, false);
    // A packet service where a byte-stream service is needed, and the reverse.
    options.stream_service = view("udp");
    expect(yume_endpoint_set_device(endpoint, &options), YUME_STATUS_NOT_FOUND,
           "packet service as the stream service");
    options = device_options(descriptor, false);
    options.packet_service = view("tcp");
    expect(yume_endpoint_set_device(endpoint, &options), YUME_STATUS_NOT_FOUND,
           "stream service as the packet service");

    options = device_options(descriptor, false);
    options.ipv4_peer = view("10.71.0.1");
    expect(yume_endpoint_set_device(endpoint, &options),
           YUME_STATUS_INVALID_ARGUMENT, "one address for both of a pair");
    options = device_options(descriptor, false);
    options.ipv4_address = view("device.example");
    expect(yume_endpoint_set_device(endpoint, &options),
           YUME_STATUS_INVALID_ARGUMENT, "a name as an address");
    options = device_options(descriptor, false);
    options.ipv4_peer = view("fd71::2");
    expect(yume_endpoint_set_device(endpoint, &options),
           YUME_STATUS_INVALID_ARGUMENT, "an address of the other family");
    options = device_options(descriptor, false);
    options.ipv4_address = view("");
    options.ipv4_peer = view("");
    expect(yume_endpoint_set_device(endpoint, &options),
           YUME_STATUS_INVALID_ARGUMENT, "no address family");
    options = device_options(descriptor, false);
    options.mtu = 575U;
    expect(yume_endpoint_set_device(endpoint, &options),
           YUME_STATUS_INVALID_ARGUMENT, "MTU below the IPv4 minimum");
    options = device_options(descriptor, true);
    options.mtu = 1279U;
    expect(yume_endpoint_set_device(endpoint, &options),
           YUME_STATUS_INVALID_ARGUMENT, "MTU below the IPv6 minimum");
    options = device_options(descriptor, false);
    options.mtu = 65536U;
    expect(yume_endpoint_set_device(endpoint, &options),
           YUME_STATUS_INVALID_ARGUMENT, "MTU above an IP packet");
    options = device_options(-1, false);
    expect(yume_endpoint_set_device(endpoint, &options),
           YUME_STATUS_INVALID_ARGUMENT, "no descriptor");
    // A number no descriptor of this process has.
    options = device_options(1 << 20, false);
    expect(yume_endpoint_set_device(endpoint, &options),
           YUME_STATUS_INVALID_ARGUMENT, "a closed descriptor");
    options = device_options(descriptor, false);
    options.struct_size = sizeof(options) - 1U;
    expect(yume_endpoint_set_device(endpoint, &options),
           YUME_STATUS_INVALID_ARGUMENT, "truncated options");
    options = device_options(descriptor, false);
    options.reserved = 1U;
    expect(yume_endpoint_set_device(endpoint, &options),
           YUME_STATUS_INVALID_ARGUMENT, "a reserved field in use");
    // Detaching a device that was never attached changes nothing.
    expect(yume_endpoint_set_device(endpoint, nullptr), YUME_STATUS_OK,
           "detach without a device", endpoint);

    // An address the device does not have: the listener cannot bind, so the
    // start fails before any session is attempted.
    options = device_options(descriptor, false);
    options.ipv4_address = view("10.99.0.1");
    options.ipv4_peer = view("10.99.0.2");
    expect(yume_endpoint_set_device(endpoint, &options), YUME_STATUS_OK,
           "attach with a foreign address", endpoint);
    expect(yume_endpoint_start(endpoint, kStartDeadline),
           YUME_STATUS_INVALID_ARGUMENT, "start with a foreign address");
    const auto failed = status_of(endpoint);
    check(failed.state == YUME_ENDPOINT_FAILED &&
              failed.last_failure == YUME_STATUS_INVALID_ARGUMENT &&
              failed.sessions == 0U,
          "a start with a foreign address did not fail before its session");
    expect(yume_endpoint_stop(endpoint, 0U), YUME_STATUS_OK,
           "stop after a failed start", endpoint);
}

void print_status(const yume_endpoint* endpoint) {
    const auto status = status_of(endpoint);
    std::cout << "status state=" << status.state
              << " session=" << status.session
              << " sessions=" << status.sessions
              << " failed=" << status.failed_attempts
              << " retry=" << status.retry_ms
              << " tcp=" << status.device_tcp_connections
              << " udp=" << status.device_udp_destinations
              << " failure=" << status.last_failure
              << " sent=" << status.payload_bytes_sent
              << " received=" << status.payload_bytes_received << std::endl;
}

// One answer line, the feed's lines separated by tabs.
void print_messages(const yume_endpoint* endpoint) {
    std::uint64_t after = 0U;
    std::string line = "messages";
    for (;;) {
        yume_message message{};
        message.struct_size = sizeof(message);
        message.abi_version = YUME_ABI_VERSION;
        const auto status = yume_endpoint_read_message(
            endpoint, after, &message, sizeof(message));
        if (status == YUME_STATUS_WOULD_BLOCK) break;
        expect(status, YUME_STATUS_OK, "message");
        after = message.seq;
        line += '\t';
        line += message.text;
    }
    std::cout << line << std::endl;
}

int run(int argc, char** argv) {
    check(argc == 4, "usage: device_probe CLIENT_DIR SERVER_DIR ipv4|dual");
    const std::filesystem::path client_directory = argv[1];
    const std::filesystem::path server_directory = argv[2];
    const bool ipv6 = std::string_view(argv[3]) == "dual";
    Peer client(client_directory, client_directory / "yume.json");
    Peer server(server_directory, server_directory / "yumed.json");
    yume_endpoint* const endpoint = client.endpoint.get();

    int descriptor = open_device();
    std::cout << "device " << kDeviceName << std::endl;
    std::string line;
    check(std::getline(std::cin, line) && line == "configured",
          "the fixture did not configure the device");

    check_refusals(client, server, descriptor);

    auto options = device_options(descriptor, ipv6);
    expect(yume_endpoint_set_device(endpoint, &options), YUME_STATUS_OK,
           "attach the device", endpoint);
    // The library keeps its own descriptor from here.
    ::close(descriptor);
    descriptor = -1;
    expect(yume_endpoint_start(endpoint, kStartDeadline), YUME_STATUS_OK,
           "start with a device", endpoint);
    options = device_options(0, ipv6);
    expect(yume_endpoint_set_device(endpoint, &options),
           YUME_STATUS_INVALID_STATE, "attach while running");
    expect(yume_endpoint_set_device(endpoint, nullptr),
           YUME_STATUS_INVALID_STATE, "detach while running");
    std::cout << "running" << std::endl;

    while (std::getline(std::cin, line)) {
        if (line == "status") {
            print_status(endpoint);
        } else if (line == "messages") {
            print_messages(endpoint);
        } else if (line == "retry") {
            std::cout << "retry " << yume_endpoint_retry_now(endpoint)
                      << std::endl;
        } else if (line == "restart") {
            // The device stays attached across a stop and a start.
            expect(yume_endpoint_stop(endpoint, 0U), YUME_STATUS_OK, "stop",
                   endpoint);
            expect(yume_endpoint_start(endpoint, kStartDeadline),
                   YUME_STATUS_OK, "restart with the device", endpoint);
            std::cout << "restarted" << std::endl;
        } else if (line == "stop") {
            expect(yume_endpoint_stop(endpoint, 0U), YUME_STATUS_OK, "stop",
                   endpoint);
            // A stopped endpoint lets its device go.
            expect(yume_endpoint_set_device(endpoint, nullptr), YUME_STATUS_OK,
                   "detach", endpoint);
            std::cout << "stopped" << std::endl;
        } else if (line == "quit") {
            return 0;
        } else {
            throw std::runtime_error("unknown command: " + line);
        }
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return run(argc, argv);
    } catch (const std::exception& error) {
        std::cerr << "device probe: " << error.what() << '\n';
        return 1;
    }
}
