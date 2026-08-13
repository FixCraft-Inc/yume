/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/transport/chrome_tls_protocol.hpp"

#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <span>
#include <string>
#include <vector>

#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

constexpr int kIpcFd = 4;
constexpr std::size_t kHeaderBytes = 32;

bool ReadExact(int fd, std::span<std::uint8_t> bytes) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const ssize_t received =
            ::read(fd, bytes.data() + offset, bytes.size() - offset);
        if (received > 0) {
            offset += static_cast<std::size_t>(received);
        } else if (received == 0) {
            return false;
        } else if (errno != EINTR) {
            return false;
        }
    }
    return true;
}

bool WriteAll(int fd, std::span<const std::uint8_t> bytes,
              bool one_byte_at_a_time = false) {
    std::size_t offset = 0;
    while (offset < bytes.size()) {
        const std::size_t requested = one_byte_at_a_time ? 1 : bytes.size() - offset;
        const ssize_t written = ::write(fd, bytes.data() + offset, requested);
        if (written > 0) {
            offset += static_cast<std::size_t>(written);
        } else if (written == 0) {
            return false;
        } else if (errno != EINTR) {
            return false;
        }
    }
    return true;
}

std::vector<std::uint8_t> ReadRequestWire() {
    std::vector<std::uint8_t> wire(kHeaderBytes);
    if (!ReadExact(kIpcFd, wire)) {
        return {};
    }
    const std::uint32_t payload_size =
        (static_cast<std::uint32_t>(wire[12]) << 24U) |
        (static_cast<std::uint32_t>(wire[13]) << 16U) |
        (static_cast<std::uint32_t>(wire[14]) << 8U) |
        static_cast<std::uint32_t>(wire[15]);
    if (payload_size > yume::client::chrome_tls::kMaxPayloadBytes) {
        return {};
    }
    wire.resize(kHeaderBytes + payload_size);
    if (!ReadExact(kIpcFd, std::span<std::uint8_t>(wire).subspan(kHeaderBytes))) {
        return {};
    }
    return wire;
}

void RecordPid() {
    const char* path = std::getenv("YUME_TEST_HELPER_PID_FILE");
    if (path == nullptr || path[0] == '\0') {
        return;
    }
    std::ofstream output(path, std::ios::trunc);
    output << ::getpid() << '\n';
}

bool ReadUntilEof() {
    std::array<std::uint8_t, 4096> buffer{};
    for (;;) {
        const ssize_t received = ::read(kIpcFd, buffer.data(), buffer.size());
        if (received > 0) {
            continue;
        }
        if (received < 0 && errno == EINTR) {
            continue;
        }
        return received == 0 || errno == ECONNRESET;
    }
}

}  // namespace

int main() {
    using namespace yume::client::chrome_tls;

    RecordPid();
    const std::string mode = [] {
        const char* value = std::getenv("YUME_TEST_HELPER_MODE");
        return value == nullptr ? std::string("ready") : std::string(value);
    }();

    const auto request_wire = ReadRequestWire();
    if (request_wire.empty()) {
        return 2;
    }
    const Request request = DecodeRequest(request_wire);

    if (mode == "crash") {
        ::_exit(77);
    }
    if (mode == "hang") {
        for (;;) {
            ::pause();
        }
    }

    Ready ready;
    ready.connection_id = request.connection_id;
    ready.build_id = request.expected_build_id;
    ready.alpn = "h2";
    ready.leaf_fingerprint.fill(0x11);
    ready.exporter.fill(0x22);

    if (mode == "error") {
        HelperError error;
        error.connection_id = request.connection_id;
        error.code = 9;
        error.message = "synthetic helper rejection";
        return WriteAll(kIpcFd, EncodeError(error)) ? 0 : 3;
    }
    if (mode == "wrong-build") {
        ready.build_id = "wrong-helper";
    } else if (mode == "wrong-alpn") {
        ready.alpn = "http/1.1";
    } else if (mode == "wrong-id") {
        ready.connection_id[0] ^= 1;
    }

    auto response = EncodeReady(ready);
    if (mode == "truncated") {
        response.resize(12);
    } else if (mode == "oversized") {
        response.resize(kHeaderBytes);
        response[12] = 0x00;
        response[13] = 0x01;
        response[14] = 0x00;
        response[15] = 0x01;
    } else if (mode == "wrong-version") {
        response[9] ^= 1;
    }
    const bool partial_response =
        mode == "partial-ready" || mode == "echo-partial";
    if (!WriteAll(kIpcFd, response, partial_response)) {
        return 3;
    }
    if (mode == "ready-hang") {
        for (;;) {
            ::pause();
        }
    }
    if (mode == "ready-half-close") {
        if (::shutdown(kIpcFd, SHUT_WR) != 0) {
            return 4;
        }
        return ReadUntilEof() ? 0 : 5;
    }
    if (mode == "ready-wait-eof") {
        return ReadUntilEof() ? 0 : 5;
    }
    if (mode == "echo-partial") {
        std::array<std::uint8_t, 127> buffer{};
        for (;;) {
            const ssize_t received = ::read(kIpcFd, buffer.data(), buffer.size());
            if (received > 0) {
                if (!WriteAll(kIpcFd,
                              std::span<const std::uint8_t>(
                                  buffer.data(), static_cast<std::size_t>(received)),
                              true)) {
                    return 6;
                }
            } else if (received == 0 || errno == ECONNRESET) {
                return 0;
            } else if (errno != EINTR) {
                return 7;
            }
        }
    }
    return 0;
}
