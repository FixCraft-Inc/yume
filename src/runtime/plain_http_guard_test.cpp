/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/plain_http_guard.hpp"

#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace std::string_view_literals;
using yume::engine::Buffer;
using yume::engine::CancellationToken;
using yume::engine::Status;
using yume::engine::StatusCode;
using yume::runtime::classify_cleartext;
using yume::runtime::Cleartext;

int g_failures = 0;

#define CHECK(condition)                                        \
    do {                                                        \
        if (!(condition)) {                                     \
            std::cerr << __FILE__ << ':' << __LINE__            \
                      << ": check failed: " #condition << '\n'; \
            ++g_failures;                                       \
        }                                                       \
    } while (false)

Cleartext classify(std::string_view text) {
    return classify_cleartext(std::span(
        reinterpret_cast<const std::byte*>(text.data()), text.size()));
}

// Records what reaches it and completes every write at once.
class Recorder final : public yume::engine::StreamResponder {
public:
    yume::engine::ExecutorAffinity executor_affinity() const noexcept override {
        return yume::engine::ExecutorAffinity(1U);
    }
    yume::engine::ServiceKind service_kind() const noexcept override {
        return yume::engine::ServiceKind::ByteStream;
    }
    std::size_t max_write_size() const noexcept override { return 4U; }
    bool terminated() const noexcept override { return closed.has_value(); }
    void async_read(CancellationToken, ReadCompletion) override {}
    void async_write(Buffer payload, CancellationToken,
                     WriteCompletion completion) override {
        const auto bytes = payload.bytes();
        writes.emplace_back(reinterpret_cast<const char*>(bytes.data()),
                            bytes.size());
        completion(Status::success(), payload.size());
    }
    Status shutdown_write() noexcept override {
        shut = true;
        return Status::success();
    }
    void close(Status reason) noexcept override { closed = reason.code(); }

    std::string sent() const {
        std::string all;
        for (const auto& write : writes) all += write;
        return all;
    }

    std::vector<std::string> writes;
    bool shut{false};
    std::optional<StatusCode> closed;
};

Status write(yume::engine::StreamResponder& stream, std::string_view text) {
    auto buffer = Buffer::copy_from(
        std::span(reinterpret_cast<const std::byte*>(text.data()), text.size()),
        text.size());
    Status result(StatusCode::Internal);
    stream.async_write(
        std::move(buffer).take_value(), {},
        [&](Status status, std::size_t) { result = std::move(status); });
    return result;
}

void test_classifier() {
    for (const char* request :
         {"GET / HTTP/1.1\r\n", "GET / HTTP/1.1\n",
          "POST /a?b=c HTTP/1.0\r\nHost: x\r\n", "M-SEARCH * HTTP/1.1\r\n",
          "CONNECT example.com:443 HTTP/1.1\r\n",
          "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"}) {
        CHECK(classify(request) == Cleartext::Http);
    }
    for (const char* start :
         {"", "G", "GET", "GET ", "GET /", "GET / HTTP/1", "GET / HTTP/1.1",
          "GET / HTTP/1.1\r", "PRI * HTTP/2"}) {
        CHECK(classify(start) == Cleartext::Undecided);
    }
    for (const char* other :
         {"\x16\x03\x01\x02", "SSH-2.0-OpenSSH_9.6\r\n", "EHLO example.com\r\n",
          "get / HTTP/1.1\r\n", "GET  / HTTP/1.1\r\n", "GET / HTTP/2\r\n",
          "GET / HTTP/1.x\r\n", "GET / HTTP/1.1\rX", "GET /\x01 HTTP/1.1\r\n",
          " GET / HTTP/1.1\r\n", "ABCDEFGHIJKLMNOPQRSTU / HTTP/1.1\r\n"}) {
        CHECK(classify(other) == Cleartext::Other);
    }
    // A prefix that still matches after the hold limit counts as a request.
    std::string long_target =
        "GET /" + std::string(yume::runtime::kCleartextHoldBytes, 'a');
    CHECK(classify(long_target) == Cleartext::Http);
}

void test_guard() {
    {
        auto inner = std::make_shared<Recorder>();
        auto guard = yume::runtime::guard_plain_http(inner);
        CHECK(write(*guard, "GE").ok());
        CHECK(write(*guard, "T / HTTP/1.1\r\n").code() ==
              StatusCode::PermissionDenied);
        CHECK(inner->writes.empty() &&
              inner->closed == StatusCode::PermissionDenied);
        CHECK(guard->terminated());
        CHECK(write(*guard, "more").code() == StatusCode::PermissionDenied);
    }
    {
        // TLS goes through at once, in the stream's pieces.
        auto inner = std::make_shared<Recorder>();
        auto guard = yume::runtime::guard_plain_http(inner);
        const auto hello = "\x16\x03\x01\x02\x00\x01"sv;
        CHECK(write(*guard, hello).ok());
        CHECK(inner->sent() == hello && inner->writes.size() == 2U);
        CHECK(write(*guard, "after").ok() && inner->writes.back() == "after");
        CHECK(!inner->closed);
    }
    {
        // Held bytes go out in order once the start is not a request.
        auto inner = std::make_shared<Recorder>();
        auto guard = yume::runtime::guard_plain_http(inner);
        CHECK(write(*guard, "EH").ok() && inner->writes.empty());
        CHECK(write(*guard, "LO x\r\n").ok());
        CHECK(inner->sent() == "EHLO x\r\n");
    }
    {
        // Ending the write direction while undecided sends what was held.
        auto inner = std::make_shared<Recorder>();
        auto guard = yume::runtime::guard_plain_http(inner);
        CHECK(write(*guard, "GET /").ok() && inner->writes.empty());
        CHECK(guard->shutdown_write().ok());
        CHECK(inner->sent() == "GET /" && inner->shut && !inner->closed);
    }
}

}  // namespace

int main() {
    test_classifier();
    test_guard();
    if (g_failures != 0) {
        std::cerr << g_failures << " plain HTTP guard check(s) failed\n";
        return EXIT_FAILURE;
    }
    std::cout << "plain HTTP guard tests passed\n";
    return EXIT_SUCCESS;
}
