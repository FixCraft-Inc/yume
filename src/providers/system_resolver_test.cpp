/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/system_resolver.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include "providers/system_resolver_helper.hpp"
#include "providers/system_resolver_protocol.hpp"

#ifndef YUME_TEST_RESOLVER_PROGRAM
#error "YUME_TEST_RESOLVER_PROGRAM names the standalone helper"
#endif
#ifndef YUME_TEST_STALL_RESOLVER_PROGRAM
#error "YUME_TEST_STALL_RESOLVER_PROGRAM names the stalling test helper"
#endif

namespace {

using yume::engine::Result;
using yume::engine::Status;
using yume::engine::StatusCode;
using yume::providers::AsioExecutionContext;
using yume::providers::SystemResolver;
using yume::providers::SystemResolverOptions;
using Addresses = std::vector<boost::asio::ip::address>;
using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;
namespace protocol = yume::providers::resolver_protocol;

int failures = 0;

#define CHECK(condition)                                                   \
    do {                                                                   \
        if (!(condition)) {                                                \
            std::fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__,    \
                         __LINE__, #condition);                            \
            ++failures;                                                    \
        }                                                                  \
    } while (false)

constexpr std::string_view kStallHost = "resolver-stall.invalid";

std::shared_ptr<AsioExecutionContext> make_context() {
    auto created = AsioExecutionContext::create(yume::engine::ExecutorAffinity(0x52534c56U));
    if (!created.ok()) std::abort();
    return std::move(created).take_value();
}

std::shared_ptr<SystemResolver> make_resolver(
    const std::shared_ptr<AsioExecutionContext>& context, std::string program,
    std::size_t max_outstanding = 64U) {
    SystemResolverOptions options;
    options.program = std::move(program);
    options.max_outstanding = max_outstanding;
    auto created = SystemResolver::create(context, std::move(options));
    if (!created.ok()) std::abort();
    return std::move(created).take_value();
}

// Runs work on the context, then closes the resolver and drains. Returns the
// time the final drain took after close was requested.
template <typename Work>
Clock::duration run_then_close(const std::shared_ptr<AsioExecutionContext>& context,
                               const std::shared_ptr<SystemResolver>& resolver,
                               std::chrono::milliseconds settle, Work work) {
    boost::asio::steady_timer timer(context->executor());
    Clock::time_point closed_at{};
    boost::asio::post(context->executor(), [&] {
        work();
        timer.expires_after(settle);
        timer.async_wait([&](const boost::system::error_code&) {
            closed_at = Clock::now();
            resolver->close();
            context->finish();
        });
    });
    context->run();
    return Clock::now() - closed_at;
}

// Descriptors held by each child of this thread. Linux lists a thread's
// children in /proc. The helper must hold only stdio and its socketpair, or a
// connection this process closes would stay open inside it.
std::vector<std::set<int>> child_descriptors() {
    std::vector<std::set<int>> result;
    std::ifstream children("/proc/self/task/" + std::to_string(::gettid()) + "/children");
    long pid = 0;
    while (children >> pid) {
        std::set<int> descriptors;
        std::error_code error;
        for (const auto& entry : std::filesystem::directory_iterator(
                 "/proc/" + std::to_string(pid) + "/fd", error)) {
            descriptors.insert(std::stoi(entry.path().filename().string()));
        }
        result.push_back(std::move(descriptors));
    }
    return result;
}

// The helper holds no capability and cannot regain one: every capability set
// is empty and no-new-privileges is set, whatever this process holds.
bool children_unprivileged() {
    std::ifstream children("/proc/self/task/" + std::to_string(::gettid()) + "/children");
    long pid = 0;
    bool any = false;
    while (children >> pid) {
        any = true;
        std::ifstream status("/proc/" + std::to_string(pid) + "/status");
        std::string line;
        unsigned checked = 0U;
        while (std::getline(status, line)) {
            for (const char* field : {"CapInh:", "CapPrm:", "CapEff:", "CapAmb:"}) {
                if (line.rfind(field, 0) == 0) {
                    if (line.find_first_not_of("0\t ", std::strlen(field)) != std::string::npos) {
                        return false;
                    }
                    ++checked;
                }
            }
            if (line.rfind("NoNewPrivs:", 0) == 0) {
                if (line.find('1') == std::string::npos) return false;
                ++checked;
            }
        }
        if (checked != 5U) return false;
    }
    return any;
}

bool is_loopback(const Addresses& addresses) {
    if (addresses.empty()) return false;
    for (const auto& address : addresses) {
        if (!address.is_loopback()) return false;
    }
    return true;
}

void test_protocol_codec() {
    std::array<std::uint8_t, protocol::kMaxRequestBytes> request{};
    CHECK(protocol::encode_request({1U, 1U, ""}, request) == 0U);
    CHECK(protocol::encode_request({0U, 1U, "example.test"}, request) == 0U);
    CHECK(protocol::encode_request({1U, 0U, "example.test"}, request) == 0U);
    CHECK(protocol::encode_request({1U, 33U, "example.test"}, request) == 0U);
    CHECK(protocol::encode_request({1U, 1U, "bad host"}, request) == 0U);
    CHECK(protocol::encode_request({1U, 1U, std::string(254U, 'a')}, request) == 0U);
    const std::size_t size = protocol::encode_request({7U, 4U, "example.test"}, request);
    const auto decoded = protocol::decode_request(std::span(request.data(), size));
    CHECK(decoded && decoded->id == 7U && decoded->max_addresses == 4U &&
          decoded->host == "example.test");
    CHECK(!protocol::decode_request(std::span(request.data(), size - 1U)));

    protocol::Response response;
    response.id = 9U;
    response.status = protocol::LookupStatus::Ok;
    response.count = 2U;
    response.addresses[0].family = 4U;
    response.addresses[0].bytes[0] = 127U;
    response.addresses[0].bytes[3] = 1U;
    response.addresses[1].family = 6U;
    response.addresses[1].bytes[15] = 1U;
    response.addresses[1].scope_id = 2U;
    std::array<std::uint8_t, protocol::kMaxResponseBytes> encoded{};
    const std::size_t length = protocol::encode_response(response, encoded);
    const auto parsed = protocol::decode_response(std::span(encoded.data(), length));
    CHECK(parsed && parsed->id == 9U && parsed->count == 2U &&
          parsed->addresses[1].scope_id == 2U);
    // IPv4 entries have exactly one encoding.
    encoded[protocol::kResponseHeaderBytes + 5U] = 1U;
    CHECK(!protocol::decode_response(std::span(encoded.data(), length)));
    encoded[protocol::kResponseHeaderBytes + 5U] = 0U;
    encoded[protocol::kResponseHeaderBytes] = 5U;
    CHECK(!protocol::decode_response(std::span(encoded.data(), length)));
    encoded[protocol::kResponseHeaderBytes] = 4U;
    CHECK(!protocol::decode_response(std::span(encoded.data(), length - 1U)));
    response.status = protocol::LookupStatus::NotFound;
    CHECK(protocol::encode_response(response, encoded) == 0U);
}

void test_options() {
    const auto context = make_context();
    SystemResolverOptions relative;
    relative.program = "yume-resolver";
    CHECK(SystemResolver::create(context, relative).status().code() ==
          StatusCode::InvalidArgument);
    SystemResolverOptions missing;
    missing.program = "/nonexistent/yume-resolver";
    CHECK(SystemResolver::create(context, missing).status().code() ==
          StatusCode::FailedPrecondition);
    SystemResolverOptions too_many;
    too_many.max_outstanding = protocol::kMaxOutstanding + 1U;
    CHECK(SystemResolver::create(context, too_many).status().code() ==
          StatusCode::InvalidArgument);
    CHECK(!SystemResolver::create(nullptr, {}).ok());

    // Without a helper, hostname lookup fails closed and invokes nothing.
    auto unconfigured = make_resolver(context, "");
    bool invoked = false;
    std::optional<StatusCode> refused;
    run_then_close(context, unconfigured, 0ms, [&] {
        refused = unconfigured->resolve("localhost", 4U, [&](Result<Addresses>) {
            invoked = true;
        }).status().code();
        CHECK(unconfigured->resolve("bad host", 4U, [](Result<Addresses>) {})
                  .status().code() == StatusCode::InvalidArgument);
    });
    CHECK(refused == StatusCode::FailedPrecondition && !invoked);
}

void test_lookup(const std::string& program) {
    const auto context = make_context();
    const auto resolver = make_resolver(context, program);
    std::optional<Result<Addresses>> localhost;
    std::optional<Result<Addresses>> missing;
    boost::asio::post(context->executor(), [&] {
        CHECK(resolver->resolve("localhost", 8U, [&](Result<Addresses> result) {
            localhost = std::move(result);
            // RFC 6761 reserves .invalid, so the system never resolves it.
            CHECK(resolver->resolve("definitely-missing.invalid", 8U,
                [&](Result<Addresses> second) {
                    missing = std::move(second);
                    resolver->close();
                    context->finish();
                }).ok());
        }).ok());
    });
    context->run();
    CHECK(localhost && localhost->ok() && is_loopback(localhost->value()));
    CHECK(missing && missing->status().code() == StatusCode::NotFound);
    // A closed resolver refuses later lookups synchronously.
    std::optional<StatusCode> after_close;
    boost::asio::post(context->executor(), [&] {
        after_close = resolver->resolve("localhost", 1U, [](Result<Addresses>) {})
                          .status().code();
    });
    context->run();
    CHECK(after_close == StatusCode::Closed);
}

// A lookup that never returns is cancelled at once, does not delay other
// names, and does not hold final drain: close kills and reaps the helper.
void test_stalled_lookup() {
    const auto context = make_context();
    const auto resolver = make_resolver(context, YUME_TEST_STALL_RESOLVER_PROGRAM);
    bool stalled_invoked = false;
    std::optional<Result<Addresses>> concurrent;
    std::optional<Result<Addresses>> closed_live;
    std::uint64_t stalled = 0U;
    // An inheritable descriptor, as Asio creates sockets without FD_CLOEXEC.
    int inheritable[2] = {-1, -1};
    CHECK(::pipe(inheritable) == 0);
    std::vector<std::set<int>> helper_descriptors;
    bool helper_unprivileged = false;
    const auto drain = run_then_close(context, resolver, 300ms, [&] {
        auto started = resolver->resolve(kStallHost, 4U, [&](Result<Addresses>) {
            stalled_invoked = true;
        });
        CHECK(started.ok());
        if (started.ok()) stalled = started.value();
        CHECK(resolver->resolve("localhost", 4U, [&](Result<Addresses> result) {
            concurrent = std::move(result);
            helper_descriptors = child_descriptors();
            helper_unprivileged = children_unprivileged();
            resolver->cancel(stalled);
            // A second stall is still live when the resolver closes.
            CHECK(resolver->resolve(kStallHost, 4U, [&](Result<Addresses> late) {
                closed_live = std::move(late);
            }).ok());
        }).ok());
    });
    ::close(inheritable[0]);
    ::close(inheritable[1]);
    CHECK(!stalled_invoked);
    CHECK(concurrent && concurrent->ok() && is_loopback(concurrent->value()));
    CHECK(helper_descriptors.size() == 1U &&
          helper_descriptors.front() == std::set<int>({0, 1, 2, 3}));
    CHECK(helper_unprivileged);
    // Close reaped the helper: no child remains.
    CHECK(child_descriptors().empty());
    CHECK(closed_live && closed_live->status().code() == StatusCode::Closed);
    CHECK(drain < 2s);
}

// Abandoned stalls fill every slot. The next lookup is refused, and the
// helper is replaced so later lookups succeed.
void test_saturation_replacement() {
    const auto context = make_context();
    const auto resolver = make_resolver(context, YUME_TEST_STALL_RESOLVER_PROGRAM, 2U);
    std::optional<StatusCode> saturated;
    std::optional<Result<Addresses>> after;
    boost::asio::steady_timer timer(context->executor());
    boost::asio::post(context->executor(), [&] {
        for (int index = 0; index < 2; ++index) {
            auto lookup = resolver->resolve(kStallHost, 1U, [](Result<Addresses>) {});
            CHECK(lookup.ok());
            if (lookup.ok()) resolver->cancel(lookup.value());
        }
        saturated = resolver->resolve("localhost", 1U, [](Result<Addresses>) {})
                        .status().code();
        timer.expires_after(50ms);
        timer.async_wait([&](const boost::system::error_code&) {
            CHECK(resolver->resolve("localhost", 4U, [&](Result<Addresses> result) {
                after = std::move(result);
                resolver->close();
                context->finish();
            }).ok());
        });
    });
    context->run();
    CHECK(saturated == StatusCode::ResourceExhausted);
    CHECK(after && after->ok() && is_loopback(after->value()));
}

// A program that is not a helper never says hello. Its exit fails the lookup
// instead of leaving it pending.
void test_non_helper_program() {
    const auto context = make_context();
    const auto resolver = make_resolver(context, "/bin/true");
    std::optional<Result<Addresses>> result;
    boost::asio::post(context->executor(), [&] {
        CHECK(resolver->resolve("localhost", 1U, [&](Result<Addresses> value) {
            result = std::move(value);
            resolver->close();
            context->finish();
        }).ok());
    });
    context->run();
    CHECK(result && !result->ok());
}

}  // namespace

int main(int argc, char** argv) {
    // This test binary also serves as the /proc/self/exe helper.
    if (yume::providers::is_system_resolver_helper(argc, argv)) {
        return yume::providers::run_system_resolver_helper();
    }
    test_protocol_codec();
    test_options();
    test_lookup(YUME_TEST_RESOLVER_PROGRAM);
    test_lookup("/proc/self/exe");
    test_stalled_lookup();
    test_saturation_replacement();
    test_non_helper_program();
    if (failures != 0) {
        std::fprintf(stderr, "%d system resolver check(s) failed\n", failures);
        return 1;
    }
    std::puts("system resolver tests passed");
    return 0;
}
