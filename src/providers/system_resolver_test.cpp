/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/system_resolver.hpp"

#define YUME_TEST_ALIGNED_ALLOCATIONS
#include "test_support/allocation_failure.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <set>
#include <string>
#include <thread>
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
constexpr std::string_view kMissingHost = "resolver-missing.invalid";

std::shared_ptr<AsioExecutionContext> make_context() {
    auto created = AsioExecutionContext::create(yume::engine::ExecutorAffinity(0x52534c56U));
    if (!created.ok()) std::abort();
    return std::move(created).take_value();
}

std::shared_ptr<SystemResolver> make_resolver(
    const std::shared_ptr<AsioExecutionContext>& context, std::string program,
    std::size_t max_outstanding = 64U, std::size_t max_waiting = 1024U) {
    SystemResolverOptions options;
    options.program = std::move(program);
    options.max_outstanding = max_outstanding;
    options.max_waiting = max_waiting;
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
    SystemResolverOptions too_many_waiting;
    too_many_waiting.max_waiting = 65537U;
    CHECK(SystemResolver::create(context, too_many_waiting).status().code() ==
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

// localhost resolves from the host's files. A missing name comes from the
// test helper, since what the system answers for one depends on its DNS: a
// namespace without a resolver reports a temporary failure instead.
void test_lookup(const std::string& program, bool test_names) {
    const auto context = make_context();
    const auto resolver = make_resolver(context, program);
    std::optional<Result<Addresses>> localhost;
    std::optional<Result<Addresses>> missing;
    boost::asio::post(context->executor(), [&] {
        CHECK(resolver->resolve("localhost", 8U, [&](Result<Addresses> result) {
            localhost = std::move(result);
            if (!test_names) {
                resolver->close();
                context->finish();
                return;
            }
            CHECK(resolver->resolve(kMissingHost, 8U,
                [&](Result<Addresses> second) {
                    missing = std::move(second);
                    resolver->close();
                    context->finish();
                }).ok());
        }).ok());
    });
    context->run();
    CHECK(localhost && localhost->ok() && is_loopback(localhost->value()));
    CHECK(!test_names ||
          (missing && missing->status().code() == StatusCode::NotFound));
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

// Live lookups fill both slots, so later ones wait instead of failing, up to
// max_waiting, and start as earlier ones answer. A cancelled waiting lookup
// never completes, and no completion runs inside a caller's resolve().
void test_waiting_lookups() {
    const auto context = make_context();
    SystemResolverOptions options;
    options.program = YUME_TEST_STALL_RESOLVER_PROGRAM;
    options.max_outstanding = 2U;
    options.max_waiting = 2U;
    auto created = SystemResolver::create(context, std::move(options));
    CHECK(created.ok());
    const auto resolver = std::move(created).take_value();
    bool inside_resolve = false;
    bool completed_inside = false;
    std::optional<Result<Addresses>> stalled, second, waited, cancelled_result;
    std::optional<StatusCode> overflow;
    const auto drain = run_then_close(context, resolver, 300ms, [&] {
        inside_resolve = true;
        CHECK(resolver->resolve(kStallHost, 4U, [&](Result<Addresses> result) {
            completed_inside = completed_inside || inside_resolve;
            stalled = std::move(result);
        }).ok());
        CHECK(resolver->resolve("localhost", 4U, [&](Result<Addresses> result) {
            completed_inside = completed_inside || inside_resolve;
            second = std::move(result);
        }).ok());
        CHECK(resolver->resolve("localhost", 4U, [&](Result<Addresses> result) {
            completed_inside = completed_inside || inside_resolve;
            waited = std::move(result);
        }).ok());
        auto dropped = resolver->resolve("localhost", 4U, [&](Result<Addresses> result) {
            cancelled_result = std::move(result);
        });
        CHECK(dropped.ok());
        overflow = resolver->resolve("localhost", 4U, [](Result<Addresses>) {})
                       .status().code();
        if (dropped.ok()) resolver->cancel(dropped.value());
        inside_resolve = false;
    });
    CHECK(!completed_inside);
    CHECK(overflow == StatusCode::ResourceExhausted);
    CHECK(second && second->ok() && is_loopback(second->value()));
    CHECK(waited && waited->ok() && is_loopback(waited->value()));
    CHECK(!cancelled_result);
    // The stall was still live when the resolver closed.
    CHECK(stalled && stalled->status().code() == StatusCode::Closed);
    CHECK(drain < 2s);
}

// Closing fails a waiting lookup with the live one it waited behind.
void test_close_fails_waiting_lookups() {
    const auto context = make_context();
    const auto resolver = make_resolver(context, YUME_TEST_STALL_RESOLVER_PROGRAM, 1U);
    std::optional<Result<Addresses>> live, queued;
    run_then_close(context, resolver, 50ms, [&] {
        CHECK(resolver->resolve(kStallHost, 1U, [&](Result<Addresses> result) {
            live = std::move(result);
        }).ok());
        CHECK(resolver->resolve("localhost", 1U, [&](Result<Addresses> result) {
            queued = std::move(result);
        }).ok());
    });
    CHECK(live && live->status().code() == StatusCode::Closed);
    CHECK(queued && queued->status().code() == StatusCode::Closed);
}

// A program that is not a helper never says hello. Its exit fails the lookup
// instead of leaving it pending.
void test_non_helper_program() {
    const auto context = make_context();
    const auto resolver = make_resolver(context, "/bin/true");
    std::optional<Result<Addresses>> result;
    boost::asio::post(context->executor(), [&] {
        auto lookup =
            resolver->resolve("localhost", 1U, [&](Result<Addresses> value) {
                result = std::move(value);
                resolver->close();
                context->finish();
            });
        // The program can exit before the request is written. That refusal
        // runs no completion and fails the lookup just as well.
        if (!lookup.ok()) {
            result.emplace(lookup.status());
            resolver->close();
            context->finish();
        }
    });
    context->run();
    CHECK(result && !result->ok());
}

// These fixtures drive the two actual contexts separately, so injection is
// armed only during the selected owner or caller turn. No helper response or
// test-thread allocation shares the injected turn for a stalled lookup.
std::shared_ptr<SystemResolver> make_remote(
    const std::shared_ptr<AsioExecutionContext>& context,
    const std::shared_ptr<SystemResolver>& owner) {
    auto made = SystemResolver::create_remote(context, owner);
    if (!made.ok()) std::abort();
    return std::move(made).take_value();
}

template <typename Predicate>
bool poll_until(const std::shared_ptr<AsioExecutionContext>& context,
                Predicate predicate) {
    const auto deadline = Clock::now() + 2s;
    do {
        context->poll();
        if (predicate()) return true;
        std::this_thread::sleep_for(1ms);
    } while (Clock::now() < deadline);
    return predicate();
}

void close_remote_fixture(
    const std::shared_ptr<AsioExecutionContext>& context,
    const std::shared_ptr<SystemResolver>& remote,
    const std::shared_ptr<AsioExecutionContext>& owner_context,
    const std::shared_ptr<SystemResolver>& owner) {
    remote->close();
    context->poll();
    owner->close();
    owner_context->poll();
    context->poll();
    context->finish();
    owner_context->finish();
    context->poll();
    owner_context->poll();
}

// Warm the helper and its receive operation before an allocation sweep, so
// each failed allocation concerns the accepted remote lookup, not startup.
void warm_owner(const std::shared_ptr<AsioExecutionContext>& context,
                const std::shared_ptr<SystemResolver>& owner) {
    bool answered = false;
    boost::asio::post(context->executor(), [&] {
        CHECK(owner
                  ->resolve("localhost", 1U,
                            [&](Result<Addresses> result) {
                                CHECK(result.ok() &&
                                      is_loopback(result.value()));
                                answered = true;
                            })
                  .ok());
    });
    CHECK(poll_until(context, [&] { return answered; }));
}

// With one outstanding slot and no waiting slots, a cancelled stall refuses
// once and requests replacement. A live registration whose cancellation ID
// was lost refuses both attempts and cannot make this healthy lookup succeed.
void check_owner_slot_reusable(
    const std::shared_ptr<AsioExecutionContext>& context,
    const std::shared_ptr<SystemResolver>& owner) {
    bool accepted = false;
    bool answered = false;
    for (unsigned attempt = 0; attempt < 2U && !accepted; ++attempt) {
        boost::asio::post(context->executor(), [&] {
            auto lookup =
                owner->resolve("localhost", 1U, [&](Result<Addresses> result) {
                    CHECK(result.ok() && is_loopback(result.value()));
                    answered = true;
                });
            accepted = lookup.ok();
            CHECK(accepted ||
                  lookup.status().code() == StatusCode::ResourceExhausted);
        });
        context->poll();
    }
    CHECK(accepted);
    if (accepted) CHECK(poll_until(context, [&] { return answered; }));
}

thread_local unsigned denied_allocations = 0;

void deny_allocation(std::size_t) {
    ++denied_allocations;
    throw std::bad_alloc();
}

struct AllocationDenial final {
    AllocationDenial() {
        denied_allocations = 0;
        yume::test::before_allocate = deny_allocation;
        // Prove denial is armed and the hook fires, even when the corrected
        // terminal path deliberately performs no allocations.
        bool fired = false;
        try {
            void* storage = ::operator new(1U);
            ::operator delete(storage);
        } catch (const std::bad_alloc&) {
            fired = true;
        }
        CHECK(fired && denied_allocations == 1U);
    }
    ~AllocationDenial() { yume::test::before_allocate = nullptr; }
};

// The owner's synchronous refusal must reach the caller once despite
// sustained allocation failure. Its diagnostic attempts an allocation, so
// the premise checks both a denied probe and an actual resolver allocation.
void test_remote_refusal_during_allocation_denial() {
    const auto owner_context = make_context();
    const auto context = make_context();
    const auto owner =
        make_resolver(owner_context, YUME_TEST_STALL_RESOLVER_PROGRAM);
    const auto remote = make_remote(context, owner);
    owner->close();
    owner_context->poll();
    unsigned completions = 0;
    boost::asio::post(context->executor(), [&] {
        CHECK(remote
                  ->resolve("localhost", 1U,
                            [&](Result<Addresses> result) {
                                CHECK(context->running_in_this_thread());
                                CHECK(!owner_context->running_in_this_thread());
                                CHECK(!result.ok());
                                ++completions;
                            })
                  .ok());
    });
    context->poll();
    {
        AllocationDenial denial;
        owner_context->poll();
        CHECK(denied_allocations > 1U);
        context->poll();
    }
    CHECK(completions == 1U);
    close_remote_fixture(context, remote, owner_context, owner);
    CHECK(completions == 1U);
}

// Sweep every owner-side allocation after remote acceptance. A failed
// forward must answer ResourceExhausted and leave no live owner registration;
// an accepted stall must remain cancellable without allocating another node.
void test_remote_forward_allocation_rollback() {
    bool reached_end = false;
    unsigned injected = 0;
    for (std::size_t nth = 1U; nth <= 16U && !reached_end; ++nth) {
        const auto owner_context = make_context();
        const auto context = make_context();
        const auto owner = make_resolver(
            owner_context, YUME_TEST_STALL_RESOLVER_PROGRAM, 1U, 0U);
        warm_owner(owner_context, owner);
        const auto remote = make_remote(context, owner);
        std::uint64_t id = 0U;
        unsigned completions = 0;
        boost::asio::post(context->executor(), [&] {
            auto lookup =
                remote->resolve(kStallHost, 1U, [&](Result<Addresses> result) {
                    CHECK(context->running_in_this_thread());
                    CHECK(result.status().code() ==
                          StatusCode::ResourceExhausted);
                    ++completions;
                });
            CHECK(lookup.ok());
            if (lookup.ok()) id = lookup.value();
        });
        context->poll();
        CHECK(id != 0U);
        yume::test::arm_allocation_failure(nth);
        owner_context->poll();
        const bool fired = yume::test::disarm_allocation_failure();
        injected += fired ? 1U : 0U;
        reached_end = !fired;
        context->poll();
        CHECK(completions == (fired ? 1U : 0U));
        boost::asio::post(context->executor(), [&] { remote->cancel(id); });
        context->poll();
        owner_context->poll();
        check_owner_slot_reusable(owner_context, owner);
        close_remote_fixture(context, remote, owner_context, owner);
        CHECK(completions == (fired ? 1U : 0U));
    }
    CHECK(reached_end && injected != 0U);
}

// Cancel and close use lookup-owned controls even when ordinary posts cannot
// allocate. Reclaiming the one owner slot distinguishes a delivered cancel
// from merely dropping the caller's callback.
void test_remote_cancel_and_close_during_allocation_denial() {
    for (const bool close : {false, true}) {
        const auto owner_context = make_context();
        const auto context = make_context();
        const auto owner = make_resolver(
            owner_context, YUME_TEST_STALL_RESOLVER_PROGRAM, 1U, 0U);
        warm_owner(owner_context, owner);
        const auto remote = make_remote(context, owner);
        std::uint64_t id = 0U;
        unsigned completions = 0;
        boost::asio::post(context->executor(), [&] {
            auto lookup =
                remote->resolve(kStallHost, 1U, [&](Result<Addresses> result) {
                    CHECK(context->running_in_this_thread());
                    CHECK(close &&
                          result.status().code() == StatusCode::Closed);
                    ++completions;
                });
            CHECK(lookup.ok());
            if (lookup.ok()) id = lookup.value();
        });
        context->poll();
        owner_context->poll();
        CHECK(id != 0U && completions == 0U);
        boost::asio::post(context->executor(), [&] {
            if (close)
                remote->close();
            else
                remote->cancel(id);
        });
        {
            AllocationDenial denial;
            context->poll();
            owner_context->poll();
        }
        CHECK(completions == (close ? 1U : 0U));
        check_owner_slot_reusable(owner_context, owner);
        close_remote_fixture(context, remote, owner_context, owner);
        CHECK(completions == (close ? 1U : 0U));
    }
}

}  // namespace

// A remote resolver on one context sends its lookups to an owner's helper on
// another and answers on its own. Cancel keeps a completion from running,
// close fails what is outstanding, and the owner's refusal arrives through
// the completion.
void test_remote_lookups() {
    const auto owner_context = make_context();
    auto created = AsioExecutionContext::create(
        yume::engine::ExecutorAffinity(0x52534c57U));
    CHECK(created.ok());
    const auto context = std::move(created).take_value();
    const auto owner =
        make_resolver(owner_context, YUME_TEST_STALL_RESOLVER_PROGRAM);
    std::thread owner_thread([&] { owner_context->run(); });
    auto made = SystemResolver::create_remote(context, owner);
    CHECK(made.ok());
    const auto remote = std::move(made).take_value();
    auto second = SystemResolver::create_remote(context, owner);
    CHECK(second.ok());
    const auto refused_remote = std::move(second).take_value();
    CHECK(remote->executor_affinity() == context->affinity());
    std::optional<Result<Addresses>> localhost;
    bool answered_here = false;
    bool cancelled_invoked = false;
    std::optional<Result<Addresses>> closed_live;
    std::optional<Result<Addresses>> refused;
    boost::asio::post(context->executor(), [&] {
        CHECK(
            remote
                ->resolve(
                    "localhost", 4U,
                    [&](Result<Addresses> result) {
                        localhost = std::move(result);
                        answered_here = context->running_in_this_thread();
                        auto cancelled = remote->resolve(
                            kStallHost, 4U, [&](Result<Addresses>) {
                                cancelled_invoked = true;
                            });
                        CHECK(cancelled.ok());
                        remote->cancel(cancelled.value());
                        CHECK(
                            remote
                                ->resolve(
                                    kStallHost, 4U,
                                    [&](Result<Addresses> late) {
                                        closed_live = std::move(late);
                                        owner->close();
                                        CHECK(
                                            refused_remote
                                                ->resolve(
                                                    "localhost", 4U,
                                                    [&](Result<Addresses>
                                                            answer) {
                                                        refused =
                                                            std::move(answer);
                                                        refused_remote->close();
                                                        context->finish();
                                                        owner_context->finish();
                                                    })
                                                .ok());
                                    })
                                .ok());
                        remote->close();
                    })
                .ok());
    });
    context->run();
    owner_thread.join();
    CHECK(localhost && localhost->ok() && is_loopback(localhost->value()));
    CHECK(answered_here);
    CHECK(!cancelled_invoked);
    CHECK(closed_live && closed_live->status().code() == StatusCode::Closed);
    CHECK(refused && refused->status().code() == StatusCode::Closed);
}

int main(int argc, char** argv) {
    // This test binary also serves as the /proc/self/exe helper.
    if (yume::providers::is_system_resolver_helper(argc, argv)) {
        return yume::providers::run_system_resolver_helper();
    }
    test_protocol_codec();
    test_options();
    test_lookup(YUME_TEST_RESOLVER_PROGRAM, false);
    test_lookup("/proc/self/exe", false);
    test_lookup(YUME_TEST_STALL_RESOLVER_PROGRAM, true);
    test_stalled_lookup();
    test_saturation_replacement();
    test_waiting_lookups();
    test_close_fails_waiting_lookups();
    test_non_helper_program();
    test_remote_lookups();
    test_remote_refusal_during_allocation_denial();
    test_remote_forward_allocation_rollback();
    test_remote_cancel_and_close_during_allocation_denial();
    if (failures != 0) {
        std::fprintf(stderr, "%d system resolver check(s) failed\n", failures);
        return 1;
    }
    std::puts("system resolver tests passed");
    return 0;
}
