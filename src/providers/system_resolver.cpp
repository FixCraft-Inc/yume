/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/system_resolver.hpp"

#include <array>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <map>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <utility>

#include <fcntl.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <boost/asio/buffer.hpp>
#include <boost/asio/local/seq_packet_protocol.hpp>
#include <boost/asio/basic_seq_packet_socket.hpp>
#include <boost/system/error_code.hpp>

#include "providers/child_process.hpp"
#include "providers/system_resolver_protocol.hpp"

namespace yume::providers {
namespace {

namespace protocol = resolver_protocol;
static_assert(protocol::kHelperDescriptor == kPassedDescriptor);

using engine::Result;
using engine::Status;
using engine::StatusCode;
using Addresses = std::vector<boost::asio::ip::address>;
using Socket = boost::asio::basic_seq_packet_socket<
    boost::asio::local::seq_packet_protocol, AsioExecutionContext::Executor>;

Status safe_status(StatusCode code, std::string_view message) noexcept {
    try {
        return Status(code, message);
    } catch (...) {
        return Status(code);
    }
}

template <typename Callback, typename... Args>
void invoke_contained(Callback& callback, Args&&... args) noexcept {
    if (!callback) return;
    try {
        callback(std::forward<Args>(args)...);
    } catch (...) {
        // Completions belong to callers outside this owner.
    }
}

Result<Addresses> lookup_result(const protocol::Response& response) noexcept {
    switch (response.status) {
    case protocol::LookupStatus::Ok:
        break;
    case protocol::LookupStatus::NotFound:
        return Result<Addresses>(safe_status(StatusCode::NotFound,
                                             "name has no addresses"));
    case protocol::LookupStatus::TemporaryFailure:
        return Result<Addresses>(safe_status(StatusCode::NotFound,
                                             "temporary name resolution failure"));
    case protocol::LookupStatus::Failure:
        return Result<Addresses>(safe_status(StatusCode::NotFound,
                                             "system name resolution failed"));
    case protocol::LookupStatus::Busy:
        return Result<Addresses>(safe_status(StatusCode::ResourceExhausted,
                                             "system resolver helper is busy"));
    }
    try {
        Addresses addresses;
        addresses.reserve(response.count);
        for (std::size_t index = 0; index < response.count; ++index) {
            const protocol::Address& entry = response.addresses[index];
            if (entry.family == 4U) {
                addresses.emplace_back(boost::asio::ip::address_v4(
                    boost::asio::ip::address_v4::bytes_type{
                        entry.bytes[0], entry.bytes[1], entry.bytes[2], entry.bytes[3]}));
            } else {
                boost::asio::ip::address_v6::bytes_type bytes{};
                std::copy(entry.bytes.begin(), entry.bytes.end(), bytes.begin());
                addresses.emplace_back(boost::asio::ip::address_v6(bytes, entry.scope_id));
            }
        }
        return Result<Addresses>(std::move(addresses));
    } catch (...) {
        return Result<Addresses>(Status(StatusCode::ResourceExhausted));
    }
}

}  // namespace

struct SystemResolver::State final : std::enable_shared_from_this<State> {
    // One spawned helper and its private receive state. Handlers hold the
    // helper they started on, so a replaced helper's late completion finds
    // its own buffer and is ignored.
    struct Helper final {
        explicit Helper(AsioExecutionContext::Executor executor, std::uint32_t id)
            : socket(executor), generation(id) {}
        Socket socket;
        ChildProcess child;
        std::array<std::uint8_t, protocol::kMaxResponseBytes + 1U> buffer{};
        boost::asio::socket_base::message_flags flags{0};
        const std::uint32_t generation;
        bool hello{false};
    };

    struct Lookup final {
        Completion completion;
        bool cancelled{false};
    };

    State(std::shared_ptr<AsioExecutionContext> execution, SystemResolverOptions settings)
        : context(std::move(execution)),
          options(std::move(settings)),
          close_task([](void* owner) noexcept {
              static_cast<State*>(owner)->close_on_context();
          }),
          replace_task([](void* owner) noexcept {
              static_cast<State*>(owner)->replace_on_context();
          }) {}

    ~State() {
        if (helper) stop_helper();
    }

    Result<std::uint64_t> resolve(std::string_view host, std::size_t max_addresses,
                                  Completion completion) {
        context->require_context();
        if (closed || close_requested.load(std::memory_order_acquire)) {
            return Result<std::uint64_t>(safe_status(StatusCode::Closed,
                                                     "system resolver is closed"));
        }
        if (!completion || max_addresses == 0U ||
            !protocol::valid_host(host)) {
            return Result<std::uint64_t>(safe_status(StatusCode::InvalidArgument,
                                                     "invalid system lookup"));
        }
        if (options.program.empty()) {
            return Result<std::uint64_t>(safe_status(StatusCode::FailedPrecondition,
                "hostname resolution needs a resolver program or a numeric address"));
        }
        if (lookups.size() >= options.max_outstanding) {
            // Every slot is in use. Abandoned lookups may never return, and
            // only a new helper reclaims them. Replace it outside this call
            // so other lookups never complete inside a caller's resolve().
            if (cancelled_lookups != 0U) request_replacement();
            return Result<std::uint64_t>(safe_status(StatusCode::ResourceExhausted,
                                                     "too many outstanding system lookups"));
        }
        if (!helper) {
            Status started = start_helper();
            if (!started.ok()) return Result<std::uint64_t>(std::move(started));
        }
        const std::uint32_t id = next_id();
        std::array<std::uint8_t, protocol::kMaxRequestBytes> message{};
        const std::size_t size = protocol::encode_request(
            {id, static_cast<std::uint8_t>(std::min(max_addresses, protocol::kMaxAddresses)),
             host},
            message);
        if (size == 0U) {
            return Result<std::uint64_t>(safe_status(StatusCode::InvalidArgument,
                                                     "invalid system lookup"));
        }
        const auto inserted = lookups.try_emplace(id, Lookup{std::move(completion), false});
        boost::system::error_code error;
        helper->socket.send(boost::asio::buffer(message.data(), size), 0, error);
        if (!error) {
            return Result<std::uint64_t>(
                (static_cast<std::uint64_t>(helper->generation) << 32U) | id);
        }
        // Refusal invokes nothing. A helper that exited is replaced when its
        // receive observes the end of the socket.
        lookups.erase(inserted.first);
        return Result<std::uint64_t>(safe_status(
            error == boost::asio::error::would_block ||
                    error == boost::asio::error::no_buffer_space
                ? StatusCode::ResourceExhausted
                : StatusCode::NotFound,
            "system resolver helper did not accept the lookup"));
    }

    void cancel(std::uint64_t lookup) noexcept {
        if (!helper || (lookup >> 32U) != helper->generation) return;
        const auto found = lookups.find(static_cast<std::uint32_t>(lookup));
        if (found == lookups.end() || found->second.cancelled) return;
        // The entry keeps the helper slot until its response arrives.
        Completion released = std::move(found->second.completion);
        found->second.completion = nullptr;
        found->second.cancelled = true;
        ++cancelled_lookups;
    }

    void request_replacement() noexcept {
        if (replacement_requested) return;
        replacement_requested = true;
        context->submit(replace_task, shared_from_this());
    }

    void replace_on_context() noexcept {
        replacement_requested = false;
        if (closed || lookups.size() < options.max_outstanding || cancelled_lookups == 0U) {
            return;
        }
        replace_helper(safe_status(StatusCode::ResourceExhausted,
                                   "system resolver was replaced after stalled lookups"));
    }

    void request_close() noexcept {
        if (close_requested.exchange(true, std::memory_order_acq_rel)) return;
        context->submit(close_task, shared_from_this());
    }

    void close_on_context() noexcept {
        if (closed) return;
        closed = true;
        replace_helper(safe_status(StatusCode::Closed, "system resolver is closed"));
    }

    std::uint32_t next_id() noexcept {
        do {
            ++last_id;
        } while (last_id == 0U || lookups.find(last_id) != lookups.end());
        return last_id;
    }

    Status start_helper() noexcept {
        Status valid = validate_program(options.program, "resolver helper");
        if (!valid.ok()) return valid;
        try {
            int pair[2] = {-1, -1};
            if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) != 0) {
                return safe_status(StatusCode::ResourceExhausted,
                                   "resolver helper socket creation failed");
            }
            Descriptor parent(pair[0]);
            Descriptor child(pair[1]);
            auto started = std::make_shared<Helper>(context->executor(), ++generation);
            const std::string arguments[] = {std::string(protocol::kHelperArgv0)};
            auto spawned = ChildProcess::spawn(options.program, arguments, child.get());
            if (!spawned.ok()) {
                return safe_status(spawned.status().code(),
                                   spawned.status().message().empty()
                                       ? std::string_view("resolver helper could not start")
                                       : std::string_view(spawned.status().message()));
            }
            started->child = std::move(spawned).take_value();
            child.reset();
            boost::system::error_code error;
            started->socket.assign(boost::asio::local::seq_packet_protocol(),
                                   parent.get(), error);
            if (error) {
                return safe_status(StatusCode::Internal,
                                   "resolver helper socket adoption failed");
            }
            parent.release();
            started->socket.non_blocking(true, error);
            if (error) {
                return safe_status(StatusCode::Internal,
                                   "resolver helper socket setup failed");
            }
            helper = std::move(started);
            receive(helper);
            return helper ? Status::success()
                          : safe_status(StatusCode::ResourceExhausted,
                                        "resolver helper receive failed");
        } catch (...) {
            return Status(StatusCode::ResourceExhausted);
        }
    }

    void receive(const std::shared_ptr<Helper>& current) noexcept {
        try {
            current->socket.async_receive(
                boost::asio::buffer(current->buffer), current->flags,
                [self = shared_from_this(), current](
                    const boost::system::error_code& error, std::size_t size) noexcept {
                    self->received(current, error, size);
                });
        } catch (...) {
            replace_helper(Status(StatusCode::ResourceExhausted));
        }
    }

    void received(const std::shared_ptr<Helper>& current,
                  const boost::system::error_code& error, std::size_t size) noexcept {
        if (helper != current) return;
        // Every valid message is nonempty, so size zero is the helper's EOF.
        if (error || size == 0U) {
            replace_helper(safe_status(StatusCode::NotFound, "system resolver helper exited"));
            return;
        }
        const std::span<const std::uint8_t> message(current->buffer.data(), size);
        if ((current->flags & MSG_TRUNC) != 0 || size > protocol::kMaxResponseBytes) {
            replace_helper(safe_status(StatusCode::Internal,
                                       "system resolver helper sent an oversize message"));
            return;
        }
        if (!current->hello) {
            if (!protocol::valid_hello(message)) {
                replace_helper(safe_status(StatusCode::FailedPrecondition,
                                           "resolver helper protocol mismatch"));
                return;
            }
            current->hello = true;
            receive(current);
            return;
        }
        const auto response = protocol::decode_response(message);
        const auto found = response ? lookups.find(response->id) : lookups.end();
        if (found == lookups.end()) {
            replace_helper(safe_status(StatusCode::Internal,
                                       "system resolver helper sent an invalid response"));
            return;
        }
        auto node = lookups.extract(found);
        if (node.mapped().cancelled) --cancelled_lookups;
        // Rearm first: the completion may start or cancel other lookups.
        receive(current);
        if (!node.mapped().cancelled) {
            invoke_contained(node.mapped().completion, lookup_result(*response));
        }
    }

    // Ends the current helper and fails its live lookups with status.
    // Completions run after the state is settled and may start new lookups.
    void replace_helper(const Status& status) noexcept {
        if (helper) stop_helper();
        std::map<std::uint32_t, Lookup> failed;
        failed.swap(lookups);
        cancelled_lookups = 0U;
        for (auto& [id, lookup] : failed) {
            if (lookup.cancelled) continue;
            Status copy = safe_status(status.code(), status.message());
            invoke_contained(lookup.completion, Result<Addresses>(std::move(copy)));
        }
    }

    void stop_helper() noexcept {
        boost::system::error_code ignored;
        helper->socket.close(ignored);
        helper->child.kill_and_reap();
        helper.reset();
    }

    const std::shared_ptr<AsioExecutionContext> context;
    const SystemResolverOptions options;
    AsioExecutionContext::ControlTask close_task;
    AsioExecutionContext::ControlTask replace_task;
    std::atomic<bool> close_requested{false};
    bool closed{false};
    bool replacement_requested{false};
    std::shared_ptr<Helper> helper;
    std::map<std::uint32_t, Lookup> lookups;
    std::size_t cancelled_lookups{0U};
    std::uint32_t last_id{0U};
    std::uint32_t generation{0U};
};

Result<std::shared_ptr<SystemResolver>> SystemResolver::create(
    std::shared_ptr<AsioExecutionContext> context, SystemResolverOptions options) {
    if (!context || options.max_outstanding == 0U ||
        options.max_outstanding > protocol::kMaxOutstanding) {
        return Result<std::shared_ptr<SystemResolver>>(safe_status(
            StatusCode::InvalidArgument, "invalid system resolver options"));
    }
    if (!options.program.empty()) {
        Status valid = validate_program(options.program, "resolver helper");
        if (!valid.ok()) return Result<std::shared_ptr<SystemResolver>>(std::move(valid));
    }
    try {
        auto state = std::make_shared<State>(std::move(context), std::move(options));
        return Result<std::shared_ptr<SystemResolver>>(
            std::shared_ptr<SystemResolver>(new SystemResolver(std::move(state))));
    } catch (...) {
        return Result<std::shared_ptr<SystemResolver>>(Status(StatusCode::ResourceExhausted));
    }
}

SystemResolver::SystemResolver(std::shared_ptr<State> state) noexcept
    : state_(std::move(state)) {}

SystemResolver::~SystemResolver() noexcept { close(); }

Result<std::uint64_t> SystemResolver::resolve(std::string_view host,
                                              std::size_t max_addresses,
                                              Completion completion) {
    return state_->resolve(host, max_addresses, std::move(completion));
}

void SystemResolver::cancel(std::uint64_t lookup) noexcept { state_->cancel(lookup); }

void SystemResolver::close() noexcept { state_->request_close(); }

engine::ExecutorAffinity SystemResolver::executor_affinity() const noexcept {
    return state_->context->affinity();
}

}  // namespace yume::providers
