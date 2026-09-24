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

#include "providers/system_resolver_protocol.hpp"

namespace yume::providers {
namespace {

namespace protocol = resolver_protocol;

using engine::Result;
using engine::Status;
using engine::StatusCode;
using Addresses = std::vector<boost::asio::ip::address>;
using Socket = boost::asio::basic_seq_packet_socket<
    boost::asio::local::seq_packet_protocol, AsioExecutionContext::Executor>;

// glibc 2.34 added the descriptor-closing spawn action. Without it the helper
// would inherit every descriptor lacking FD_CLOEXEC, including accepted
// connections, and keep them open after this process closes them.
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 34))
constexpr bool kSpawnSupported = true;
#else
constexpr bool kSpawnSupported = false;
#endif

constexpr std::string_view kSelfProgram = "/proc/self/exe";

Status safe_status(StatusCode code, std::string_view message) noexcept {
    try {
        return Status(code, message);
    } catch (...) {
        return Status(code);
    }
}

Status validate_program(const std::filesystem::path& program) noexcept {
    if (program.native() == kSelfProgram) return Status::success();
    if (!program.is_absolute()) {
        return safe_status(StatusCode::InvalidArgument,
                           "resolver helper path must be absolute");
    }
    struct stat status {};
    if (::lstat(program.c_str(), &status) != 0) {
        return safe_status(StatusCode::FailedPrecondition,
                           "resolver helper is missing");
    }
    if (!S_ISREG(status.st_mode)) {
        return safe_status(StatusCode::FailedPrecondition,
                           "resolver helper is not a regular file");
    }
    if ((status.st_mode & (S_IWGRP | S_IWOTH)) != 0U ||
        (status.st_uid != 0U && status.st_uid != ::geteuid())) {
        return safe_status(StatusCode::PermissionDenied,
                           "resolver helper must be owned by root or this user "
                           "and not writable by others");
    }
    if (::access(program.c_str(), X_OK) != 0) {
        return safe_status(StatusCode::PermissionDenied,
                           "resolver helper is not executable");
    }
    return Status::success();
}

class Descriptor final {
public:
    explicit Descriptor(int value = -1) noexcept : value_(value) {}
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    ~Descriptor() { reset(); }
    int get() const noexcept { return value_; }
    int release() noexcept { return std::exchange(value_, -1); }
    void reset() noexcept {
        if (value_ >= 0) ::close(value_);
        value_ = -1;
    }

private:
    int value_;
};

// A spawned helper. pidfd signalling cannot reach an unrelated process that
// reused the PID after a host reaped this child, for example by ignoring
// SIGCHLD. Reaping waits only for this PID after SIGKILL, which ends it.
class ChildProcess final {
public:
    ChildProcess() = default;
    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;
    ~ChildProcess() { terminate(); }

    void adopt(pid_t pid) noexcept {
        pid_ = pid;
#if defined(SYS_pidfd_open)
        pidfd_ = static_cast<int>(::syscall(SYS_pidfd_open, pid, 0));
#endif
    }

    void terminate() noexcept {
        if (pid_ <= 0) return;
#if defined(SYS_pidfd_send_signal)
        if (pidfd_ >= 0) {
            (void)::syscall(SYS_pidfd_send_signal, pidfd_, SIGKILL, nullptr, 0U);
        } else {
            (void)::kill(pid_, SIGKILL);
        }
#else
        (void)::kill(pid_, SIGKILL);
#endif
        int status = 0;
        while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {
        }
        if (pidfd_ >= 0) ::close(pidfd_);
        pidfd_ = -1;
        pid_ = -1;
    }

private:
    pid_t pid_{-1};
    int pidfd_{-1};
};

class SpawnSetup final {
public:
    SpawnSetup() noexcept {
        actions_ready_ = ::posix_spawn_file_actions_init(&actions_) == 0;
        attributes_ready_ = ::posix_spawnattr_init(&attributes_) == 0;
    }
    SpawnSetup(const SpawnSetup&) = delete;
    SpawnSetup& operator=(const SpawnSetup&) = delete;
    ~SpawnSetup() {
        if (actions_ready_) (void)::posix_spawn_file_actions_destroy(&actions_);
        if (attributes_ready_) (void)::posix_spawnattr_destroy(&attributes_);
    }

    // The helper gets the socketpair as descriptor 3, /dev/null as input and
    // the inherited output streams, and nothing else. It starts with default
    // signal handling and an empty mask, in its own process group so terminal
    // signals reach only the parent, which ends the helper itself.
    bool prepare(int helper_socket) noexcept {
        if (!actions_ready_ || !attributes_ready_) return false;
        sigset_t empty;
        sigset_t all;
        sigemptyset(&empty);
        sigfillset(&all);
        bool ok = ::posix_spawn_file_actions_addopen(
                      &actions_, 0, "/dev/null", O_RDONLY, 0) == 0 &&
                  ::posix_spawn_file_actions_adddup2(
                      &actions_, helper_socket, protocol::kHelperDescriptor) == 0;
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 34))
        ok = ok && ::posix_spawn_file_actions_addclosefrom_np(
                       &actions_, protocol::kHelperDescriptor + 1) == 0;
#else
        ok = false;
#endif
        return ok &&
               ::posix_spawnattr_setflags(&attributes_,
                   POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF |
                   POSIX_SPAWN_SETPGROUP) == 0 &&
               ::posix_spawnattr_setsigmask(&attributes_, &empty) == 0 &&
               ::posix_spawnattr_setsigdefault(&attributes_, &all) == 0 &&
               ::posix_spawnattr_setpgroup(&attributes_, 0) == 0;
    }

    const posix_spawn_file_actions_t* actions() const noexcept { return &actions_; }
    const posix_spawnattr_t* attributes() const noexcept { return &attributes_; }

private:
    posix_spawn_file_actions_t actions_{};
    posix_spawnattr_t attributes_{};
    bool actions_ready_{false};
    bool attributes_ready_{false};
};

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
        if (!kSpawnSupported) {
            return safe_status(StatusCode::FailedPrecondition,
                               "a resolver helper is unsupported on this platform");
        }
        Status valid = validate_program(options.program);
        if (!valid.ok()) return valid;
        try {
            int pair[2] = {-1, -1};
            if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) != 0) {
                return safe_status(StatusCode::ResourceExhausted,
                                   "resolver helper socket creation failed");
            }
            Descriptor parent(pair[0]);
            Descriptor child(pair[1]);
            // dup2 onto an equal descriptor would keep FD_CLOEXEC set. A copy
            // above the target makes the spawn action always clear it.
            Descriptor child_copy(::fcntl(child.get(), F_DUPFD_CLOEXEC,
                                          protocol::kHelperDescriptor + 1));
            if (child_copy.get() < 0) {
                return safe_status(StatusCode::ResourceExhausted,
                                   "resolver helper descriptor copy failed");
            }
            auto started = std::make_shared<Helper>(context->executor(), ++generation);
            SpawnSetup setup;
            if (!setup.prepare(child_copy.get())) {
                return safe_status(StatusCode::ResourceExhausted,
                                   "resolver helper spawn setup failed");
            }
            std::string program = options.program.string();
            std::string argv0(protocol::kHelperArgv0);
            char* arguments[] = {argv0.data(), nullptr};
            pid_t pid = -1;
            const int spawn_error = ::posix_spawn(&pid, program.c_str(), setup.actions(),
                                                  setup.attributes(), arguments, environ);
            if (spawn_error != 0) {
                return safe_status(spawn_error == ENOMEM || spawn_error == EAGAIN
                                       ? StatusCode::ResourceExhausted
                                       : StatusCode::FailedPrecondition,
                                   "resolver helper could not start");
            }
            started->child.adopt(pid);
            child.reset();
            child_copy.reset();
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
        helper->child.terminate();
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
        Status valid = validate_program(options.program);
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
