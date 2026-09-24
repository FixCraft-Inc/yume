/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/module_supervisor.hpp"

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <new>
#include <string>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <boost/asio/basic_waitable_timer.hpp>
#include <boost/asio/posix/basic_stream_descriptor.hpp>

#include "engine/buffer.hpp"
#include "engine/cancellation.hpp"
#include "providers/asio_tcp_byte_channel_provider.hpp"
#include "providers/child_process.hpp"
#include "providers/direct_route_handler.hpp"
#include "runtime/module_launcher.hpp"

namespace yume::runtime {
namespace {
using engine::Buffer;
using engine::ByteChannel;
using engine::Result;
using engine::Status;
using engine::StatusCode;
using engine::StreamResponder;
using Clock = std::chrono::steady_clock;
using Executor = providers::AsioExecutionContext::Executor;
using Timer = boost::asio::basic_waitable_timer<Clock, boost::asio::wait_traits<Clock>, Executor>;
using ExitWatch = boost::asio::posix::basic_stream_descriptor<Executor>;
using Error = boost::system::error_code;
using Local = boost::asio::local::stream_protocol;

constexpr std::string_view kSocketName = "module.sock";

Status diagnostic(StatusCode code, std::string_view first, std::string_view second = {}) noexcept {
    try {
        std::string message(first);
        message += second;
        return Status(code, message);
    } catch (...) {
        return Status(code);
    }
}

std::string describe_exit(int status) {
    if (WIFEXITED(status)) return "exit status " + std::to_string(WEXITSTATUS(status));
    if (WIFSIGNALED(status)) return "signal " + std::to_string(WTERMSIG(status));
    return "wait status " + std::to_string(status);
}

// The composite fingerprint is hexadecimal. Anything else would let a
// provider's label change the header's shape.
bool header_safe(std::string_view identity) noexcept {
    return !identity.empty() && identity.size() <= 128U &&
           std::all_of(identity.begin(), identity.end(), [](char ch) {
               return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
           });
}

template <typename Completion, typename... Args>
void complete(Completion& completion, Args&&... args) noexcept {
    auto owned = std::move(completion);
    if (!owned) return;
    try {
        owned(std::forward<Args>(args)...);
    } catch (...) {
    }
}

}  // namespace

struct ModuleSupervisor::State final : std::enable_shared_from_this<State> {
    State(std::shared_ptr<providers::AsioExecutionContext> execution, const config::v1::ModuleAdapter& adapter,
          ModuleSupervisorOptions settings, ModuleReport reporter,
          std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> owner)
        : context(std::move(execution)),
          service(adapter.service()),
          program(adapter.program()),
          arguments(adapter.arguments()),
          options(std::move(settings)),
          report(std::move(reporter)),
          channels(std::move(owner)),
          exit_watch(context->executor()),
          restart_timer(context->executor()),
          stop_timer(context->executor()),
          next_delay(options.restart_initial) {}

    ~State() { finish_close(); }

    bool running() const noexcept { return child.running() && !closing; }

    void say(std::string_view text) noexcept {
        if (!report) return;
        try {
            report("module " + service + ": " + std::string(text));
        } catch (...) {
        }
    }

    Status start() {
        context->require_context();
        if (started || closing) return Status(StatusCode::FailedPrecondition);
        started = true;
        auto valid = providers::validate_program(options.launcher, "module launcher");
        if (valid.ok()) valid = providers::validate_program(program, "module program");
        if (!valid.ok()) return valid;
        auto socket = open_socket();
        if (!socket.ok()) return socket;
        return spawn();
    }

    // A fresh 0700 directory holds the socket, so no other user can reach it
    // and no earlier file can stand in its place.
    Status open_socket() noexcept {
        try {
            std::string pattern = (std::filesystem::temp_directory_path() / "yume-module-XXXXXX").string();
            if (::mkdtemp(pattern.data()) == nullptr)
                return diagnostic(StatusCode::Internal, "module socket directory could not be created");
            directory = pattern;
            socket_path = directory / kSocketName;
            sockaddr_un address{};
            const std::string path = socket_path.string();
            if (path.size() >= sizeof(address.sun_path))
                return diagnostic(StatusCode::FailedPrecondition,
                    "module socket path is too long, set TMPDIR to a shorter directory");
            address.sun_family = AF_UNIX;
            path.copy(address.sun_path, path.size());
            listener = providers::Descriptor(::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
            if (listener.get() < 0 ||
                ::bind(listener.get(), reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 ||
                ::chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0 ||
                ::listen(listener.get(), SOMAXCONN) != 0)
                return diagnostic(StatusCode::Internal, "module socket could not open");
            return Status::success();
        } catch (const std::bad_alloc&) {
            return Status(StatusCode::ResourceExhausted);
        } catch (...) {
            return Status(StatusCode::Internal);
        }
    }

    Status spawn() noexcept {
        try {
            std::vector<std::string> command{std::string(kModuleLauncherArgv0), program};
            command.insert(command.end(), arguments.begin(), arguments.end());
            auto spawned = providers::ChildProcess::spawn(options.launcher, command, listener.get());
            if (!spawned.ok()) return spawned.status();
            auto process = std::move(spawned).take_value();
            if (process.pidfd() < 0)
                return diagnostic(StatusCode::FailedPrecondition,
                                  "module supervision needs pidfd (Linux 5.3 or newer)");
            const int watched = ::fcntl(process.pidfd(), F_DUPFD_CLOEXEC, 0);
            if (watched < 0) return Status(StatusCode::ResourceExhausted);
            Error error;
            exit_watch.assign(watched, error);
            if (error) {
                ::close(watched);
                return Status(StatusCode::Internal);
            }
            child = std::move(process);
        } catch (const std::bad_alloc&) {
            return Status(StatusCode::ResourceExhausted);
        } catch (...) {
            return Status(StatusCode::Internal);
        }
        started_at = Clock::now();
        watch(++generation);
        try {
            say("started as process " + std::to_string(child.pid()));
        } catch (...) {
        }
        return Status::success();
    }

    void watch(std::uint64_t current) noexcept {
        try {
            exit_watch.async_wait(boost::asio::posix::descriptor_base::wait_read,
                [self = shared_from_this(), current](const Error& error) noexcept {
                    self->exited(current, error);
                });
        } catch (...) {
            // Without a watch the exit would go unnoticed, so end the module
            // and let the restart path try again.
            child.kill_and_reap();
            Error ignored;
            exit_watch.close(ignored);
            say("could not watch the module, restarting it");
            schedule_restart();
        }
    }

    void exited(std::uint64_t current, const Error& error) noexcept {
        if (current != generation || !child.running()) return;
        const auto status = child.try_reap();
        if (!status) {
            if (!error) watch(current);
            return;
        }
        Error ignored;
        exit_watch.close(ignored);
        if (closing) {
            finish_close();
            return;
        }
        if (Clock::now() - started_at >= options.stable_after) next_delay = options.restart_initial;
        try {
            say("exited with " + describe_exit(*status) + ", restarting in " +
                std::to_string(next_delay.count()) + " ms");
        } catch (...) {
        }
        schedule_restart();
    }

    void schedule_restart() noexcept {
        if (closing) return;
        const auto delay = next_delay;
        next_delay = std::min(next_delay * 2, options.restart_max);
        try {
            restart_timer.expires_after(delay);
            restart_timer.async_wait([self = shared_from_this()](const Error& error) noexcept {
                if (error || self->closing) return;
                const auto spawned = self->spawn();
                if (spawned.ok()) return;
                try {
                    self->say("could not start: " + spawned.message());
                } catch (...) {
                }
                self->schedule_restart();
            });
        } catch (...) {
            say("could not schedule a restart, the module stays down");
        }
    }

    void close() noexcept {
        if (closing) return;
        closing = true;
        Error ignored;
        restart_timer.cancel(ignored);
        if (!child.running()) {
            finish_close();
            return;
        }
        child.signal(SIGTERM);
        try {
            stop_timer.expires_after(options.stop_grace);
            stop_timer.async_wait([self = shared_from_this()](const Error& error) noexcept {
                if (error || self->finished) return;
                self->child.kill_and_reap();
                self->finish_close();
            });
        } catch (...) {
            child.kill_and_reap();
            finish_close();
        }
    }

    void finish_close() noexcept {
        if (finished) return;
        finished = true;
        closing = true;
        child.kill_and_reap();
        Error ignored;
        stop_timer.cancel(ignored);
        restart_timer.cancel(ignored);
        exit_watch.close(ignored);
        listener.reset();
        if (channels) channels->cancel();
        if (!socket_path.empty()) (void)::unlink(socket_path.c_str());
        if (!directory.empty()) (void)::rmdir(directory.c_str());
    }

    const std::shared_ptr<providers::AsioExecutionContext> context;
    const std::string service;
    const std::string program;
    const std::vector<std::string> arguments;
    const ModuleSupervisorOptions options;
    ModuleReport report;
    const std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> channels;
    std::shared_ptr<engine::StreamHandler> handler;
    std::filesystem::path directory;
    std::filesystem::path socket_path;
    providers::Descriptor listener;
    providers::ChildProcess child;
    ExitWatch exit_watch;
    Timer restart_timer;
    Timer stop_timer;
    Clock::time_point started_at{};
    std::chrono::milliseconds next_delay;
    std::uint64_t generation{0U};
    bool started{false};
    bool closing{false};
    bool finished{false};
};

namespace {

// One OPEN from the connection attempt until the stream is bridged or refused.
class ModuleOpen final : public std::enable_shared_from_this<ModuleOpen> {
public:
    ModuleOpen(std::shared_ptr<ModuleSupervisor::State> state,
               std::shared_ptr<StreamResponder> stream,
               engine::StreamHandler::AcceptanceCompletion completion, std::string header)
        : state_(std::move(state)),
          stream_(std::move(stream)),
          completion_(std::move(completion)),
          header_(std::move(header)),
          socket_(state_->context->executor()),
          timer_(state_->context->executor()) {}

    void start() noexcept {
        try {
            timer_.expires_after(state_->options.connect_timeout);
            timer_.async_wait([self = shared_from_this()](const Error& error) noexcept {
                if (!error) {
                    self->fail(diagnostic(StatusCode::Cancelled,
                                          "the module did not take the stream in time"));
                }
            });
            socket_.async_connect(Local::endpoint(state_->socket_path.string()),
                [self = shared_from_this()](const Error& error) noexcept { self->connected(error); });
        } catch (...) {
            fail(Status(StatusCode::ResourceExhausted));
        }
    }

private:
    void connected(const Error& error) noexcept {
        if (done_) return;
        if (error) {
            fail(diagnostic(StatusCode::FailedPrecondition, "the module refused the stream"));
            return;
        }
        auto channel = state_->channels->adopt(std::move(socket_));
        if (!channel.ok()) {
            fail(channel.status());
            return;
        }
        channel_ = std::move(channel).take_value();
        auto header = Buffer::copy_from(
            {reinterpret_cast<const std::byte*>(header_.data()), header_.size()}, header_.size());
        if (!header.ok()) {
            fail(header.status());
            return;
        }
        try {
            channel_->async_write(std::move(header).take_value(), cancellation_.token(),
                [self = shared_from_this()](Status status, std::size_t written) noexcept {
                    self->written(std::move(status), written);
                });
        } catch (...) {
            fail(Status(StatusCode::ResourceExhausted));
        }
    }

    void written(Status status, std::size_t written) noexcept {
        if (done_) return;
        if (!status.ok() || written != header_.size()) {
            fail(diagnostic(StatusCode::FailedPrecondition, "the module closed the stream"));
            return;
        }
        done_ = true;
        Error ignored;
        timer_.cancel(ignored);
        complete(completion_, Status::success());
        auto connection = engine::RouteConnection::byte_stream(std::move(channel_));
        if (!connection.ok()) {
            stream_->close(connection.status());
            return;
        }
        providers::bridge_established_route(std::move(stream_), std::move(connection).take_value());
    }

    void fail(Status status) noexcept {
        if (done_) return;
        done_ = true;
        Error ignored;
        timer_.cancel(ignored);
        socket_.close(ignored);
        cancellation_.cancel();
        if (channel_) {
            channel_->cancel();
            channel_->close();
        }
        const auto code = status.code();
        complete(completion_, std::move(status));
        if (stream_) stream_->close(Status(code));
    }

    std::shared_ptr<ModuleSupervisor::State> state_;
    std::shared_ptr<StreamResponder> stream_;
    engine::StreamHandler::AcceptanceCompletion completion_;
    std::string header_;
    providers::AsioUnixSocket socket_;
    Timer timer_;
    engine::CancellationSource cancellation_;
    std::unique_ptr<ByteChannel> channel_;
    bool done_{false};
};

class ModuleHandler final : public engine::StreamHandler {
public:
    ModuleHandler(std::weak_ptr<ModuleSupervisor::State> state, engine::ProviderDescriptor descriptor)
        : state_(std::move(state)), descriptor_(std::move(descriptor)) {}

    const engine::ProviderDescriptor& descriptor() const noexcept override { return descriptor_; }
    engine::ServiceKind service_kind() const noexcept override { return engine::ServiceKind::ByteStream; }

    Status authorize(const engine::StreamOpenContext& context) override {
        if (context.destination_if())
            return diagnostic(StatusCode::InvalidArgument, "a module stream names no destination");
        const auto state = state_.lock();
        if (!state || !state->running())
            return diagnostic(StatusCode::FailedPrecondition, "the module is not running");
        return Status::success();
    }

    void async_open(engine::StreamOpenContext context, std::shared_ptr<StreamResponder> stream,
                    AcceptanceCompletion completion) override {
        if (!stream) return;
        const auto state = state_.lock();
        const auto& identity = context.peer_evidence().identity();
        if (!state || !state->running() || !header_safe(identity)) {
            const auto code = !state || !state->running() ? StatusCode::FailedPrecondition
                                                          : StatusCode::PermissionDenied;
            complete(completion, Status(code));
            stream->close(Status(code));
            return;
        }
        try {
            std::string header(kModuleHeaderPrefix);
            header += identity;
            header += ' ';
            header += context.service_name();
            header += '\n';
            std::make_shared<ModuleOpen>(state, stream, std::move(completion),
                                         std::move(header))->start();
        } catch (const std::bad_alloc&) {
            complete(completion, Status(StatusCode::ResourceExhausted));
            stream->close(Status(StatusCode::ResourceExhausted));
        }
    }

    void on_open(engine::StreamOpenContext context, std::shared_ptr<StreamResponder> stream) override {
        async_open(std::move(context), std::move(stream), {});
    }

private:
    std::weak_ptr<ModuleSupervisor::State> state_;
    engine::ProviderDescriptor descriptor_;
};

}  // namespace

engine::Result<std::shared_ptr<ModuleSupervisor>> ModuleSupervisor::create(
    std::shared_ptr<providers::AsioExecutionContext> context,
    const config::v1::ModuleAdapter& adapter, ModuleSupervisorOptions options, ModuleReport report) {
    using Created = engine::Result<std::shared_ptr<ModuleSupervisor>>;
    const auto zero = std::chrono::milliseconds::zero();
    if (!context || options.launcher.empty() || options.restart_initial <= zero ||
        options.restart_max < options.restart_initial || options.stable_after <= zero ||
        options.stop_grace <= zero || options.connect_timeout <= zero ||
        options.max_streams == 0U || options.max_streams > 65'536U)
        return Created(Status(StatusCode::InvalidArgument));
    context->require_context();
    try {
        providers::AsioTcpChannelLimits limits;
        limits.max_active_channels = options.max_streams;
        auto channels = providers::AsioTcpAcceptedChannelOwner::create(context, limits);
        if (!channels.ok()) return Created(channels.status());
        auto descriptor = engine::ProviderDescriptor::create(
            "yume.module", engine::ProviderKind::StreamHandler, 1U,
            engine::mandatory_capabilities(engine::ProviderKind::StreamHandler));
        if (!descriptor.ok()) return Created(descriptor.status());
        auto state = std::make_shared<State>(std::move(context), adapter, std::move(options),
                                             std::move(report), std::move(channels).take_value());
        state->handler = std::make_shared<ModuleHandler>(state, std::move(descriptor).take_value());
        return Created(std::shared_ptr<ModuleSupervisor>(new ModuleSupervisor(std::move(state))));
    } catch (const std::bad_alloc&) {
        return Created(Status(StatusCode::ResourceExhausted));
    }
}

ModuleSupervisor::ModuleSupervisor(std::shared_ptr<State> state) noexcept : state_(std::move(state)) {}
ModuleSupervisor::~ModuleSupervisor() noexcept { close(); }
engine::Status ModuleSupervisor::start() { return state_->start(); }
std::shared_ptr<engine::StreamHandler> ModuleSupervisor::handler() const noexcept {
    return state_->handler;
}
pid_t ModuleSupervisor::pid() const noexcept {
    return state_->running() ? state_->child.pid() : -1;
}
const std::filesystem::path& ModuleSupervisor::socket_directory() const noexcept {
    return state_->directory;
}
void ModuleSupervisor::close() noexcept { state_->close(); }

}  // namespace yume::runtime
