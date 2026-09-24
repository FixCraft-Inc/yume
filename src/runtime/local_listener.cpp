/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/local_listener.hpp"

#include <cerrno>
#include <chrono>
#include <new>
#include <string>
#include <type_traits>
#include <utility>

#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <boost/asio/basic_socket_acceptor.hpp>
#include <boost/asio/basic_waitable_timer.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/local/stream_protocol.hpp>

namespace yume::runtime {
namespace {
using engine::Status;
using engine::StatusCode;
using Clock = std::chrono::steady_clock;
using Executor = providers::AsioExecutionContext::Executor;
using Timer = boost::asio::basic_waitable_timer<Clock, boost::asio::wait_traits<Clock>, Executor>;
using Error = boost::system::error_code;
using Unix = boost::asio::local::stream_protocol;

constexpr std::chrono::seconds kAcceptRetryDelay{1};

Status diagnostic(StatusCode code, std::string_view name, std::string_view detail) noexcept {
    try {
        std::string message(name);
        message += detail;
        return Status(code, message);
    } catch (...) {
        return Status(code);
    }
}

StatusCode bind_failure(const Error& error) noexcept {
    if (error == boost::asio::error::address_in_use) return StatusCode::AddressInUse;
    if (error == boost::asio::error::access_denied) return StatusCode::PermissionDenied;
    return StatusCode::Internal;
}

// Whether the connected peer runs as this process's user.
bool same_user(int descriptor) noexcept {
#ifdef SO_PEERCRED
    ucred credentials{};
    socklen_t length = sizeof(credentials);
    return ::getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &credentials, &length) == 0 &&
           length == sizeof(credentials) && credentials.uid == ::geteuid();
#else
    uid_t user = 0;
    gid_t group = 0;
    return ::getpeereid(descriptor, &user, &group) == 0 && user == ::geteuid();
#endif
}

// The socket file this listener created, identified so close never removes a
// file that replaced it.
struct SocketFile final {
    std::filesystem::path path;
    dev_t device{};
    ino_t inode{};
};

}  // namespace

class LocalListener::Loop {
public:
    virtual ~Loop() = default;
    virtual void start(Accepted accepted, Full full, Failed on_failure) noexcept = 0;
    virtual void resume() noexcept = 0;
    virtual boost::asio::ip::tcp::endpoint tcp_endpoint() const noexcept = 0;
    virtual void close() noexcept = 0;
};

namespace {

template <typename Protocol>
class AcceptLoop final : public LocalListener::Loop,
                         public std::enable_shared_from_this<AcceptLoop<Protocol>> {
public:
    using Socket = boost::asio::basic_stream_socket<Protocol, Executor>;
    using Acceptor = boost::asio::basic_socket_acceptor<Protocol, Executor>;

    AcceptLoop(std::shared_ptr<providers::AsioExecutionContext> context,
               std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> channels,
               Acceptor acceptor, std::optional<SocketFile> file) noexcept
        : context_(std::move(context)),
          channels_(std::move(channels)),
          acceptor_(std::move(acceptor)),
          retry_(context_->executor()),
          file_(std::move(file)) {}

    ~AcceptLoop() noexcept override { close(); }

    void start(LocalListener::Accepted accepted, LocalListener::Full full,
               LocalListener::Failed on_failure) noexcept override {
        accepted_ = std::move(accepted);
        full_ = std::move(full);
        failed_ = std::move(on_failure);
        start_accept();
    }

    void resume() noexcept override { start_accept(); }

    boost::asio::ip::tcp::endpoint tcp_endpoint() const noexcept override {
        if constexpr (std::is_same_v<Protocol, boost::asio::ip::tcp>) {
            Error ignored;
            return acceptor_.local_endpoint(ignored);
        } else {
            return {};
        }
    }

    void close() noexcept override {
        if (closing_) return;
        closing_ = true;
        Error ignored;
        acceptor_.close(ignored);
        retry_.cancel(ignored);
        remove_socket_file();
        accepted_ = {};
        full_ = {};
        failed_ = {};
    }

private:
    bool full() const noexcept {
        try {
            return full_ && full_();
        } catch (...) {
            return true;
        }
    }

    void start_accept() noexcept {
        if (closing_ || accepting_ || retry_pending_ || full()) return;
        try {
            accepting_ = true;
            acceptor_.async_accept(context_->executor(),
                [self = this->shared_from_this()](const Error& error, Socket socket) noexcept {
                    self->accepting_ = false;
                    if (self->closing_) {
                        Error ignored;
                        socket.close(ignored);
                        return;
                    }
                    if (error) {
                        // A local listener survives transient failures such
                        // as descriptor exhaustion and tries again after a pause.
                        self->retry_accept();
                        return;
                    }
                    self->deliver(std::move(socket));
                    self->start_accept();
                });
        } catch (...) {
            accepting_ = false;
            retry_accept();
        }
    }

    void retry_accept() noexcept {
        if (closing_ || retry_pending_) return;
        try {
            retry_pending_ = true;
            retry_.expires_after(kAcceptRetryDelay);
            retry_.async_wait([self = this->shared_from_this()](const Error& error) noexcept {
                self->retry_pending_ = false;
                if (self->closing_) return;
                if (error) {
                    self->fail(Status(StatusCode::Internal));
                    return;
                }
                self->start_accept();
            });
        } catch (const std::bad_alloc&) {
            // Without a retry nothing would ever accept again, so stop visibly.
            retry_pending_ = false;
            fail(Status(StatusCode::ResourceExhausted));
        } catch (...) {
            retry_pending_ = false;
            fail(Status(StatusCode::Internal));
        }
    }

    // A socket that fails a check closes when it leaves scope.
    void deliver(Socket socket) noexcept {
        try {
            LocalListener::Connection connection;
            if constexpr (std::is_same_v<Protocol, boost::asio::ip::tcp>) {
                Error error;
                const auto peer = socket.remote_endpoint(error);
                if (error) return;
                connection.peer_address = peer.address();
            } else {
                if (!same_user(socket.native_handle())) return;
            }
            auto channel = channels_->adopt(std::move(socket));
            if (!channel.ok()) return;
            connection.channel = std::move(channel).take_value();
            if (accepted_) accepted_(std::move(connection));
        } catch (...) {
        }
    }

    void fail(Status status) noexcept {
        if (closing_) return;
        auto failed = std::move(failed_);
        close();
        if (failed) {
            try { failed(std::move(status)); } catch (...) {}
        }
    }

    void remove_socket_file() noexcept {
        if (!file_) return;
        struct stat info{};
        if (::lstat(file_->path.c_str(), &info) == 0 && S_ISSOCK(info.st_mode) &&
            info.st_dev == file_->device && info.st_ino == file_->inode) {
            (void)::unlink(file_->path.c_str());
        }
        file_.reset();
    }

    const std::shared_ptr<providers::AsioExecutionContext> context_;
    const std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> channels_;
    Acceptor acceptor_;
    Timer retry_;
    std::optional<SocketFile> file_;
    LocalListener::Accepted accepted_;
    LocalListener::Full full_;
    LocalListener::Failed failed_;
    bool accepting_{false};
    bool retry_pending_{false};
    bool closing_{false};
};

using TcpLoop = AcceptLoop<boost::asio::ip::tcp>;
using UnixLoop = AcceptLoop<Unix>;

engine::Result<std::shared_ptr<LocalListener::Loop>> open_loopback(
    const std::shared_ptr<providers::AsioExecutionContext>& context,
    const LocalListener::Loopback& address,
    std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> channels, std::string_view name) {
    using Opened = engine::Result<std::shared_ptr<LocalListener::Loop>>;
    if (!address.address.is_loopback())
        return Opened(diagnostic(StatusCode::InvalidArgument, name, " must be loopback"));
    TcpLoop::Acceptor acceptor(context->executor());
    const boost::asio::ip::tcp::endpoint listen{address.address, address.port};
    Error error;
    acceptor.open(listen.protocol(), error);
    if (!error && address.address.is_v6()) acceptor.set_option(boost::asio::ip::v6_only(true), error);
    if (!error) acceptor.set_option(boost::asio::socket_base::reuse_address(true), error);
    if (!error) acceptor.bind(listen, error);
    if (!error) acceptor.listen(boost::asio::socket_base::max_listen_connections, error);
    if (error) return Opened(diagnostic(bind_failure(error), name, " could not open"));
    return Opened(std::shared_ptr<LocalListener::Loop>(std::make_shared<TcpLoop>(
        context, std::move(channels), std::move(acceptor), std::nullopt)));
}

engine::Result<std::shared_ptr<LocalListener::Loop>> open_unix(
    const std::shared_ptr<providers::AsioExecutionContext>& context,
    const LocalListener::Unix& address,
    std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> channels, std::string_view name) {
    using Opened = engine::Result<std::shared_ptr<LocalListener::Loop>>;
    const auto& path = address.path;
    if (!path.is_absolute() || !path.has_filename())
        return Opened(diagnostic(StatusCode::InvalidArgument, name, " path must be absolute"));
    // The directory decides who can replace the socket file or plant a link
    // in its place, so it must belong to this user alone.
    struct stat directory{};
    if (::lstat(path.parent_path().c_str(), &directory) != 0 || !S_ISDIR(directory.st_mode) ||
        directory.st_uid != ::geteuid() || (directory.st_mode & (S_IWGRP | S_IWOTH)) != 0U)
        return Opened(diagnostic(StatusCode::FailedPrecondition, name,
            " directory must belong to this user and be closed to others' writes"));
    const Unix::endpoint endpoint(path.string());
    struct stat existing{};
    if (::lstat(path.c_str(), &existing) == 0) {
        if (!S_ISSOCK(existing.st_mode) || existing.st_uid != ::geteuid())
            return Opened(diagnostic(StatusCode::AlreadyExists, name, " path holds another file"));
        // A live listener answers or is busy. Only a refused connect marks a
        // file left behind by an earlier run.
        UnixLoop::Socket probe(context->executor());
        Error error;
        probe.open(Unix(), error);
        if (!error) probe.non_blocking(true, error);
        if (!error) probe.connect(endpoint, error);
        const bool gone = error == boost::system::errc::no_such_file_or_directory;
        if (error != boost::asio::error::connection_refused && !gone)
            return Opened(diagnostic(StatusCode::AddressInUse, name, " path is in use"));
        if (!gone && ::unlink(path.c_str()) != 0 && errno != ENOENT)
            return Opened(diagnostic(StatusCode::Internal, name, " could not replace its old socket"));
    } else if (errno != ENOENT) {
        return Opened(diagnostic(StatusCode::Internal, name, " path could not be checked"));
    }
    UnixLoop::Acceptor acceptor(context->executor());
    Error error;
    acceptor.open(Unix(), error);
    if (!error) acceptor.bind(endpoint, error);
    if (error) return Opened(diagnostic(bind_failure(error), name, " could not open"));
    struct stat created{};
    SocketFile file{path, {}, {}};
    if (::chmod(path.c_str(), S_IRUSR | S_IWUSR) != 0 || ::lstat(path.c_str(), &created) != 0 ||
        !S_ISSOCK(created.st_mode)) {
        acceptor.close(error);
        (void)::unlink(path.c_str());
        return Opened(diagnostic(StatusCode::Internal, name, " could not restrict its socket"));
    }
    file.device = created.st_dev;
    file.inode = created.st_ino;
    acceptor.listen(boost::asio::socket_base::max_listen_connections, error);
    if (error) {
        acceptor.close(error);
        (void)::unlink(path.c_str());
        return Opened(diagnostic(StatusCode::Internal, name, " could not open"));
    }
    return Opened(std::shared_ptr<LocalListener::Loop>(std::make_shared<UnixLoop>(
        context, std::move(channels), std::move(acceptor), std::move(file))));
}

}  // namespace

engine::Result<std::shared_ptr<LocalListener>> LocalListener::open(
    std::shared_ptr<providers::AsioExecutionContext> context, const Address& address,
    std::shared_ptr<providers::AsioTcpAcceptedChannelOwner> channels, std::string_view name) {
    using Opened = engine::Result<std::shared_ptr<LocalListener>>;
    if (!context || !channels) return Opened(Status(StatusCode::InvalidArgument));
    context->require_context();
    try {
        auto loop = std::holds_alternative<Loopback>(address)
            ? open_loopback(context, std::get<Loopback>(address), std::move(channels), name)
            : open_unix(context, std::get<Unix>(address), std::move(channels), name);
        if (!loop.ok()) return Opened(loop.status());
        return Opened(std::shared_ptr<LocalListener>(new LocalListener(std::move(loop).take_value())));
    } catch (const std::bad_alloc&) {
        return Opened(Status(StatusCode::ResourceExhausted));
    } catch (...) {
        return Opened(Status(StatusCode::Internal));
    }
}

LocalListener::LocalListener(std::shared_ptr<Loop> loop) noexcept : loop_(std::move(loop)) {}
LocalListener::~LocalListener() noexcept { close(); }
void LocalListener::start(Accepted accepted, Full full, Failed on_failure) noexcept {
    loop_->start(std::move(accepted), std::move(full), std::move(on_failure));
}
void LocalListener::resume() noexcept { loop_->resume(); }
boost::asio::ip::tcp::endpoint LocalListener::tcp_endpoint() const noexcept {
    return loop_->tcp_endpoint();
}
void LocalListener::close() noexcept { loop_->close(); }

}  // namespace yume::runtime
