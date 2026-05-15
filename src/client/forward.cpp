/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/forward.hpp"

#include "util.hpp"

#include <filesystem>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cctype>
#include <fstream>
#include <stdexcept>
#include <thread>
#include <chrono>
#if defined(_WIN32)
#ifndef WINVER
#define WINVER 0x0600
#endif
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <processthreadsapi.h>
#else
#include <unistd.h>
#endif
#if defined(__APPLE__)
#include <libproc.h>
#endif

namespace yume::client {

namespace {
std::string pid_path_for_port(const char* proto, int port) {
    std::filesystem::path base;
    try {
        base = std::filesystem::temp_directory_path();
    } catch (...) {
        base = ".";
    }
    std::string name = "yume-" + std::string(proto) + "-" + std::to_string(port) + ".pid";
    return (base / name).string();
}

#if defined(_WIN32)
using pid_type = DWORD;
#else
using pid_type = pid_t;
#endif

pid_type current_pid() {
#if defined(_WIN32)
    return GetCurrentProcessId();
#else
    return static_cast<pid_type>(::getpid());
#endif
}

bool read_pidfile(const std::string& path, pid_type& pid) {
    std::ifstream in(path);
    if (!in) {
        return false;
    }
    long long value = 0;
    in >> value;
    if (!in || value <= 0) {
        return false;
    }
    pid = static_cast<pid_type>(value);
    return true;
}

bool pid_running(pid_type pid) {
    if (pid <= 0) {
        return false;
    }
#if defined(_WIN32)
    HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!handle) {
        return GetLastError() == ERROR_ACCESS_DENIED;
    }
    DWORD code = 0;
    bool running = GetExitCodeProcess(handle, &code) && code == STILL_ACTIVE;
    CloseHandle(handle);
    return running;
#else
    if (::kill(pid, 0) == 0) {
        return true;
    }
    return errno == EPERM;
#endif
}

bool is_yume_process(pid_type pid) {
#if defined(_WIN32)
    HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!handle) {
        return false;
    }
    char path_buf[MAX_PATH];
    DWORD size = MAX_PATH;
    bool ok = QueryFullProcessImageNameA(handle, 0, path_buf, &size);
    CloseHandle(handle);
    if (!ok) {
        return false;
    }
    std::string path(path_buf, size);
    std::string name = std::filesystem::path(path).filename().string();
    for (auto& c : name) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return name == "yume.exe" || name == "fixcraft-yume.exe" || name == "yume";
#elif defined(__APPLE__)
    char path_buf[PROC_PIDPATHINFO_MAXSIZE];
    int len = proc_pidpath(pid, path_buf, sizeof(path_buf));
    if (len <= 0) {
        return false;
    }
    std::string name = std::filesystem::path(path_buf).filename().string();
    return name == "yume" || name == "fixcraft-yume";
#else
    std::ifstream comm("/proc/" + std::to_string(pid) + "/comm");
    if (!comm) {
        return false;
    }
    std::string name;
    std::getline(comm, name);
    return name == "yume" || name == "fixcraft-yume";
#endif
}

void remove_pidfile(const std::string& path) {
    if (!path.empty()) {
        std::remove(path.c_str());
    }
}

bool kill_process(pid_type pid) {
    if (pid <= 0) {
        return false;
    }
#if defined(_WIN32)
    HANDLE handle = OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!handle) {
        return false;
    }
    BOOL ok = TerminateProcess(handle, 1);
    CloseHandle(handle);
    return ok == TRUE;
#else
    if (::kill(pid, SIGTERM) != 0 && errno != ESRCH) {
        return false;
    }
    for (int i = 0; i < 10; ++i) {
        if (!pid_running(pid)) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    if (::kill(pid, SIGKILL) != 0 && errno != ESRCH) {
        return false;
    }
    return true;
#endif
}

bool reclaim_pidfile(const std::string& path) {
    pid_type pid = 0;
    if (!read_pidfile(path, pid)) {
        return false;
    }
    if (pid == current_pid()) {
        return false;
    }
    if (!pid_running(pid)) {
        remove_pidfile(path);
        return true;
    }
    if (!is_yume_process(pid)) {
        return false;
    }
    if (kill_process(pid)) {
        remove_pidfile(path);
        return true;
    }
    return false;
}

void write_pidfile(const std::string& path) {
    std::ofstream out(path, std::ios::trunc);
    if (out) {
        out << current_pid();
    }
}

bool is_private_ipv4(const boost::asio::ip::address_v4& addr) {
    const auto bytes = addr.to_bytes();
    const uint8_t a = bytes[0];
    const uint8_t b = bytes[1];
    if (a == 10) return true;
    if (a == 127) return true;
    if (a == 0) return true;
    if (a == 169 && b == 254) return true;
    if (a == 172 && (b >= 16 && b <= 31)) return true;
    if (a == 192 && b == 168) return true;
    return false;
}

bool is_private_ipv6(const boost::asio::ip::address_v6& addr) {
    if (addr.is_loopback() || addr.is_unspecified()) {
        return true;
    }
    const auto bytes = addr.to_bytes();
    if ((bytes[0] & 0xFE) == 0xFC) { // fc00::/7
        return true;
    }
    if (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80) { // fe80::/10
        return true;
    }
    if (addr.is_v4_mapped()) {
        boost::asio::ip::address_v4::bytes_type v4bytes{
            {bytes[12], bytes[13], bytes[14], bytes[15]}
        };
        return is_private_ipv4(boost::asio::ip::address_v4(v4bytes));
    }
    return false;
}

bool is_private_address(const boost::asio::ip::address& addr) {
    if (addr.is_v4()) return is_private_ipv4(addr.to_v4());
    if (addr.is_v6()) return is_private_ipv6(addr.to_v6());
    return false;
}

bool is_blocked_literal(const std::string& host) {
    if (host == "localhost" || host == "localhost.localdomain") {
        return true;
    }
    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(host, ec);
    if (!ec) {
        return is_private_address(addr);
    }
    return false;
}

std::string udp_endpoint_key(const boost::asio::ip::udp::endpoint& ep) {
    return ep.address().to_string() + ":" + std::to_string(ep.port());
}
}  // namespace

ForwardSession::ForwardSession(boost::asio::ip::tcp::socket socket,
                               std::shared_ptr<Tunnel> tunnel,
                               std::string target_host,
                               int target_port)
    : socket_(std::move(socket))
    , tunnel_(std::move(tunnel))
    , strand_(socket_.get_executor())
    , target_host_(std::move(target_host))
    , target_port_(target_port) {}

void ForwardSession::start() {
    start_tunnel();
}

void ForwardSession::start_tunnel() {
    stream_id_ = tunnel_->reserve_stream_id();
    if (stream_id_ == 0) {
        util::log_warn("forward: no stream ids available");
        close();
        return;
    }

    tunnel_->register_stream(
        stream_id_,
        [self = shared_from_this()](const Tunnel::Bytes& data) { self->deliver_from_tunnel(data); },
        [self = shared_from_this()](const std::string&) { self->close_from_tunnel(); });

    tunnel_->open_stream(stream_id_, target_host_, target_port_,
                         [self = shared_from_this()](bool ok, const std::string& reason) {
                             if (!ok) {
                                 util::log_warn("forward open failed: " + reason);
                                 self->close();
                                 return;
                             }
                             self->open_confirmed_ = true;
                             self->start_client_read();
                         });
}

void ForwardSession::start_client_read() {
    auto self = shared_from_this();
    socket_.async_read_some(boost::asio::buffer(read_buf_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec, std::size_t bytes) {
                                                           self->on_client_read(ec, bytes);
                                                       }));
}

void ForwardSession::on_client_read(const boost::system::error_code& ec, std::size_t bytes) {
    if (ec) {
        close();
        return;
    }

    Tunnel::Bytes payload(read_buf_.data(), read_buf_.data() + bytes);
    tunnel_->send_data(stream_id_, payload);
    start_client_read();
}

void ForwardSession::deliver_from_tunnel(const Tunnel::Bytes& data) {
    auto self = shared_from_this();
    boost::asio::post(strand_, [self, data]() {
        auto buf = std::make_shared<std::vector<uint8_t>>(data.begin(), data.end());
        self->enqueue_write(buf);
    });
}

void ForwardSession::close_from_tunnel() {
    auto self = shared_from_this();
    boost::asio::post(strand_, [self]() { self->close(); });
}

void ForwardSession::enqueue_write(std::shared_ptr<std::vector<uint8_t>> data) {
    boost::asio::post(strand_, [self = shared_from_this(), data = std::move(data)]() mutable {
        self->write_queue_.push_back(std::move(data));
        if (!self->write_in_flight_) {
            self->do_write();
        }
    });
}

void ForwardSession::do_write() {
    if (write_queue_.empty()) {
        write_in_flight_ = false;
        return;
    }
    write_in_flight_ = true;

    auto data = std::move(write_queue_.front());
    write_queue_.pop_front();

    auto self = shared_from_this();
    boost::asio::async_write(socket_, boost::asio::buffer(*data),
                             boost::asio::bind_executor(strand_,
                                                        [self, data](const boost::system::error_code& ec, std::size_t) {
                                                            if (ec) {
                                                                self->close();
                                                                return;
                                                            }
                                                            self->do_write();
                                                        }));
}

void ForwardSession::close() {
    if (stream_id_ != 0) {
        tunnel_->send_close(stream_id_, "client closed");
        tunnel_->unregister_stream(stream_id_);
        stream_id_ = 0;
    }

    boost::system::error_code ec;
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    socket_.close(ec);
}

ForwardServer::ForwardServer(boost::asio::io_context& io,
                             int listen_port,
                             std::string target_host,
                             int target_port,
                             std::shared_ptr<Tunnel> tunnel,
                             bool allow_local_ip)
    : acceptor_(io)
    , listen_port_(listen_port)
    , pid_path_(pid_path_for_port("tcp", listen_port))
    , target_host_(std::move(target_host))
    , target_port_(target_port)
    , tunnel_(std::move(tunnel))
    , allow_local_ip_(allow_local_ip) {
    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), listen_port);
    boost::system::error_code ec;
    reclaim_pidfile(pid_path_);
    acceptor_.open(ep.protocol(), ec);
    if (ec) {
        util::log_error("forward listen open failed: " + ec.message());
        throw std::runtime_error("forward listen open failed: " + ec.message());
    }
    acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true), ec);
    acceptor_.bind(ep, ec);
    if (ec == boost::asio::error::address_in_use) {
        if (reclaim_pidfile(pid_path_)) {
            ec.clear();
            acceptor_.bind(ep, ec);
        }
    }
    if (ec) {
        util::log_error("forward listen bind failed: " + ec.message());
        throw std::runtime_error("forward listen bind failed: " + ec.message());
    }
    acceptor_.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) {
        util::log_error("forward listen failed: " + ec.message());
        throw std::runtime_error("forward listen failed: " + ec.message());
    }
    write_pidfile(pid_path_);
}

ForwardServer::~ForwardServer() {
    remove_pidfile(pid_path_);
}

void ForwardServer::start() {
    do_accept();
}

bool ForwardServer::is_local_target() const {
    if (allow_local_ip_) {
        return false;
    }
    return is_blocked_literal(target_host_);
}

void ForwardServer::do_accept() {
    acceptor_.async_accept([this](const boost::system::error_code& ec, boost::asio::ip::tcp::socket socket) {
        if (!ec) {
            if (is_local_target()) {
                auto session = std::make_shared<LocalForwardSession>(std::move(socket), target_host_, target_port_);
                session->start();
            } else {
                auto session = std::make_shared<ForwardSession>(std::move(socket), tunnel_, target_host_, target_port_);
                session->start();
            }
        } else {
            util::log_warn(std::string("forward accept failed: ") + ec.message());
        }
        do_accept();
    });
}

UdpForwardServer::UdpForwardServer(boost::asio::io_context& io,
                                   int listen_port,
                                   std::string target_host,
                                   int target_port,
                                   std::shared_ptr<Tunnel> tunnel,
                                   bool allow_local_ip)
    : socket_(io)
    , strand_(io.get_executor())
    , tunnel_(std::move(tunnel))
    , listen_port_(listen_port)
    , pid_path_(pid_path_for_port("udp", listen_port))
    , target_host_(std::move(target_host))
    , target_port_(target_port)
    , allow_local_ip_(allow_local_ip) {
    boost::asio::ip::udp::endpoint ep(boost::asio::ip::udp::v4(), listen_port);
    boost::system::error_code ec;
    reclaim_pidfile(pid_path_);
    socket_.open(ep.protocol(), ec);
    if (ec) {
        util::log_error("udp forward open failed: " + ec.message());
        throw std::runtime_error("udp forward open failed: " + ec.message());
    }
    socket_.bind(ep, ec);
    if (ec == boost::asio::error::address_in_use) {
        if (reclaim_pidfile(pid_path_)) {
            ec.clear();
            socket_.bind(ep, ec);
        }
    }
    if (ec) {
        util::log_error("udp forward bind failed: " + ec.message());
        throw std::runtime_error("udp forward bind failed: " + ec.message());
    }
    write_pidfile(pid_path_);
}

UdpForwardServer::~UdpForwardServer() {
    remove_pidfile(pid_path_);
}

void UdpForwardServer::start() {
    do_receive();
}

void UdpForwardServer::do_receive() {
    auto self = shared_from_this();
    socket_.async_receive_from(boost::asio::buffer(read_buf_), sender_,
                               boost::asio::bind_executor(strand_,
                                                          [self](const boost::system::error_code& ec, std::size_t bytes) {
                                                              if (!ec && bytes > 0) {
                                                                  Tunnel::Bytes data(self->read_buf_.data(),
                                                                                     self->read_buf_.data() + bytes);
                                                                  self->handle_datagram(self->sender_, data);
                                                              }
                                                              self->do_receive();
                                                          }));
}

void UdpForwardServer::handle_datagram(const boost::asio::ip::udp::endpoint& client, const Tunnel::Bytes& data) {
    if (!allow_local_ip_ && is_blocked_literal(target_host_)) {
        if (!blocked_local_warned_) {
            util::log_warn("udp forward blocked: local target requires --allow-local-ip");
            blocked_local_warned_ = true;
        }
        return;
    }
    const std::string key = udp_endpoint_key(client);
    auto it = by_client_.find(key);
    if (it == by_client_.end()) {
        uint8_t stream_id = tunnel_->reserve_stream_id();
        if (stream_id == 0) {
            util::log_warn("udp forward: no stream ids available");
            return;
        }
        auto mapping = std::make_shared<UdpMapping>();
        mapping->client = client;
        mapping->stream_id = stream_id;
        by_client_[key] = mapping;
        by_stream_[stream_id] = mapping;

        tunnel_->register_stream(
            stream_id,
            [self = shared_from_this(), stream_id](const Tunnel::Bytes& payload) { self->deliver_from_tunnel(stream_id, payload); },
            [self = shared_from_this(), stream_id](const std::string& reason) {
                self->close_stream(stream_id, reason.empty() ? "remote closed" : reason);
            });
        tunnel_->open_stream(stream_id, target_host_, target_port_,
                             [self = shared_from_this(), stream_id](bool ok, const std::string& reason) {
                                 self->on_open_result(stream_id, ok, reason);
                             },
                             "udp");
        it = by_client_.find(key);
    }

    auto mapping = it->second;
    if (mapping->open_confirmed) {
        tunnel_->send_data(mapping->stream_id, data);
    } else {
        mapping->pending.push_back(data);
    }
}

void UdpForwardServer::on_open_result(uint8_t stream_id, bool ok, const std::string& reason) {
    auto it = by_stream_.find(stream_id);
    if (it == by_stream_.end()) {
        return;
    }
    auto mapping = it->second;
    if (!ok) {
        util::log_warn("udp forward open failed: " + reason);
        close_stream(stream_id, "open failed");
        return;
    }
    mapping->open_confirmed = true;
    while (!mapping->pending.empty()) {
        tunnel_->send_data(stream_id, mapping->pending.front());
        mapping->pending.pop_front();
    }
}

void UdpForwardServer::deliver_from_tunnel(uint8_t stream_id, const Tunnel::Bytes& data) {
    auto it = by_stream_.find(stream_id);
    if (it == by_stream_.end()) {
        return;
    }
    auto mapping = it->second;
    auto buffer = std::make_shared<std::vector<uint8_t>>(data.begin(), data.end());
    auto self = shared_from_this();
    socket_.async_send_to(boost::asio::buffer(*buffer), mapping->client,
                          boost::asio::bind_executor(strand_,
                                                     [self, buffer](const boost::system::error_code&, std::size_t) {}));
}

void UdpForwardServer::close_stream(uint8_t stream_id, const std::string&) {
    auto it = by_stream_.find(stream_id);
    if (it == by_stream_.end()) {
        return;
    }
    auto mapping = it->second;
    by_stream_.erase(it);
    by_client_.erase(udp_endpoint_key(mapping->client));
    tunnel_->unregister_stream(stream_id);
}

LocalForwardSession::LocalForwardSession(boost::asio::ip::tcp::socket socket,
                                         std::string target_host,
                                         int target_port)
    : socket_(std::move(socket))
    , remote_(socket_.get_executor())
    , resolver_(socket_.get_executor())
    , strand_(socket_.get_executor())
    , target_host_(std::move(target_host))
    , target_port_(target_port) {}

void LocalForwardSession::start() {
    start_connect();
}

void LocalForwardSession::start_connect() {
    auto self = shared_from_this();
    resolver_.async_resolve(boost::asio::ip::tcp::v4(), target_host_, std::to_string(target_port_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec,
                                                              const boost::asio::ip::tcp::resolver::results_type& results) {
                                                           if (ec) {
                                                               util::log_warn("local forward resolve failed: " + ec.message());
                                                               self->close();
                                                               return;
                                                           }
                                                           boost::asio::async_connect(self->remote_, results,
                                                                                      boost::asio::bind_executor(self->strand_,
                                                                                                                 [self](const boost::system::error_code& ec2,
                                                                                                                        const boost::asio::ip::tcp::endpoint&) {
                                                                                                                     if (ec2) {
                                                                                                                         util::log_warn("local forward connect failed: " + ec2.message());
                                                                                                                         self->close();
                                                                                                                         return;
                                                                                                                     }
                                                                                                                     self->start_client_read();
                                                                                                                     self->start_remote_read();
                                                                                                                 }));
                                                       }));
}

void LocalForwardSession::start_client_read() {
    auto self = shared_from_this();
    socket_.async_read_some(boost::asio::buffer(client_buf_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec, std::size_t bytes) {
                                                           self->on_client_read(ec, bytes);
                                                       }));
}

void LocalForwardSession::start_remote_read() {
    auto self = shared_from_this();
    remote_.async_read_some(boost::asio::buffer(remote_buf_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec, std::size_t bytes) {
                                                           self->on_remote_read(ec, bytes);
                                                       }));
}

void LocalForwardSession::on_client_read(const boost::system::error_code& ec, std::size_t bytes) {
    if (ec) {
        close();
        return;
    }
    auto self = shared_from_this();
    boost::asio::async_write(remote_, boost::asio::buffer(client_buf_.data(), bytes),
                             boost::asio::bind_executor(strand_,
                                                        [self](const boost::system::error_code& ec2, std::size_t) {
                                                            if (ec2) {
                                                                self->close();
                                                                return;
                                                            }
                                                            self->start_client_read();
                                                        }));
}

void LocalForwardSession::on_remote_read(const boost::system::error_code& ec, std::size_t bytes) {
    if (ec) {
        close();
        return;
    }
    auto self = shared_from_this();
    boost::asio::async_write(socket_, boost::asio::buffer(remote_buf_.data(), bytes),
                             boost::asio::bind_executor(strand_,
                                                        [self](const boost::system::error_code& ec2, std::size_t) {
                                                            if (ec2) {
                                                                self->close();
                                                                return;
                                                            }
                                                            self->start_remote_read();
                                                        }));
}

void LocalForwardSession::close() {
    boost::system::error_code ec;
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    socket_.close(ec);
    remote_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    remote_.close(ec);
}

ReverseForwardSession::ReverseForwardSession(std::shared_ptr<Tunnel> tunnel,
                                             uint8_t stream_id,
                                             std::string target_host,
                                             int target_port)
    : tunnel_(std::move(tunnel))
    , stream_id_(stream_id)
    , local_(tunnel_->get_executor())
    , resolver_(tunnel_->get_executor())
    , strand_(tunnel_->get_executor())
    , target_host_(std::move(target_host))
    , target_port_(target_port) {}

void ReverseForwardSession::start() {
    tunnel_->register_stream(
        stream_id_,
        [self = shared_from_this()](const Tunnel::Bytes& data) { self->deliver_from_tunnel(data); },
        [self = shared_from_this()](const std::string&) { self->close_from_tunnel(); });
    start_connect();
}

void ReverseForwardSession::start_connect() {
    auto self = shared_from_this();
    resolver_.async_resolve(boost::asio::ip::tcp::v4(), target_host_, std::to_string(target_port_),
                            boost::asio::bind_executor(strand_,
                                                       [self](const boost::system::error_code& ec,
                                                              const boost::asio::ip::tcp::resolver::results_type& results) {
                                                           if (ec) {
                                                               self->tunnel_->send_open_ack(self->stream_id_, false, "local resolve failed");
                                                               self->close();
                                                               return;
                                                           }
                                                           boost::asio::async_connect(self->local_, results,
                                                                                      boost::asio::bind_executor(self->strand_,
                                                                                                                 [self](const boost::system::error_code& ec2,
                                                                                                                        const boost::asio::ip::tcp::endpoint&) {
                                                                                                                     if (ec2) {
                                                                                                                         self->tunnel_->send_open_ack(self->stream_id_, false, "local connect failed");
                                                                                                                         self->close();
                                                                                                                         return;
                                                                                                                     }
                                                                                                                     self->open_confirmed_ = true;
                                                                                                                     self->tunnel_->send_open_ack(self->stream_id_, true, "");
                                                                                                                     self->start_local_read();
                                                                                                                 }));
                                                       }));
}

void ReverseForwardSession::start_local_read() {
    auto self = shared_from_this();
    local_.async_read_some(boost::asio::buffer(read_buf_),
                           boost::asio::bind_executor(strand_,
                                                      [self](const boost::system::error_code& ec, std::size_t bytes) {
                                                          self->on_local_read(ec, bytes);
                                                      }));
}

void ReverseForwardSession::on_local_read(const boost::system::error_code& ec, std::size_t bytes) {
    if (ec) {
        close();
        return;
    }
    Tunnel::Bytes payload(read_buf_.data(), read_buf_.data() + bytes);
    tunnel_->send_data(stream_id_, payload);
    start_local_read();
}

void ReverseForwardSession::deliver_from_tunnel(const Tunnel::Bytes& data) {
    auto self = shared_from_this();
    boost::asio::post(strand_, [self, data]() {
        if (!self->open_confirmed_) {
            return;
        }
        boost::asio::async_write(self->local_, boost::asio::buffer(data),
                                 boost::asio::bind_executor(self->strand_,
                                                            [self](const boost::system::error_code& ec, std::size_t) {
                                                                if (ec) {
                                                                    self->close();
                                                                }
                                                            }));
    });
}

void ReverseForwardSession::close_from_tunnel() {
    auto self = shared_from_this();
    boost::asio::post(strand_, [self]() { self->close(); });
}

void ReverseForwardSession::close() {
    if (stream_id_ != 0) {
        tunnel_->send_close(stream_id_, "reverse closed");
        tunnel_->unregister_stream(stream_id_);
        stream_id_ = 0;
    }
    boost::system::error_code ec;
    local_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    local_.close(ec);
}

}  // namespace yume::client
