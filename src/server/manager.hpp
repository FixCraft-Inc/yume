#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "core/crypto.hpp"
#include "core/obfs.hpp"
#include "server/config.hpp"

namespace yume::server {

class Manager {
public:
    Manager(boost::asio::io_context& io, const ServerConfig& cfg);

    void start();
    void stop();

private:
    void do_accept();

    boost::asio::io_context& io_;
    ServerConfig cfg_;
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ssl::context ssl_ctx_;
    std::shared_ptr<std::vector<crypto::Bytes>> authorized_keys_;

    std::atomic<uint64_t> next_session_id_{1};
};

}  // namespace yume::server
