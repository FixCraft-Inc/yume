#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

#include "core/crypto.hpp"
#include "core/obfs.hpp"
#include "server/config.hpp"

namespace yume::server {

class Session;

class Manager {
public:
    Manager(boost::asio::io_context& io, const ServerConfig& cfg);

    void start();
    void stop();
    void update_anonym_proof(const std::string& hash,
                             const std::string& sig,
                             const std::string& ts,
                             const std::string& nonce,
                             const std::string& certfp,
                             const std::string& ca_sig,
                             const std::string& ca_alg,
                             const std::string& sub_sig,
                             const std::string& sub_alg,
                             const std::string& sub_cert_b64,
                             const std::string& pq_pub_b64,
                             const std::string& pq_sig,
                             const std::string& pq_alg);
    void register_reverse_listener(int port, const std::shared_ptr<Session>& session);
    void unregister_reverse_listener(int port, Session* session);
    bool reclaim_reverse_listener(int port);

private:
    void do_accept();

    boost::asio::io_context& io_;
    ServerConfig cfg_;
    std::mutex cfg_mutex_;
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::ssl::context ssl_ctx_;
    std::shared_ptr<std::vector<crypto::Bytes>> authorized_keys_;

    std::atomic<uint64_t> next_session_id_{1};
    std::mutex reverse_mutex_;
    std::unordered_map<int, std::weak_ptr<Session>> reverse_port_sessions_;
};

}  // namespace yume::server
