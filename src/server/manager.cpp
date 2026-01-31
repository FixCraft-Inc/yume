/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "server/manager.hpp"

#include "server/auth.hpp"
#include "server/session.hpp"
#include "util.hpp"

#include <iostream>
#include <stdexcept>

namespace yume::server {

Manager::Manager(boost::asio::io_context& io, const ServerConfig& cfg)
    : io_(io)
    , cfg_(cfg)
    , acceptor_(io)
    , ssl_ctx_(obfs::create_server_context(cfg.tls_cert, cfg.tls_key, !cfg.real_http))
    , authorized_keys_(std::make_shared<std::vector<crypto::Bytes>>()) {}

void Manager::start() {
    if (cfg_.auth_keys.empty()) {
        throw std::runtime_error("auth_keys must be set");
    }

    try {
        *authorized_keys_ = load_authorized_keys(cfg_.auth_keys);
    } catch (const std::exception& ex) {
        throw std::runtime_error(std::string("authorized_keys load failed: ") + ex.what());
    }

    if (authorized_keys_->empty()) {
        util::log_warn("authorized_keys is empty");
    }

    boost::asio::ip::tcp::endpoint ep(boost::asio::ip::tcp::v4(), cfg_.listen_port);
    acceptor_.open(ep.protocol());
    acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    acceptor_.bind(ep);
    acceptor_.listen();

    if (util::is_logging_enabled()) {
        util::log_info("yumed listening on port " + std::to_string(cfg_.listen_port));
    } else {
        std::cerr << "\033[1;33myumed listening on port " << cfg_.listen_port << "\033[0m\n";
    }
    do_accept();
}

void Manager::stop() {
    boost::system::error_code ec;
    acceptor_.close(ec);
}

void Manager::update_anonym_proof(const std::string& hash,
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
                                  const std::string& pq_alg) {
    std::lock_guard<std::mutex> lock(cfg_mutex_);
    cfg_.anonym_hash = hash;
    cfg_.anonym_sig = sig;
    cfg_.anonym_ts = ts;
    cfg_.anonym_nonce = nonce;
    cfg_.anonym_certfp = certfp;
    cfg_.anonym_ca_sig = ca_sig;
    cfg_.anonym_ca_alg = ca_alg;
    cfg_.anonym_sub_sig = sub_sig;
    cfg_.anonym_sub_alg = sub_alg;
    cfg_.anonym_sub_cert_b64 = sub_cert_b64;
    cfg_.pq_pub_b64 = pq_pub_b64;
    cfg_.pq_sig = pq_sig;
    cfg_.pq_alg = pq_alg;
}

void Manager::do_accept() {
    acceptor_.async_accept([this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
        if (!ec) {
            uint64_t session_id = next_session_id_.fetch_add(1);
            ServerConfig cfg_copy;
            {
                std::lock_guard<std::mutex> lock(cfg_mutex_);
                cfg_copy = cfg_;
            }
            auto session = std::make_shared<Session>(std::move(socket), ssl_ctx_, cfg_copy, authorized_keys_, session_id);
            session->start();
        } else {
            util::log_warn(std::string("accept failed: ") + ec.message());
        }
        do_accept();
    });
}

}  // namespace yume::server
