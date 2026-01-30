/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/cli.hpp"

#include <iostream>
#include <optional>
#include <stdexcept>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/pem.h>

#include "client/forward.hpp"
#include "client/socks.hpp"
#include "client/tunnel.hpp"
#include "core/crypto.hpp"
#include "core/inner_crypto.hpp"
#include "core/obfs.hpp"
#include "core/protocol.hpp"
#include "util.hpp"

namespace yume::client {

namespace {
struct ParsedArgs {
    std::string config_path{"config/yume.json"};
    std::string server;
    int port{0};
    std::string identity;
    int socks_port{0};
    int lport{0};
    std::string rhost;
    int rport{0};
    std::string run_cmd;
};

ParsedArgs parse_args(int argc, char** argv) {
    ParsedArgs args;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--config" && i + 1 < argc) {
            args.config_path = argv[++i];
        } else if (arg == "--server" && i + 1 < argc) {
            args.server = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            args.port = std::stoi(argv[++i]);
        } else if (arg == "--auth" && i + 1 < argc) {
            args.identity = argv[++i];
        } else if (arg == "--socks" && i + 1 < argc) {
            args.socks_port = std::stoi(argv[++i]);
        } else if (arg == "--lport" && i + 1 < argc) {
            args.lport = std::stoi(argv[++i]);
        } else if (arg == "--rhost" && i + 1 < argc) {
            args.rhost = argv[++i];
        } else if (arg == "--rport" && i + 1 < argc) {
            args.rport = std::stoi(argv[++i]);
        } else if (arg == "--run" && i + 1 < argc) {
            args.run_cmd = argv[++i];
        }
    }
    return args;
}

crypto::Bytes auth_payload(EVP_PKEY* pubkey,
                           const crypto::Bytes& signature,
                           const std::optional<crypto::Bytes>& pq_ciphertext) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw std::runtime_error("failed to allocate pubkey bio");
    }
    if (PEM_write_bio_PUBKEY(bio, pubkey) != 1) {
        BIO_free(bio);
        throw std::runtime_error("failed to write public key");
    }

    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    if (len <= 0) {
        BIO_free(bio);
        throw std::runtime_error("failed to read public key");
    }

    crypto::Bytes pub_bytes(reinterpret_cast<uint8_t*>(data), reinterpret_cast<uint8_t*>(data) + len);
    BIO_free(bio);

    crypto::Bytes payload;
    payload.reserve(2 + pub_bytes.size() + 2 + signature.size());

    uint16_t pub_len = static_cast<uint16_t>(pub_bytes.size());
    payload.push_back(static_cast<uint8_t>((pub_len >> 8) & 0xFF));
    payload.push_back(static_cast<uint8_t>(pub_len & 0xFF));
    payload.insert(payload.end(), pub_bytes.begin(), pub_bytes.end());

    uint16_t sig_len = static_cast<uint16_t>(signature.size());
    payload.push_back(static_cast<uint8_t>((sig_len >> 8) & 0xFF));
    payload.push_back(static_cast<uint8_t>(sig_len & 0xFF));
    payload.insert(payload.end(), signature.begin(), signature.end());

    if (pq_ciphertext.has_value()) {
        uint16_t pq_len = static_cast<uint16_t>(pq_ciphertext->size());
        payload.push_back(static_cast<uint8_t>((pq_len >> 8) & 0xFF));
        payload.push_back(static_cast<uint8_t>(pq_len & 0xFF));
        payload.insert(payload.end(), pq_ciphertext->begin(), pq_ciphertext->end());
    }

    return payload;
}

void authenticate(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                  const std::string& identity_path,
                  const std::optional<crypto::Bytes>& pq_ciphertext) {
    protocol::Frame challenge = protocol::read_frame(stream);
    if (challenge.header.type != protocol::AUTH) {
        throw std::runtime_error("server did not send AUTH challenge");
    }

    auto kp = crypto::load_keypair(identity_path, "");
    crypto::Bytes signature = crypto::sign_message(kp.private_key.get(), challenge.payload);
    crypto::Bytes payload = auth_payload(kp.public_key.get() ? kp.public_key.get() : kp.private_key.get(),
                                         signature,
                                         pq_ciphertext);

    protocol::Frame response{{static_cast<uint32_t>(payload.size()), protocol::AUTH, 0, 0}, payload};
    protocol::send_frame(stream, response);
}

}  // namespace

int Cli::run(int argc, char** argv) {
    util::init_logging();

    ParsedArgs args = parse_args(argc, argv);
    ClientConfig cfg;

    try {
        auto json = util::read_json_config(args.config_path);
        if (json.contains("server")) {
            cfg.server = json["server"].get<std::string>();
        }
        if (json.contains("port")) {
            cfg.port = json["port"].get<int>();
        }
        if (json.contains("identity")) {
            cfg.identity = util::expand_user(json["identity"].get<std::string>());
        }
        if (json.contains("socks_port")) {
            cfg.socks_port = json["socks_port"].get<int>();
        }
        if (json.contains("obfuscation")) {
            cfg.obfuscation = json["obfuscation"].get<bool>();
        }
        if (json.contains("inner_crypto")) {
            cfg.inner_crypto = json["inner_crypto"].get<bool>();
        }
        if (json.contains("pq_public_key")) {
            cfg.pq_public_key = util::expand_user(json["pq_public_key"].get<std::string>());
        }
    } catch (const std::exception& ex) {
        util::log_warn(std::string("config load failed: ") + ex.what());
    }

    if (!args.server.empty()) {
        cfg.server = args.server;
    }
    if (args.port > 0) {
        cfg.port = args.port;
    }
    if (!args.identity.empty()) {
        cfg.identity = util::expand_user(args.identity);
    }
    if (args.socks_port > 0) {
        cfg.socks_port = args.socks_port;
    }

    if (cfg.server.empty() || cfg.identity.empty()) {
        util::log_error("--server and --auth (identity) are required");
        return 1;
    }

    try {
        boost::asio::io_context io;
        auto ctx = obfs::create_client_context();
        ctx.set_verify_mode(boost::asio::ssl::verify_none);

        boost::asio::ip::tcp::resolver resolver(io);
        auto endpoints = resolver.resolve(cfg.server, std::to_string(cfg.port));
        boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream(io, ctx);
        boost::asio::connect(stream.next_layer(), endpoints);
        stream.handshake(boost::asio::ssl::stream_base::client);

        inner::Config inner_cfg;
        inner_cfg.enabled = cfg.inner_crypto;
        inner_cfg.pq_public_key = cfg.pq_public_key;

        std::optional<crypto::Bytes> pq_ciphertext;
        std::optional<crypto::Bytes> inner_key;
        if (inner_cfg.enabled) {
            auto hs = inner::client_prepare(inner_cfg);
            if (!hs.enabled || hs.key.empty()) {
                throw std::runtime_error("inner crypto init failed");
            }
            pq_ciphertext = hs.pq_ciphertext;
            inner_key = hs.key;
        }

        authenticate(stream, cfg.identity, pq_ciphertext);
        util::log_info("authenticated to server");

        if (!args.run_cmd.empty()) {
            crypto::Bytes payload(args.run_cmd.begin(), args.run_cmd.end());
            uint16_t flags = 0;
            if (inner_key.has_value()) {
                payload = inner::encrypt_payload(*inner_key, protocol::EXEC, 1, payload);
                flags |= protocol::kFlagInnerEncrypted;
            }
            protocol::Frame exec{{static_cast<uint32_t>(payload.size()), protocol::EXEC, 1, flags}, payload};
            protocol::send_frame(stream, exec);

            protocol::Frame reply = protocol::read_frame(stream);
            if (reply.header.type == protocol::DATA) {
                crypto::Bytes payload = reply.payload;
                if (inner_key.has_value()) {
                    if ((reply.header.flags & protocol::kFlagInnerEncrypted) == 0) {
                        throw std::runtime_error("EXEC reply missing inner encryption flag");
                    }
                    payload = inner::decrypt_payload(*inner_key, reply.header.type, reply.header.stream_id, reply.payload);
                }
                std::string output(payload.begin(), payload.end());
                std::cout << output << std::endl;
            } else {
                util::log_warn("unexpected response to EXEC");
            }
            return 0;
        }

        auto tunnel = std::make_shared<Tunnel>(std::move(stream));
        if (inner_key.has_value()) {
            tunnel->set_inner_key(*inner_key);
        }
        tunnel->start();

        if (args.lport > 0 || !args.rhost.empty() || args.rport > 0) {
            if (args.lport <= 0 || args.rhost.empty() || args.rport <= 0) {
                util::log_error("--lport, --rhost, and --rport must be set together");
                return 1;
            }

            auto forward = std::make_shared<ForwardServer>(io, args.lport, args.rhost, args.rport, tunnel);
            forward->start();
            util::log_info("forwarding localhost:" + std::to_string(args.lport) + " -> " +
                           args.rhost + ":" + std::to_string(args.rport));
            io.run();
            return 0;
        }

        if (cfg.socks_port > 0) {
            auto socks = std::make_shared<SocksServer>(io, cfg.socks_port, tunnel);
            socks->start();
            util::log_info("SOCKS5 listening on 127.0.0.1:" + std::to_string(cfg.socks_port));
            io.run();
            return 0;
        }

        util::log_warn("no mode selected");
        return 1;
    } catch (const std::exception& ex) {
        util::log_error(std::string("client error: ") + ex.what());
        return 1;
    }
}

}  // namespace yume::client
