/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/connect/auth.hpp"

#include <array>
#include <cstring>
#include <ctime>
#include <limits>
#include <stdexcept>

#include <openssl/pem.h>
#include <nlohmann/json.hpp>

#include "client/cli/connect/io.hpp"
#include "core/stealth/obfs.hpp"
#include "core/stealth/obfs_h2.hpp"
#include "core/stealth/obfs_signal.hpp"
#include "core/protocol/protocol_stream.hpp"
#include "util.hpp"

namespace yume::client {
namespace {

crypto::Bytes auth_payload(EVP_PKEY* pubkey,
                           const crypto::Bytes& signature,
                           const std::optional<crypto::Bytes>& pq_ciphertext,
                           const std::optional<crypto::Bytes>& pq_salt,
                           const std::optional<std::string>& inner_mode,
                           const std::optional<bool>& inner_hop,
                           const std::optional<inner::KdfParams>& inner_kdf) {
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

    auto checked_add = [](size_t a, size_t b) {
        if (a > (std::numeric_limits<size_t>::max() - b)) {
            throw std::runtime_error("auth payload size overflow");
        }
        return a + b;
    };

    if (pub_bytes.size() > 0xFFFF || signature.size() > 0xFFFF) {
        throw std::runtime_error("auth payload too large");
    }
    if (pq_ciphertext && pq_ciphertext->size() > 0xFFFF) {
        throw std::runtime_error("PQ ciphertext too large");
    }
    if (pq_salt && pq_salt->size() > 0xFFFF) {
        throw std::runtime_error("PQ salt too large");
    }
    if (inner_mode && inner_mode->size() > 0xFFFF) {
        throw std::runtime_error("inner mode too large");
    }
    if (inner_hop && !pq_ciphertext.has_value()) {
        throw std::runtime_error("inner hop without PQ data");
    }
    if (inner_mode && !pq_ciphertext.has_value()) {
        throw std::runtime_error("inner mode without PQ data");
    }
    if (inner_kdf && !pq_ciphertext.has_value()) {
        throw std::runtime_error("inner kdf without PQ data");
    }
    if (inner_kdf && inner_kdf->name.size() > 0xFFFF) {
        throw std::runtime_error("inner kdf too large");
    }

    size_t total = 0;
    total = checked_add(total, 2 + pub_bytes.size());
    total = checked_add(total, 2 + signature.size());
    if (pq_ciphertext) {
        total = checked_add(total, 2 + pq_ciphertext->size());
    }
    if (pq_salt) {
        total = checked_add(total, 2 + pq_salt->size());
    }
    if (inner_mode) {
        total = checked_add(total, 2 + inner_mode->size());
    }
    if (inner_hop) {
        total = checked_add(total, 2 + 1);
    }
    if (inner_kdf) {
        total = checked_add(total, 2 + inner_kdf->name.size());
        total = checked_add(total, 2 + 16);
    }

    crypto::Bytes payload(total);
    size_t off = 0;
    auto write_len = [&](uint16_t v) {
        payload[off++] = static_cast<uint8_t>((v >> 8) & 0xFF);
        payload[off++] = static_cast<uint8_t>(v & 0xFF);
    };
    auto write_bytes = [&](const crypto::Bytes& bytes) {
        if (!bytes.empty()) {
            std::memcpy(payload.data() + off, bytes.data(), bytes.size());
            off += bytes.size();
        }
    };

    write_len(static_cast<uint16_t>(pub_bytes.size()));
    write_bytes(pub_bytes);
    write_len(static_cast<uint16_t>(signature.size()));
    write_bytes(signature);
    if (pq_ciphertext) {
        write_len(static_cast<uint16_t>(pq_ciphertext->size()));
        write_bytes(*pq_ciphertext);
        if (pq_salt) {
            write_len(static_cast<uint16_t>(pq_salt->size()));
            write_bytes(*pq_salt);
        }
        if (inner_mode) {
            crypto::Bytes mode_bytes(inner_mode->begin(), inner_mode->end());
            write_len(static_cast<uint16_t>(mode_bytes.size()));
            write_bytes(mode_bytes);
        }
        if (inner_hop) {
            crypto::Bytes hop_bytes(1, *inner_hop ? static_cast<uint8_t>('1') : static_cast<uint8_t>('0'));
            write_len(static_cast<uint16_t>(hop_bytes.size()));
            write_bytes(hop_bytes);
        }
        if (inner_kdf) {
            crypto::Bytes kdf_bytes(inner_kdf->name.begin(), inner_kdf->name.end());
            write_len(static_cast<uint16_t>(kdf_bytes.size()));
            write_bytes(kdf_bytes);
            crypto::Bytes param_bytes(16, 0);
            auto write_u32 = [&](size_t offset, std::uint32_t val) {
                param_bytes[offset] = static_cast<uint8_t>((val >> 24) & 0xFF);
                param_bytes[offset + 1] = static_cast<uint8_t>((val >> 16) & 0xFF);
                param_bytes[offset + 2] = static_cast<uint8_t>((val >> 8) & 0xFF);
                param_bytes[offset + 3] = static_cast<uint8_t>(val & 0xFF);
            };
            write_u32(0, inner_kdf->argon2_time);
            write_u32(4, inner_kdf->argon2_memory);
            write_u32(8, inner_kdf->argon2_parallelism);
            write_u32(12, inner_kdf->pbkdf2_iters);
            write_len(static_cast<uint16_t>(param_bytes.size()));
            write_bytes(param_bytes);
        }
    }

    return payload;
}

}  // namespace

protocol::Frame read_auth_challenge(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                                    boost::asio::io_context& io,
                                    const std::string& server_host,
                                    int server_port,
                                    std::vector<uint8_t>* prefetched) {
    protocol::Frame challenge = read_frame_with_timeout(
        stream,
        io,
        kAuthChallengeTimeout,
        "AUTH challenge",
        server_host,
        server_port,
        true,
        prefetched);
    if (challenge.header.type != protocol::AUTH) {
        throw FatalError("this endpoint is not a yume server (server did not send AUTH challenge); please check the origin and try again");
    }
    return challenge;
}

inner::Argon2Limits parse_auth_challenge_argon2_limits(const protocol::Frame& challenge) {
    inner::Argon2Limits limits;
    if (challenge.payload.size() <= 32 || challenge.payload[32] != static_cast<std::uint8_t>('{')) {
        return limits;
    }

    try {
        std::string meta_text(challenge.payload.begin() + 32, challenge.payload.end());
        auto meta = nlohmann::json::parse(meta_text);
        auto read_u32 = [&](const char* key) -> std::uint32_t {
            if (!meta.contains(key) || !meta[key].is_number()) {
                return 0;
            }
            std::uint64_t value = meta[key].get<std::uint64_t>();
            return static_cast<std::uint32_t>(
                std::min<std::uint64_t>(value, std::numeric_limits<std::uint32_t>::max()));
        };
        limits.time_max = read_u32("argon2_time_max");
        limits.memory_max = read_u32("argon2_mem_max");
        limits.parallelism_max = read_u32("argon2_par_max");
    } catch (...) {
        return inner::Argon2Limits{};
    }
    return limits;
}

std::string describe_argon2_limits(const inner::Argon2Limits& limits) {
    std::vector<std::string> parts;
    if (limits.time_max > 0) {
        parts.push_back("time<=" + std::to_string(limits.time_max));
    }
    if (limits.memory_max > 0) {
        parts.push_back("mem<=" + std::to_string(limits.memory_max));
    }
    if (limits.parallelism_max > 0) {
        parts.push_back("par<=" + std::to_string(limits.parallelism_max));
    }
    std::string out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i > 0) {
            out += ", ";
        }
        out += parts[i];
    }
    return out;
}

void send_auth_response(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                        const std::string& identity_path,
                        const protocol::Frame& challenge,
                        const std::optional<crypto::Bytes>& pq_ciphertext,
                        const std::optional<crypto::Bytes>& pq_salt,
                        const std::optional<std::string>& inner_mode,
                        const std::optional<bool>& inner_hop,
                        const std::optional<inner::KdfParams>& inner_kdf) {
    auto kp = crypto::load_keypair(identity_path, "");
    crypto::Bytes signature = crypto::sign_message(kp.private_key.get(), challenge.payload);
    crypto::Bytes payload = auth_payload(kp.public_key.get() ? kp.public_key.get() : kp.private_key.get(),
                                         signature,
                                         pq_ciphertext,
                                         pq_salt,
                                         inner_mode,
                                         inner_hop,
                                         inner_kdf);

    protocol::Frame response{{static_cast<uint32_t>(payload.size()), protocol::AUTH, 0, 0}, payload};
    protocol::send_frame(stream, response);
}

void require_h2_carrier_alpn(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                             const std::string& server_host,
                             int server_port) {
    const std::string negotiated = obfs::selected_alpn(stream.native_handle());
    const std::string label = negotiated.empty() ? std::string("(none)") : negotiated;
    util::log_info("TLS ALPN selected: " + label);
    if (negotiated != "h2") {
        throw FatalError("HTTPS h2 carrier requires TLS ALPN h2; negotiated " + label +
                         " with " + server_host + ":" + std::to_string(server_port));
    }
}

void perform_h2_carrier_handshake(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                                  boost::asio::io_context& io,
                                  const std::string& server_host,
                                  int server_port,
                                  const std::string& obfs_secret,
                                  std::vector<uint8_t>* prefetched) {
    crypto::Bytes signal = obfs::derive_signal_key(obfs_secret);
    std::int64_t hour = static_cast<std::int64_t>(std::time(nullptr)) / 3600;
    std::string token = obfs::derive_path_token(signal, server_host, hour);
    std::string nonce = obfs::random_nonce_hex();
    std::string path = obfs::build_path(token, nonce);
    static const std::string kUserAgent =
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36";
    crypto::Bytes hello = obfs::encode_client_handshake(server_host, path, kUserAgent);

    auto cancel = [&]() {
        boost::system::error_code ignored;
        stream.lowest_layer().cancel(ignored);
        stream.lowest_layer().close(ignored);
    };

    IoOpResult wr = write_all_with_timeout(stream, io, boost::asio::buffer(hello.data(), hello.size()),
                                           kAuthChallengeTimeout, cancel);
    if (wr.timed_out) {
        throw FatalError("this endpoint is not a yume obfs endpoint (" + server_host + ":" +
                         std::to_string(server_port) + "; h2 preface timed out)");
    }
    if (wr.ec) {
        throw FatalError("this endpoint is not a yume obfs endpoint (" + server_host + ":" +
                         std::to_string(server_port) + "; h2 preface failed: " + wr.ec.message() + ")");
    }

    obfs::H2InboundDecoder decoder(false);
    std::array<std::uint8_t, 4096> scratch{};
    auto read_some_with_timeout = [&](std::size_t* bytes_out) -> IoOpResult {
        IoOpResult r;
        bool done = false;
        boost::asio::steady_timer timer(io);
        timer.expires_after(kAuthChallengeTimeout);
        timer.async_wait([&](const boost::system::error_code& ec) {
            if (!ec && !done) {
                r.timed_out = true;
                cancel();
            }
        });
        stream.async_read_some(boost::asio::buffer(scratch),
                               [&](const boost::system::error_code& ec, std::size_t n) {
                                   r.ec = ec;
                                   r.bytes = n;
                                   *bytes_out = n;
                                   timer.cancel();
                                   done = true;
                               });
        io.restart();
        io.run();
        return r;
    };

    while (!decoder.headers_seen()) {
        std::size_t n = 0;
        IoOpResult rr = read_some_with_timeout(&n);
        if (rr.timed_out) {
            throw FatalError("this endpoint is not a yume obfs endpoint (" + server_host + ":" +
                             std::to_string(server_port) + "; h2 server reply timed out)");
        }
        if (rr.ec) {
            throw FatalError("this endpoint is not a yume obfs endpoint (" + server_host + ":" +
                             std::to_string(server_port) + "; h2 server reply failed: " + rr.ec.message() + ")");
        }
        if (n == 0) {
            throw FatalError("this endpoint is not a yume obfs endpoint (" + server_host + ":" +
                             std::to_string(server_port) + "; h2 server reply was empty)");
        }
        decoder.feed(scratch.data(), n);
        if (decoder.failed()) {
            throw FatalError("this endpoint is not a yume obfs endpoint (" + server_host + ":" +
                             std::to_string(server_port) + "; h2 decode failed: " + decoder.error() + ")");
        }
    }

    if (prefetched) {
        std::vector<std::uint8_t> leftover;
        decoder.drain_inbound_buffer(&leftover);
        if (!leftover.empty()) {
            prefetched->insert(prefetched->end(), leftover.begin(), leftover.end());
        }
    }
}

}  // namespace yume::client
