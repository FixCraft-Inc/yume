/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/connect/auth.hpp"
#include "core/security/secure_erase.hpp"

#include <array>
#include <algorithm>
#include <cstring>
#include <ctime>
#include <limits>
#include <stdexcept>

#include <openssl/pem.h>
#include <nlohmann/json.hpp>

#if YUME_USE_BASEFWX
#include <basefwx/crypto.hpp>
#include <basefwx/pq.hpp>
#include <basefwx/x25519.hpp>
#endif

#include "client/cli/connect/io.hpp"
#include "core/stealth/obfs.hpp"
#include "core/stealth/obfs_signal.hpp"
#include "core/stealth/http_profile.hpp"
#include "core/protocol/protocol_stream.hpp"
#include "core/security/auth_v2.hpp"
#include "util.hpp"

namespace yume::client {
namespace {

class WipeBytesOnExit {
public:
    explicit WipeBytesOnExit(crypto::Bytes& bytes) : bytes_(bytes) {}
    ~WipeBytesOnExit() { security::secure_erase(bytes_); }
private:
    crypto::Bytes& bytes_;
};

crypto::Bytes PublicKeyPem(EVP_PKEY* key) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()), BIO_free);
    if (!bio || PEM_write_bio_PUBKEY(bio.get(), key) != 1) {
        throw std::runtime_error("failed to encode Ed25519 public identity");
    }
    char* data = nullptr;
    const long length = BIO_get_mem_data(bio.get(), &data);
    if (length <= 0 || !data) {
        throw std::runtime_error("failed to read Ed25519 public identity");
    }
    return crypto::Bytes(reinterpret_cast<std::uint8_t*>(data),
                         reinterpret_cast<std::uint8_t*>(data) + length);
}

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
                                    std::vector<uint8_t>* prefetched,
                                    obfs::H2Carrier* carrier) {
    protocol::Frame challenge = carrier
        ? read_frame_over_h2_with_timeout(stream, io, *carrier, prefetched,
                                          kAuthChallengeTimeout, "AUTH challenge",
                                          server_host, server_port)
        : read_frame_with_timeout(stream, io, kAuthChallengeTimeout,
                                  "AUTH challenge", server_host, server_port,
                                  true, prefetched);
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
                        const std::optional<inner::KdfParams>& inner_kdf,
                        boost::asio::io_context* io,
                        obfs::H2Carrier* carrier) {
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
    if (carrier) {
        if (!io) throw std::runtime_error("H2 AUTH send missing I/O context");
        send_frame_over_h2_with_timeout(stream, *io, *carrier, response,
                                        kAuthChallengeTimeout, "AUTH response");
    } else {
        protocol::send_frame(stream, response);
    }
}

std::unique_ptr<ratchet::SessionRatchet> send_auth_v2_response(
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
    boost::asio::io_context& io,
    const std::string& identity_path,
    const protocol::Frame& challenge_frame,
    const security::Secret32& inner_psk,
    obfs::H2Carrier& carrier) {
#if YUME_USE_BASEFWX
    const auth_v2::Challenge challenge =
        auth_v2::ParseChallenge(challenge_frame.payload);
    auto identity_key = crypto::load_keypair(identity_path, "");
    EVP_PKEY* public_key = identity_key.public_key
        ? identity_key.public_key.get() : identity_key.private_key.get();
    if (!public_key || EVP_PKEY_base_id(public_key) != EVP_PKEY_ED25519) {
        throw FatalError("YUME 2.0 requires an Ed25519 client identity");
    }
    crypto::Bytes identity = PublicKeyPem(public_key);

    basefwx::pq::KemResult kem = basefwx::pq::KemEncrypt(
        basefwx::pq::KemAlgorithm::MlKem1024, challenge.mlkem_public_key);
    basefwx::x25519::KeyPair x25519 = basefwx::x25519::GenerateKeyPair();
    basefwx::crypto::SecureBytes x_shared{
        basefwx::x25519::DeriveSharedSecret(x25519.private_key,
                                            challenge.x25519_public_key)};
    crypto::Bytes unsigned_response = auth_v2::BuildUnsignedResponse(
        x25519.public_key, kem.ciphertext, identity);
    crypto::Bytes signature_input = auth_v2::BuildSignatureInput(
        challenge.encoded, unsigned_response);
    crypto::Bytes signature = crypto::sign_message(
        identity_key.private_key.get(), signature_input);
    basefwx::crypto::SecureClear(signature_input);
    crypto::Bytes response_payload = auth_v2::BuildResponse(
        x25519.public_key, kem.ciphertext, identity, signature);

    basefwx::crypto::SecureBytes file_psk{inner_psk.CopyBytes()};
    basefwx::crypto::SecureBytes psk_key{
        ratchet::DerivePskKey(file_psk.bytes(), challenge.psk_salt)};
    crypto::Bytes initial_root = ratchet::DeriveInitialRoot(
        kem.shared, x_shared.bytes(), psk_key.bytes(), challenge.transcript_salt);
    auto session_ratchet = std::make_unique<ratchet::SessionRatchet>(
        ratchet::EndpointRole::Client, std::move(initial_root),
        psk_key.Release());

    protocol::Frame response{{static_cast<std::uint32_t>(response_payload.size()),
                              protocol::AUTH, 0, 0},
                             std::move(response_payload)};
    send_frame_over_h2_with_timeout(stream, io, carrier, response,
                                    kAuthChallengeTimeout, "AUTH v2 response");
    return session_ratchet;
#else
    (void)stream;
    (void)io;
    (void)identity_path;
    (void)challenge_frame;
    (void)inner_psk;
    (void)carrier;
    throw FatalError("YUME 2.0 requires a BaseFWX crypto build");
#endif
}

protocol::Frame open_auth_ok_v2(ratchet::SessionRatchet& ratchet,
                                const protocol::Frame& protected_frame) {
    ratchet::OpenResult opened = ratchet.Open(
        protected_frame, std::chrono::steady_clock::now());
    if (!opened.application_frame.has_value() ||
        opened.application_frame->header.type != protocol::ANON ||
        opened.control_response.has_value()) {
        throw FatalError("invalid encrypted AUTH_OK response");
    }
    protocol::Frame frame = std::move(*opened.application_frame);
    frame.payload = auth_v2::ParseAuthOk(frame.payload);
    frame.header.len = static_cast<std::uint32_t>(frame.payload.size());
    return frame;
}

void send_frame_over_h2_with_timeout(
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
    boost::asio::io_context& io,
    obfs::H2Carrier& carrier,
    const protocol::Frame& frame,
    std::chrono::milliseconds timeout,
    const char* what) {
    crypto::Bytes encoded = protocol::encode_frame(
        static_cast<protocol::FrameType>(frame.header.type),
        frame.header.stream_id, frame.header.flags, frame.payload);
    if (!carrier.SendBinary(encoded)) {
        throw FatalError(std::string("failed to queue ") + what +
                         " on H2 carrier: " + carrier.error());
    }
    crypto::Bytes wire = carrier.TakeOutbound();
    if (wire.empty() || carrier.queued_output_bytes() != 0) {
        throw FatalError(std::string("H2 flow control stalled while sending ") + what);
    }
    auto cancel = [&]() {
        boost::system::error_code ignored;
        stream.lowest_layer().cancel(ignored);
        stream.lowest_layer().close(ignored);
    };
    const IoOpResult result = write_all_with_timeout(
        stream, io, boost::asio::buffer(wire), timeout, cancel);
    if (result.timed_out) {
        throw FatalError(std::string("timed out sending ") + what + " over H2");
    }
    if (result.ec) {
        throw FatalError(std::string("failed sending ") + what + " over H2: " +
                         result.ec.message());
    }
}

protocol::Frame read_frame_over_h2_with_timeout(
    boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
    boost::asio::io_context& io,
    obfs::H2Carrier& carrier,
    std::vector<uint8_t>* prefetched,
    std::chrono::milliseconds timeout,
    const char* what,
    const std::string& server_host,
    int server_port) {
    std::vector<uint8_t> local_prefetched;
    std::vector<uint8_t>& decoded = prefetched ? *prefetched : local_prefetched;
    std::array<uint8_t, 16U * 1024U> scratch{};
    auto cancel = [&]() {
        boost::system::error_code ignored;
        stream.lowest_layer().cancel(ignored);
        stream.lowest_layer().close(ignored);
    };
    auto write_protocol_replies = [&]() {
        crypto::Bytes replies = carrier.TakeOutbound();
        if (replies.empty()) return;
        const IoOpResult result = write_all_with_timeout(
            stream, io, boost::asio::buffer(replies), timeout, cancel);
        if (result.timed_out) {
            throw FatalError(std::string("timed out sending H2 reply while reading ") + what);
        }
        if (result.ec) {
            throw FatalError(std::string("failed sending H2 reply while reading ") + what +
                             ": " + result.ec.message());
        }
    };
    auto fill = [&](std::size_t needed) {
        while (decoded.size() < needed) {
            crypto::Bytes ready = carrier.TakeTunnelBytes();
            decoded.insert(decoded.end(), ready.begin(), ready.end());
            if (decoded.size() >= needed) break;
            if (carrier.failed() || carrier.carrier_closed()) {
                throw FatalError(std::string("H2 carrier closed while reading ") + what +
                                 (carrier.error().empty() ? std::string{} :
                                  ": " + carrier.error()));
            }
            const IoOpResult result = read_some_with_timeout(
                stream, io, boost::asio::buffer(scratch), timeout, cancel);
            if (result.timed_out) {
                throw FatalError(std::string("timed out waiting for ") + what + " (" +
                                 server_host + ":" + std::to_string(server_port) + ")");
            }
            if (result.ec) {
                throw FatalError(std::string("failed reading ") + what + " over H2: " +
                                 result.ec.message());
            }
            if (result.bytes == 0) {
                throw FatalError(std::string("empty H2 read while waiting for ") + what);
            }
            carrier.Feed(scratch.data(), result.bytes);
            if (carrier.failed()) {
                throw FatalError(std::string("invalid H2 while reading ") + what + ": " +
                                 carrier.error());
            }
            write_protocol_replies();
        }
    };

    fill(8);
    std::array<uint8_t, 8> header{};
    std::copy_n(decoded.begin(), header.size(), header.begin());
    if (!looks_like_yume_header(header)) {
        throw FatalError(std::string("unexpected ") + what + " inside H2 carrier");
    }
    const std::uint32_t payload_size =
        (static_cast<std::uint32_t>(header[0]) << 24) |
        (static_cast<std::uint32_t>(header[1]) << 16) |
        (static_cast<std::uint32_t>(header[2]) << 8) |
        static_cast<std::uint32_t>(header[3]);
    fill(8U + payload_size);
    crypto::Bytes encoded(decoded.begin(),
                          decoded.begin() + static_cast<std::ptrdiff_t>(8U + payload_size));
    decoded.erase(decoded.begin(),
                  decoded.begin() + static_cast<std::ptrdiff_t>(8U + payload_size));
    return protocol::decode_frame(encoded);
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
                                  const security::Secret32& obfs_secret,
                                  std::string_view user_agent,
                                  std::vector<uint8_t>* prefetched,
                                  std::unique_ptr<obfs::H2Carrier>* carrier_out) {
    crypto::Bytes admission_key = obfs_secret.CopyBytes();
    WipeBytesOnExit wipe_admission_key(admission_key);
    std::int64_t hour = static_cast<std::int64_t>(std::time(nullptr)) / 3600;
    std::string nonce = obfs::random_nonce_hex();
    std::string token = obfs::derive_path_token(admission_key, server_host, hour, nonce);
    std::string path = obfs::build_path(token, nonce);
    auto carrier = std::make_unique<obfs::H2Carrier>(obfs::H2CarrierRole::Client);
    std::string authority = server_host;
    if (server_port != 443) authority += ":" + std::to_string(server_port);
    if (!carrier->StartClient(authority, std::string(user_agent))) {
        throw FatalError("failed to start H2 carrier: " + carrier->error());
    }

    auto cancel = [&]() {
        boost::system::error_code ignored;
        stream.lowest_layer().cancel(ignored);
        stream.lowest_layer().close(ignored);
    };

    auto flush = [&]() {
        crypto::Bytes wire = carrier->TakeOutbound();
        if (wire.empty()) return;
        IoOpResult wr = write_all_with_timeout(
            stream, io, boost::asio::buffer(wire), kAuthChallengeTimeout, cancel);
        if (wr.timed_out) throw FatalError("H2 carrier write timed out");
        if (wr.ec) throw FatalError("H2 carrier write failed: " + wr.ec.message());
    };
    flush();

    std::array<std::uint8_t, 16U * 1024U> scratch{};
    auto receive = [&]() {
        IoOpResult rr = read_some_with_timeout(
            stream, io, boost::asio::buffer(scratch), kAuthChallengeTimeout, cancel);
        if (rr.timed_out) {
            throw FatalError("this endpoint is not a yume obfs endpoint (" + server_host + ":" +
                             std::to_string(server_port) + "; h2 server reply timed out)");
        }
        if (rr.ec) {
            throw FatalError("this endpoint is not a yume obfs endpoint (" + server_host + ":" +
                             std::to_string(server_port) + "; h2 server reply failed: " + rr.ec.message() + ")");
        }
        if (rr.bytes == 0) {
            throw FatalError("this endpoint is not a yume obfs endpoint (" + server_host + ":" +
                             std::to_string(server_port) + "; h2 server reply was empty)");
        }
        carrier->Feed(scratch.data(), rr.bytes);
        if (carrier->failed()) {
            throw FatalError("this endpoint is not a yume obfs endpoint (" + server_host + ":" +
                             std::to_string(server_port) + "; h2 decode failed: " + carrier->error() + ")");
        }
        flush();
    };

    while (!carrier->priming_complete()) {
        receive();
    }
    if (!carrier->peer_extended_connect_enabled()) {
        throw FatalError("HTTPS endpoint did not enable RFC 8441 extended CONNECT");
    }
    if (!carrier->SubmitExtendedConnect(path)) {
        throw FatalError("failed to submit RFC 8441 carrier: " + carrier->error());
    }
    flush();
    while (!carrier->carrier_active()) {
        if (carrier->carrier_closed()) {
            throw FatalError("endpoint responded as ordinary HTTPS; carrier admission was not accepted");
        }
        receive();
    }
    if (prefetched) {
        crypto::Bytes ready = carrier->TakeTunnelBytes();
        prefetched->insert(prefetched->end(), ready.begin(), ready.end());
    }
    if (carrier_out) {
        *carrier_out = std::move(carrier);
    }
}

}  // namespace yume::client
