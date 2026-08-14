/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/connect/auth.hpp"
#include "core/security/secure_erase.hpp"

#include <algorithm>
#include <array>
#include <ctime>
#include <stdexcept>

#include <openssl/pem.h>

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
#include "core/security/channel_binding.hpp"
#include "util.hpp"

namespace yume::client {
namespace {

class WipeBytesOnExit {
public:
    explicit WipeBytesOnExit(crypto::Bytes& bytes) noexcept : bytes_(bytes) {}
    ~WipeBytesOnExit() { security::secure_erase(bytes_); }

    WipeBytesOnExit(const WipeBytesOnExit&) = delete;
    WipeBytesOnExit& operator=(const WipeBytesOnExit&) = delete;

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

}  // namespace

protocol::Frame read_auth_challenge(ClientTransportStream& stream,
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

std::unique_ptr<ratchet::SessionRatchet> send_auth_v2_response(
    ClientTransportStream& stream,
    boost::asio::io_context& io,
    const std::string& identity_path,
    const protocol::Frame& challenge_frame,
    const security::Secret32& inner_psk,
    crypto::Bytes channel_binding,
    obfs::H2Carrier& carrier,
    std::uint16_t rekey_window,
    const ratchet::RatchetPolicy& ratchet_policy) {
    WipeBytesOnExit wipe_channel_binding(channel_binding);
    if (channel_binding.size() != auth_v2::kChannelBindingLen) {
        throw FatalError("YUME 2.0 requires an exact TLS exporter binding");
    }
#if YUME_USE_BASEFWX
    const auth_v2::Challenge challenge =
        auth_v2::ParseChallenge(challenge_frame.payload);
    // Accept what this client was configured for, send no deeper than the
    // server's TLS-protected, transcript-bound advertisement.
    const std::uint16_t local_window = ratchet::ClampRekeyWindow(rekey_window);
    const std::uint16_t send_window =
        std::min(local_window, challenge.rekey_window);
    if (!ratchet::IsRatchetPolicyValid(ratchet_policy)) {
        throw FatalError("invalid local YUME 2.0 ratchet policy");
    }
    const ratchet::RatchetPolicy send_policy =
        ratchet::NegotiateRatchetPolicy(
            ratchet_policy, challenge.ratchet_policy);
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
        x25519.public_key, kem.ciphertext, identity, local_window,
        ratchet_policy);
    crypto::Bytes signature_input = auth_v2::BuildSignatureInput(
        challenge.encoded, unsigned_response, channel_binding);
    crypto::Bytes signature = crypto::sign_message(
        identity_key.private_key.get(), signature_input);
    basefwx::crypto::SecureClear(signature_input);
    crypto::Bytes response_payload = auth_v2::BuildResponse(
        x25519.public_key, kem.ciphertext, identity, local_window,
        ratchet_policy, signature);

    basefwx::crypto::SecureBytes file_psk{inner_psk.CopyBytes()};
    basefwx::crypto::SecureBytes psk_key{
        ratchet::DerivePskKey(file_psk.bytes(), challenge.psk_salt)};
    crypto::Bytes initial_root = ratchet::DeriveInitialRoot(
        kem.shared, x_shared.bytes(), psk_key.bytes(),
        challenge.transcript_salt, channel_binding);
    auto session_ratchet = std::make_unique<ratchet::SessionRatchet>(
        ratchet::EndpointRole::Client, std::move(initial_root),
        psk_key.Release(), send_window, local_window, send_policy,
        send_policy);
    // The negotiated depth sets the per-round-trip transfer ceiling, so it is
    // the first thing to check when a high-latency link underperforms.
    util::log_info("ratchet epoch window: send=" + std::to_string(send_window) +
                   " accept=" + std::to_string(local_window) +
                   " (server advertised " +
                   std::to_string(challenge.rekey_window) + ")");
    util::log_info(
        "ratchet policy: negotiated bytes=" +
        std::to_string(send_policy.epoch_byte_limit) + " frames=" +
        std::to_string(send_policy.epoch_frame_limit) + " active_ms=" +
        std::to_string(send_policy.epoch_active_limit.count()) +
        " local_advertised_bytes=" +
        std::to_string(ratchet_policy.epoch_byte_limit) + " frames=" +
        std::to_string(ratchet_policy.epoch_frame_limit) + " active_ms=" +
        std::to_string(ratchet_policy.epoch_active_limit.count()));

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
    (void)channel_binding;
    (void)carrier;
    (void)rekey_window;
    (void)ratchet_policy;
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
    ClientTransportStream& stream,
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
        stream.cancel_and_close();
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
    ClientTransportStream& stream,
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
        stream.cancel_and_close();
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

void require_h2_carrier_alpn(ClientTransportStream& stream,
                             const std::string& server_host,
                             int server_port) {
    const std::string& negotiated = stream.metadata().alpn;
    const std::string label = negotiated.empty() ? std::string("(none)") : negotiated;
    util::log_info("TLS ALPN selected: " + label);
    if (negotiated != "h2") {
        throw FatalError("HTTPS h2 carrier requires TLS ALPN h2; negotiated " + label +
                         " with " + server_host + ":" + std::to_string(server_port));
    }
}

void perform_h2_carrier_handshake(ClientTransportStream& stream,
                                  boost::asio::io_context& io,
                                  const std::string& server_host,
                                  int server_port,
                                  const security::Secret32& obfs_secret,
                                  std::vector<uint8_t>* prefetched,
                                  std::unique_ptr<obfs::H2Carrier>* carrier_out,
                                  std::shared_ptr<obfs::OuterCarrierTrace> outer_trace) {
    crypto::Bytes admission_key = obfs_secret.CopyBytes();
    WipeBytesOnExit wipe_admission_key(admission_key);
    std::int64_t hour = static_cast<std::int64_t>(std::time(nullptr)) / 3600;
    std::string nonce = obfs::random_nonce_hex();
    std::string token = obfs::derive_path_token(admission_key, server_host, hour, nonce);
    std::string path = obfs::build_path(token, nonce);
    auto carrier = std::make_unique<obfs::H2Carrier>(
        obfs::H2CarrierRole::Client, std::move(outer_trace));
#if YUME_ENABLE_DEV_DIAGNOSTICS
    carrier->set_timing_enabled(YUME_TIMING_ENABLED());
#endif
    std::string authority = server_host;
    if (server_port != 443) authority += ":" + std::to_string(server_port);
    if (!carrier->StartClient(authority)) {
        throw FatalError("failed to start H2 carrier: " + carrier->error());
    }

    auto cancel = [&]() {
        stream.cancel_and_close();
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
