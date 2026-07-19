#include "core/security/session_ratchet.hpp"

#include <cassert>
#include <chrono>
#include <stdexcept>

#if YUME_USE_BASEFWX
#include <basefwx/x25519.hpp>
#endif

namespace {

void AppendU64(yume::ratchet::Bytes& out, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

yume::protocol::Frame Envelope(std::uint8_t type,
                               std::uint8_t stream_id,
                               yume::ratchet::SealedFrame sealed) {
    yume::ratchet::Bytes payload;
    AppendU64(payload, sealed.epoch);
    AppendU64(payload, sealed.sequence);
    payload.insert(payload.end(), sealed.ciphertext.begin(),
                   sealed.ciphertext.end());
    return {{static_cast<std::uint32_t>(payload.size()), type, stream_id,
             yume::protocol::kFlagInnerEncrypted},
            std::move(payload)};
}

template <typename Fn>
bool Throws(Fn&& fn) {
    try {
        fn();
        return false;
    } catch (const std::exception&) {
        return true;
    }
}

void TestX25519RejectsAllZeroPeer() {
#if YUME_USE_BASEFWX
    auto local = basefwx::x25519::GenerateKeyPair();
    assert(Throws([&] {
        (void)basefwx::x25519::DeriveSharedSecret(
            local.private_key, basefwx::x25519::Bytes(32, 0));
    }));
#endif
}

void TestOldEpochApplicationRejectedAfterInit() {
    using namespace yume;
    const ratchet::Bytes root(32, 0x71);
    const ratchet::Bytes psk(32, 0x82);
    ratchet::SessionRatchet client(ratchet::EndpointRole::Client, root, psk);
    ratchet::SessionRatchet server(ratchet::EndpointRole::Server, root, psk);
    ratchet::DirectionalRatchet old_sender(
        ratchet::Direction::ClientToServer,
        ratchet::DeriveDirectionRoot(root,
                                     ratchet::Direction::ClientToServer));
    const auto now = std::chrono::steady_clock::time_point{};

    auto init = client.BeginOutboundRekey(now);
    auto init_result = server.Open(init, now);
    assert(init_result.control_response.has_value());

    // Advance the independent test sender over the INIT's old-chain sequence,
    // then construct an otherwise authentic old-epoch DATA frame.
    (void)old_sender.Encrypt(protocol::REKEY_INIT, 0,
                             protocol::kFlagInnerEncrypted, {}, now, false);
    auto stale = old_sender.Encrypt(protocol::DATA, 1,
                                    protocol::kFlagInnerEncrypted, {0x55}, now);
    assert(Throws([&] {
        (void)server.Open(Envelope(protocol::DATA, 1, std::move(stale)), now);
    }));
}

void TestSimultaneousDirectionalRekey() {
    using namespace yume;
    using namespace std::chrono_literals;
    const ratchet::Bytes root(32, 0x51);
    const ratchet::Bytes psk(32, 0x62);
    ratchet::SessionRatchet client(ratchet::EndpointRole::Client, root, psk);
    ratchet::SessionRatchet server(ratchet::EndpointRole::Server, root, psk);
    const auto now = std::chrono::steady_clock::time_point{} + 2s;

    auto client_init = client.BeginOutboundRekey(now);
    auto server_init = server.BeginOutboundRekey(now);
    assert(!client.rekey_timed_out(now + 4999ms));
    assert(client.rekey_timed_out(now + 5s));

    auto server_received_init = server.Open(client_init, now + 1ms);
    auto client_received_init = client.Open(server_init, now + 1ms);
    assert(server_received_init.control_response.has_value());
    assert(client_received_init.control_response.has_value());

    auto client_received_ack = client.Open(
        *server_received_init.control_response, now + 2ms);
    auto server_received_ack = server.Open(
        *client_received_init.control_response, now + 2ms);
    assert(client_received_ack.outbound_rekey_completed);
    assert(server_received_ack.outbound_rekey_completed);
    assert(client.outbound_epoch() == 1 && server.outbound_epoch() == 1);

    protocol::Frame c2s{{1, protocol::DATA, 1, 0}, {0xa1}};
    protocol::Frame s2c{{1, protocol::DATA, 2, 0}, {0xb2}};
    auto opened_c2s = server.Open(client.Seal(c2s, now + 3ms), now + 3ms);
    auto opened_s2c = client.Open(server.Seal(s2c, now + 3ms), now + 3ms);
    assert(opened_c2s.application_frame->payload == c2s.payload);
    assert(opened_s2c.application_frame->payload == s2c.payload);
    assert(client.inbound_epoch() == 1 && server.inbound_epoch() == 1);
}

}  // namespace

int main() {
    using namespace yume;
    using namespace std::chrono_literals;
    const ratchet::Bytes root(32, 0x31);
    const ratchet::Bytes psk(32, 0x42);
    ratchet::SessionRatchet client(ratchet::EndpointRole::Client, root, psk);
    ratchet::SessionRatchet server(ratchet::EndpointRole::Server, root, psk);

    const auto start = std::chrono::steady_clock::time_point{} + 1s;
    protocol::Frame first{{3, protocol::DATA, 7, 0}, {1, 2, 3}};
    auto opened = server.Open(client.Seal(first, start), start);
    assert(opened.application_frame.has_value());
    assert(opened.application_frame->payload == first.payload);

    protocol::Frame next{{1, protocol::DATA, 7, 0}, {4}};
    assert(client.ShouldStartRekey(next, start + 501ms));
    const auto init = client.BeginOutboundRekey(start + 501ms);
    assert(client.outbound_rekey_pending());
    auto init_result = server.Open(init, start + 502ms);
    assert(init_result.control_response.has_value());
    const auto ack_result = client.Open(*init_result.control_response,
                                        start + 503ms);
    assert(ack_result.outbound_rekey_completed);
    assert(!client.outbound_rekey_pending());
    assert(client.outbound_epoch() == 1);

    auto epoch_one = client.Seal(next, start + 504ms);
    auto epoch_one_open = server.Open(epoch_one, start + 505ms);
    assert(epoch_one_open.application_frame.has_value());
    assert(server.inbound_epoch() == 1);
    TestSimultaneousDirectionalRekey();
    TestX25519RejectsAllZeroPeer();
    TestOldEpochApplicationRejectedAfterInit();
    return 0;
}
