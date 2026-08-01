#include "core/security/auth_v2.hpp"

#include <cassert>
#include <chrono>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>

#include <openssl/evp.h>

#include "core/security/ratchet.hpp"

namespace {

template <typename Fn>
bool Throws(Fn&& fn) {
    try {
        fn();
        return false;
    } catch (const std::runtime_error&) {
        return true;
    }
}

std::string Sha256Hex(const yume::auth_v2::Bytes& value) {
    EVP_MD_CTX* raw = EVP_MD_CTX_new();
    assert(raw != nullptr);
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(
        raw, &EVP_MD_CTX_free);
    assert(EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) == 1);
    assert(EVP_DigestUpdate(ctx.get(), value.data(), value.size()) == 1);
    unsigned char digest[EVP_MAX_MD_SIZE]{};
    unsigned int size = 0;
    assert(EVP_DigestFinal_ex(ctx.get(), digest, &size) == 1);
    assert(size == 32);
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < size; ++i) {
        out << std::setw(2) << static_cast<unsigned int>(digest[i]);
    }
    return out.str();
}

}  // namespace

int main() {
    using namespace yume::auth_v2;
    const Bytes challenge(32, 0x11);
    const Bytes kem_public(1568, 0x22);
    const Bytes x_public(32, 0x33);
    const Bytes psk_salt(32, 0x44);
    const Bytes transcript_salt(32, 0x55);
    const std::uint16_t rekey_window = 8;
    const auto policy = yume::ratchet::kExtremePolicy;
    const Bytes encoded = BuildChallenge(challenge, kem_public, x_public,
                                         psk_salt, transcript_salt,
                                         rekey_window, policy);
    assert(encoded.size() == 1778);
    assert(Sha256Hex(encoded) ==
           "158918528bdbb6a87284be4f11d0098cef0dad2a14f3fede993168f489f58b19");
    const auto parsed = ParseChallenge(encoded);
    assert(parsed.challenge == challenge);
    assert(parsed.mlkem_public_key == kem_public);
    assert(parsed.rekey_window == rekey_window);
    assert(parsed.ratchet_policy == policy);

    const Bytes ciphertext(1568, 0x66);
    const Bytes identity{'i', 'd'};
    const Bytes unsigned_response = BuildUnsignedResponse(x_public, ciphertext,
                                                          identity,
                                                          rekey_window,
                                                          policy);
    assert(unsigned_response.size() == 1658);
    assert(Sha256Hex(unsigned_response) ==
           "f6cb361be8ebc4ee07ae2d35d0ad5cadd65bd93d399ccea6ecadd6a761c3a915");
    const Bytes signature(64, 0x77);
    const auto response = ParseResponse(BuildResponse(
        x_public, ciphertext, identity, rekey_window, policy, signature));
    assert(response.signature == signature);
    assert(response.rekey_window == rekey_window);
    assert(response.ratchet_policy == policy);
    // The advertised depth sits in the unsigned record, so the transcript the
    // client signs commits to the negotiated window.
    const Bytes channel_binding(kChannelBindingLen, 0x88);
    const Bytes signature_input = BuildSignatureInput(encoded, unsigned_response,
                                                      channel_binding);
    assert(signature_input.size() == 3506);
    assert(Sha256Hex(signature_input) ==
           "820d6c792cc17329e430395d67ef111b3ac65fe2fdb8ae0051600f7595cd7757");

    // The binding is what a relaying endpoint cannot reproduce: the same
    // records under a different live TLS connection sign a different input.
    const Bytes relayed_binding(kChannelBindingLen, 0x89);
    assert(BuildSignatureInput(encoded, unsigned_response, relayed_binding) !=
           signature_input);

    // No unbound transcript exists. A caller that could not read its own
    // exporter must fail, not sign a v1-shaped input.
    for (std::size_t bad_size : {std::size_t{0}, std::size_t{16},
                                 std::size_t{33}}) {
        assert(Throws([&] {
            (void)BuildSignatureInput(encoded, unsigned_response,
                                      Bytes(bad_size, 0x88));
        }));
    }

    // Out-of-range depths are rejected on both build and parse so no peer can
    // reserve unbounded ML-KEM work or retained roots.
    assert(Throws([&] {
        (void)BuildChallenge(challenge, kem_public, x_public, psk_salt,
                             transcript_salt, 0, policy);
    }));
    assert(Throws([&] {
        (void)BuildChallenge(challenge, kem_public, x_public, psk_salt,
                             transcript_salt,
                             yume::ratchet::kMaxRekeyWindow + 1, policy);
    }));
    assert(Throws([&] {
        (void)BuildUnsignedResponse(
            x_public, ciphertext, identity, 0, policy);
    }));
    Bytes zero_window = encoded;
    zero_window[zero_window.size() - 28] = 0;
    zero_window[zero_window.size() - 27] = 0;
    assert(Throws([&] { (void)ParseChallenge(zero_window); }));

    auto invalid_policy = policy;
    invalid_policy.epoch_active_limit = std::chrono::milliseconds(0);
    assert(Throws([&] {
        (void)BuildChallenge(challenge, kem_public, x_public, psk_salt,
                             transcript_salt, rekey_window, invalid_policy);
    }));

    const Bytes info{'{', '}'};
    assert(ParseAuthOk(BuildAuthOk(info)) == info);
    const auto init = ParseRekeyInit(BuildRekeyInit(1, kem_public, x_public));
    assert(init.next_epoch == 1);
    const auto ack = ParseRekeyAck(BuildRekeyAck(1, ciphertext, x_public));
    assert(ack.next_epoch == 1);

    Bytes trailing = encoded;
    trailing.push_back(0);
    assert(Throws([&] { (void)ParseChallenge(trailing); }));

    Bytes wrong_version = encoded;
    wrong_version[10] = '1';
    assert(Throws([&] { (void)ParseChallenge(wrong_version); }));

    assert(Throws([&] {
        (void)EncodeRecord(RecordKind::Challenge,
                           {{1, true, Bytes{'a'}}, {1, true, Bytes{'b'}}});
    }));

    const Bytes unknown_critical = EncodeRecord(RecordKind::Challenge, {
        {1, true, Bytes(kTransportVersion.begin(), kTransportVersion.end())},
        {2, true, challenge}, {3, true, kem_public}, {4, true, x_public},
        {5, true, psk_salt}, {6, true, transcript_salt},
        {7, true, Bytes{0, 8}},
        {8, true, Bytes(20, 1)}, {9, true, Bytes{0}},
    });
    assert(Throws([&] { (void)ParseChallenge(unknown_critical); }));
    return 0;
}
