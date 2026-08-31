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
    assert(encoded.size() == 1805);
    assert(Sha256Hex(encoded) ==
           "1d55a549a640df215557c4f556b7ef8ce7de925e66ea5e5e9c3529d0b93e9874");
    const auto parsed = ParseChallenge(encoded);
    assert(parsed.challenge == challenge);
    assert(parsed.mlkem_public_key == kem_public);
    assert(parsed.rekey_window == rekey_window);
    assert(parsed.ratchet_policy == policy);
    assert(parsed.transport_profile == kTransportProfile);

    const Bytes ciphertext(1568, 0x66);
    const Bytes identity{'i', 'd'};
    const Bytes unsigned_response = BuildUnsignedResponse(x_public, ciphertext,
                                                          identity,
                                                          rekey_window,
                                                          policy);
    assert(unsigned_response.size() == 1683);
    assert(Sha256Hex(unsigned_response) ==
           "08ab8fdf2387322c4904079db21d0760a634f40c52be4530e60fe8e4c55f5b98");
    // Composite: Ed25519 (64) followed by ML-DSA-87 (4627). This assertion is
    // what keeps auth_v2.hpp's kCompositeSignatureLen -- which is duplicated to
    // keep OpenSSL out of that translation unit -- pinned to crypto.hpp's.
    static_assert(kCompositeSignatureLen == 64 + 4627);
    const Bytes signature(kCompositeSignatureLen, 0x77);
    const auto response = ParseResponse(BuildResponse(
        x_public, ciphertext, identity, rekey_window, policy, signature));
    assert(response.signature == signature);
    assert(response.rekey_window == rekey_window);
    assert(response.ratchet_policy == policy);
    assert(response.transport_profile == kTransportProfile);
    // The advertised depth sits in the unsigned record, so the transcript the
    // client signs commits to the negotiated window.
    const Bytes channel_binding(kChannelBindingLen, 0x88);
    const Bytes signature_input = BuildSignatureInput(encoded, unsigned_response,
                                                      channel_binding);
    assert(signature_input.size() == 3558);
    // Pin the exact development wire as well as the v4 signature domain. A
    // stale version string or v3 signature transcript must not verify here.
    assert(Sha256Hex(signature_input) ==
           "f870f40854f93044f48ae8e7350bc527b71a9a0c9b55570c998891f0b9a489bd");

    // The admin second factor covers the same transcript under a different
    // domain and is additionally bound to the visitor identity that presented
    // it. Both properties are load-bearing: without the domain change a visitor
    // signature would verify as an admin one, and without the identity binding
    // an admin proof could be lifted onto a different visitor's response.
    const Bytes admin_input = BuildAdminSignatureInput(
        encoded, unsigned_response, channel_binding, identity);
    assert(admin_input.size() == 3560);
    assert(Sha256Hex(admin_input) ==
           "75da6e2313408ecfe8ad7d2641b98243739a183fa0ba8670d7260086fb4d327a");
    assert(admin_input != signature_input);

    // Pin the domain separation itself, not just "the two inputs differ".
    // Appending the visitor identity already makes them differ, so a weaker
    // assertion passes even when both inputs share the visitor domain -- which
    // is exactly the state in which a captured visitor signature would verify
    // as an admin one. Reconstruct what the admin input WOULD be if the domain
    // had not changed, and require that the real one is not that.
    Bytes same_domain = signature_input;
    const auto identity_len = static_cast<std::uint32_t>(identity.size());
    same_domain.push_back(static_cast<std::uint8_t>(identity_len >> 24));
    same_domain.push_back(static_cast<std::uint8_t>(identity_len >> 16));
    same_domain.push_back(static_cast<std::uint8_t>(identity_len >> 8));
    same_domain.push_back(static_cast<std::uint8_t>(identity_len));
    same_domain.insert(same_domain.end(), identity.begin(), identity.end());
    // Only inequality is asserted: the two domain strings are different
    // lengths, so the sizes legitimately differ too. If the domains were ever
    // made equal, this reconstruction would match exactly.
    assert(admin_input != same_domain);
    const Bytes other_identity(identity.size(), 0x5a);
    assert(BuildAdminSignatureInput(encoded, unsigned_response, channel_binding,
                                    other_identity) != admin_input);
    assert(Throws([&] {
        (void)BuildAdminSignatureInput(encoded, unsigned_response,
                                       channel_binding, Bytes{});
    }));

    // Admin identity and admin signature are both-or-neither. A half-supplied
    // claim must be rejected outright rather than read as a plain visitor
    // response with extra data attached.
    const Bytes admin_signature(kCompositeSignatureLen, 0x66);
    assert(Throws([&] {
        (void)BuildResponse(x_public, ciphertext, identity, rekey_window, policy,
                            signature, identity, Bytes{});
    }));
    assert(Throws([&] {
        (void)BuildResponse(x_public, ciphertext, identity, rekey_window, policy,
                            signature, Bytes{}, admin_signature);
    }));
    const auto admin_response = ParseResponse(BuildResponse(
        x_public, ciphertext, identity, rekey_window, policy, signature,
        identity, admin_signature));
    assert(admin_response.claims_admin());
    assert(admin_response.admin_signature == admin_signature);
    // A response without the admin fields must not read as an admin claim.
    assert(!response.claims_admin());

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
    Record zero_window_record = DecodeRecord(
        encoded, RecordKind::Challenge, {1, 2, 3, 4, 5, 6, 7, 8, 9});
    zero_window_record.fields[6].value = Bytes{0, 0};
    const Bytes zero_window = EncodeRecord(RecordKind::Challenge,
                                           zero_window_record.fields);
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

    // dev5 schema 2 and every stale/mismatched profile are hard failures.
    Bytes dev5_schema = encoded;
    dev5_schema[0] = 2;
    assert(Throws([&] { (void)ParseChallenge(dev5_schema); }));

    Record stale_challenge = DecodeRecord(
        encoded, RecordKind::Challenge, {1, 2, 3, 4, 5, 6, 7, 8, 9});
    stale_challenge.fields[8].value =
        Bytes{'c', 'h', 'r', 'o', 'm', 'e', '1', '5', '0'};
    assert(Throws([&] {
        (void)ParseChallenge(EncodeRecord(RecordKind::Challenge,
                                          stale_challenge.fields));
    }));

    Record stale_response = DecodeRecord(
        BuildResponse(x_public, ciphertext, identity, rekey_window, policy,
                      signature),
        RecordKind::Response, {1, 2, 3, 4, 5, 6, 7, 8, 9});
    stale_response.fields[5].value = Bytes{'s', 't', 'a', 'l', 'e'};
    assert(Throws([&] {
        (void)ParseResponse(EncodeRecord(RecordKind::Response,
                                         stale_response.fields));
    }));

    Record stale_auth_ok = DecodeRecord(BuildAuthOk(info), RecordKind::AuthOk,
                                        {1, 2, 3});
    stale_auth_ok.fields[2].value = Bytes{'s', 't', 'a', 'l', 'e'};
    assert(Throws([&] {
        (void)ParseAuthOk(EncodeRecord(RecordKind::AuthOk,
                                       stale_auth_ok.fields));
    }));

    assert(Throws([&] {
        (void)EncodeRecord(RecordKind::Challenge,
                           {{1, true, Bytes{'a'}}, {1, true, Bytes{'b'}}});
    }));

    std::vector<Field> too_many_fields;
    for (std::uint16_t id = 1; id <= 65; ++id) {
        too_many_fields.push_back(
            Field{static_cast<std::uint8_t>(id), false, {}});
    }
    assert(Throws([&] {
        (void)EncodeRecord(RecordKind::Challenge, too_many_fields);
    }));

    const Bytes unknown_critical = EncodeRecord(RecordKind::Challenge, {
        {1, true, Bytes(kTransportVersion.begin(), kTransportVersion.end())},
        {2, true, challenge}, {3, true, kem_public}, {4, true, x_public},
        {5, true, psk_salt}, {6, true, transcript_salt},
        {7, true, Bytes{0, 8}},
        {8, true, Bytes(20, 1)},
        {9, true, Bytes(kTransportProfile.begin(), kTransportProfile.end())},
        {10, true, Bytes{0}},
    });
    assert(Throws([&] { (void)ParseChallenge(unknown_critical); }));
    return 0;
}
