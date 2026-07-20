#include "core/security/auth_v2.hpp"

#include <cassert>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>

#include <openssl/evp.h>

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
    const Bytes encoded = BuildChallenge(challenge, kem_public, x_public,
                                         psk_salt, transcript_salt);
    assert(encoded.size() == 1744);
    assert(Sha256Hex(encoded) ==
           "c3b8010ba56d0d26b9215b38c60e183de87bd4558b0e45b880543af2e4efbc43");
    const auto parsed = ParseChallenge(encoded);
    assert(parsed.challenge == challenge);
    assert(parsed.mlkem_public_key == kem_public);

    const Bytes ciphertext(1568, 0x66);
    const Bytes identity{'i', 'd'};
    const Bytes unsigned_response = BuildUnsignedResponse(x_public, ciphertext,
                                                          identity);
    assert(unsigned_response.size() == 1624);
    assert(Sha256Hex(unsigned_response) ==
           "58908d07af8efb03affcec05c6ac232c336639d0e4a9c4e3bbcfa26a3b63b013");
    const Bytes signature(64, 0x77);
    const auto response = ParseResponse(BuildResponse(
        x_public, ciphertext, identity, signature));
    assert(response.signature == signature);
    const Bytes signature_input = BuildSignatureInput(encoded, unsigned_response);
    assert(signature_input.size() == 3402);
    assert(Sha256Hex(signature_input) ==
           "a24a8e4fdebc92adf629d23118a3e00857fb3a5aaa14d1b7620ce6f6bb0c658f");

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
        {7, true, Bytes{0}},
    });
    assert(Throws([&] { (void)ParseChallenge(unknown_critical); }));
    return 0;
}
