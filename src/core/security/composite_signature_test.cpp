/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Properties of the composite (Ed25519 + ML-DSA-87) identity.
//
// The property this file exists to defend is that the composite is an AND, not
// an OR. An OR-composite is weaker than either algorithm alone, because forging
// either half would suffice -- and it is an easy mistake to make when wiring
// two verifiers together. Both single-half-forgery cases are tested explicitly.

// These security checks must remain active in RelWithDebInfo, where CMake
// normally defines NDEBUG and would otherwise compile every assert away.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <iostream>
#include <string>

#include "core/security/crypto.hpp"

namespace {

yume::crypto::Bytes message(const std::string& text) {
    return yume::crypto::Bytes(text.begin(), text.end());
}

void test_roundtrip_and_sizes() {
    const auto keys = yume::crypto::generate_composite_keypair();
    const auto msg = message("yume/2.0/auth-signature/v4 transcript");
    const auto sig = yume::crypto::sign_composite(keys, msg);

    // Fixed width: parsing must never be steered by an attacker-supplied length.
    assert(sig.size() == yume::crypto::kCompositeSignatureLen);
    assert(yume::crypto::kCompositeSignatureLen == 64 + 4627);

    assert(yume::crypto::verify_composite(keys.classical.public_key.get(),
                                          keys.pq.public_key.get(), msg, sig));
}

void test_wrong_message_fails() {
    const auto keys = yume::crypto::generate_composite_keypair();
    const auto sig = yume::crypto::sign_composite(keys, message("admin"));
    assert(!yume::crypto::verify_composite(keys.classical.public_key.get(),
                                           keys.pq.public_key.get(),
                                           message("visitor"), sig));
}

void test_forging_one_half_is_not_enough() {
    const auto keys = yume::crypto::generate_composite_keypair();
    const auto other = yume::crypto::generate_composite_keypair();
    const auto msg = message("privilege escalation attempt");
    const auto good = yume::crypto::sign_composite(keys, msg);
    const auto forged = yume::crypto::sign_composite(other, msg);

    // Valid Ed25519 half, wrong ML-DSA half.
    yume::crypto::Bytes classical_only(good.begin(),
                                       good.begin() + yume::crypto::kEd25519SignatureLen);
    classical_only.insert(classical_only.end(),
                          forged.begin() + yume::crypto::kEd25519SignatureLen,
                          forged.end());
    assert(!yume::crypto::verify_composite(keys.classical.public_key.get(),
                                           keys.pq.public_key.get(),
                                           msg, classical_only));

    // Wrong Ed25519 half, valid ML-DSA half.
    yume::crypto::Bytes pq_only(forged.begin(),
                                forged.begin() + yume::crypto::kEd25519SignatureLen);
    pq_only.insert(pq_only.end(),
                   good.begin() + yume::crypto::kEd25519SignatureLen, good.end());
    assert(!yume::crypto::verify_composite(keys.classical.public_key.get(),
                                           keys.pq.public_key.get(),
                                           msg, pq_only));
}

void test_malformed_inputs_fail_closed() {
    const auto keys = yume::crypto::generate_composite_keypair();
    const auto msg = message("m");
    const auto sig = yume::crypto::sign_composite(keys, msg);

    assert(!yume::crypto::verify_composite(nullptr, keys.pq.public_key.get(), msg, sig));
    assert(!yume::crypto::verify_composite(keys.classical.public_key.get(), nullptr, msg, sig));
    assert(!yume::crypto::verify_composite(keys.classical.public_key.get(),
                                           keys.pq.public_key.get(), msg, {}));

    yume::crypto::Bytes truncated(sig.begin(), sig.end() - 1);
    assert(!yume::crypto::verify_composite(keys.classical.public_key.get(),
                                           keys.pq.public_key.get(), msg, truncated));

    yume::crypto::Bytes extended = sig;
    extended.push_back(0);
    assert(!yume::crypto::verify_composite(keys.classical.public_key.get(),
                                           keys.pq.public_key.get(), msg, extended));

    const auto encoded = yume::crypto::encode_composite_identity(
        keys.classical.public_key.get(), keys.pq.public_key.get());
    assert(yume::crypto::parse_composite_identity(encoded).valid());

    auto leading_junk = encoded;
    leading_junk.insert(leading_junk.begin(), {'x', '\n'});
    assert(!yume::crypto::parse_composite_identity(leading_junk).valid());

    auto trailing_junk = encoded;
    trailing_junk.insert(trailing_junk.end(), {'\n', 'x'});
    assert(!yume::crypto::parse_composite_identity(trailing_junk).valid());

    auto third_block = encoded;
    const auto extra = yume::crypto::encode_public_key_pem(
        keys.classical.public_key.get());
    third_block.insert(third_block.end(), extra.begin(), extra.end());
    assert(!yume::crypto::parse_composite_identity(third_block).valid());
}

void test_distinct_keypairs() {
    // Two generations must not collide; a constant key would silently make
    // every identity interchangeable.
    const auto a = yume::crypto::generate_composite_keypair();
    const auto b = yume::crypto::generate_composite_keypair();
    const auto msg = message("distinctness");
    const auto sig_a = yume::crypto::sign_composite(a, msg);
    assert(!yume::crypto::verify_composite(b.classical.public_key.get(),
                                           b.pq.public_key.get(), msg, sig_a));
}

}  // namespace

int main() {
    test_roundtrip_and_sizes();
    test_wrong_message_fails();
    test_forging_one_half_is_not_enough();
    test_malformed_inputs_fail_closed();
    test_distinct_keypairs();
    std::cout << "composite_signature_test ok\n";
    return 0;
}
