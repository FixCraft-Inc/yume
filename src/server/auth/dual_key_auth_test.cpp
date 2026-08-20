/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// The dual-key requirement, tested from the store side.
//
// The property is: a visitor needs one key, an admin needs two, and the second
// must come from a separate list. Every test here is a way that property could
// be quietly lost -- by merging halves across entries, by accepting a
// half-written store, or by letting an admin flag survive in the visitor file.

// These security checks must remain active in RelWithDebInfo, where CMake
// normally defines NDEBUG and would otherwise compile every assert away.
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <cassert>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <unistd.h>
#include <iostream>
#include <string>

#include "core/security/crypto.hpp"
#include "server/auth/auth.hpp"

namespace {

namespace fs = std::filesystem;

struct TempDir {
    fs::path path;
    TempDir() {
        path = fs::temp_directory_path() /
               ("yume-dual-key-" + std::to_string(::getpid()));
        fs::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

std::string pem_of(const yume::crypto::CompositeKeyPair& keys) {
    const auto bytes = yume::crypto::encode_composite_identity(
        keys.classical.public_key.get(), keys.pq.public_key.get());
    return std::string(bytes.begin(), bytes.end());
}

void write_file(const fs::path& path, const std::string& contents) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << contents;
}

yume::crypto::CompositePublicKey public_view(
    const yume::crypto::CompositeKeyPair& keys) {
    const auto bytes = yume::crypto::encode_composite_identity(
        keys.classical.public_key.get(), keys.pq.public_key.get());
    return yume::crypto::parse_composite_identity(bytes);
}

bool throws(const std::function<void()>& fn) {
    try {
        fn();
        return false;
    } catch (const std::exception&) {
        return true;
    }
}

void test_store_roundtrip_and_membership() {
    TempDir dir;
    const auto visitor = yume::crypto::generate_composite_keypair();
    const auto stranger = yume::crypto::generate_composite_keypair();
    const auto store = dir.path / "authorized_keys";
    write_file(store, pem_of(visitor));

    const auto loaded = yume::server::load_authorized_keys(store.string());
    assert(loaded.size() == 1);
    assert(yume::server::is_composite_authorized(public_view(visitor), loaded));
    assert(!yume::server::is_composite_authorized(public_view(stranger), loaded));
}

void test_halves_cannot_be_mixed_across_entries() {
    // The reason entries are stored as one canonical blob rather than two
    // independent keys. If the halves were matched separately, someone holding
    // A's Ed25519 key and B's ML-DSA key could assemble an identity that
    // matches neither owner's actual credential.
    TempDir dir;
    const auto a = yume::crypto::generate_composite_keypair();
    const auto b = yume::crypto::generate_composite_keypair();
    const auto store = dir.path / "authorized_keys";
    write_file(store, pem_of(a) + pem_of(b));

    const auto loaded = yume::server::load_authorized_keys(store.string());
    assert(loaded.size() == 2);
    assert(yume::server::is_composite_authorized(public_view(a), loaded));
    assert(yume::server::is_composite_authorized(public_view(b), loaded));

    yume::crypto::CompositePublicKey frankenstein;
    const auto a_bytes = yume::crypto::encode_composite_identity(
        a.classical.public_key.get(), a.pq.public_key.get());
    const auto b_bytes = yume::crypto::encode_composite_identity(
        b.classical.public_key.get(), b.pq.public_key.get());
    auto a_view = yume::crypto::parse_composite_identity(a_bytes);
    auto b_view = yume::crypto::parse_composite_identity(b_bytes);
    frankenstein.classical = std::move(a_view.classical);
    frankenstein.pq = std::move(b_view.pq);
    assert(frankenstein.valid());
    assert(!yume::server::is_composite_authorized(frankenstein, loaded));
}

void test_incomplete_entry_is_refused() {
    // A half-written authorized_keys file must stop the server, not silently
    // authorize nothing -- an operator would not notice the difference until
    // the wrong person could or could not connect.
    TempDir dir;
    const auto visitor = yume::crypto::generate_composite_keypair();
    const auto only_classical = yume::crypto::encode_public_key_pem(
        visitor.classical.public_key.get());
    const auto store = dir.path / "half";
    write_file(store, std::string(only_classical.begin(), only_classical.end()));
    assert(throws([&] { (void)yume::server::load_authorized_keys(store.string()); }));
}

void test_non_pem_material_is_refused() {
    TempDir dir;
    const auto visitor = yume::crypto::generate_composite_keypair();
    const auto store = dir.path / "junk";

    write_file(store, "not a key\n" + pem_of(visitor));
    assert(throws([&] { (void)yume::server::load_authorized_keys(store.string()); }));

    write_file(store, pem_of(visitor) + "not a key\n");
    assert(throws([&] { (void)yume::server::load_authorized_keys(store.string()); }));
}

void test_wrong_algorithm_order_is_refused() {
    TempDir dir;
    const auto visitor = yume::crypto::generate_composite_keypair();
    const auto classical = yume::crypto::encode_public_key_pem(
        visitor.classical.public_key.get());
    const auto pq = yume::crypto::encode_public_key_pem(
        visitor.pq.public_key.get());
    const auto store = dir.path / "swapped";
    write_file(store, std::string(pq.begin(), pq.end()) +
                          std::string(classical.begin(), classical.end()));
    assert(throws([&] { (void)yume::server::load_authorized_keys(store.string()); }));
}

void test_admin_store_is_separate() {
    // Loading the same path through both entry points yields the same content,
    // but the server holds them as two stores. What matters is that membership
    // in one is not membership in the other, which is enforced by the caller
    // holding two distinct vectors -- so this test pins that a key enrolled as
    // admin is not thereby a visitor.
    TempDir dir;
    const auto visitor = yume::crypto::generate_composite_keypair();
    const auto admin = yume::crypto::generate_composite_keypair();
    const auto visitor_store = dir.path / "authorized_keys";
    const auto admin_store = dir.path / "admin_keys";
    write_file(visitor_store, pem_of(visitor));
    write_file(admin_store, pem_of(admin));

    const auto visitors = yume::server::load_authorized_keys(visitor_store.string());
    const auto admins = yume::server::load_admin_keys(admin_store.string());

    assert(yume::server::is_composite_authorized(public_view(visitor), visitors));
    assert(!yume::server::is_composite_authorized(public_view(visitor), admins));
    assert(yume::server::is_composite_authorized(public_view(admin), admins));
    assert(!yume::server::is_composite_authorized(public_view(admin), visitors));
}

void test_missing_admin_store_grants_nothing() {
    // Fail closed: no admin file means admin is impossible, not unrestricted.
    const auto admins = yume::server::load_admin_keys("");
    assert(admins.empty());
    const auto anyone = yume::crypto::generate_composite_keypair();
    assert(!yume::server::is_composite_authorized(public_view(anyone), admins));
}

void test_admin_flags_in_visitor_policy_are_refused() {
    // The old escalation path: a boolean in the policy file granting admin to
    // whoever holds one key. It must now stop the server rather than be
    // ignored. Silently clearing would leave an operator believing a key is
    // privileged when it is not -- the mirror of the failure being prevented.
    TempDir dir;
    const auto meta = dir.path / "meta.json";
    for (const char* flag : {"allow_inbound_admin", "allow_outbound_admin",
                             "control_full"}) {
        // Root maps fingerprint -> entry directly; there is no "keys" wrapper.
        write_file(meta, std::string(R"({"abc123":{"permissions":{")") + flag +
                             R"(":true}}})");
        const bool refused = throws([&] {
            (void)yume::server::load_auth_policies(meta.string());
        });
        if (!refused) {
            std::fprintf(stderr, "policy flag %s was NOT refused\n", flag);
        }
        assert(refused);
    }
    // A policy with no admin-granting flags still loads.
    write_file(meta, R"({"abc123":{"permissions":{"allow_chat":true}}})");
    (void)yume::server::load_auth_policies(meta.string());
}

}  // namespace

int main() {
    test_store_roundtrip_and_membership();
    test_halves_cannot_be_mixed_across_entries();
    test_incomplete_entry_is_refused();
    test_non_pem_material_is_refused();
    test_wrong_algorithm_order_is_refused();
    test_admin_store_is_separate();
    test_missing_admin_store_grants_nothing();
    test_admin_flags_in_visitor_policy_are_refused();
    std::cout << "dual_key_auth_test ok\n";
    return 0;
}
