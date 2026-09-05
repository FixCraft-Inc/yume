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
#include <atomic>
#include <barrier>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <iostream>
#include <iterator>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "core/runtime/file_transaction_lock.hpp"
#include "core/security/crypto.hpp"
#include "core/security/secret_file.hpp"
#include "facade/keys/keys.hpp"
#include "server/auth/auth.hpp"
#include "server/cli/key.hpp"
#include "server/config/config.hpp"
#include "server/runtime/manager.hpp"

namespace {

namespace fs = std::filesystem;

long current_process_id() noexcept {
#if defined(_WIN32)
    return static_cast<long>(::_getpid());
#else
    return static_cast<long>(::getpid());
#endif
}

struct TempDir {
    fs::path path;
    TempDir() {
        path = fs::temp_directory_path() /
               ("yume-dual-key-" + std::to_string(current_process_id()));
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

std::string read_file(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

void write_test_tls_identity(const fs::path& certificate_path,
                             const fs::path& private_key_path) {
    using KeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using CertPtr = std::unique_ptr<X509, decltype(&X509_free)>;
    using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

    KeyPtr key(EVP_EC_gen("P-256"), EVP_PKEY_free);
    assert(key);
    CertPtr certificate(X509_new(), X509_free);
    assert(certificate);
    assert(X509_set_version(certificate.get(), 2) == 1);
    assert(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1) == 1);
    assert(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0));
    assert(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600));
    assert(X509_set_pubkey(certificate.get(), key.get()) == 1);
    X509_NAME* name = X509_get_subject_name(certificate.get());
    assert(name);
    assert(X509_NAME_add_entry_by_txt(
               name, "CN", MBSTRING_ASC,
               reinterpret_cast<const unsigned char*>("yume-lock-test"), -1,
               -1, 0) == 1);
    assert(X509_set_issuer_name(certificate.get(), name) == 1);
    assert(X509_sign(certificate.get(), key.get(), EVP_sha256()) > 0);

    BioPtr certificate_bio(BIO_new(BIO_s_mem()), BIO_free);
    BioPtr key_bio(BIO_new(BIO_s_mem()), BIO_free);
    assert(certificate_bio && key_bio);
    assert(PEM_write_bio_X509(certificate_bio.get(), certificate.get()) == 1);
    assert(PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr, nullptr,
                                    0, nullptr, nullptr) == 1);
    char* certificate_data = nullptr;
    char* key_data = nullptr;
    const long certificate_size =
        BIO_get_mem_data(certificate_bio.get(), &certificate_data);
    const long key_size = BIO_get_mem_data(key_bio.get(), &key_data);
    assert(certificate_size > 0 && certificate_data);
    assert(key_size > 0 && key_data);
    write_file(certificate_path,
               std::string(certificate_data,
                           static_cast<std::size_t>(certificate_size)));
    write_file(private_key_path,
               std::string(key_data, static_cast<std::size_t>(key_size)));
}

yume::server::cli::CliCommandResult run_manager_ui(
    yume::server::ServerConfig* config,
    const std::string& input_text) {
    std::istringstream input(input_text);
    std::ostringstream output;
    auto* old_input = std::cin.rdbuf(input.rdbuf());
    auto* old_output = std::cout.rdbuf(output.rdbuf());
    std::cin.clear();
    yume::server::cli::ServerKeyCommand command;
    yume::server::cli::CliCommandResult result;
    try {
        result = yume::server::cli::run_server_manager_ui(*config, command);
    } catch (...) {
        std::cin.rdbuf(old_input);
        std::cout.rdbuf(old_output);
        std::cin.clear();
        throw;
    }
    std::cin.rdbuf(old_input);
    std::cout.rdbuf(old_output);
    std::cin.clear();
    return result;
}

std::pair<yume::server::cli::CliCommandResult, std::string> run_key_command(
    yume::server::ServerConfig* config,
    yume::server::cli::ServerKeyCommand command) {
    std::ostringstream output;
    auto* old_output = std::cout.rdbuf(output.rdbuf());
    yume::server::cli::CliCommandResult result;
    try {
        result = yume::server::cli::run_server_key_command(*config, command);
    } catch (...) {
        std::cout.rdbuf(old_output);
        throw;
    }
    std::cout.rdbuf(old_output);
    return {result, output.str()};
}

std::size_t occurrence_count(const std::string& text,
                             const std::string& needle) {
    std::size_t count = 0;
    std::size_t position = 0;
    while ((position = text.find(needle, position)) != std::string::npos) {
        ++count;
        position += needle.size();
    }
    return count;
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

void test_file_transaction_lock_retry_and_process_serialization() {
    TempDir dir;
    const auto first_resource = dir.path / "a-resource";
    const auto failing_resource = dir.path / "z-resource";
    const auto failing_sidecar =
        fs::path(failing_resource.string() + ".yume.lock");
    fs::create_directory(failing_sidecar);

    std::string error;
    {
        yume::runtime::FileTransactionLock transaction;
        assert(!transaction.Acquire({first_resource, failing_resource},
                                    &error));
        assert(!transaction.owns_lock());
        assert(!error.empty());

        // A failed multi-resource acquisition must release every earlier
        // descriptor and process-local mutex so the same object can retry.
        assert(fs::remove(failing_sidecar));
        error.clear();
        assert(transaction.Acquire({first_resource, failing_resource},
                                   &error));
        assert(transaction.owns_lock());
        assert(error.empty());
    }
    assert(fs::is_regular_file(
        fs::path(first_resource.string() + ".yume.lock")));
    assert(fs::is_regular_file(failing_sidecar));

    auto first = std::make_unique<yume::runtime::FileTransactionLock>();
    assert(first->Acquire({first_resource}, &error));
    std::promise<void> second_started;
    std::promise<bool> second_acquired;
    auto started = second_started.get_future();
    auto acquired = second_acquired.get_future();
    std::thread contender([&] {
        yume::runtime::FileTransactionLock second;
        second_started.set_value();
        std::string contender_error;
        second_acquired.set_value(
            second.Acquire({first_resource}, &contender_error));
    });
    started.get();
    assert(acquired.wait_for(std::chrono::milliseconds(100)) ==
           std::future_status::timeout);
    first.reset();
    assert(acquired.wait_for(std::chrono::seconds(5)) ==
           std::future_status::ready);
    assert(acquired.get());
    contender.join();

    constexpr int kThreadCount = 6;
    constexpr int kIterations = 50;
    std::barrier begin(kThreadCount + 1);
    std::atomic<int> inside{0};
    std::atomic<bool> overlapped{false};
    std::vector<std::thread> contenders;
    contenders.reserve(kThreadCount);
    for (int thread_index = 0; thread_index < kThreadCount; ++thread_index) {
        contenders.emplace_back([&] {
            begin.arrive_and_wait();
            for (int iteration = 0; iteration < kIterations; ++iteration) {
                yume::runtime::FileTransactionLock transaction;
                std::string lock_error;
                assert(transaction.Acquire({first_resource}, &lock_error));
                if (inside.fetch_add(1, std::memory_order_acq_rel) != 0) {
                    overlapped.store(true, std::memory_order_release);
                }
                std::this_thread::yield();
                assert(inside.fetch_sub(1, std::memory_order_acq_rel) == 1);
            }
        });
    }
    begin.arrive_and_wait();
    for (auto& thread : contenders) thread.join();
    assert(!overlapped.load(std::memory_order_acquire));
}

void test_manager_auth_snapshot_waits_for_transaction_writer() {
    TempDir dir;
    const auto visitor = yume::crypto::generate_composite_keypair();
    yume::server::ServerConfig config;
    config.auth_keys = (dir.path / "manager-auth-keys").string();
    config.auth_keys_meta = (dir.path / "manager-auth-meta.json").string();
    config.operator_keys = (dir.path / "manager-operator-keys").string();
    config.operator_keys_meta =
        (dir.path / "manager-operator-meta.json").string();
    config.admin_keys = (dir.path / "manager-admin-keys").string();
    config.tls_cert = (dir.path / "manager-cert.pem").string();
    config.tls_key = (dir.path / "manager-key.pem").string();
    config.listen_address = "127.0.0.1";
    config.listen_port = 0;
    write_file(config.auth_keys, pem_of(visitor));
    const std::string visitor_fingerprint =
        yume::crypto::composite_fingerprint(public_view(visitor));
    write_file(config.auth_keys_meta,
               "{\"" + visitor_fingerprint +
                   R"(":{"permissions":{"allow_chat":false}}})");
    write_file(config.operator_keys, "");
    write_file(config.operator_keys_meta, "{}");
    write_file(config.admin_keys, "");
    write_test_tls_identity(config.tls_cert, config.tls_key);

    const std::vector<fs::path> resources{
        config.auth_keys, config.auth_keys_meta, config.operator_keys,
        config.operator_keys_meta, config.admin_keys};
    boost::asio::io_context io;
    yume::server::Manager manager(io, config);

    auto paused_writer =
        std::make_unique<yume::runtime::FileTransactionLock>();
    std::string lock_error;
    assert(paused_writer->Acquire(resources, &lock_error));
    std::promise<void> start_entered;
    std::promise<std::string> start_outcome;
    auto entered = start_entered.get_future();
    auto outcome = start_outcome.get_future();
    std::thread starter([&] {
        start_entered.set_value();
        try {
            manager.start();
            start_outcome.set_value("");
        } catch (const std::exception& ex) {
            start_outcome.set_value(ex.what());
        }
    });
    entered.get();
    assert(outcome.wait_for(std::chrono::milliseconds(100)) ==
           std::future_status::timeout);
    // Simulate a writer paused between the two publications of a revoke. The
    // reader must not consume the old key together with the new empty policy.
    write_file(config.auth_keys, "");
    write_file(config.auth_keys_meta, "{}");
    paused_writer.reset();
    assert(outcome.wait_for(std::chrono::seconds(5)) ==
           std::future_status::ready);
    assert(outcome.get().empty());
    starter.join();
    manager.stop();

    write_file(config.auth_keys, pem_of(visitor));
    write_file(config.auth_keys_meta,
               "{\"" + visitor_fingerprint +
                   R"(":{"permissions":{"allow_chat":false}}})");
    paused_writer = std::make_unique<yume::runtime::FileTransactionLock>();
    assert(paused_writer->Acquire(resources, &lock_error));
    std::promise<void> reload_entered;
    std::promise<std::pair<bool, std::string>> reload_outcome;
    auto reload_started = reload_entered.get_future();
    auto reload_result = reload_outcome.get_future();
    std::thread reloader([&] {
        reload_entered.set_value();
        std::string error;
        const bool result = manager.reload_auth(&error);
        reload_outcome.set_value({result, std::move(error)});
    });
    reload_started.get();
    assert(reload_result.wait_for(std::chrono::milliseconds(100)) ==
           std::future_status::timeout);
    write_file(config.auth_keys, "");
    write_file(config.auth_keys_meta, "{}");
    paused_writer.reset();
    assert(reload_result.wait_for(std::chrono::seconds(5)) ==
           std::future_status::ready);
    const auto [reloaded, reload_error] = reload_result.get();
    assert(reloaded);
    assert(reload_error.empty());
    reloader.join();
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

void test_auth_policy_loader_is_type_strict_and_exact() {
    TempDir dir;
    const auto meta = dir.path / "strict-meta.json";
    for (const char* malformed : {
             R"({"abc":"silently ignored before strict validation"})",
             R"({"abc":{"permissions":{"allow_chat":"yes"}}})",
             R"({"abc":{"priority":0}})",
             R"({"abc":{"priority":101}})",
             R"({"abc":{"priority":4294967396}})",
             R"({"abc":{"max_sessions":18446744073709551615}})"}) {
        write_file(meta, malformed);
        assert(throws(
            [&] { (void)yume::server::load_auth_policies(meta.string()); }));
    }
    write_file(meta,
               R"({"abc":{"weight":1.5,"permissions":{"allow_chat":false}}})");
    const auto policies = yume::server::load_auth_policies(meta.string());
    assert(policies.at("abc").weight == 1.5);
    assert(policies.at("abc").allow_chat == false);

    const auto directory = dir.path / "metadata-directory";
    assert(fs::create_directory(directory));
    assert(throws(
        [&] { (void)yume::server::load_auth_policies(directory.string()); }));

    const auto oversized = dir.path / "oversized-meta.json";
    {
        std::ofstream output(oversized, std::ios::binary);
        output.seekp(16 * 1024 * 1024);
        output.put('x');
    }
    assert(throws(
        [&] { (void)yume::server::load_auth_policies(oversized.string()); }));
}

void test_cli_manages_whole_composite_identities() {
    using yume::server::cli::ServerKeyCommand;
    using yume::server::cli::run_server_key_command;

    TempDir dir;
    const auto first = yume::crypto::generate_composite_keypair();
    const auto second = yume::crypto::generate_composite_keypair();
    const auto first_public = dir.path / "first.pub";
    const auto second_public = dir.path / "second.pub";
    write_file(first_public, pem_of(first));
    write_file(second_public, pem_of(second));

    yume::server::ServerConfig config;
    config.auth_keys = (dir.path / "authorized_keys").string();
    config.auth_keys_meta = (dir.path / "authorized_keys.json").string();

    std::string first_fingerprint;
    std::string second_fingerprint;
    assert(yume::server::cli::append_authorized_public_key(
        config, first_public.string(), "alpha", &first_fingerprint));
    assert(yume::server::cli::append_authorized_public_key(
        config, second_public.string(), "beta", &second_fingerprint));
    assert(first_fingerprint ==
           yume::crypto::composite_fingerprint(public_view(first)));
    assert(second_fingerprint ==
           yume::crypto::composite_fingerprint(public_view(second)));
    assert(yume::server::load_authorized_keys(config.auth_keys).size() == 2);

    ServerKeyCommand list;
    list.list = true;
    const auto [list_result, list_output] = run_key_command(&config, list);
    assert(list_result.handled && list_result.exit_code == 0);
    assert(occurrence_count(list_output, first_fingerprint) == 1);
    assert(occurrence_count(list_output, second_fingerprint) == 1);
    assert(list_output.find(yume::server::fingerprint_pubkey(
               first.classical.public_key.get())) == std::string::npos);
    assert(list_output.find(yume::server::fingerprint_pubkey(
               first.pq.public_key.get())) == std::string::npos);

    // A half-key fingerprint is not an identity selector. Accepting it used to
    // remove only one PEM block and leave the store structurally corrupt.
    const std::string classical_fingerprint =
        yume::server::fingerprint_pubkey(first.classical.public_key.get());
    const std::string before_half_remove = read_file(config.auth_keys);
    ServerKeyCommand half_remove;
    half_remove.remove = classical_fingerprint;
    const auto half_result = run_server_key_command(config, half_remove);
    assert(half_result.handled && half_result.exit_code == 1);
    assert(read_file(config.auth_keys) == before_half_remove);
    assert(yume::server::load_authorized_keys(config.auth_keys).size() == 2);

    ServerKeyCommand rename;
    rename.alias = first_fingerprint;
    rename.alias_value = "renamed-alpha";
    const auto rename_result = run_server_key_command(config, rename);
    assert(rename_result.handled && rename_result.exit_code == 0);
    auto metadata = nlohmann::json::parse(read_file(config.auth_keys_meta));
    assert(metadata[first_fingerprint]["alias"] == "renamed-alpha");

    // Aliases are selectors, so duplicates would make revocation ambiguous.
    const std::string metadata_before_duplicate = read_file(config.auth_keys_meta);
    ServerKeyCommand duplicate_alias;
    duplicate_alias.alias = first_fingerprint;
    duplicate_alias.alias_value = "beta";
    const auto duplicate_result =
        run_server_key_command(config, duplicate_alias);
    assert(duplicate_result.handled && duplicate_result.exit_code == 1);
    assert(read_file(config.auth_keys_meta) == metadata_before_duplicate);

    ServerKeyCommand remove;
    remove.remove = "beta";
    const auto remove_result = run_server_key_command(config, remove);
    assert(remove_result.handled && remove_result.exit_code == 0);
    const auto remaining = yume::server::load_authorized_keys(config.auth_keys);
    assert(remaining.size() == 1);
    assert(remaining.front() ==
           yume::crypto::composite_canonical_encoding(public_view(first)));
    metadata = nlohmann::json::parse(read_file(config.auth_keys_meta));
    assert(!metadata.contains(second_fingerprint));

    // Malformed metadata must not be reset to an empty object by aliasing.
    const std::string malformed_metadata = R"({"broken":)";
    write_file(config.auth_keys_meta, malformed_metadata);
    const std::string store_before_bad_meta = read_file(config.auth_keys);
    ServerKeyCommand alias_with_bad_meta;
    alias_with_bad_meta.alias = first_fingerprint;
    alias_with_bad_meta.alias_value = "must-not-land";
    const auto bad_meta_result =
        run_server_key_command(config, alias_with_bad_meta);
    assert(bad_meta_result.handled && bad_meta_result.exit_code == 1);
    assert(read_file(config.auth_keys_meta) == malformed_metadata);
    assert(read_file(config.auth_keys) == store_before_bad_meta);

    // A malformed existing key store is also preserved during enrollment.
    const auto only_classical = yume::crypto::encode_public_key_pem(
        first.classical.public_key.get());
    const std::string incomplete(only_classical.begin(), only_classical.end());
    write_file(config.auth_keys, incomplete);
    write_file(config.auth_keys_meta, "{}");
    assert(!yume::server::cli::append_authorized_public_key(
        config, second_public.string(), "gamma"));
    assert(read_file(config.auth_keys) == incomplete);
}

void test_cli_rejects_non_exact_candidates_and_typed_metadata() {
    TempDir dir;
    const auto first = yume::crypto::generate_composite_keypair();
    const auto second = yume::crypto::generate_composite_keypair();
    const auto first_public = dir.path / "first.pub";
    const auto multiple_public = dir.path / "multiple.pub";
    const auto trailing_public = dir.path / "trailing.pub";
    write_file(first_public, pem_of(first));
    write_file(multiple_public, pem_of(first) + pem_of(second));
    write_file(trailing_public, pem_of(first) + "trailing-data\n");

    yume::server::ServerConfig config;
    config.auth_keys = (dir.path / "authorized_keys").string();
    config.auth_keys_meta = (dir.path / "authorized_keys.json").string();
    write_file(config.auth_keys, pem_of(second));
    const std::string original_store = read_file(config.auth_keys);
    const std::string original_metadata =
        R"({"sentinel":{"alias":"keep"}})";
    write_file(config.auth_keys_meta, original_metadata);

    std::string fingerprint = "must-be-cleared";
    assert(!yume::server::cli::append_authorized_public_key(
        config, multiple_public.string(), "multiple", &fingerprint));
    assert(fingerprint.empty());
    assert(read_file(config.auth_keys) == original_store);
    assert(read_file(config.auth_keys_meta) == original_metadata);
    assert(!yume::server::cli::append_authorized_public_key(
        config, trailing_public.string(), "trailing"));
    assert(read_file(config.auth_keys) == original_store);
    assert(read_file(config.auth_keys_meta) == original_metadata);

    const std::string wrong_typed_metadata =
        R"({"sentinel":{"permissions":{"allow_chat":"yes"}}})";
    write_file(config.auth_keys_meta, wrong_typed_metadata);
    assert(!yume::server::cli::append_authorized_public_key(
        config, first_public.string(), "must-not-land"));
    assert(read_file(config.auth_keys) == original_store);
    assert(read_file(config.auth_keys_meta) == wrong_typed_metadata);

    yume::server::cli::ServerKeyCommand alias;
    alias.alias = yume::crypto::composite_fingerprint(public_view(second));
    alias.alias_value = "also-must-not-land";
    const auto alias_result =
        yume::server::cli::run_server_key_command(config, alias);
    assert(alias_result.handled && alias_result.exit_code == 1);
    assert(read_file(config.auth_keys) == original_store);
    assert(read_file(config.auth_keys_meta) == wrong_typed_metadata);
}

void test_cli_failure_order_is_fail_closed() {
#if !defined(_WIN32)
    TempDir dir;
    const auto identity = yume::crypto::generate_composite_keypair();
    const auto public_path = dir.path / "identity.pub";
    write_file(public_path, pem_of(identity));
    const std::string unique = std::to_string(current_process_id());

    // If metadata cannot be published, authorization must never be attempted.
    yume::server::ServerConfig metadata_failure;
    metadata_failure.auth_keys = (dir.path / "metadata-failure-keys").string();
    metadata_failure.auth_keys_meta =
        "/proc/yume-metadata-write-failure-" + unique;
    std::string failed_fingerprint = "must-be-cleared";
    assert(!yume::server::cli::append_authorized_public_key(
        metadata_failure, public_path.string(), "blocked",
        &failed_fingerprint));
    assert(failed_fingerprint.empty());
    assert(!fs::exists(metadata_failure.auth_keys));
    assert(!fs::exists(metadata_failure.auth_keys_meta));

    // If auth publication fails after metadata succeeded, the exact metadata
    // snapshot is restored. This is the recoverable in-process transaction;
    // the publication order still fails closed across a crash.
    yume::server::ServerConfig auth_failure;
    auth_failure.auth_keys = "/proc/yume-auth-write-failure-" + unique;
    auth_failure.auth_keys_meta = (dir.path / "rollback-meta.json").string();
    const std::string original_metadata =
        "{\n  \"sentinel\": {\"alias\": \"preserve bytes\"}\n}\n";
    write_file(auth_failure.auth_keys_meta, original_metadata);
    assert(!yume::server::cli::append_authorized_public_key(
        auth_failure, public_path.string(), "rolled-back",
        &failed_fingerprint));
    assert(failed_fingerprint.empty());
    assert(!fs::exists(auth_failure.auth_keys));
    assert(read_file(auth_failure.auth_keys_meta) == original_metadata);

    // If the complete transaction cannot be locked, revocation refuses before
    // publication and preserves both stores.
    yume::server::ServerConfig revoke_failure;
    revoke_failure.auth_keys = (dir.path / "revoke-keys").string();
    revoke_failure.auth_keys_meta =
        "/proc/yume-revoke-metadata-failure-" + unique;
    write_file(revoke_failure.auth_keys, pem_of(identity));
    yume::server::cli::ServerKeyCommand remove;
    remove.remove = yume::crypto::composite_fingerprint(public_view(identity));
    const auto remove_result =
        yume::server::cli::run_server_key_command(revoke_failure, remove);
    assert(remove_result.handled && remove_result.exit_code == 1);
    assert(yume::server::load_authorized_keys(revoke_failure.auth_keys).size() ==
           1);
    assert(read_file(revoke_failure.auth_keys) == pem_of(identity));
    assert(!fs::exists(revoke_failure.auth_keys_meta));
#endif
}

void test_facade_key_mutations_are_atomic_and_exact() {
    TempDir dir;
    const auto first = yume::crypto::generate_composite_keypair();
    const auto second = yume::crypto::generate_composite_keypair();
    const std::string first_pem = pem_of(first);
    const std::string second_pem = pem_of(second);
    const std::string first_fingerprint =
        yume::crypto::composite_fingerprint(public_view(first));
    const auto auth_path = dir.path / "facade-authorized-keys";
    const auto meta_path = dir.path / "facade-authorized-keys.json";
    const auto admin_path = dir.path / "facade-admin-keys";

    yume::facade::keys::AuthorizedKeyEntry entry;
    entry.alias = "facade-first";
    std::string error;
    assert(yume::facade::keys::append_authorized(
        auth_path, meta_path, admin_path, first_pem, entry, &error));
    assert(error.empty());
    const auto listed =
        yume::facade::keys::list_authorized(auth_path, meta_path);
    assert(listed.size() == 1);
    assert(listed.front().fingerprint == first_fingerprint);
    assert(listed.front().alias == "facade-first");

    const std::string original_store = read_file(auth_path);
    const std::string original_metadata = read_file(meta_path);
    assert(!yume::facade::keys::append_authorized(
        auth_path, meta_path, admin_path, first_pem + second_pem, entry,
        &error));
    assert(read_file(auth_path) == original_store);
    assert(read_file(meta_path) == original_metadata);

    assert(!yume::facade::keys::append_authorized(
        auth_path, meta_path, auth_path, second_pem, entry, &error));
    assert(read_file(auth_path) == original_store);
    assert(read_file(meta_path) == original_metadata);

    // Facade/GUI enrollment participates in the same visitor/admin
    // disjointness transaction as the CLI.
    write_file(admin_path, second_pem);
    assert(!yume::facade::keys::append_authorized(
        auth_path, meta_path, admin_path, second_pem, entry, &error));
    assert(read_file(auth_path) == original_store);
    assert(read_file(meta_path) == original_metadata);
    assert(fs::remove(admin_path));

    const std::string malformed_metadata = R"({"broken":)";
    write_file(meta_path, malformed_metadata);
    assert(!yume::facade::keys::append_authorized(
        auth_path, meta_path, admin_path, second_pem, entry, &error));
    assert(read_file(auth_path) == original_store);
    assert(read_file(meta_path) == malformed_metadata);

    const auto classical = yume::crypto::encode_public_key_pem(
        first.classical.public_key.get());
    const std::string incomplete(classical.begin(), classical.end());
    write_file(auth_path, incomplete);
    write_file(meta_path, "{}");
    yume::facade::keys::AuthorizedKeyEntry patch;
    patch.alias = "must-not-land";
    assert(!yume::facade::keys::update_authorized(
        auth_path, meta_path, first_fingerprint, patch, &error));
    assert(read_file(auth_path) == incomplete);
    assert(read_file(meta_path) == "{}");

    const auto federation_auth = dir.path / "facade-federation-keys";
    const auto federation_meta = dir.path / "facade-federation-meta.json";
    const auto federation_admin = dir.path / "facade-federation-admin";
    yume::facade::keys::AuthorizedKeyEntry federation_entry;
    federation_entry.alias = "edge-west";
    federation_entry.federation_peer_id = "edge-west";
    assert(!yume::facade::keys::append_authorized(
        federation_auth, federation_meta, federation_admin, second_pem,
        federation_entry, &error));
    assert(!fs::exists(federation_auth));
    assert(!fs::exists(federation_meta));
    federation_entry.federation_psk_file = "secrets/edge-west.psk";
    assert(!yume::facade::keys::append_authorized(
        federation_auth, federation_meta, federation_admin, second_pem,
        federation_entry, &error));
    assert(!fs::exists(federation_auth));
    assert(!fs::exists(federation_meta));

    const auto federation_psk = dir.path / "secrets/edge-west.psk";
    const std::vector<std::uint8_t> secret_hex(64, 'a');
    assert(yume::security::WriteFileExclusive0600(
        federation_psk, secret_hex, &error));
#if defined(_WIN32)
    // Protected secret loading deliberately remains unavailable on Windows.
    // Facade enrollment must therefore fail closed even when the DACL-safe
    // writer created an otherwise valid 64-byte secret.
    assert(!yume::facade::keys::append_authorized(
        federation_auth, federation_meta, federation_admin, second_pem,
        federation_entry, &error));
    assert(error.find("Linux/POSIX only") != std::string::npos);
    assert(!fs::exists(federation_auth));
    assert(!fs::exists(federation_meta));
#else
    assert(yume::facade::keys::append_authorized(
        federation_auth, federation_meta, federation_admin, second_pem,
        federation_entry, &error));
    const auto federation_list = yume::facade::keys::list_authorized(
        federation_auth, federation_meta);
    assert(federation_list.size() == 1);
    assert(federation_list.front().federation_peer_id == "edge-west");
    assert(federation_list.front().federation_psk_file ==
           "secrets/edge-west.psk");

    const std::string federation_store = read_file(federation_auth);
    const std::string federation_metadata = read_file(federation_meta);
    yume::facade::keys::AuthorizedKeyEntry duplicate_peer = federation_entry;
    duplicate_peer.alias = "edge-west-duplicate";
    assert(!yume::facade::keys::append_authorized(
        federation_auth, federation_meta, federation_admin, first_pem,
        duplicate_peer, &error));
    assert(read_file(federation_auth) == federation_store);
    assert(read_file(federation_meta) == federation_metadata);

    yume::facade::keys::AuthorizedKeyEntry broken_update;
    broken_update.alias = "must-not-land";
    broken_update.federation_psk_file = "secrets/missing.psk";
    assert(!yume::facade::keys::update_authorized(
        federation_auth, federation_meta,
        federation_list.front().fingerprint, broken_update, &error));
    assert(read_file(federation_auth) == federation_store);
    assert(read_file(federation_meta) == federation_metadata);

    yume::facade::keys::AuthorizedKeyEntry ambiguous_clear;
    ambiguous_clear.alias = "edge-west";
    ambiguous_clear.clear_federation_enrollment = true;
    ambiguous_clear.federation_peer_id = "replacement";
    assert(!yume::facade::keys::update_authorized(
        federation_auth, federation_meta,
        federation_list.front().fingerprint, ambiguous_clear, &error));
    assert(read_file(federation_auth) == federation_store);
    assert(read_file(federation_meta) == federation_metadata);

    yume::facade::keys::AuthorizedKeyEntry clear_enrollment;
    clear_enrollment.alias = "edge-west";
    clear_enrollment.clear_federation_enrollment = true;
    assert(yume::facade::keys::update_authorized(
        federation_auth, federation_meta,
        federation_list.front().fingerprint, clear_enrollment, &error));
    assert(read_file(federation_auth) == federation_store);
    const auto cleared_list = yume::facade::keys::list_authorized(
        federation_auth, federation_meta);
    assert(cleared_list.size() == 1);
    assert(cleared_list.front().federation_peer_id.empty());
    assert(cleared_list.front().federation_psk_file.empty());
    const auto cleared_metadata =
        nlohmann::json::parse(read_file(federation_meta));
    const auto& cleared_entry =
        cleared_metadata.at(federation_list.front().fingerprint);
    assert(!cleared_entry.contains("federation_peer_id"));
    assert(!cleared_entry.contains("federation_psk_file"));
#endif

#if !defined(_WIN32)
    const std::string unique = std::to_string(current_process_id());
    yume::facade::keys::AuthorizedKeyEntry failure_entry;
    failure_entry.alias = "failure";

    const auto metadata_failure_auth = dir.path / "facade-meta-failure-keys";
    const fs::path metadata_failure_meta(
        "/proc/yume-facade-meta-failure-" + unique);
    assert(!yume::facade::keys::append_authorized(
        metadata_failure_auth, metadata_failure_meta, admin_path, first_pem,
        failure_entry, &error));
    assert(!fs::exists(metadata_failure_auth));
    assert(!fs::exists(metadata_failure_meta));

    const fs::path auth_failure_auth(
        "/proc/yume-facade-auth-failure-" + unique);
    const auto auth_failure_meta = dir.path / "facade-rollback-meta.json";
    const std::string rollback_metadata =
        "{\n  \"sentinel\": {\"alias\": \"preserve bytes\"}\n}\n";
    write_file(auth_failure_meta, rollback_metadata);
    assert(!yume::facade::keys::append_authorized(
        auth_failure_auth, auth_failure_meta, admin_path, first_pem,
        failure_entry, &error));
    assert(!fs::exists(auth_failure_auth));
    assert(read_file(auth_failure_meta) == rollback_metadata);

    const auto revoke_auth = dir.path / "facade-revoke-keys";
    const fs::path revoke_meta(
        "/proc/yume-facade-revoke-meta-failure-" + unique);
    write_file(revoke_auth, first_pem);
    assert(!yume::facade::keys::remove_authorized(
        revoke_auth, revoke_meta, first_fingerprint, &error));
    assert(yume::server::load_authorized_keys(revoke_auth.string()).size() ==
           1);
    assert(read_file(revoke_auth) == first_pem);
    assert(!fs::exists(revoke_meta));
#endif
}

void test_concurrent_cli_facade_authorization_transactions() {
    using yume::server::cli::ServerKeyCommand;
    using yume::server::cli::run_server_key_command;

    TempDir dir;
    const auto first = yume::crypto::generate_composite_keypair();
    const auto second = yume::crypto::generate_composite_keypair();
    const auto contested = yume::crypto::generate_composite_keypair();
    const auto first_public = dir.path / "concurrent-first.pub";
    const auto contested_public = dir.path / "concurrent-contested.pub";
    write_file(first_public, pem_of(first));
    write_file(contested_public, pem_of(contested));
    const std::string first_fingerprint =
        yume::crypto::composite_fingerprint(public_view(first));
    const std::string second_fingerprint =
        yume::crypto::composite_fingerprint(public_view(second));
    const std::string contested_fingerprint =
        yume::crypto::composite_fingerprint(public_view(contested));

    // A facade visitor add races a CLI admin add of the same identity. The
    // shared visitor/admin transaction must permit exactly one publication.
    for (int iteration = 0; iteration < 8; ++iteration) {
        yume::server::ServerConfig config;
        const auto stem = std::to_string(iteration);
        config.auth_keys =
            (dir.path / ("cross-visitor-" + stem)).string();
        config.auth_keys_meta =
            (dir.path / ("cross-meta-" + stem + ".json")).string();
        config.admin_keys =
            (dir.path / ("cross-admin-" + stem)).string();

        std::barrier begin(3);
        bool visitor_added = false;
        bool admin_added = false;
        std::thread visitor([&] {
            yume::facade::keys::AuthorizedKeyEntry entry;
            entry.alias = "contested-visitor";
            std::string error;
            begin.arrive_and_wait();
            visitor_added = yume::facade::keys::append_authorized(
                config.auth_keys, config.auth_keys_meta, config.admin_keys,
                pem_of(contested), entry, &error);
        });
        std::thread admin([&] {
            begin.arrive_and_wait();
            admin_added = yume::server::cli::append_authorized_public_key(
                config, contested_public.string(), "contested-admin", nullptr,
                true);
        });
        begin.arrive_and_wait();
        visitor.join();
        admin.join();

        assert(visitor_added != admin_added);
        const auto visitors = fs::exists(config.auth_keys)
                                  ? yume::server::load_authorized_keys(
                                        config.auth_keys)
                                  : std::vector<yume::crypto::Bytes>{};
        const auto admins = fs::exists(config.admin_keys)
                                ? yume::server::load_admin_keys(
                                      config.admin_keys)
                                : std::vector<yume::crypto::Bytes>{};
        assert(visitors.size() + admins.size() == 1);
        assert(!yume::server::is_composite_authorized(
                   public_view(contested), visitors) ||
               !yume::server::is_composite_authorized(
                   public_view(contested), admins));
        if (visitor_added) {
            const auto metadata =
                nlohmann::json::parse(read_file(config.auth_keys_meta));
            assert(metadata.contains(contested_fingerprint));
        } else {
            assert(!fs::exists(config.auth_keys_meta));
        }
    }

    // A facade add and CLI revoke operate on both files as one transaction.
    // Neither ordering may lose the new identity, resurrect the revoked one,
    // or detach authorization from its metadata.
    for (int iteration = 0; iteration < 8; ++iteration) {
        yume::server::ServerConfig config;
        const auto stem = std::to_string(iteration);
        config.auth_keys =
            (dir.path / ("mutation-visitor-" + stem)).string();
        config.auth_keys_meta =
            (dir.path / ("mutation-meta-" + stem + ".json")).string();
        config.admin_keys =
            (dir.path / ("mutation-admin-" + stem)).string();
        assert(yume::server::cli::append_authorized_public_key(
            config, first_public.string(), "first"));

        std::barrier begin(3);
        bool second_added = false;
        bool first_revoked = false;
        std::thread add([&] {
            yume::facade::keys::AuthorizedKeyEntry entry;
            entry.alias = "second";
            std::string error;
            begin.arrive_and_wait();
            second_added = yume::facade::keys::append_authorized(
                config.auth_keys, config.auth_keys_meta, config.admin_keys,
                pem_of(second), entry, &error);
        });
        std::thread revoke([&] {
            ServerKeyCommand remove;
            remove.remove = first_fingerprint;
            begin.arrive_and_wait();
            const auto result = run_server_key_command(config, remove);
            first_revoked = result.handled && result.exit_code == 0;
        });
        begin.arrive_and_wait();
        add.join();
        revoke.join();

        assert(second_added);
        assert(first_revoked);
        const auto visitors =
            yume::server::load_authorized_keys(config.auth_keys);
        assert(visitors.size() == 1);
        assert(yume::server::is_composite_authorized(public_view(second),
                                                     visitors));
        assert(!yume::server::is_composite_authorized(public_view(first),
                                                      visitors));
        const auto metadata =
            nlohmann::json::parse(read_file(config.auth_keys_meta));
        assert(metadata.contains(second_fingerprint));
        assert(!metadata.contains(first_fingerprint));
    }
}

void test_manager_ui_preserves_unusable_config() {
    TempDir dir;
    yume::server::ServerConfig config;

    const auto malformed_path = dir.path / "malformed-yumed.json";
    const std::string malformed = R"({"listen_port":443,)";
    write_file(malformed_path, malformed);
    const auto malformed_result = run_manager_ui(
        &config, "6\n" + malformed_path.string() + "\n");
    assert(malformed_result.handled && malformed_result.exit_code == 1);
    assert(read_file(malformed_path) == malformed);

    const auto wrong_type_path = dir.path / "wrong-type-yumed.json";
    const std::string wrong_type = R"({"listen_port":"443"})";
    write_file(wrong_type_path, wrong_type);
    const auto wrong_type_result = run_manager_ui(
        &config, "6\n" + wrong_type_path.string() + "\n");
    assert(wrong_type_result.handled && wrong_type_result.exit_code == 1);
    assert(read_file(wrong_type_path) == wrong_type);

    // Blank responses retain the effective values and publish through the
    // same durable atomic helper used by the non-interactive config writers.
    const auto saved_path = dir.path / "nested" / "yumed.json";
    const auto save_result = run_manager_ui(
        &config, "6\n" + saved_path.string() + "\n" +
                     std::string(64, '\n'));
    assert(save_result.handled && save_result.exit_code == 0);
    const auto saved = nlohmann::json::parse(read_file(saved_path));
    assert(saved.is_object());
    assert(saved["listen_port"] == config.listen_port);

#if !defined(_WIN32)
    const auto failure_path = fs::path(
        "/proc/yume-ui-write-failure-" +
        std::to_string(current_process_id()));
    const auto failure_result = run_manager_ui(
        &config, "6\n" + failure_path.string() + "\n" +
                     std::string(64, '\n'));
    assert(failure_result.handled && failure_result.exit_code == 1);
    assert(!fs::exists(failure_path));
#endif
}

}  // namespace

int main() {
    test_file_transaction_lock_retry_and_process_serialization();
    test_manager_auth_snapshot_waits_for_transaction_writer();
    test_store_roundtrip_and_membership();
    test_halves_cannot_be_mixed_across_entries();
    test_incomplete_entry_is_refused();
    test_non_pem_material_is_refused();
    test_wrong_algorithm_order_is_refused();
    test_admin_store_is_separate();
    test_missing_admin_store_grants_nothing();
    test_admin_flags_in_visitor_policy_are_refused();
    test_auth_policy_loader_is_type_strict_and_exact();
    test_cli_manages_whole_composite_identities();
    test_cli_rejects_non_exact_candidates_and_typed_metadata();
    test_cli_failure_order_is_fail_closed();
    test_facade_key_mutations_are_atomic_and_exact();
    test_concurrent_cli_facade_authorization_transactions();
    test_manager_ui_preserves_unusable_config();
    std::cout << "dual_key_auth_test ok\n";
    return 0;
}
