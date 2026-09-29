/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/cluster_list.hpp"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace {
namespace cluster = yume::runtime::cluster;
namespace keys = yume::providers::keys;
using yume::engine::StatusCode;
using Json = nlohmann::json;
using Clock = std::chrono::system_clock;
using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

void check(bool condition, const char* description) {
    if (!condition) throw std::runtime_error(description);
}

PkeyPtr generate(const char* algorithm) {
    PkeyPtr key(EVP_PKEY_Q_keygen(nullptr, nullptr, algorithm), EVP_PKEY_free);
    check(static_cast<bool>(key), "key generation failed");
    return key;
}

std::string public_pem(EVP_PKEY* key) {
    std::unique_ptr<BIO, decltype(&BIO_free)> out(BIO_new(BIO_s_mem()),
                                                  BIO_free);
    check(out && PEM_write_bio_PUBKEY(out.get(), key) == 1,
          "PEM export failed");
    char* data = nullptr;
    const long size = BIO_get_mem_data(out.get(), &data);
    return std::string(data, static_cast<std::size_t>(size));
}

std::vector<unsigned char> sign_one(EVP_PKEY* key,
                                    const std::vector<unsigned char>& message) {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> context(
        EVP_MD_CTX_new(), EVP_MD_CTX_free);
    std::size_t size = 0;
    check(context &&
              EVP_DigestSignInit_ex(context.get(), nullptr, nullptr, nullptr,
                                    nullptr, key, nullptr) == 1 &&
              EVP_DigestSign(context.get(), nullptr, &size, message.data(),
                             message.size()) == 1,
          "signing setup failed");
    std::vector<unsigned char> signature(size);
    check(EVP_DigestSign(context.get(), signature.data(), &size, message.data(),
                         message.size()) == 1,
          "signing failed");
    signature.resize(size);
    return signature;
}

struct Composite final {
    PkeyPtr classical = generate("ED25519");
    PkeyPtr post_quantum = generate("ML-DSA-87");
    std::string pem =
        public_pem(classical.get()) + public_pem(post_quantum.get());
    std::string fingerprint() const {
        const keys::KeyContext context;
        return keys::composite_public_from_pem(context, pem).fingerprint;
    }
    // The composite signature over the list domain, a zero byte and bytes.
    std::vector<std::byte> sign(const std::string& bytes) const {
        std::vector<unsigned char> message(cluster::kListDomain.begin(),
                                           cluster::kListDomain.end());
        message.push_back(0U);
        message.insert(message.end(), bytes.begin(), bytes.end());
        auto signature = sign_one(classical.get(), message);
        const auto second = sign_one(post_quantum.get(), message);
        signature.insert(signature.end(), second.begin(), second.end());
        const auto* start =
            reinterpret_cast<const std::byte*>(signature.data());
        return {start, start + signature.size()};
    }
};

std::string certificate_pem() {
    auto key = generate("ED25519");
    std::unique_ptr<X509, decltype(&X509_free)> certificate(X509_new(),
                                                            X509_free);
    check(certificate && X509_set_version(certificate.get(), 2L) == 1 &&
              ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1L) ==
                  1 &&
              X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60L) &&
              X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600L) &&
              X509_set_pubkey(certificate.get(), key.get()) == 1,
          "certificate setup failed");
    X509_NAME* name = X509_get_subject_name(certificate.get());
    check(X509_NAME_add_entry_by_txt(
              name, "CN", MBSTRING_ASC,
              reinterpret_cast<const unsigned char*>("cluster test"), -1, -1,
              0) == 1 &&
              X509_set_issuer_name(certificate.get(), name) == 1 &&
              X509_sign(certificate.get(), key.get(), nullptr) > 0,
          "certificate signing failed");
    std::unique_ptr<BIO, decltype(&BIO_free)> out(BIO_new(BIO_s_mem()),
                                                  BIO_free);
    check(out && PEM_write_bio_X509(out.get(), certificate.get()) == 1,
          "certificate export failed");
    char* data = nullptr;
    const long size = BIO_get_mem_data(out.get(), &data);
    return std::string(data, static_cast<std::size_t>(size));
}

struct Fixture final {
    Composite operator_key;
    Composite node_a;
    Composite node_b;
    std::string kem = public_pem(generate("ML-KEM-1024").get());
    std::string trust = certificate_pem();

    Json node(const Composite& key, const std::string& name,
              std::uint16_t port) const {
        return {{"name", name},
                {"identity", key.fingerprint()},
                {"host", "node.example.net"},
                {"port", port},
                {"identity_key", key.pem},
                {"mlkem_key", kem},
                {"tls_trust", trust}};
    }
    Json document() const {
        return {{"schema", 1},
                {"cluster", operator_key.fingerprint()},
                {"serial", 7},
                {"not_after", "2099-01-01T00:00:00Z"},
                {"nodes", Json::array({node(node_a, "gloomy-data", 443),
                                       node(node_b, "sweet-fox", 8443)})}};
    }
    yume::engine::Result<cluster::List> verify(
        const std::string& bytes,
        const std::vector<std::byte>& signature) const {
        const auto* start = reinterpret_cast<const std::byte*>(bytes.data());
        return cluster::verify_list({start, bytes.size()}, signature,
                                    operator_key.pem, Clock::now());
    }
    yume::engine::Result<cluster::List> signed_list(const Json& value) const {
        const auto bytes = value.dump();
        return verify(bytes, operator_key.sign(bytes));
    }
};

void expect_refused(const yume::engine::Result<cluster::List>& result,
                    const char* description,
                    StatusCode code = StatusCode::InvalidArgument) {
    if (result.ok() || result.status().code() != code)
        throw std::runtime_error(description);
}

void test_valid_list(const Fixture& fixture) {
    Json with_address = fixture.document();
    with_address["nodes"][0]["address"] = "127.0.0.2";
    with_address["nodes"][1]["address"] = "::1";
    auto addressed = fixture.signed_list(with_address);
    check(addressed.ok() && addressed.value().nodes[0].address == "127.0.0.2" &&
              addressed.value().nodes[1].address == "::1",
          "node addresses were not retained");
    auto list = fixture.signed_list(fixture.document());
    check(list.ok(), "a valid list was refused");
    const auto& value = list.value();
    check(value.cluster == fixture.operator_key.fingerprint() &&
              value.serial == 7U && value.nodes.size() == 2U,
          "the list's header fields are wrong");
    const auto* b = value.find(fixture.node_b.fingerprint());
    check(b != nullptr && b->name == "sweet-fox" && b->port == 8443U &&
              b->host == "node.example.net" && !b->mlkem_key.empty() &&
              b->tls_trust == fixture.trust,
          "a node's fields are wrong");
    check(value.find(std::string(64, '0')) == nullptr,
          "an unknown identity was found");
}

void test_signature_refusals(const Fixture& fixture) {
    const auto bytes = fixture.document().dump();
    auto signature = fixture.operator_key.sign(bytes);
    for (const std::size_t position :
         {std::size_t{0}, std::size_t{100}, signature.size() - 1U}) {
        auto changed = signature;
        changed[position] ^= std::byte{1};
        expect_refused(fixture.verify(bytes, changed),
                       "a changed signature verified");
    }
    auto shorter = signature;
    shorter.pop_back();
    expect_refused(fixture.verify(bytes, shorter),
                   "a short signature verified");
    auto changed_list = bytes;
    changed_list[changed_list.size() / 2U] ^= 1;
    expect_refused(fixture.verify(changed_list, signature),
                   "a changed list verified");
    expect_refused(fixture.verify(bytes, fixture.node_a.sign(bytes)),
                   "another key's signature verified");
}

void test_document_refusals(const Fixture& fixture) {
    const auto refused = [&](Json value, const char* description,
                             StatusCode code = StatusCode::InvalidArgument) {
        expect_refused(fixture.signed_list(value), description, code);
    };
    Json value = fixture.document();
    value["cluster"] = fixture.node_a.fingerprint();
    refused(value, "a list naming another operator was accepted");
    value = fixture.document();
    value["not_after"] = "2020-01-01T00:00:00Z";
    refused(value, "an expired list was accepted",
            StatusCode::FailedPrecondition);
    for (const char* key :
         {"schema", "serial", "not_after", "nodes", "cluster"}) {
        value = fixture.document();
        value.erase(key);
        refused(value, "a list without a required field was accepted");
    }
    value = fixture.document();
    value["extra"] = true;
    refused(value, "a list with an unknown field was accepted");
    value = fixture.document();
    value["schema"] = 2;
    refused(value, "schema 2 was accepted");
    value = fixture.document();
    value["serial"] = 0;
    refused(value, "serial 0 was accepted");
    value = fixture.document();
    value["nodes"] = Json::array();
    refused(value, "a list without nodes was accepted");
    value = fixture.document();
    value["nodes"] = Json::array();
    for (int index = 0; index < 65; ++index)
        value["nodes"].push_back(fixture.document()["nodes"][0]);
    refused(value, "65 nodes were accepted");
    value = fixture.document();
    value["nodes"][1]["name"] = "gloomy-data";
    refused(value, "a repeated name was accepted");
    value = fixture.document();
    value["nodes"][1] = value["nodes"][0];
    value["nodes"][1]["name"] = "other";
    refused(value, "a repeated identity was accepted");
    const std::pair<const char*, Json> bad_fields[] = {
        {"identity", fixture.node_b.fingerprint()},
        {"host", "bad host"},
        {"port", 0},
        {"port", 65536},
        {"name", "-bad"},
        {"mlkem_key", fixture.node_a.pem},
        {"tls_trust",
         "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"},
        {"tls_trust", fixture.kem},
        {"identity_key", fixture.kem},
    };
    for (const auto& [field, bad] : bad_fields) {
        value = fixture.document();
        value["nodes"][0][field] = bad;
        refused(value, "a node with a bad field was accepted");
    }
    value = fixture.document();
    value["nodes"][0]["region"] = "eu";
    refused(value, "a node with an unknown field was accepted");
    for (const char* address : {"node.example.net", "1.2.3", "", "::1x"}) {
        value = fixture.document();
        value["nodes"][0]["address"] = address;
        refused(value, "a node address that is not an IP literal was accepted");
    }
}

void test_dates() {
    check(cluster::parse_utc("2026-09-28T12:34:56Z").has_value(),
          "a valid date was refused");
    for (const char* text :
         {"2026-02-30T00:00:00Z", "2026-13-01T00:00:00Z",
          "2026-09-28T24:00:00Z", "2026-09-28 12:34:56Z", "2026-09-28T12:34:56",
          "1999-12-31T23:59:59Z", ""}) {
        check(!cluster::parse_utc(text).has_value(),
              "an invalid date was accepted");
    }
}

}  // namespace

int main() {
    try {
        const Fixture fixture;
        test_valid_list(fixture);
        test_signature_refusals(fixture);
        test_document_refusals(fixture);
        test_dates();
    } catch (const std::exception& error) {
        std::cerr << "cluster list test failure: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "cluster list tests passed\n";
    return EXIT_SUCCESS;
}
