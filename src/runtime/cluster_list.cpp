/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/cluster_list.hpp"

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <initializer_list>
#include <memory>
#include <new>
#include <set>

#include <nlohmann/json.hpp>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "config/v1/config.hpp"

namespace yume::runtime::cluster {
namespace {

namespace keys = providers::keys;
using engine::Result;
using engine::Status;
using engine::StatusCode;
using Json = nlohmann::json;
using keys::require;

void closed(const Json& value, std::initializer_list<std::string_view> fields) {
    require(value.is_object() && value.size() == fields.size(),
            "cluster list object has missing or unknown fields");
    for (const auto field : fields) {
        require(value.contains(field),
                "cluster list object is missing a field");
    }
}

const std::string& text(const Json& value, std::size_t maximum) {
    require(value.is_string() && !value.get_ref<const std::string&>().empty() &&
                value.get_ref<const std::string&>().size() <= maximum,
            "cluster list text field is missing or too long");
    return value.get_ref<const std::string&>();
}

bool fingerprint_text(std::string_view value) noexcept {
    return value.size() == 64U &&
           std::all_of(value.begin(), value.end(), [](char ch) {
               return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
           });
}

bool label_text(std::string_view value) noexcept {
    const auto alnum = [](char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
               (ch >= '0' && ch <= '9');
    };
    return !value.empty() && value.size() <= kMaxNameBytes &&
           alnum(value.front()) && alnum(value.back()) &&
           std::all_of(value.begin(), value.end(), [&](char ch) {
               return alnum(ch) || ch == '.' || ch == '_' || ch == '-';
           });
}

// One to eight PEM certificates and nothing else, each parsed now so a bad
// anchor fails when the list is checked rather than when a link starts.
bool trust_text(const keys::KeyContext& keys, std::string_view value) {
    constexpr std::string_view begin = "-----BEGIN CERTIFICATE-----";
    constexpr std::string_view end = "-----END CERTIFICATE-----";
    std::size_t blocks = 0U;
    while (true) {
        const auto first = value.find_first_not_of(" \t\r\n");
        if (first == std::string_view::npos) break;
        value.remove_prefix(first);
        if (!value.starts_with(begin)) return false;
        const auto stop = value.find(end);
        if (stop == std::string_view::npos || ++blocks > 8U) return false;
        const auto block = value.substr(0U, stop + end.size());
        std::unique_ptr<BIO, decltype(&BIO_free)> input(
            BIO_new_mem_buf(block.data(), static_cast<int>(block.size())),
            BIO_free);
        // A certificate object made in the private context keeps the parse
        // there. PEM_read_bio_X509 fills the object it is given, and a failed
        // decode frees it and clears the pointer, so ownership is taken from
        // the pointer as the call leaves it.
        X509* target =
            input ? X509_new_ex(keys.context(), "provider=default") : nullptr;
        X509* const read =
            target ? PEM_read_bio_X509(input.get(), &target, nullptr, nullptr)
                   : nullptr;
        const std::unique_ptr<X509, decltype(&X509_free)> certificate(
            read ? read : target, X509_free);
        if (read == nullptr) return false;
        value.remove_prefix(block.size());
    }
    return blocks >= 1U;
}

Node parse_node(const keys::KeyContext& keys, const Json& entry) {
    if (entry.is_object() && entry.contains("address")) {
        closed(entry, {"name", "identity", "host", "address", "port",
                       "identity_key", "mlkem_key", "tls_trust"});
    } else {
        closed(entry, {"name", "identity", "host", "port", "identity_key",
                       "mlkem_key", "tls_trust"});
    }
    Node node;
    if (entry.contains("address")) {
        node.address = text(entry.at("address"), 64U);
        require(config::v1::IsIpAddressLiteral(node.address),
                "cluster node address must be an IP literal");
    }
    node.name = text(entry.at("name"), kMaxNameBytes);
    require(label_text(node.name), "cluster node name is invalid");
    node.host = text(entry.at("host"), 253U);
    require(config::v1::IsEndpointHost(node.host),
            "cluster node host is invalid");
    const auto& port = entry.at("port");
    require(port.is_number_unsigned() && port.get<std::uint64_t>() >= 1U &&
                port.get<std::uint64_t>() <= 65535U,
            "cluster node port must be 1 to 65535");
    node.port = static_cast<std::uint16_t>(port.get<std::uint64_t>());
    const auto& identity = text(entry.at("identity"), 64U);
    require(fingerprint_text(identity),
            "cluster node identity must be lowercase SHA-256");
    node.identity = keys::composite_public_from_pem(
        keys, text(entry.at("identity_key"), 32768U));
    require(node.identity.fingerprint == identity,
            "cluster node identity does not match its key");
    const auto kem_blocks =
        keys::pem_blocks(text(entry.at("mlkem_key"), 8192U), false, 1U);
    const auto kem = keys::parse_key(keys, kem_blocks[0], false, "ML-KEM-1024");
    node.mlkem_key = keys::public_der(kem.get());
    node.tls_trust = text(entry.at("tls_trust"), kMaxTrustBytes);
    require(trust_text(keys, node.tls_trust),
            "cluster node TLS trust must be PEM certificates");
    return node;
}

List parse_list(const keys::KeyContext& keys, std::span<const std::byte> bytes,
                const std::string& operator_fingerprint,
                std::chrono::system_clock::time_point now) {
    const std::string_view view(reinterpret_cast<const char*>(bytes.data()),
                                bytes.size());
    const Json document = Json::parse(view, nullptr, false);
    require(!document.is_discarded(), "cluster list is not JSON");
    closed(document, {"schema", "cluster", "serial", "not_after", "nodes"});
    require(document.at("schema").is_number_unsigned() &&
                document.at("schema").get<std::uint64_t>() == 1U,
            "cluster list schema must be 1");
    List list;
    list.cluster = text(document.at("cluster"), 64U);
    require(list.cluster == operator_fingerprint,
            "cluster list names another operator than its signer");
    const auto& serial = document.at("serial");
    require(serial.is_number_unsigned() && serial.get<std::uint64_t>() >= 1U,
            "cluster list serial must be a positive integer");
    list.serial = serial.get<std::uint64_t>();
    const auto not_after = parse_utc(text(document.at("not_after"), 20U));
    require(not_after.has_value(),
            "cluster list not_after must be YYYY-MM-DDTHH:MM:SSZ");
    list.not_after = *not_after;
    require(list.not_after > now, "cluster list has expired",
            StatusCode::FailedPrecondition);
    const auto& nodes = document.at("nodes");
    require(nodes.is_array() && !nodes.empty() && nodes.size() <= kMaxNodes,
            "cluster list must name 1 to 64 nodes");
    std::set<std::string> names;
    std::set<std::string> identities;
    list.nodes.reserve(nodes.size());
    for (const auto& entry : nodes) {
        auto node = parse_node(keys, entry);
        require(names.insert(node.name).second,
                "cluster list repeats a node name");
        require(identities.insert(node.identity.fingerprint).second,
                "cluster list repeats a node identity");
        list.nodes.push_back(std::move(node));
    }
    return list;
}

}  // namespace

const Node* List::find(std::string_view identity) const noexcept {
    for (const auto& node : nodes) {
        if (node.identity.fingerprint == identity) return &node;
    }
    return nullptr;
}

std::optional<std::chrono::system_clock::time_point> parse_utc(
    std::string_view value) {
    if (value.size() != 20U || value[4] != '-' || value[7] != '-' ||
        value[10] != 'T' || value[13] != ':' || value[16] != ':' ||
        value[19] != 'Z') {
        return std::nullopt;
    }
    const auto number = [&](std::size_t at, std::size_t digits, int& out) {
        out = 0;
        for (std::size_t i = at; i < at + digits; ++i) {
            if (value[i] < '0' || value[i] > '9') return false;
            out = out * 10 + (value[i] - '0');
        }
        return true;
    };
    int year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0;
    if (!number(0, 4, year) || !number(5, 2, month) || !number(8, 2, day) ||
        !number(11, 2, hour) || !number(14, 2, minute) ||
        !number(17, 2, second) || year < 2000 || month < 1 || month > 12 ||
        day < 1 || hour > 23 || minute > 59 || second > 59) {
        return std::nullopt;
    }
    std::tm parts{};
    parts.tm_year = year - 1900;
    parts.tm_mon = month - 1;
    parts.tm_mday = day;
    parts.tm_hour = hour;
    parts.tm_min = minute;
    parts.tm_sec = second;
    const std::time_t seconds = ::timegm(&parts);
    std::tm check{};
    // timegm normalizes a day such as February 30. Round-tripping refuses it.
    if (seconds == static_cast<std::time_t>(-1) ||
        ::gmtime_r(&seconds, &check) == nullptr ||
        check.tm_year != parts.tm_year || check.tm_mon != month - 1 ||
        check.tm_mday != day) {
        return std::nullopt;
    }
    return std::chrono::system_clock::from_time_t(seconds);
}

Result<List> verify_list(std::span<const std::byte> list,
                         std::span<const std::byte> signature,
                         std::string_view operator_key_pem,
                         std::chrono::system_clock::time_point now) {
    try {
        require(!list.empty() && list.size() <= kMaxListBytes,
                "cluster list must hold 1 byte to 1 MiB");
        const keys::KeyContext keys;
        const auto operator_key =
            keys::composite_public_from_pem(keys, operator_key_pem);
        std::vector<std::byte> message;
        message.reserve(kListDomain.size() + 1U + list.size());
        for (const char ch : kListDomain)
            message.push_back(static_cast<std::byte>(ch));
        message.push_back(std::byte{0});
        message.insert(message.end(), list.begin(), list.end());
        require(keys::verify_composite(keys, operator_key, message, signature),
                "cluster list signature does not verify");
        return Result<List>(
            parse_list(keys, list, operator_key.fingerprint, now));
    } catch (const std::bad_alloc&) {
        return Result<List>(Status(StatusCode::ResourceExhausted));
    } catch (const keys::KeyError& error) {
        return Result<List>(Status::diagnostic(error.code(), error.what()));
    } catch (...) {
        return Result<List>(Status::diagnostic(StatusCode::InvalidArgument,
                                               "cluster list is malformed"));
    }
}

}  // namespace yume::runtime::cluster
