/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "admission/h2_admission.hpp"
#include "providers/ytp1_h2_admission.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace {

using namespace yume::admission;
using yume::providers::build_ytp1_h2_admission_path;
using yume::providers::verify_ytp1_h2_admission_path;

constexpr std::array<std::byte, yume::providers::kYtp1H2AdmissionKeyBytes>
    kAdmissionKey = [] {
        std::array<std::byte, yume::providers::kYtp1H2AdmissionKeyBytes> key{};
        for (std::size_t index = 0U; index < key.size(); ++index) {
            key[index] = static_cast<std::byte>(0x40U + index);
        }
        return key;
    }();

// A proof built for these fields must verify, and the same proof must fail
// on another connection's exporter and with any one character changed. A
// fuzzed path that verifies must be the one spelling the builder writes.
void check_proof(const std::uint8_t* data, std::size_t size,
                 std::string_view path, std::string_view authority,
                 std::string_view server_name,
                 std::optional<std::uint16_t> port) {
    std::array<std::byte, yume::providers::kYtp1H2AdmissionExporterBytes> exporter{};
    Nonce nonce{};
    for (std::size_t index = 0U; size != 0U && index < exporter.size(); ++index) {
        exporter[index] = static_cast<std::byte>(data[index % size] ^ index);
        nonce[index] = static_cast<std::byte>(data[(index * 7U + 3U) % size] ^ 0x5aU);
    }
    if (verify_ytp1_h2_admission_path(kAdmissionKey, authority, server_name,
                                      exporter, path, port)) {
        const auto parsed = parse_path(path);
        const auto rebuilt = parsed ? build_ytp1_h2_admission_path(
                                          kAdmissionKey, server_name, exporter,
                                          parsed->nonce)
                                    : std::nullopt;
        if (!rebuilt || *rebuilt != path) __builtin_trap();
    }
    const auto built =
        build_ytp1_h2_admission_path(kAdmissionKey, server_name, exporter, nonce);
    if (!built) return;
    if (authority_matches_tls_sni(server_name, server_name) &&
        !verify_ytp1_h2_admission_path(kAdmissionKey, server_name, server_name,
                                       exporter, *built)) {
        __builtin_trap();
    }
    auto other_connection = exporter;
    other_connection[0] ^= std::byte{0x01};
    if (verify_ytp1_h2_admission_path(kAdmissionKey, server_name, server_name,
                                      other_connection, *built)) {
        __builtin_trap();
    }
    if (size != 0U) {
        std::string changed = *built;
        changed[data[0] % changed.size()] ^= static_cast<char>(data[size - 1U] | 1U);
        if (verify_ytp1_h2_admission_path(kAdmissionKey, server_name, server_name,
                                          exporter, changed)) {
            __builtin_trap();
        }
    }
}

// Each input byte is one reservation against a four-entry cache with a
// three-tick lifetime. Its low three bits pick one of eight nonces, the next
// two advance the clock, a top value of seven steps the clock back and 0xff
// jumps to the end of the tick range. The cache must decide exactly as this
// model of its contract does, and hold as many nonces.
void check_replay(const std::uint8_t* data, std::size_t size) {
    constexpr std::size_t kEntries = 4U;
    constexpr std::uint64_t kTtl = 3U;
    ReplayCache cache(kEntries, kTtl);
    std::map<std::uint8_t, std::uint64_t> model;
    bool has_last = false;
    std::uint64_t last = 0U;
    std::uint64_t now = 0U;
    for (std::size_t index = 0U; index < size && index < 512U; ++index) {
        const std::uint8_t op = data[index];
        if (op == 0xffU) {
            now = std::numeric_limits<std::uint64_t>::max() - 1U;
        } else if ((op >> 5U) == 7U) {
            if (now != 0U) --now;
        } else if (now <= std::numeric_limits<std::uint64_t>::max() - 3U) {
            now += (op >> 3U) & 3U;
        }
        const std::uint8_t id = op & 7U;
        Nonce nonce{};
        nonce.fill(static_cast<std::byte>(id));

        bool expected = false;
        if (!(has_last && now < last) &&
            now <= std::numeric_limits<std::uint64_t>::max() - kTtl) {
            has_last = true;
            last = now;
            std::erase_if(model, [this_now = now](const auto& entry) {
                return entry.second <= this_now;
            });
            if (!model.contains(id) && model.size() < kEntries) {
                model.emplace(id, now + kTtl);
                expected = true;
            }
        }
        const bool accepted = cache.reserve(nonce, now) == ReplayDecision::Accepted;
        if (accepted != expected || cache.size() != model.size()) __builtin_trap();
    }
}

}  // namespace

// Any TLS client reaches the request path that carries the admission token
// and nonce, and the :authority checked against the TLS server name, before
// it is admitted. The input is the path, then the authority and the server
// name, separated by newlines, and two bytes of listener port. The same bytes
// also seed a proof and drive the replay cache.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    std::string_view input(reinterpret_cast<const char*>(data), size);
    std::optional<std::uint16_t> port;
    if (input.size() >= 2U) {
        port = static_cast<std::uint16_t>(
            (static_cast<unsigned>(data[size - 2U]) << 8U) | data[size - 1U]);
        if (*port == 0U) port.reset();
        input.remove_suffix(2U);
    }
    const auto field = [&input]() {
        const auto end = input.find('\n');
        const auto value = input.substr(0U, end);
        input.remove_prefix(end == std::string_view::npos ? input.size()
                                                          : end + 1U);
        return value;
    };
    const auto path = field();
    const auto authority = field();
    const auto server_name = field();

    // An accepted path has exactly one spelling, so building it again from
    // what was parsed must give back the same text.
    if (const auto parsed = parse_path(path)) {
        if (build_path(parsed->token, parsed->nonce) != path) __builtin_trap();
    }
    (void)authority_matches_tls_sni(authority, server_name, port);
    check_proof(data, size, path, authority, server_name, port);
    check_replay(data, size);
    return 0;
}
