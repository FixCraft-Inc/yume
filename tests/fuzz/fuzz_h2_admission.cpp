/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "admission/h2_admission.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

// Any TLS client reaches these before it is admitted: the request path that
// carries the admission token and nonce, and the :authority checked against
// the TLS server name. The input is the path, then the authority and the
// server name, separated by newlines, and two bytes of listener port.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    using namespace yume::admission;
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
    return 0;
}
