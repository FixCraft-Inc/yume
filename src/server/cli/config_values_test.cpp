/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <cassert>
#include <cstdint>
#include <limits>
#include <stdexcept>

#include <nlohmann/json.hpp>

#include "server/cli/numeric_parse.hpp"
#include "server/config/json_values.hpp"

namespace {

template <typename Fn>
void assert_invalid(Fn&& fn) {
    try {
        fn();
        assert(false && "expected invalid_argument");
    } catch (const std::invalid_argument&) {
    }
}

void test_strict_cli_numbers() {
    int signed_value = 0;
    assert(yume::server::cli::parse_int_strict("-1", &signed_value));
    assert(signed_value == -1);
    assert(!yume::server::cli::parse_int_strict(" 1", &signed_value));
    assert(!yume::server::cli::parse_int_strict("1 ", &signed_value));
    assert(!yume::server::cli::parse_int_strict("1x", &signed_value));
    assert(!yume::server::cli::parse_int_strict("2147483648", &signed_value));

    std::uint32_t unsigned_value = 0;
    assert(yume::server::cli::parse_u32_strict("0", &unsigned_value));
    assert(unsigned_value == 0);
    assert(yume::server::cli::parse_u32_strict("4294967295", &unsigned_value));
    assert(unsigned_value == std::numeric_limits<std::uint32_t>::max());
    assert(!yume::server::cli::parse_u32_strict("-1", &unsigned_value));
    assert(!yume::server::cli::parse_u32_strict("+1", &unsigned_value));
    assert(!yume::server::cli::parse_u32_strict("1 ", &unsigned_value));
    assert(!yume::server::cli::parse_u32_strict("4294967296", &unsigned_value));
}

void test_positive_json_numbers() {
    nlohmann::json json;
    json["limit"] = 1;
    assert(yume::server::json_positive_u32(json, "limit") == 1);
    json["limit"] = std::numeric_limits<std::uint32_t>::max();
    assert(yume::server::json_positive_u32(json, "limit") ==
           std::numeric_limits<std::uint32_t>::max());

    json["limit"] = 0;
    assert_invalid([&]() { yume::server::json_positive_u32(json, "limit"); });
    json["limit"] = -1;
    assert_invalid([&]() { yume::server::json_positive_u32(json, "limit"); });
    json["limit"] = 4294967296ULL;
    assert_invalid([&]() { yume::server::json_positive_u32(json, "limit"); });
    json["limit"] = "4";
    assert_invalid([&]() { yume::server::json_positive_u32(json, "limit"); });
    json["limit"] = 1.5;
    assert_invalid([&]() { yume::server::json_positive_u32(json, "limit"); });
}

}  // namespace

int main() {
    test_strict_cli_numbers();
    test_positive_json_numbers();
    return 0;
}
