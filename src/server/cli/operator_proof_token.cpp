/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/operator_proof_token.hpp"

#include "core/security/secret_file.hpp"
#include "core/security/secure_erase.hpp"
#include "server/cli/curl_json_transport.hpp"

#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace yume::server::cli {
namespace {

class BytesWiper final {
public:
    explicit BytesWiper(std::vector<std::uint8_t>& value) noexcept
        : value_(value) {}
    ~BytesWiper() { security::secure_erase(value_); }

    BytesWiper(const BytesWiper&) = delete;
    BytesWiper& operator=(const BytesWiper&) = delete;

private:
    std::vector<std::uint8_t>& value_;
};

}  // namespace

std::string load_operator_proof_token_file(const std::string& path) {
    if (path.empty()) return {};

    auto bytes = security::read_private_file_strict(
        path, kMaxOperatorProofTokenBytes, "operator proof token");
    BytesWiper bytes_wiper(bytes);
    if (bytes.empty()) {
        throw std::runtime_error("operator proof token file is empty");
    }
    const std::string_view token(
        reinterpret_cast<const char*>(bytes.data()), bytes.size());
    detail::validate_http_field_value(token, "operator proof token");
    return std::string(token);
}

}  // namespace yume::server::cli
