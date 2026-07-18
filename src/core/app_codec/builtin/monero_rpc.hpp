/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <string>
#include <string_view>

#include "core/app_codec/codec.hpp"

// Monero daemon RPC, the first built-in application codec. Generic lookup and
// dispatch reach it through the descriptor assembled into the registry in
// codec.cpp. Removing the codec means removing this unit, its registry entry,
// and its product-surface callers.
namespace yume::app_codec::builtin {

inline constexpr std::string_view kMoneroRpcCodecId = "monero-rpc-v1";
inline constexpr std::string_view kMoneroRpcAlias = "monero-rpc";
inline constexpr std::size_t kMoneroRpcMaxRequestBody = 8U * 1024U * 1024U;
inline constexpr std::size_t kMoneroRpcMaxResponseBody = 15U * 1024U * 1024U;
inline constexpr int kMoneroRpcDefaultPort = 18089;
inline constexpr std::string_view kMoneroRpcDefaultHost = "127.0.0.1";

// Allow-list policy: method, body size, path shape, and JSON-RPC method.
bool validate_monero_rpc_request(const HttpRequest& request,
                                 std::string* reason = nullptr);

const CodecDescriptor& monero_rpc_descriptor();

}  // namespace yume::app_codec::builtin
