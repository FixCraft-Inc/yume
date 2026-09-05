/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/app_codec/builtin/monero_rpc.hpp"

#include <set>

#include <nlohmann/json.hpp>

#include "core/app_codec/internal.hpp"

namespace yume::app_codec::builtin {
namespace {

bool json_rpc_method_allowed(std::string_view method) {
    static const std::set<std::string> kAllowed{
        "get_alternate_chains",
        "get_block",
        "get_block_count",
        "get_block_header_by_hash",
        "get_block_header_by_height",
        "get_block_headers_range",
        "get_coinbase_tx_sum",
        "get_connections",
        "get_fee_estimate",
        "get_height",
        "get_info",
        "get_last_block_header",
        "get_output_distribution",
        "get_output_histogram",
        "get_outs",
        "get_peer_list",
        "get_transaction_pool",
        "get_transaction_pool_hashes",
        "get_transaction_pool_stats",
        "get_transactions",
        "get_txpool_backlog",
        "get_version",
        "hard_fork_info",
        "is_key_image_spent",
        "on_get_block_hash",
        "relay_tx",
        "send_raw_transaction",
        "sync_info",
    };
    return kAllowed.count(std::string(method)) != 0;
}

bool rpc_path_allowed(std::string_view path) {
    static const std::set<std::string> kAllowed{
        "/json_rpc",
        "/get_height",
        "/get_blocks.bin",
        "/get_hashes.bin",
        "/get_o_indexes.bin",
        "/get_outs.bin",
        "/gettransactions",
        "/get_alt_blocks_hashes",
        "/is_key_image_spent",
        "/send_raw_transaction",
        "/sendrawtransaction",
        "/get_transaction_pool",
        "/get_transaction_pool_hashes.bin",
        "/get_transaction_pool_stats",
        "/get_output_distribution",
        "/get_fee_estimate",
        "/get_version",
        "/get_info",
    };
    return kAllowed.count(std::string(path)) != 0;
}

bool validate_json_rpc_body(const Bytes& body, std::string* reason) {
    if (body.empty()) {
        if (reason) {
            *reason = "empty JSON-RPC body";
        }
        return false;
    }
    try {
        const auto json = nlohmann::json::parse(body.begin(), body.end());
        auto validate_one = [&](const nlohmann::json& item) {
            if (!item.is_object() || !item.contains("method") || !item["method"].is_string()) {
                return false;
            }
            return json_rpc_method_allowed(item["method"].get<std::string>());
        };
        if (json.is_array()) {
            if (json.empty() || json.size() > 16) {
                if (reason) {
                    *reason = "JSON-RPC batch size not allowed";
                }
                return false;
            }
            for (const auto& item : json) {
                if (!validate_one(item)) {
                    if (reason) {
                        *reason = "JSON-RPC method not allowed";
                    }
                    return false;
                }
            }
            return true;
        }
        if (!validate_one(json)) {
            if (reason) {
                *reason = "JSON-RPC method not allowed";
            }
            return false;
        }
        return true;
    } catch (const std::exception&) {
        if (reason) {
            *reason = "invalid JSON-RPC body";
        }
        return false;
    }
}

}  // namespace

bool validate_monero_rpc_request(const HttpRequest& request,
                                 std::string* reason) {
    const std::string method = detail::lower_ascii(request.method);
    if (method != "get" && method != "post") {
        if (reason) {
            *reason = "HTTP method not allowed";
        }
        return false;
    }
    if (request.body.size() > kMoneroRpcMaxRequestBody) {
        if (reason) {
            *reason = "request body too large";
        }
        return false;
    }
    if (request.path.empty() || request.path.front() != '/' ||
        request.path.find("..") != std::string::npos ||
        request.path.find("://") != std::string::npos) {
        if (reason) {
            *reason = "RPC path not allowed";
        }
        return false;
    }
    if (!rpc_path_allowed(request.path)) {
        if (reason) {
            *reason = "RPC path not allowed";
        }
        return false;
    }
    if (request.path == "/json_rpc") {
        if (method != "post") {
            if (reason) {
                *reason = "JSON-RPC requires POST";
            }
            return false;
        }
        return validate_json_rpc_body(request.body, reason);
    }
    return true;
}

const CodecDescriptor& monero_rpc_descriptor() {
    static const CodecDescriptor kDescriptor{
        std::string(kMoneroRpcCodecId),
        {std::string(kMoneroRpcAlias), "monero"},
        "Monero RPC",
        Endpoint{std::string(kMoneroRpcDefaultHost), kMoneroRpcDefaultPort},
        kMoneroRpcMaxRequestBody,
        kMoneroRpcMaxResponseBody,
        &validate_monero_rpc_request,
        true,
    };
    return kDescriptor;
}

}  // namespace yume::app_codec::builtin
