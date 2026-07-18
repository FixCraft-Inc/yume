/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>

#include <nlohmann/json.hpp>

#include "core/app_codec/codec.hpp"

namespace {

using yume::app_codec::Bytes;

void append_u32(Bytes* out, std::uint32_t value) {
    out->push_back(static_cast<std::uint8_t>((value >> 24) & 0xff));
    out->push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
    out->push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    out->push_back(static_cast<std::uint8_t>(value & 0xff));
}

Bytes raw_request_envelope(nlohmann::json metadata) {
    const std::string text = metadata.dump();
    Bytes out{'Y', 'A', 'C', '1', 1, 1, 0, 0};
    append_u32(&out, static_cast<std::uint32_t>(text.size()));
    append_u32(&out, 0);
    out.insert(out.end(), text.begin(), text.end());
    return out;
}

void test_rejects_target_metadata_mismatch() {
    auto payload = raw_request_envelope({
        {"method", "POST"},
        {"target", "/stop_daemon"},
        {"path", "/json_rpc"},
        {"query", ""},
        {"headers", nlohmann::json::array()},
    });
    yume::app_codec::Envelope envelope;
    std::string error;
    assert(!yume::app_codec::decode_envelope(payload, 1024, &envelope, &error));
    assert(error.find("mismatch") != std::string::npos);
}

void test_rejects_target_injection_and_response_reason_injection() {
    auto request = raw_request_envelope({
        {"method", "POST"},
        {"target", "/json_rpc\r\nX-Injected: yes"},
        {"path", "/json_rpc"},
        {"query", ""},
        {"headers", nlohmann::json::array()},
    });
    yume::app_codec::Envelope envelope;
    std::string error;
    assert(!yume::app_codec::decode_envelope(request, 1024, &envelope, &error));

    yume::app_codec::HttpResponse response;
    assert(yume::app_codec::parse_http_response_head(
        "HTTP/1.1 200 OK\r\nX-Test: one\r\n\r\n", &response, &error));
    response.reason = "OK\r\nX-Injected: yes";
    const std::string built = yume::app_codec::build_client_http_response(response);
    assert(built.find("X-Injected") == std::string::npos);
}

void test_strips_connection_nominated_headers() {
    yume::app_codec::HttpRequest request;
    request.method = "POST";
    request.target = "/json_rpc?x=1";
    request.path = "/json_rpc";
    request.query = "x=1";
    request.headers = {
        {"Connection", "X-Remove"},
        {"X-Remove", "secret"},
        {"X-Keep", "present"},
    };
    const auto built = yume::app_codec::build_backend_http_request(
        request, {"127.0.0.1", 18089});
    assert(built.has_value());
    assert(built->find("X-Remove") == std::string::npos);
    assert(built->find("X-Keep: present") != std::string::npos);
}

void test_rejects_over_limit_headers_and_non_http11_response() {
    nlohmann::json headers = nlohmann::json::array();
    for (int i = 0; i < 97; ++i) {
        headers.push_back(nlohmann::json::array({"X-Test", "value"}));
    }
    auto payload = raw_request_envelope({
        {"method", "POST"},
        {"target", "/json_rpc"},
        {"path", "/json_rpc"},
        {"query", ""},
        {"headers", headers},
    });
    yume::app_codec::Envelope envelope;
    std::string error;
    assert(!yume::app_codec::decode_envelope(payload, 1024, &envelope, &error));

    yume::app_codec::HttpResponse response;
    assert(!yume::app_codec::parse_http_response_head(
        "HTTP/1.9 200 OK\r\n\r\n", &response, &error));
}

// Every registry entry must resolve through the generic lookups. This caught a
// hardcoded is_supported_codec() that accepted only the first built-in and
// would have silently rejected any codec added after it.
void test_registry_drives_every_codec_lookup() {
    const auto ids = yume::app_codec::builtin_codec_ids();
    assert(!ids.empty());
    for (const auto& id : ids) {
        assert(yume::app_codec::is_supported_codec(id));
        const auto descriptor = yume::app_codec::builtin_codec(id);
        assert(descriptor.has_value());
        assert(descriptor->id == id);
        assert(yume::app_codec::canonical_codec_id(id) == id);
        // Dispatch is fail-closed: a codec with no policy admits nothing, so a
        // registered codec must carry a validator to be usable at all.
        assert(descriptor->validate_request != nullptr);
        for (const auto& alias : descriptor->aliases) {
            assert(yume::app_codec::canonical_codec_id(alias) == id);
            assert(yume::app_codec::is_supported_codec(alias));
        }
    }
    assert(!yume::app_codec::is_supported_codec("not-a-real-codec"));
    assert(!yume::app_codec::builtin_codec("not-a-real-codec").has_value());
}

// The generic Endpoint must not carry any codec's defaults.
void test_generic_endpoint_has_no_codec_defaults() {
    const yume::app_codec::Endpoint endpoint;
    assert(endpoint.host.empty());
    assert(endpoint.port == 0);
}

}  // namespace

int main() {
    test_rejects_target_metadata_mismatch();
    test_rejects_target_injection_and_response_reason_injection();
    test_strips_connection_nominated_headers();
    test_rejects_over_limit_headers_and_non_http11_response();
    test_registry_drives_every_codec_lookup();
    test_generic_endpoint_has_no_codec_defaults();
    std::cout << "codec_test ok\n";
    return 0;
}
