/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/transport/chrome_tls_protocol.hpp"

#include <cassert>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

template <typename Callback>
void ExpectFailure(Callback&& callback, const std::string& expected) {
    try {
        callback();
    } catch (const std::runtime_error& error) {
        assert(std::string(error.what()).find(expected) != std::string::npos);
        return;
    }
    assert(false && "expected runtime_error");
}

}  // namespace

int main() {
    using namespace yume::client::chrome_tls;

    Request request;
    request.connection_id[0] = 0x42;
    request.server_name = "localhost";
    request.ca_path = "/tmp/yume-ca.pem";
    request.leaf_pin.assign(kSha256Bytes, 0xA5);
    const auto request_wire = EncodeRequest(request);
    const Request decoded_request = DecodeRequest(request_wire);
    assert(decoded_request.connection_id == request.connection_id);
    assert(decoded_request.expected_build_id == kBuildId);
    assert(decoded_request.server_name == request.server_name);
    assert(decoded_request.ca_path == request.ca_path);
    assert(decoded_request.leaf_pin == request.leaf_pin);
    assert(decoded_request.timeout_ms == 12000);

    Ready ready;
    ready.connection_id = request.connection_id;
    ready.build_id = std::string(kBuildId);
    ready.alpn = "h2";
    ready.leaf_fingerprint.fill(0x11);
    ready.exporter.fill(0x22);
    const Response ready_response = DecodeResponse(
        EncodeReady(ready), request.connection_id);
    assert(ready_response.kind == ResponseKind::Ready);
    assert(ready_response.ready.leaf_fingerprint == ready.leaf_fingerprint);
    assert(ready_response.ready.exporter == ready.exporter);

    HelperError helper_error;
    helper_error.connection_id = request.connection_id;
    helper_error.code = 8;
    helper_error.message = "TLS leaf pin mismatch";
    const Response error_response = DecodeResponse(
        EncodeError(helper_error), request.connection_id);
    assert(error_response.kind == ResponseKind::Error);
    assert(error_response.error.code == 8);
    assert(error_response.error.message == helper_error.message);

    auto trailing = request_wire;
    trailing.push_back(0);
    ExpectFailure([&]() { (void)DecodeRequest(trailing); }, "trailing");

    auto wrong_id = request.connection_id;
    wrong_id[0] ^= 1;
    ExpectFailure(
        [&]() { (void)DecodeResponse(EncodeReady(ready), wrong_id); },
        "connection ID");

    auto bad_version = request_wire;
    bad_version[9] = 2;
    ExpectFailure([&]() { (void)DecodeRequest(bad_version); }, "version");

    auto oversized = request_wire;
    oversized[12] = 0x00;
    oversized[13] = 0x01;
    oversized[14] = 0x00;
    oversized[15] = 0x01;
    ExpectFailure([&]() { (void)DecodeRequest(oversized); }, "exceeds cap");

    Request invalid_pin = request;
    invalid_pin.leaf_pin.resize(31);
    ExpectFailure([&]() { (void)EncodeRequest(invalid_pin); }, "leaf pin");

    return 0;
}
