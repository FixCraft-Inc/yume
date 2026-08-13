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

constexpr std::string_view kExpectedBuildId = "test-browser-helper-v1";

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

template <typename Callback>
void ExpectFailure(Callback&& callback) {
    try {
        callback();
    } catch (const std::runtime_error&) {
        return;
    }
    assert(false && "expected runtime_error");
}

}  // namespace

int main() {
    using namespace yume::client::chrome_tls;

    Request request;
    request.connection_id[0] = 0x42;
    request.expected_build_id = std::string(kExpectedBuildId);
    request.server_name = "localhost";
    request.ca_path = "/tmp/yume-ca.pem";
    request.leaf_pin.assign(kSha256Bytes, 0xA5);
    const auto request_wire = EncodeRequest(request);
    const Request decoded_request = DecodeRequest(request_wire);
    assert(decoded_request.connection_id == request.connection_id);
    assert(decoded_request.expected_build_id == kExpectedBuildId);
    assert(decoded_request.server_name == request.server_name);
    assert(decoded_request.ca_path == request.ca_path);
    assert(decoded_request.leaf_pin == request.leaf_pin);
    assert(decoded_request.timeout_ms == 12000);

    Ready ready;
    ready.connection_id = request.connection_id;
    ready.build_id = std::string(kExpectedBuildId);
    ready.alpn = "h2";
    ready.leaf_fingerprint.fill(0x11);
    ready.exporter.fill(0x22);
    const Response ready_response = DecodeResponse(
        EncodeReady(ready), request.connection_id, kExpectedBuildId);
    assert(ready_response.kind == ResponseKind::Ready);
    assert(ready_response.ready.leaf_fingerprint == ready.leaf_fingerprint);
    assert(ready_response.ready.exporter == ready.exporter);

    HelperError helper_error;
    helper_error.connection_id = request.connection_id;
    helper_error.code = 8;
    helper_error.message = "TLS leaf pin mismatch";
    const Response error_response = DecodeResponse(
        EncodeError(helper_error), request.connection_id, kExpectedBuildId);
    assert(error_response.kind == ResponseKind::Error);
    assert(error_response.error.code == 8);
    assert(error_response.error.message == helper_error.message);

    auto trailing = request_wire;
    trailing.push_back(0);
    ExpectFailure([&]() { (void)DecodeRequest(trailing); }, "trailing");

    for (std::size_t size = 0; size < request_wire.size(); ++size) {
        auto truncated = request_wire;
        truncated.resize(size);
        ExpectFailure([&]() { (void)DecodeRequest(truncated); });
    }

    auto bad_magic = request_wire;
    bad_magic[0] ^= 1;
    ExpectFailure([&]() { (void)DecodeRequest(bad_magic); }, "magic");

    auto wrong_request_type = request_wire;
    wrong_request_type[10] = 0;
    wrong_request_type[11] = 2;
    ExpectFailure(
        [&]() { (void)DecodeRequest(wrong_request_type); },
        "request type");

    auto wrong_id = request.connection_id;
    wrong_id[0] ^= 1;
    ExpectFailure(
        [&]() {
            (void)DecodeResponse(EncodeReady(ready), wrong_id,
                                 kExpectedBuildId);
        },
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

    Request empty_name = request;
    empty_name.server_name.clear();
    ExpectFailure([&]() { (void)EncodeRequest(empty_name); }, "server name");

    Request long_name = request;
    long_name.server_name.assign(254, 'a');
    ExpectFailure([&]() { (void)EncodeRequest(long_name); }, "server name");

    Request long_ca = request;
    long_ca.ca_path.assign(4097, 'a');
    ExpectFailure([&]() { (void)EncodeRequest(long_ca); }, "custom CA path");

    Request long_build_id = request;
    long_build_id.expected_build_id.assign(257, 'a');
    ExpectFailure([&]() { (void)EncodeRequest(long_build_id); }, "build ID");

    for (const std::uint32_t timeout : {999U, 120001U}) {
        Request invalid_timeout = request;
        invalid_timeout.timeout_ms = timeout;
        ExpectFailure(
            [&]() { (void)EncodeRequest(invalid_timeout); }, "timeout");
    }

    Request invalid_pin = request;
    invalid_pin.leaf_pin.resize(31);
    ExpectFailure([&]() { (void)EncodeRequest(invalid_pin); }, "leaf pin");

    const auto ready_wire = EncodeReady(ready);
    for (std::size_t size = 0; size < ready_wire.size(); ++size) {
        auto truncated = ready_wire;
        truncated.resize(size);
        ExpectFailure(
            [&]() {
                (void)DecodeResponse(truncated, request.connection_id,
                                     kExpectedBuildId);
            });
    }

    auto trailing_ready = ready_wire;
    trailing_ready.push_back(0);
    ExpectFailure(
        [&]() {
            (void)DecodeResponse(trailing_ready, request.connection_id,
                                 kExpectedBuildId);
        },
        "trailing");

    auto wrong_response_type = ready_wire;
    wrong_response_type[10] = 0;
    wrong_response_type[11] = 1;
    ExpectFailure(
        [&]() {
            (void)DecodeResponse(wrong_response_type, request.connection_id,
                                 kExpectedBuildId);
        },
        "response type");

    auto oversized_response = ready_wire;
    oversized_response[12] = 0x00;
    oversized_response[13] = 0x01;
    oversized_response[14] = 0x00;
    oversized_response[15] = 0x01;
    ExpectFailure(
        [&]() {
            (void)DecodeResponse(oversized_response, request.connection_id,
                                 kExpectedBuildId);
        },
        "exceeds cap");

    Ready wrong_build = ready;
    wrong_build.build_id = "wrong-helper";
    ExpectFailure(
        [&]() {
            (void)DecodeResponse(
                EncodeReady(wrong_build), request.connection_id,
                kExpectedBuildId);
        },
        "build identity");

    Ready wrong_alpn = ready;
    wrong_alpn.alpn = "http/1.1";
    ExpectFailure(
        [&]() {
            (void)DecodeResponse(
                EncodeReady(wrong_alpn), request.connection_id,
                kExpectedBuildId);
        },
        "negotiate h2");

    Ready long_ready_build = ready;
    long_ready_build.build_id.assign(257, 'a');
    ExpectFailure([&]() { (void)EncodeReady(long_ready_build); }, "build ID");

    Ready long_alpn = ready;
    long_alpn.alpn.assign(256, 'a');
    ExpectFailure([&]() { (void)EncodeReady(long_alpn); }, "ALPN");

    HelperError long_error = helper_error;
    long_error.message.assign(1025, 'a');
    ExpectFailure([&]() { (void)EncodeError(long_error); }, "helper error");

    return 0;
}
