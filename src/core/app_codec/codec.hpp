/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yume::app_codec {

using Bytes = std::vector<std::uint8_t>;

inline constexpr std::string_view kOpenProto = "app-codec-v1";

inline constexpr std::size_t kMaxHttpHeaderBytes = 32U * 1024U;

struct Endpoint {
    std::string host;
    int port{0};
};

struct HttpRequest;

// Codec-specific admission policy, run before a request reaches the backend.
// Returns false and sets *reason to refuse. Codecs must supply one: dispatch is
// fail-closed, so a descriptor without a validator refuses every request.
using RequestValidator = bool (*)(const HttpRequest& request, std::string* reason);

struct CodecDescriptor {
    std::string id;
    std::vector<std::string> aliases;
    std::string display_name;
    Endpoint default_endpoint;
    std::size_t max_request_body{0};
    std::size_t max_response_body{0};
    RequestValidator validate_request{nullptr};
    // Backends are loopback-only unless a codec deliberately opts out.
    bool require_loopback_backend{true};
};

struct HttpHeader {
    std::string name;
    std::string value;
};

struct HttpRequest {
    std::string method;
    std::string target;
    std::string path;
    std::string query;
    std::vector<HttpHeader> headers;
    Bytes body;
};

struct HttpResponse {
    int status_code{502};
    std::string reason{"Bad Gateway"};
    std::vector<HttpHeader> headers;
    Bytes body;
};

enum class EnvelopeKind : std::uint8_t {
    Request = 1,
    Response = 2,
    Error = 3,
};

struct Envelope {
    EnvelopeKind kind{EnvelopeKind::Error};
    HttpRequest request;
    HttpResponse response;
    int error_status{502};
    std::string error_message{"codec error"};
};

// Registry lookup. Every codec-identity question resolves through the registry;
// core never compares against a specific codec id.
std::string canonical_codec_id(std::string_view value);
bool is_supported_codec(std::string_view value);
std::vector<std::string> builtin_codec_ids();
std::optional<CodecDescriptor> builtin_codec(std::string_view value);
bool same_codec(std::string_view lhs, std::string_view rhs);
bool contains_codec(const std::vector<std::string>& codecs, std::string_view codec);
void add_codec_unique(std::vector<std::string>* codecs, std::string_view codec);

std::optional<Endpoint> parse_endpoint_spec(std::string_view value,
                                            std::string_view default_host,
                                            int default_port,
                                            std::string* error = nullptr);
bool is_loopback_host_literal(std::string_view host);

bool parse_http_request_head(std::string_view header_block,
                             HttpRequest* out,
                             std::string* error = nullptr);
bool parse_http_response_head(std::string_view header_block,
                              HttpResponse* out,
                              std::string* error = nullptr);
std::optional<std::size_t> content_length(const std::vector<HttpHeader>& headers,
                                          std::string* error = nullptr);
bool has_transfer_encoding_chunked(const std::vector<HttpHeader>& headers);

std::optional<std::string> build_backend_http_request(const HttpRequest& request,
                                                      const Endpoint& backend,
                                                      std::string* error = nullptr);
std::string build_client_http_response(const HttpResponse& response);

Bytes encode_request(const HttpRequest& request);
Bytes encode_response(const HttpResponse& response);
Bytes encode_error(int http_status, std::string_view message);
bool decode_envelope(const Bytes& payload,
                     std::size_t max_body_bytes,
                     Envelope* out,
                     std::string* error = nullptr);

}  // namespace yume::app_codec
