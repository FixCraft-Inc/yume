/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/app_codec/codec.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <limits>
#include <set>
#include <sstream>

#include <boost/asio/ip/address.hpp>
#include <nlohmann/json.hpp>

namespace yume::app_codec {
namespace {

constexpr std::array<std::uint8_t, 4> kEnvelopeMagic{{'Y', 'A', 'C', '1'}};
constexpr std::uint8_t kEnvelopeVersion = 1;
constexpr std::size_t kMaxMetaBytes = 64U * 1024U;
constexpr std::size_t kMaxHeaders = 96;
constexpr std::size_t kMaxHeaderNameBytes = 64;
constexpr std::size_t kMaxHeaderValueBytes = 8192;

std::string lower_ascii(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    for (unsigned char c : value) {
        out.push_back(static_cast<char>(std::tolower(c)));
    }
    return out;
}

std::string trim_ascii(std::string_view value) {
    std::size_t first = 0;
    while (first < value.size() &&
           std::isspace(static_cast<unsigned char>(value[first])) != 0) {
        ++first;
    }
    std::size_t last = value.size();
    while (last > first &&
           std::isspace(static_cast<unsigned char>(value[last - 1])) != 0) {
        --last;
    }
    return std::string(value.substr(first, last - first));
}

bool valid_header_name(std::string_view name) {
    if (name.empty() || name.size() > kMaxHeaderNameBytes) {
        return false;
    }
    for (unsigned char c : name) {
        const bool ok = std::isalnum(c) != 0 || c == '!' || c == '#' ||
                        c == '$' || c == '%' || c == '&' || c == '\'' ||
                        c == '*' || c == '+' || c == '-' || c == '.' ||
                        c == '^' || c == '_' || c == '`' || c == '|' ||
                        c == '~';
        if (!ok) {
            return false;
        }
    }
    return true;
}

bool valid_header_value(std::string_view value) {
    if (value.size() > kMaxHeaderValueBytes) {
        return false;
    }
    for (unsigned char c : value) {
        if ((c < 0x20 && c != '\t') || c == 0x7f) {
            return false;
        }
    }
    return true;
}

bool hop_by_hop_header(std::string_view name) {
    const std::string lower = lower_ascii(name);
    return lower == "connection" ||
           lower == "proxy-connection" ||
           lower == "keep-alive" ||
           lower == "transfer-encoding" ||
           lower == "upgrade" ||
           lower == "trailer" ||
           lower == "te" ||
           lower == "content-length" ||
           lower == "host";
}

std::vector<HttpHeader> sanitized_headers(const std::vector<HttpHeader>& headers) {
    std::vector<HttpHeader> out;
    out.reserve(std::min(headers.size(), kMaxHeaders));
    for (const auto& header : headers) {
        if (out.size() >= kMaxHeaders) {
            break;
        }
        if (hop_by_hop_header(header.name)) {
            continue;
        }
        if (!valid_header_name(header.name) || !valid_header_value(header.value)) {
            continue;
        }
        out.push_back(header);
    }
    return out;
}

std::string path_from_target(std::string_view target, std::string* query) {
    if (query) {
        query->clear();
    }
    const auto hash = target.find('#');
    const std::string_view no_fragment = hash == std::string_view::npos
        ? target
        : target.substr(0, hash);
    const auto q = no_fragment.find('?');
    if (q == std::string_view::npos) {
        return std::string(no_fragment);
    }
    if (query) {
        *query = std::string(no_fragment.substr(q + 1));
    }
    return std::string(no_fragment.substr(0, q));
}

bool append_headers_from_lines(std::string_view lines,
                               std::vector<HttpHeader>* headers,
                               std::string* error) {
    if (!headers) {
        return false;
    }
    headers->clear();
    std::size_t pos = 0;
    while (pos < lines.size()) {
        const auto eol = lines.find("\r\n", pos);
        if (eol == std::string_view::npos) {
            break;
        }
        if (eol == pos) {
            break;
        }
        std::string_view line = lines.substr(pos, eol - pos);
        pos = eol + 2;
        const auto colon = line.find(':');
        if (colon == std::string_view::npos) {
            if (error) {
                *error = "malformed HTTP header";
            }
            return false;
        }
        std::string name = trim_ascii(line.substr(0, colon));
        std::string value = trim_ascii(line.substr(colon + 1));
        if (!valid_header_name(name) || !valid_header_value(value)) {
            if (error) {
                *error = "invalid HTTP header";
            }
            return false;
        }
        if (headers->size() >= kMaxHeaders) {
            if (error) {
                *error = "too many HTTP headers";
            }
            return false;
        }
        headers->push_back(HttpHeader{std::move(name), std::move(value)});
    }
    return true;
}

void append_u32(Bytes* out, std::uint32_t value) {
    out->push_back(static_cast<std::uint8_t>((value >> 24) & 0xff));
    out->push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
    out->push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    out->push_back(static_cast<std::uint8_t>(value & 0xff));
}

std::uint32_t read_u32(const Bytes& data, std::size_t offset) {
    return (static_cast<std::uint32_t>(data[offset]) << 24) |
           (static_cast<std::uint32_t>(data[offset + 1]) << 16) |
           (static_cast<std::uint32_t>(data[offset + 2]) << 8) |
           static_cast<std::uint32_t>(data[offset + 3]);
}

nlohmann::json headers_to_json(const std::vector<HttpHeader>& headers) {
    nlohmann::json array = nlohmann::json::array();
    for (const auto& header : headers) {
        array.push_back(nlohmann::json::array({header.name, header.value}));
    }
    return array;
}

std::vector<HttpHeader> headers_from_json(const nlohmann::json& json) {
    std::vector<HttpHeader> headers;
    if (!json.is_array()) {
        return headers;
    }
    for (const auto& item : json) {
        if (!item.is_array() || item.size() != 2 ||
            !item[0].is_string() || !item[1].is_string()) {
            continue;
        }
        std::string name = item[0].get<std::string>();
        std::string value = item[1].get<std::string>();
        if (valid_header_name(name) && valid_header_value(value)) {
            headers.push_back(HttpHeader{std::move(name), std::move(value)});
        }
    }
    return headers;
}

Bytes encode_envelope(EnvelopeKind kind, nlohmann::json meta, const Bytes& body) {
    meta["codec_frame"] = 1;
    const std::string meta_text = meta.dump();
    Bytes out;
    out.reserve(16 + meta_text.size() + body.size());
    out.insert(out.end(), kEnvelopeMagic.begin(), kEnvelopeMagic.end());
    out.push_back(kEnvelopeVersion);
    out.push_back(static_cast<std::uint8_t>(kind));
    out.push_back(0);
    out.push_back(0);
    append_u32(&out, static_cast<std::uint32_t>(meta_text.size()));
    append_u32(&out, static_cast<std::uint32_t>(body.size()));
    out.insert(out.end(), meta_text.begin(), meta_text.end());
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

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

const std::vector<CodecDescriptor>& builtin_registry() {
    static const std::vector<CodecDescriptor> kRegistry{
        CodecDescriptor{
            std::string(kMoneroRpcCodecId),
            {std::string(kMoneroRpcAlias), "monero"},
            "allow_monero_rpc",
            "Monero RPC",
            Endpoint{std::string(kMoneroRpcDefaultHost), kMoneroRpcDefaultPort},
            kMoneroRpcMaxRequestBody,
            kMoneroRpcMaxResponseBody,
        },
    };
    return kRegistry;
}

}  // namespace

std::string canonical_codec_id(std::string_view value) {
    std::string lowered = lower_ascii(trim_ascii(value));
    std::replace(lowered.begin(), lowered.end(), '_', '-');
    for (const auto& codec : builtin_registry()) {
        if (lowered == codec.id) {
            return codec.id;
        }
        for (const auto& alias : codec.aliases) {
            if (lowered == alias) {
                return codec.id;
            }
        }
    }
    return lowered;
}

bool is_supported_codec(std::string_view value) {
    return canonical_codec_id(value) == std::string(kMoneroRpcCodecId);
}

std::vector<std::string> builtin_codec_ids() {
    std::vector<std::string> ids;
    ids.reserve(builtin_registry().size());
    for (const auto& codec : builtin_registry()) {
        ids.push_back(codec.id);
    }
    return ids;
}

std::optional<CodecDescriptor> builtin_codec(std::string_view value) {
    const std::string id = canonical_codec_id(value);
    for (const auto& codec : builtin_registry()) {
        if (codec.id == id) {
            return codec;
        }
    }
    return std::nullopt;
}

bool same_codec(std::string_view lhs, std::string_view rhs) {
    return canonical_codec_id(lhs) == canonical_codec_id(rhs);
}

bool contains_codec(const std::vector<std::string>& codecs, std::string_view codec) {
    const std::string id = canonical_codec_id(codec);
    return std::any_of(codecs.begin(), codecs.end(), [&](const std::string& value) {
        return canonical_codec_id(value) == id;
    });
}

void add_codec_unique(std::vector<std::string>* codecs, std::string_view codec) {
    if (!codecs) {
        return;
    }
    const std::string id = canonical_codec_id(codec);
    if (id.empty() || contains_codec(*codecs, id)) {
        return;
    }
    codecs->push_back(id);
}

std::optional<Endpoint> parse_endpoint_spec(std::string_view value,
                                            std::string_view default_host,
                                            int default_port,
                                            std::string* error) {
    std::string raw = trim_ascii(value);
    if (raw.empty()) {
        return Endpoint{std::string(default_host), default_port};
    }

    Endpoint endpoint{std::string(default_host), default_port};
    std::string port_text;
    if (raw.front() == '[') {
        const auto end = raw.find(']');
        if (end == std::string::npos || end + 1 >= raw.size() || raw[end + 1] != ':') {
            if (error) {
                *error = "endpoint must be [addr]:port";
            }
            return std::nullopt;
        }
        endpoint.host = raw.substr(1, end - 1);
        port_text = raw.substr(end + 2);
    } else {
        const auto colon = raw.rfind(':');
        if (colon == std::string::npos) {
            port_text = raw;
        } else {
            endpoint.host = raw.substr(0, colon);
            port_text = raw.substr(colon + 1);
        }
    }
    int port = 0;
    const auto* first = port_text.data();
    const auto* last = first + port_text.size();
    auto [ptr, ec] = std::from_chars(first, last, port);
    if (ec != std::errc() || ptr != last || port < 1 || port > 65535) {
        if (error) {
            *error = "endpoint port must be 1..65535";
        }
        return std::nullopt;
    }
    endpoint.port = port;
    if (endpoint.host.empty()) {
        endpoint.host = std::string(default_host);
    }
    return endpoint;
}

bool is_loopback_host_literal(std::string_view host) {
    const std::string text = std::string(host);
    boost::system::error_code ec;
    auto addr = boost::asio::ip::make_address(text, ec);
    return !ec && addr.is_loopback();
}

bool parse_http_request_head(std::string_view header_block,
                             HttpRequest* out,
                             std::string* error) {
    if (!out) {
        return false;
    }
    if (header_block.size() > kMaxHttpHeaderBytes) {
        if (error) {
            *error = "HTTP request headers too large";
        }
        return false;
    }
    const auto first_eol = header_block.find("\r\n");
    if (first_eol == std::string_view::npos) {
        if (error) {
            *error = "missing HTTP request line";
        }
        return false;
    }
    std::string_view request_line = header_block.substr(0, first_eol);
    const auto sp1 = request_line.find(' ');
    const auto sp2 = sp1 == std::string_view::npos
        ? std::string_view::npos
        : request_line.find(' ', sp1 + 1);
    if (sp1 == std::string_view::npos || sp2 == std::string_view::npos) {
        if (error) {
            *error = "malformed HTTP request line";
        }
        return false;
    }
    HttpRequest req;
    req.method = std::string(request_line.substr(0, sp1));
    req.target = std::string(request_line.substr(sp1 + 1, sp2 - sp1 - 1));
    const std::string version = std::string(request_line.substr(sp2 + 1));
    if (version != "HTTP/1.0" && version != "HTTP/1.1") {
        if (error) {
            *error = "unsupported HTTP version";
        }
        return false;
    }
    if (req.target.empty() || req.target.front() != '/' ||
        req.target.find("..") != std::string::npos ||
        req.target.find("://") != std::string::npos) {
        if (error) {
            *error = "invalid HTTP target";
        }
        return false;
    }
    req.path = path_from_target(req.target, &req.query);
    if (!append_headers_from_lines(header_block.substr(first_eol + 2), &req.headers, error)) {
        return false;
    }
    *out = std::move(req);
    return true;
}

bool parse_http_response_head(std::string_view header_block,
                              HttpResponse* out,
                              std::string* error) {
    if (!out) {
        return false;
    }
    if (header_block.size() > kMaxHttpHeaderBytes) {
        if (error) {
            *error = "HTTP response headers too large";
        }
        return false;
    }
    const auto first_eol = header_block.find("\r\n");
    if (first_eol == std::string_view::npos) {
        if (error) {
            *error = "missing HTTP status line";
        }
        return false;
    }
    std::string_view status_line = header_block.substr(0, first_eol);
    if (!status_line.starts_with("HTTP/1.")) {
        if (error) {
            *error = "invalid HTTP status line";
        }
        return false;
    }
    const auto sp1 = status_line.find(' ');
    if (sp1 == std::string_view::npos || sp1 + 4 > status_line.size()) {
        if (error) {
            *error = "malformed HTTP status line";
        }
        return false;
    }
    int code = 0;
    const auto code_text = status_line.substr(sp1 + 1, 3);
    auto [ptr, ec] = std::from_chars(code_text.data(), code_text.data() + code_text.size(), code);
    if (ec != std::errc() || ptr != code_text.data() + code_text.size() || code < 100 || code > 599) {
        if (error) {
            *error = "invalid HTTP status code";
        }
        return false;
    }
    HttpResponse resp;
    resp.status_code = code;
    if (sp1 + 5 <= status_line.size()) {
        resp.reason = trim_ascii(status_line.substr(sp1 + 5));
    } else {
        resp.reason.clear();
    }
    if (resp.reason.empty()) {
        resp.reason = code == 200 ? "OK" : "Upstream Response";
    }
    if (!append_headers_from_lines(header_block.substr(first_eol + 2), &resp.headers, error)) {
        return false;
    }
    *out = std::move(resp);
    return true;
}

std::optional<std::size_t> content_length(const std::vector<HttpHeader>& headers,
                                          std::string* error) {
    std::optional<std::size_t> found;
    for (const auto& header : headers) {
        if (lower_ascii(header.name) != "content-length") {
            continue;
        }
        if (header.value.empty()) {
            if (error) {
                *error = "empty Content-Length";
            }
            return std::nullopt;
        }
        unsigned long long parsed = 0;
        const auto* first = header.value.data();
        const auto* last = first + header.value.size();
        auto [ptr, ec] = std::from_chars(first, last, parsed);
        if (ec != std::errc() || ptr != last ||
            parsed > static_cast<unsigned long long>(std::numeric_limits<std::size_t>::max())) {
            if (error) {
                *error = "invalid Content-Length";
            }
            return std::nullopt;
        }
        const auto value = static_cast<std::size_t>(parsed);
        if (found.has_value() && *found != value) {
            if (error) {
                *error = "conflicting Content-Length headers";
            }
            return std::nullopt;
        }
        found = value;
    }
    return found;
}

bool has_transfer_encoding_chunked(const std::vector<HttpHeader>& headers) {
    for (const auto& header : headers) {
        if (lower_ascii(header.name) != "transfer-encoding") {
            continue;
        }
        std::string value = lower_ascii(header.value);
        if (value.find("chunked") != std::string::npos) {
            return true;
        }
    }
    return false;
}

std::string build_backend_http_request(const HttpRequest& request,
                                       const Endpoint& backend) {
    std::ostringstream out;
    out << request.method << " " << request.target << " HTTP/1.1\r\n";
    out << "Host: " << backend.host << ":" << backend.port << "\r\n";
    for (const auto& header : sanitized_headers(request.headers)) {
        out << header.name << ": " << header.value << "\r\n";
    }
    out << "Content-Length: " << request.body.size() << "\r\n";
    out << "Connection: close\r\n\r\n";
    out.write(reinterpret_cast<const char*>(request.body.data()),
              static_cast<std::streamsize>(request.body.size()));
    return out.str();
}

std::string build_client_http_response(const HttpResponse& response) {
    std::ostringstream out;
    out << "HTTP/1.1 " << response.status_code << " " << response.reason << "\r\n";
    for (const auto& header : sanitized_headers(response.headers)) {
        out << header.name << ": " << header.value << "\r\n";
    }
    out << "Content-Length: " << response.body.size() << "\r\n";
    out << "Connection: close\r\n\r\n";
    out.write(reinterpret_cast<const char*>(response.body.data()),
              static_cast<std::streamsize>(response.body.size()));
    return out.str();
}

Bytes encode_request(const HttpRequest& request) {
    nlohmann::json meta{
        {"method", request.method},
        {"target", request.target},
        {"path", request.path},
        {"query", request.query},
        {"headers", headers_to_json(request.headers)},
    };
    return encode_envelope(EnvelopeKind::Request, std::move(meta), request.body);
}

Bytes encode_response(const HttpResponse& response) {
    nlohmann::json meta{
        {"status", response.status_code},
        {"reason", response.reason},
        {"headers", headers_to_json(response.headers)},
    };
    return encode_envelope(EnvelopeKind::Response, std::move(meta), response.body);
}

Bytes encode_error(int http_status, std::string_view message) {
    nlohmann::json meta{
        {"status", http_status},
        {"message", std::string(message)},
    };
    return encode_envelope(EnvelopeKind::Error, std::move(meta), Bytes{});
}

bool decode_envelope(const Bytes& payload,
                     std::size_t max_body_bytes,
                     Envelope* out,
                     std::string* error) {
    if (!out) {
        return false;
    }
    if (payload.size() < 16) {
        if (error) {
            *error = "codec frame too small";
        }
        return false;
    }
    if (!std::equal(kEnvelopeMagic.begin(), kEnvelopeMagic.end(), payload.begin())) {
        if (error) {
            *error = "codec frame magic mismatch";
        }
        return false;
    }
    if (payload[4] != kEnvelopeVersion) {
        if (error) {
            *error = "unsupported codec frame version";
        }
        return false;
    }
    const auto kind = static_cast<EnvelopeKind>(payload[5]);
    const std::uint32_t meta_len = read_u32(payload, 8);
    const std::uint32_t body_len = read_u32(payload, 12);
    if (meta_len > kMaxMetaBytes || body_len > max_body_bytes) {
        if (error) {
            *error = "codec frame exceeds size limit";
        }
        return false;
    }
    const std::size_t need = 16U + static_cast<std::size_t>(meta_len) +
                             static_cast<std::size_t>(body_len);
    if (payload.size() != need) {
        if (error) {
            *error = "codec frame length mismatch";
        }
        return false;
    }
    nlohmann::json meta;
    try {
        meta = nlohmann::json::parse(payload.begin() + 16,
                                     payload.begin() + 16 + meta_len);
    } catch (const std::exception&) {
        if (error) {
            *error = "invalid codec frame metadata";
        }
        return false;
    }
    try {
        Bytes body(payload.begin() + 16 + meta_len, payload.end());
        Envelope envelope;
        envelope.kind = kind;
        switch (kind) {
            case EnvelopeKind::Request:
                envelope.request.method = meta.value("method", "");
                envelope.request.target = meta.value("target", "");
                envelope.request.path = meta.value("path", "");
                envelope.request.query = meta.value("query", "");
                envelope.request.headers =
                    headers_from_json(meta.value("headers", nlohmann::json::array()));
                envelope.request.body = std::move(body);
                if (envelope.request.method.empty() || envelope.request.target.empty() ||
                    envelope.request.path.empty()) {
                    if (error) {
                        *error = "codec request metadata incomplete";
                    }
                    return false;
                }
                break;
            case EnvelopeKind::Response:
                envelope.response.status_code = meta.value("status", 502);
                envelope.response.reason = meta.value("reason", "Bad Gateway");
                envelope.response.headers =
                    headers_from_json(meta.value("headers", nlohmann::json::array()));
                envelope.response.body = std::move(body);
                if (envelope.response.status_code < 100 || envelope.response.status_code > 599) {
                    envelope.response.status_code = 502;
                    envelope.response.reason = "Bad Gateway";
                }
                break;
            case EnvelopeKind::Error:
                envelope.error_status = meta.value("status", 502);
                envelope.error_message = meta.value("message", "codec error");
                if (envelope.error_status < 400 || envelope.error_status > 599) {
                    envelope.error_status = 502;
                }
                break;
            default:
                if (error) {
                    *error = "unknown codec frame kind";
                }
                return false;
        }
        *out = std::move(envelope);
        return true;
    } catch (const std::exception&) {
        if (error) {
            *error = "invalid codec frame metadata";
        }
        return false;
    }
}

bool validate_monero_rpc_request(const HttpRequest& request,
                                 std::string* reason) {
    const std::string method = lower_ascii(request.method);
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

}  // namespace yume::app_codec
