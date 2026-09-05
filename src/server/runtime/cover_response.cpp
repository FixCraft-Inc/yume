/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/runtime/cover_response.hpp"

#include "core/runtime/bounded_file.hpp"

#include <exception>
#include <boost/asio/buffer.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/beast/http/string_body.hpp>

namespace yume::server::cover_response {
namespace {

void set_error(std::string* error, std::string message) {
    if (error) *error = std::move(message);
}

}  // namespace

bool normalize_http1_response(std::string_view raw,
                              std::size_t maximum_bytes,
                              std::string* normalized,
                              std::string* error) {
    if (error) error->clear();
    if (!normalized) {
        set_error(error, "capture destination is null");
        return false;
    }
    auto fail = [&](std::string message) {
        normalized->clear();
        set_error(error, std::move(message));
        return false;
    };
    if (raw.size() > maximum_bytes) {
        return fail("capture exceeds the response size limit");
    }
    try {
        // Build separately so raw may safely view *normalized. Only header
        // lines accept LF input; body and chunk framing stay byte-for-byte.
        constexpr std::size_t kMaxHeaderBytes = 64U * 1024U;
        std::string candidate;
        candidate.reserve(raw.size());
        std::size_t cursor = 0;
        bool first = true;
        while (true) {
            const auto end = raw.find('\n', cursor);
            if (end == std::string_view::npos || end >= kMaxHeaderBytes) {
                return fail("capture has no complete bounded HTTP header block");
            }
            auto line = raw.substr(cursor, end - cursor);
            if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
            if (line.find('\r') != std::string_view::npos) {
                return fail("capture contains a bare carriage return");
            }
            if (!first && !line.empty() && (line.front() == ' ' || line.front() == '\t')) {
                return fail("capture contains a folded header");
            }
            if (first && !(line.starts_with("HTTP/1.0 ") || line.starts_with("HTTP/1.1 "))) {
                return fail("capture has an invalid HTTP/1.x status line");
            }
            if (line.size() > maximum_bytes - candidate.size() ||
                maximum_bytes - candidate.size() - line.size() < 2U) {
                return fail("normalized capture exceeds the response size limit");
            }
            candidate.append(line).append("\r\n");
            cursor = end + 1;
            first = false;
            if (line.empty()) break;
        }
        if (raw.size() - cursor > maximum_bytes - candidate.size()) {
            return fail("normalized capture exceeds the response size limit");
        }
        candidate.append(raw.substr(cursor));
        boost::beast::http::response_parser<boost::beast::http::string_body> parser;
        parser.header_limit(kMaxHeaderBytes);
        parser.body_limit(maximum_bytes);
        parser.eager(true);
        boost::system::error_code ec;
        const auto used = parser.put(boost::asio::buffer(candidate), ec);
        if (ec == boost::beast::http::error::need_more) ec.clear();
        if (!ec && !parser.is_done()) parser.put_eof(ec);
        if (ec || !parser.is_done() || used != candidate.size()) {
            return fail("capture has invalid or incomplete HTTP framing");
        }
        if (parser.get().result_int() < 200 || parser.get().result_int() > 599) {
            return fail("capture must contain one final HTTP response");
        }
        *normalized = std::move(candidate);
        return true;
    } catch (const std::exception& exception) {
        return fail(std::string("cannot parse capture: ") + exception.what());
    }
}

bool load_file(const std::filesystem::path& path,
               std::string* normalized,
               std::string* error) {
    if (!normalized) {
        set_error(error, "capture destination is null");
        return false;
    }
    std::string raw;
    if (!runtime::read_text_file_bounded(
            path, kMaxResponseBytes, &raw, error)) {
        normalized->clear();
        return false;
    }
    return normalize_http1_response(raw, kMaxResponseBytes, normalized, error);
}

}  // namespace yume::server::cover_response
