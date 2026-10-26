/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/loopback_http_fetch.hpp"

#include <algorithm>
#include <cstdint>
#include <new>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

namespace yume::providers {
namespace {

namespace beast = boost::beast;
namespace http = beast::http;
using boost::asio::ip::tcp;
using engine::Result;
using engine::Status;
using engine::StatusCode;
using Executor = boost::asio::io_context::executor_type;

constexpr std::size_t kMaxTargetBytes = 8U * 1024U;
constexpr std::size_t kReadBytes = 16U * 1024U;
// Interim 1xx responses before the final one, each within the header limit.
constexpr unsigned kMaxInterimResponses = 8U;

bool hop_by_hop(std::string_view name) noexcept {
    return name == "connection" || name == "keep-alive" || name == "proxy-authenticate" ||
           name == "proxy-authorization" || name == "te" || name == "trailer" ||
           name == "transfer-encoding" || name == "upgrade";
}

bool origin_form(std::string_view target) noexcept {
    return !target.empty() && target.size() <= kMaxTargetBytes && target.front() == '/' &&
           std::all_of(target.begin(), target.end(),
                       [](char ch) { return ch > 0x20 && ch < 0x7f; });
}

}  // namespace

struct LoopbackHttpFetch::State final : std::enable_shared_from_this<State> {
    State(Executor executor, tcp::endpoint backend, bool head_request,
          LoopbackHttpLimits bounds, Completion done)
        : stream(executor),
          buffer(std::min(bounds.response_headers, SIZE_MAX - kReadBytes) +
                 kReadBytes),
          endpoint(backend),
          head(head_request),
          limits(bounds),
          completion(std::move(done)) {}

    beast::tcp_stream stream;
    // Holds unparsed bytes. A header must fit whole, and the parser moves the
    // body out as it arrives.
    beast::flat_buffer buffer;
    std::string request;
    std::size_t request_sent{0U};
    std::optional<http::response_parser<http::vector_body<std::uint8_t>>> parser;
    unsigned interim_responses{0U};
    tcp::endpoint endpoint;
    bool head;
    bool cancelled{false};
    LoopbackHttpLimits limits;
    Completion completion;

    // Every step after start runs in one of this object's own handlers, so
    // an allocation failure there settles the fetch. Beast's composed
    // operations allocate inside their intermediate handlers, where an
    // exception escapes into the executor and the completion never runs.
    void begin() noexcept {
        if (!completion) return;
        if (cancelled)
            return fail(Status::diagnostic(StatusCode::Cancelled,
                                           "backend fetch cancelled"));
        try {
            start_parser();
            stream.expires_after(limits.connect_timeout);
            stream.async_connect(endpoint, [self = shared_from_this()](const beast::error_code& error) {
                self->on_connect(error);
            });
        } catch (...) {
            fail(Status::diagnostic(StatusCode::ResourceExhausted,
                                    "backend fetch could not start"));
        }
    }

    void start_parser() {
        parser.emplace();
        parser->header_limit(static_cast<std::uint32_t>(
            std::min<std::size_t>(limits.response_headers, UINT32_MAX)));
        parser->body_limit(limits.response_body);
        parser->eager(true);
        parser->skip(head);
    }

    void on_connect(const beast::error_code& error) noexcept {
        if (settled()) return;
        if (error) return fail(failure("backend connect failed", error));
        try {
            stream.expires_after(limits.response_timeout);
        } catch (...) {
            return fail(
                Status::diagnostic(StatusCode::ResourceExhausted,
                                   "backend request could not be sent"));
        }
        write_request();
    }

    void write_request() noexcept {
        try {
            stream.async_write_some(
                boost::asio::buffer(request) + request_sent,
                [self = shared_from_this()](const beast::error_code& written,
                                            std::size_t bytes) {
                    self->on_write(written, bytes);
                });
        } catch (...) {
            fail(Status::diagnostic(StatusCode::ResourceExhausted,
                                    "backend request could not be sent"));
        }
    }

    void on_write(const beast::error_code& error, std::size_t bytes) noexcept {
        if (settled()) return;
        if (error) return fail(failure("backend request failed", error));
        request_sent += bytes;
        if (request_sent < request.size()) return write_request();
        read_response();
    }

    void read_response() noexcept {
        try {
            stream.async_read_some(
                buffer.prepare(kReadBytes),
                [self = shared_from_this()](const beast::error_code& read,
                                            std::size_t bytes) {
                    self->on_read(read, bytes);
                });
        } catch (const std::length_error&) {
            // The parser reports an oversized header first. This is the
            // buffer's own bound.
            fail(Status::diagnostic(StatusCode::ResourceExhausted,
                                    "backend response exceeds its limit"));
        } catch (...) {
            fail(Status::diagnostic(StatusCode::ResourceExhausted,
                                    "backend response could not be read"));
        }
    }

    // Parses what is buffered. True when the response needs more bytes.
    bool parse_buffered(beast::error_code& error) {
        while (!parser->is_done() && buffer.size() != 0U) {
            const std::size_t used = parser->put(buffer.data(), error);
            buffer.consume(used);
            if (error == http::error::need_more) {
                error = {};
                return true;
            }
            if (error) return false;
        }
        return !parser->is_done();
    }

    void on_read(const beast::error_code& error, std::size_t bytes) noexcept {
        if (settled()) return;
        if (error && error != boost::asio::error::eof) {
            return fail(failure("backend response failed", error));
        }
        try {
            buffer.commit(bytes);
            beast::error_code parsed;
            const bool more = parse_buffered(parsed);
            if (more && !parsed) {
                if (!error) return read_response();
                if (parser->got_some()) {
                    parser->put_eof(parsed);
                } else {
                    parsed = http::error::end_of_stream;
                }
            }
            on_parsed(parsed);
        } catch (...) {
            fail(Status::diagnostic(StatusCode::ResourceExhausted,
                                    "backend response could not be kept"));
        }
    }

    void on_parsed(const beast::error_code& error) {
        if (error == http::error::header_limit || error == http::error::body_limit ||
            error == http::error::buffer_overflow) {
            return fail(
                Status::diagnostic(StatusCode::ResourceExhausted,
                                   "backend response exceeds its limit"));
        }
        if (error) return fail(failure("backend response failed", error));
        if (!parser->is_done()) {
            return fail(
                Status::diagnostic(StatusCode::Closed,
                                   "backend ended before a complete response"));
        }
        const unsigned status = parser->get().result_int();
        // An interim response such as 103 Early Hints precedes the final one
        // (RFC 9110 15.2). A cover backend has no reason to switch protocols.
        if (status < 200U && status != 101U) {
            if (++interim_responses > kMaxInterimResponses) {
                return fail(Status::diagnostic(
                    StatusCode::Closed,
                    "backend sent too many interim responses"));
            }
            start_parser();
            beast::error_code parsed;
            if (parse_buffered(parsed) && !parsed) return read_response();
            return on_parsed(parsed);
        }
        if (status < 200U) {
            return fail(Status::diagnostic(StatusCode::Closed,
                                           "backend sent no final response"));
        }
        deliver(parser->release());
    }

    void deliver(http::response<http::vector_body<std::uint8_t>> message) {
        LoopbackHttpResponse response;
        response.status = message.result_int();
        // Fields that Connection names are hop-by-hop too (RFC 9110 7.6.1).
        std::vector<std::string> nominated;
        const auto connection =
            message.base().equal_range(http::field::connection);
        for (auto field = connection.first; field != connection.second;
             ++field) {
            for (const auto token : http::token_list(field->value())) {
                nominated.emplace_back(token.data(), token.size());
            }
        }
        std::size_t header_bytes = 0U;
        for (const auto& field : message.base()) {
            std::string name(field.name_string());
            std::transform(
                name.begin(), name.end(), name.begin(), [](unsigned char ch) {
                    return static_cast<char>(
                        ch >= 'A' && ch <= 'Z' ? ch - 'A' + 'a' : ch);
                });
            if (hop_by_hop(name) ||
                std::any_of(nominated.begin(), nominated.end(),
                            [&name](const std::string& token) {
                                return beast::iequals(token, name);
                            })) {
                continue;
            }
            // A HEAD response describes the GET representation, so its
            // length stays. A GET gets the length of the body it carries.
            if (name == "content-length" && !head) continue;
            header_bytes += name.size() + field.value().size();
            if (header_bytes > limits.response_headers) {
                return fail(
                    Status::diagnostic(StatusCode::ResourceExhausted,
                                       "backend response exceeds its limit"));
            }
            response.headers.emplace_back(std::move(name),
                                          std::string(field.value()));
        }
        response.body = std::move(message.body());
        if (!head)
            response.headers.emplace_back("content-length",
                                          std::to_string(response.body.size()));
        finish(Result<LoopbackHttpResponse>(std::move(response)));
    }

    // True once the fetch has settled or been cancelled. A cancelled fetch
    // settles here, from the handler that the closed socket completed.
    bool settled() noexcept {
        if (!completion) return true;
        if (!cancelled) return false;
        fail(Status::diagnostic(StatusCode::Cancelled,
                                "backend fetch cancelled"));
        return true;
    }

    static Status failure(std::string_view what,
                          const beast::error_code& error) noexcept {
        try {
            if (error == beast::error::timeout) {
                return Status(StatusCode::Closed,
                              std::string(what) + ": timed out");
            }
            return Status(StatusCode::Closed, std::string(what) + ": " + error.message());
        } catch (...) {
            return Status(StatusCode::Closed);
        }
    }

    void close_socket() noexcept {
        beast::error_code ignored;
        stream.socket().shutdown(tcp::socket::shutdown_both, ignored);
        // Closes the socket and cancels the stream's timer, so pending work
        // completes now rather than at the deadline.
        stream.close();
    }

    void fail(Status status) noexcept { finish(Result<LoopbackHttpResponse>(std::move(status))); }

    void finish(Result<LoopbackHttpResponse> result) noexcept {
        if (!completion) return;
        close_socket();
        auto done = std::move(completion);
        completion = nullptr;
        try {
            done(std::move(result));
        } catch (...) {
            // The owner's failure stays the owner's. The fetch is settled.
        }
    }
};

namespace {

Result<std::shared_ptr<LoopbackHttpFetch::State>> prepare(
    Executor executor, const boost::asio::ip::address& address, std::uint16_t port,
    std::string_view method, std::string_view target, LoopbackHttpLimits limits,
    LoopbackHttpFetch::Completion completion) {
    using Prepared = Result<std::shared_ptr<LoopbackHttpFetch::State>>;
    if (!address.is_loopback()) {
        return Prepared(Status::diagnostic(StatusCode::InvalidArgument,
                                           "backend address is not loopback"));
    }
    if (port == 0U)
        return Prepared(Status::diagnostic(StatusCode::InvalidArgument,
                                           "backend port is 0"));
    if (method != "GET" && method != "HEAD") {
        return Prepared(Status::diagnostic(
            StatusCode::InvalidArgument, "backend method must be GET or HEAD"));
    }
    if (!origin_form(target)) {
        return Prepared(
            Status::diagnostic(StatusCode::InvalidArgument,
                               "backend target is not an origin-form path"));
    }
    if (!completion)
        return Prepared(Status::diagnostic(StatusCode::InvalidArgument,
                                           "backend fetch needs a completion"));
    try {
        const bool head = method == "HEAD";
        auto state = std::make_shared<LoopbackHttpFetch::State>(
            executor, tcp::endpoint(address, port), head, limits, std::move(completion));
        http::request<http::empty_body> request;
        request.method(head ? http::verb::head : http::verb::get);
        request.target(beast::string_view(target.data(), target.size()));
        request.version(11);
        const tcp::endpoint& backend = state->endpoint;
        request.set(http::field::host, address.is_v6()
            ? "[" + backend.address().to_string() + "]:" + std::to_string(port)
            : backend.address().to_string() + ":" + std::to_string(port));
        request.set(http::field::accept, "*/*");
        request.set(http::field::connection, "close");
        // Serialized here, so sending it needs no allocation later. A stream
        // reports a failed allocation through its state, not by throwing.
        std::ostringstream wire;
        wire << request;
        if (!wire) return Prepared(Status(StatusCode::ResourceExhausted));
        state->request = std::move(wire).str();
        return Prepared(std::move(state));
    } catch (const std::bad_alloc&) {
        return Prepared(Status(StatusCode::ResourceExhausted));
    }
}

}  // namespace

LoopbackHttpFetch::LoopbackHttpFetch(std::shared_ptr<State> state) noexcept
    : state_(std::move(state)) {}

LoopbackHttpFetch::~LoopbackHttpFetch() = default;

Result<std::shared_ptr<LoopbackHttpFetch>> LoopbackHttpFetch::start(
    const std::shared_ptr<AsioExecutionContext>& context,
    const boost::asio::ip::address& address, std::uint16_t port, std::string_view method,
    std::string_view target, LoopbackHttpLimits limits, Completion completion) {
    using Started = Result<std::shared_ptr<LoopbackHttpFetch>>;
    if (!context)
        return Started(Status::diagnostic(StatusCode::InvalidArgument,
                                          "backend fetch needs a context"));
    context->require_context();
    auto prepared = prepare(context->executor(), address, port, method, target, limits,
                            std::move(completion));
    if (!prepared.ok()) return Started(prepared.status());
    auto state = std::move(prepared).take_value();
    try {
        auto handle = std::shared_ptr<LoopbackHttpFetch>(new LoopbackHttpFetch(state));
        // Posted, so the completion never runs inside start().
        boost::asio::post(context->executor(), [state] { state->begin(); });
        return Started(std::move(handle));
    } catch (const std::bad_alloc&) {
        return Started(Status(StatusCode::ResourceExhausted));
    }
}

void LoopbackHttpFetch::cancel() noexcept {
    if (!state_ || !state_->completion || state_->cancelled) return;
    // The handler that the closed socket completes, or the posted start,
    // delivers Cancelled. The completion never runs inside cancel().
    state_->cancelled = true;
    state_->close_socket();
}

Status probe_loopback_http(const boost::asio::ip::address& address, std::uint16_t port,
                           LoopbackHttpLimits limits) {
    boost::asio::io_context io;
    std::optional<Result<LoopbackHttpResponse>> outcome;
    auto prepared = prepare(io.get_executor(), address, port, "HEAD", "/", limits,
                            [&outcome](Result<LoopbackHttpResponse> result) {
                                outcome.emplace(std::move(result));
                            });
    if (!prepared.ok()) return prepared.status();
    auto state = std::move(prepared).take_value();
    boost::asio::post(io, [state] { state->begin(); });
    io.run();
    if (!outcome) return Status(StatusCode::Internal, "backend probe did not complete");
    if (!outcome->ok()) return outcome->status();
    const unsigned status = outcome->value().status;
    if (status >= 500U) {
        return Status::diagnostic(
            StatusCode::FailedPrecondition,
            "backend answered HTTP " + std::to_string(status));
    }
    return Status::success();
}

}  // namespace yume::providers
