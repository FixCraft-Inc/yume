/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/loopback_http_fetch.hpp"

#include <algorithm>
#include <new>
#include <optional>
#include <string>
#include <utility>

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

// The message is diagnostic. Losing it to allocation failure keeps the code.
Status status_of(StatusCode code, std::string_view message) noexcept {
    try {
        return Status(code, message);
    } catch (...) {
        return Status(code);
    }
}

}  // namespace

struct LoopbackHttpFetch::State final : std::enable_shared_from_this<State> {
    State(Executor executor, tcp::endpoint backend, bool head_request, LoopbackHttpLimits bounds,
          Completion done)
        : stream(executor), endpoint(backend), head(head_request), limits(bounds),
          completion(std::move(done)) {}

    beast::tcp_stream stream;
    beast::flat_buffer buffer;
    http::request<http::empty_body> request;
    std::optional<http::response_parser<http::vector_body<std::uint8_t>>> parser;
    tcp::endpoint endpoint;
    bool head;
    bool cancelled{false};
    LoopbackHttpLimits limits;
    Completion completion;

    void begin() noexcept {
        if (!completion) return;
        if (cancelled) return fail(status_of(StatusCode::Cancelled, "backend fetch cancelled"));
        try {
            parser.emplace();
            parser->header_limit(static_cast<std::uint32_t>(
                std::min<std::size_t>(limits.response_headers, UINT32_MAX)));
            parser->body_limit(limits.response_body);
            parser->skip(head);
            stream.expires_after(limits.connect_timeout);
            stream.async_connect(endpoint, [self = shared_from_this()](const beast::error_code& error) {
                self->on_connect(error);
            });
        } catch (...) {
            fail(status_of(StatusCode::ResourceExhausted, "backend fetch could not start"));
        }
    }

    void on_connect(const beast::error_code& error) noexcept {
        if (settled()) return;
        if (error) return fail(failure("backend connect failed", error));
        try {
            stream.expires_after(limits.response_timeout);
            http::async_write(stream, request,
                [self = shared_from_this()](const beast::error_code& written, std::size_t) {
                    self->on_write(written);
                });
        } catch (...) {
            fail(status_of(StatusCode::ResourceExhausted, "backend request could not be sent"));
        }
    }

    void on_write(const beast::error_code& error) noexcept {
        if (settled()) return;
        if (error) return fail(failure("backend request failed", error));
        try {
            http::async_read(stream, buffer, *parser,
                [self = shared_from_this()](const beast::error_code& read, std::size_t) {
                    self->on_read(read);
                });
        } catch (...) {
            fail(status_of(StatusCode::ResourceExhausted, "backend response could not be read"));
        }
    }

    void on_read(const beast::error_code& error) noexcept {
        if (settled()) return;
        if (error == http::error::header_limit || error == http::error::body_limit ||
            error == http::error::buffer_overflow) {
            return fail(status_of(StatusCode::ResourceExhausted, "backend response exceeds its limit"));
        }
        if (error) return fail(failure("backend response failed", error));
        if (!parser->is_done()) {
            return fail(status_of(StatusCode::Closed, "backend ended before a complete response"));
        }
        try {
            auto message = parser->release();
            // 1xx responses are not final, and a cover backend has no reason
            // to switch protocols.
            if (message.result_int() < 200U) {
                return fail(status_of(StatusCode::Closed, "backend sent no final response"));
            }
            LoopbackHttpResponse response;
            response.status = message.result_int();
            std::size_t header_bytes = 0U;
            for (const auto& field : message.base()) {
                std::string name(field.name_string());
                std::transform(name.begin(), name.end(), name.begin(), [](unsigned char ch) {
                    return static_cast<char>(ch >= 'A' && ch <= 'Z' ? ch - 'A' + 'a' : ch);
                });
                if (hop_by_hop(name)) continue;
                // A HEAD response describes the GET representation, so its
                // length stays. A GET gets the length of the body it carries.
                if (name == "content-length" && !head) continue;
                header_bytes += name.size() + field.value().size();
                if (header_bytes > limits.response_headers) {
                    return fail(status_of(StatusCode::ResourceExhausted,
                                            "backend response exceeds its limit"));
                }
                response.headers.emplace_back(std::move(name), std::string(field.value()));
            }
            response.body = std::move(message.body());
            if (!head) response.headers.emplace_back("content-length", std::to_string(response.body.size()));
            finish(Result<LoopbackHttpResponse>(std::move(response)));
        } catch (...) {
            fail(status_of(StatusCode::ResourceExhausted, "backend response could not be kept"));
        }
    }

    // True once the fetch has settled or been cancelled. A cancelled fetch
    // settles here, from the handler that the closed socket completed.
    bool settled() noexcept {
        if (!completion) return true;
        if (!cancelled) return false;
        fail(status_of(StatusCode::Cancelled, "backend fetch cancelled"));
        return true;
    }

    static Status failure(std::string_view what, const beast::error_code& error) noexcept {
        if (error == beast::error::timeout) {
            return status_of(StatusCode::Closed, std::string(what) + ": timed out");
        }
        try {
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
        return Prepared(status_of(StatusCode::InvalidArgument, "backend address is not loopback"));
    }
    if (port == 0U) return Prepared(status_of(StatusCode::InvalidArgument, "backend port is 0"));
    if (method != "GET" && method != "HEAD") {
        return Prepared(status_of(StatusCode::InvalidArgument, "backend method must be GET or HEAD"));
    }
    if (!origin_form(target)) {
        return Prepared(status_of(StatusCode::InvalidArgument, "backend target is not an origin-form path"));
    }
    if (!completion) return Prepared(status_of(StatusCode::InvalidArgument, "backend fetch needs a completion"));
    try {
        const bool head = method == "HEAD";
        auto state = std::make_shared<LoopbackHttpFetch::State>(
            executor, tcp::endpoint(address, port), head, limits, std::move(completion));
        auto& request = state->request;
        request.method(head ? http::verb::head : http::verb::get);
        request.target(beast::string_view(target.data(), target.size()));
        request.version(11);
        const tcp::endpoint& backend = state->endpoint;
        request.set(http::field::host, address.is_v6()
            ? "[" + backend.address().to_string() + "]:" + std::to_string(port)
            : backend.address().to_string() + ":" + std::to_string(port));
        request.set(http::field::accept, "*/*");
        request.set(http::field::connection, "close");
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
    if (!context) return Started(status_of(StatusCode::InvalidArgument, "backend fetch needs a context"));
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
        return status_of(StatusCode::FailedPrecondition,
                         "backend answered HTTP " + std::to_string(status));
    }
    return Status::success();
}

}  // namespace yume::providers
