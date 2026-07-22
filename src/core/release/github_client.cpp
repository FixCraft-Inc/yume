/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/release/github_client.hpp"

#include <algorithm>
#include <exception>
#include <functional>
#include <memory>
#include <string_view>
#include <utility>

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <nlohmann/json.hpp>
#include <openssl/ssl.h>

namespace yume::release {
namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace ssl = asio::ssl;
using tcp = asio::ip::tcp;

constexpr std::string_view kApiHost = "api.github.com";
constexpr std::size_t kMaxResponseBytes = 256 * 1024;

struct HttpResult {
    unsigned status{0};
    std::string body;
    std::string error;
};

class HttpsGetOperation : public std::enable_shared_from_this<HttpsGetOperation> {
public:
    using Completion = std::function<void(HttpResult)>;

    HttpsGetOperation(asio::io_context& io,
                      ssl::context& context,
                      std::string host,
                      std::string target,
                      std::chrono::milliseconds timeout,
                      Completion completion)
        : resolver_(io),
          stream_(io, context),
          deadline_(io),
          host_(std::move(host)),
          target_(std::move(target)),
          timeout_(timeout),
          completion_(std::move(completion)) {
        parser_.body_limit(kMaxResponseBytes);
    }

    void start() {
        if (SSL_set_tlsext_host_name(stream_.native_handle(), host_.c_str()) != 1) {
            finish_error("failed to configure TLS SNI");
            return;
        }
        stream_.set_verify_mode(ssl::verify_peer);
        stream_.set_verify_callback(ssl::host_name_verification(host_));

        request_.version(11);
        request_.method(http::verb::get);
        request_.target(target_);
        request_.set(http::field::host, host_);
        request_.set(http::field::user_agent, "Yume version checker");
        request_.set(http::field::accept, "application/vnd.github+json");
        request_.set(http::field::connection, "close");
        request_.set("X-GitHub-Api-Version", "2022-11-28");

        deadline_.expires_after(timeout_);
        deadline_.async_wait([self = shared_from_this()](const beast::error_code& error) {
            if (!error) {
                self->finish_error("request timed out");
            }
        });

        resolver_.async_resolve(
            host_, "443",
            [self = shared_from_this()](const beast::error_code& error,
                                        const tcp::resolver::results_type& endpoints) {
                self->on_resolve(error, endpoints);
            });
    }

private:
    void on_resolve(const beast::error_code& error,
                    const tcp::resolver::results_type& endpoints) {
        if (error) {
            finish_error("DNS lookup failed: " + error.message());
            return;
        }
        beast::get_lowest_layer(stream_).async_connect(
            endpoints,
            [self = shared_from_this()](const beast::error_code& connect_error,
                                        const tcp::resolver::results_type::endpoint_type&) {
                self->on_connect(connect_error);
            });
    }

    void on_connect(const beast::error_code& error) {
        if (error) {
            finish_error("connection failed: " + error.message());
            return;
        }
        stream_.async_handshake(
            ssl::stream_base::client,
            [self = shared_from_this()](const beast::error_code& handshake_error) {
                self->on_handshake(handshake_error);
            });
    }

    void on_handshake(const beast::error_code& error) {
        if (error) {
            finish_error("TLS verification failed: " + error.message());
            return;
        }
        http::async_write(
            stream_, request_,
            [self = shared_from_this()](const beast::error_code& write_error,
                                        std::size_t) {
                self->on_write(write_error);
            });
    }

    void on_write(const beast::error_code& error) {
        if (error) {
            finish_error("request write failed: " + error.message());
            return;
        }
        http::async_read(
            stream_, buffer_, parser_,
            [self = shared_from_this()](const beast::error_code& read_error,
                                        std::size_t) {
                self->on_read(read_error);
            });
    }

    void on_read(const beast::error_code& error) {
        if (error) {
            finish_error("response read failed: " + error.message());
            return;
        }
        auto response = parser_.release();
        HttpResult result;
        result.status = response.result_int();
        result.body = std::move(response.body());
        finish(std::move(result));
    }

    void finish_error(std::string message) {
        HttpResult result;
        result.error = std::move(message);
        finish(std::move(result));
    }

    void finish(HttpResult result) {
        if (finished_) {
            return;
        }
        finished_ = true;

        beast::error_code ignored;
        deadline_.cancel(ignored);
        resolver_.cancel();
        auto& socket = beast::get_lowest_layer(stream_).socket();
        socket.cancel(ignored);
        socket.shutdown(tcp::socket::shutdown_both, ignored);
        socket.close(ignored);

        auto completion = std::move(completion_);
        completion(std::move(result));
    }

    tcp::resolver resolver_;
    beast::ssl_stream<beast::tcp_stream> stream_;
    asio::steady_timer deadline_;
    beast::flat_buffer buffer_;
    http::request<http::empty_body> request_;
    http::response_parser<http::string_body> parser_;
    std::string host_;
    std::string target_;
    std::chrono::milliseconds timeout_;
    Completion completion_;
    bool finished_{false};
};

HttpResult https_get_json(std::string host,
                          std::string target,
                          std::chrono::milliseconds timeout) {
    asio::io_context io;
    ssl::context context(ssl::context::tls_client);
    beast::error_code error;
    context.set_default_verify_paths(error);
    if (error) {
        return {0, {}, "system CA certificates are unavailable: " + error.message()};
    }
    if (SSL_CTX_set_min_proto_version(context.native_handle(), TLS1_2_VERSION) != 1) {
        return {0, {}, "failed to configure the minimum TLS version"};
    }

    std::optional<HttpResult> result;
    std::make_shared<HttpsGetOperation>(
        io, context, std::move(host), std::move(target), timeout,
        [&result](HttpResult completed) { result = std::move(completed); })
        ->start();
    io.run();
    if (!result.has_value()) {
        return {0, {}, "request did not complete"};
    }
    return std::move(*result);
}

std::string project_api_path(const GitHubProject& project, std::string_view suffix) {
    return "/repos/" + project.owner + "/" + project.repository + std::string(suffix);
}

std::string project_release_url(const GitHubProject& project, const std::string& tag) {
    return "https://github.com/" + project.owner + "/" + project.repository +
           "/releases/tag/" + tag;
}

std::optional<ReleaseReference> parse_latest_release(
    const GitHubProject& project,
    const HttpResult& response,
    std::string* error) {
    if (response.status != 200) {
        if (response.status != 404) {
            *error = "GitHub latest-release request returned HTTP " +
                     std::to_string(response.status);
        }
        return std::nullopt;
    }
    try {
        const auto body = nlohmann::json::parse(response.body);
        if (!body.is_object() || body.value("draft", true) ||
            body.value("prerelease", true)) {
            *error = "GitHub did not return a stable release";
            return std::nullopt;
        }
        const std::string tag = body.value("tag_name", std::string{});
        const auto parsed = parse_version(tag);
        if (!parsed.has_value() || parsed->development) {
            *error = "GitHub stable release has an invalid version tag";
            return std::nullopt;
        }
        ReleaseReference reference;
        reference.tag = tag;
        reference.published_date = format_github_date(
            body.value("published_at", std::string{}));
        reference.url = body.value("html_url", project_release_url(project, tag));
        reference.kind = ReferenceKind::stable_release;
        return reference;
    } catch (const std::exception&) {
        *error = "GitHub latest-release response was invalid";
        return std::nullopt;
    }
}

std::optional<ReleaseReference> parse_highest_tag(
    const GitHubProject& project,
    const HttpResult& response,
    std::string* error) {
    if (response.status != 200) {
        *error = "GitHub tag request returned HTTP " + std::to_string(response.status);
        return std::nullopt;
    }
    try {
        const auto body = nlohmann::json::parse(response.body);
        if (!body.is_array()) {
            *error = "GitHub tag response was invalid";
            return std::nullopt;
        }

        std::optional<ParsedVersion> highest;
        std::string highest_name;
        for (const auto& item : body) {
            if (!item.is_object()) continue;
            const std::string name = item.value("name", std::string{});
            const auto candidate = parse_version(name);
            if (!candidate.has_value() || candidate->development) continue;
            if (!highest.has_value() || compare_version_numbers(*candidate, *highest) > 0) {
                highest = candidate;
                highest_name = name;
            }
        }
        if (!highest.has_value()) {
            *error = "No valid version tag was found";
            return std::nullopt;
        }

        return ReleaseReference{
            highest_name,
            {},
            project_release_url(project, highest_name),
            ReferenceKind::tag,
        };
    } catch (const std::exception&) {
        *error = "GitHub tag response was invalid";
        return std::nullopt;
    }
}

}  // namespace

RemoteProjectInfo query_github_project(
    const GitHubProject& project,
    const std::string& installed_version,
    std::chrono::milliseconds request_timeout) {
    RemoteProjectInfo info;
    const auto local = parse_version(installed_version);
    if (!local.has_value()) {
        info.error = "Installed version is not comparable";
        return info;
    }

    const auto started = std::chrono::steady_clock::now();
    const auto remaining_timeout = [&] {
        const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - started);
        return elapsed >= request_timeout
            ? std::chrono::milliseconds(0)
            : request_timeout - elapsed;
    };

    const HttpResult latest = https_get_json(
        std::string(kApiHost), project_api_path(project, "/releases/latest"),
        remaining_timeout());
    if (!latest.error.empty()) {
        info.error = latest.error;
        return info;
    }
    info.latest_stable_release = parse_latest_release(project, latest, &info.error);
    if (!local->development) {
        return info;
    }

    // A development build must be newer than both the latest stable release
    // and every valid version tag. A repository with only prereleases (Yume
    // currently has this shape) also needs this fallback because
    // /releases/latest returns 404.
    const auto tag_timeout = remaining_timeout();
    if (tag_timeout.count() <= 0) {
        info.error = "GitHub update-check deadline expired";
        return info;
    }
    const HttpResult tags = https_get_json(
        std::string(kApiHost), project_api_path(project, "/tags?per_page=100"),
        tag_timeout);
    if (!tags.error.empty()) {
        info.error = tags.error;
        return info;
    }
    info.highest_version_tag = parse_highest_tag(project, tags, &info.error);
    return info;
}

}  // namespace yume::release
