/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/socks5_upstream.hpp"

#include <array>
#include <cstddef>
#include <new>
#include <span>
#include <utility>
#include <vector>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/steady_timer.hpp>

#include "core/security/secure_erase.hpp"

namespace yume::providers {
namespace {

using engine::Buffer;
using engine::ByteChannel;
using engine::CancellationRegistration;
using engine::CancellationSource;
using engine::CancellationToken;
using engine::Result;
using engine::Status;
using engine::StatusCode;

constexpr std::uint8_t kVersion = 0x05U;
constexpr std::uint8_t kNoAuthentication = 0x00U;
constexpr std::uint8_t kUsernamePassword = 0x02U;
constexpr std::uint8_t kNoAcceptableMethod = 0xffU;
constexpr std::uint8_t kPasswordVersion = 0x01U;
constexpr std::uint8_t kConnect = 0x01U;
constexpr std::uint8_t kIpv4 = 0x01U;
constexpr std::uint8_t kName = 0x03U;
constexpr std::uint8_t kIpv6 = 0x04U;
constexpr std::size_t kMaxField = 255U;

// The message is diagnostic. Losing it to allocation failure keeps the code.
Status status_of(StatusCode code, std::string_view message) noexcept {
    try {
        return Status(code, message);
    } catch (...) {
        return Status(code);
    }
}

std::string_view refusal(std::uint8_t code) noexcept {
    switch (code) {
    case 0x01U: return "general SOCKS server failure";
    case 0x02U: return "connection not allowed by ruleset";
    case 0x03U: return "network unreachable";
    case 0x04U: return "host unreachable";
    case 0x05U: return "connection refused";
    case 0x06U: return "TTL expired";
    case 0x07U: return "command not supported";
    case 0x08U: return "address type not supported";
    default: return "unknown reply code";
    }
}

// VER CMD RSV ATYP DST.ADDR DST.PORT, with an IP literal as an address and
// anything else as a name for the proxy to resolve.
std::vector<std::uint8_t> connect_request(const std::string& host, std::uint16_t port) {
    std::vector<std::uint8_t> request{kVersion, kConnect, 0x00U};
    boost::system::error_code error;
    const auto address = boost::asio::ip::make_address(host, error);
    if (!error && address.is_v4()) {
        request.push_back(kIpv4);
        const auto bytes = address.to_v4().to_bytes();
        request.insert(request.end(), bytes.begin(), bytes.end());
    } else if (!error && address.is_v6() && address.to_v6().scope_id() == 0U) {
        request.push_back(kIpv6);
        const auto bytes = address.to_v6().to_bytes();
        request.insert(request.end(), bytes.begin(), bytes.end());
    } else {
        request.push_back(kName);
        request.push_back(static_cast<std::uint8_t>(host.size()));
        request.insert(request.end(), host.begin(), host.end());
    }
    request.push_back(static_cast<std::uint8_t>(port >> 8U));
    request.push_back(static_cast<std::uint8_t>(port & 0xffU));
    return request;
}

}  // namespace

struct Socks5UpstreamProvider::Settings final {
    std::vector<std::uint8_t> connect;
    std::optional<common::Socks5Credentials> credentials;
    Socks5UpstreamLimits limits;
};

namespace {

using Settings = Socks5UpstreamProvider::Settings;
using Completion = engine::ByteChannelProvider::Completion;

class Handshake final : public std::enable_shared_from_this<Handshake> {
public:
    Handshake(std::shared_ptr<AsioExecutionContext> context,
              std::shared_ptr<engine::ByteChannelProvider> proxy,
              std::shared_ptr<const Settings> settings, Completion completion)
        : context_(std::move(context)), proxy_(std::move(proxy)), settings_(std::move(settings)),
          timer_(context_->executor()), completion_(std::move(completion)) {}

    void start(engine::EndpointRole role, const CancellationToken& caller) {
        const std::weak_ptr<Handshake> weak = weak_from_this();
        // The caller may cancel from any thread. Cancelling the source is
        // thread-safe, and every operation it stops completes on the context.
        auto registered = caller.register_callback([weak] {
            if (const auto self = weak.lock()) self->source_.cancel();
        });
        if (!registered.ok()) return fail(registered.status());
        registration_ = std::move(registered).take_value();
        timer_.expires_after(settings_->limits.handshake_timeout);
        timer_.async_wait([weak](const boost::system::error_code& error) {
            if (error) return;
            if (const auto self = weak.lock()) {
                self->timed_out_ = true;
                self->source_.cancel();
            }
        });
        proxy_->async_create(role, source_.token(),
            [self = shared_from_this()](Result<std::unique_ptr<ByteChannel>> created) {
                self->on_connected(std::move(created));
            });
    }

private:
    enum class Step : std::uint8_t {
        Method,
        Password,
        ReplyHead,
        ReplyName,
        ReplyRest,
    };

    void on_connected(Result<std::unique_ptr<ByteChannel>> created) {
        if (!created.ok()) return fail(created.status());
        channel_ = std::move(created).take_value();
        const bool password = settings_->credentials.has_value();
        send({kVersion, 0x01U, password ? kUsernamePassword : kNoAuthentication}, Step::Method, 2U);
    }

    void send(std::vector<std::uint8_t> bytes, Step next, std::size_t reply_bytes) {
        const security::ScopedErase wipe(bytes);
        if (bytes.size() > channel_->max_write_size()) {
            return fail(status_of(StatusCode::InvalidArgument, "SOCKS5 request exceeds the channel's writes"));
        }
        auto buffer = Buffer::copy_from(std::as_bytes(std::span(bytes)), bytes.size());
        if (!buffer.ok()) return fail(buffer.status());
        const std::size_t size = bytes.size();
        channel_->async_write(std::move(buffer).take_value(), source_.token(),
            [self = shared_from_this(), size, next, reply_bytes](Status status, std::size_t written) {
                if (!status.ok()) return self->fail(std::move(status));
                if (written != size) {
                    return self->fail(status_of(StatusCode::Closed, "SOCKS5 request was cut short"));
                }
                self->expect(next, reply_bytes);
            });
    }

    // Reads exactly `count` bytes, so nothing after the proxy's reply is
    // consumed.
    void expect(Step step, std::size_t count) {
        step_ = step;
        input_.clear();
        wanted_ = count;
        read();
    }

    void read() {
        channel_->async_read(wanted_ - input_.size(), source_.token(),
            [self = shared_from_this()](Result<Buffer> received) { self->on_read(std::move(received)); });
    }

    void on_read(Result<Buffer> received) {
        if (!received.ok()) return fail(received.status());
        const auto bytes = received.value().bytes();
        if (bytes.empty() || bytes.size() > wanted_ - input_.size()) {
            return fail(status_of(StatusCode::Closed, "proxy ended the SOCKS5 exchange"));
        }
        for (const std::byte byte : bytes) input_.push_back(static_cast<std::uint8_t>(byte));
        if (input_.size() < wanted_) return read();
        advance();
    }

    void advance() {
        switch (step_) {
        case Step::Method: {
            const bool password = settings_->credentials.has_value();
            if (input_[0] != kVersion) return protocol_error();
            if (input_[1] == kNoAcceptableMethod) {
                return fail(status_of(StatusCode::PermissionDenied,
                                      password ? "proxy does not accept username and password"
                                               : "proxy requires authentication"));
            }
            if (input_[1] != (password ? kUsernamePassword : kNoAuthentication)) return protocol_error();
            if (!password) return send(settings_->connect, Step::ReplyHead, 4U);
            const auto& credentials = *settings_->credentials;
            std::vector<std::uint8_t> request;
            const security::ScopedErase wipe(request);
            request.reserve(3U + credentials.username().size() + credentials.password().size());
            request.push_back(kPasswordVersion);
            request.push_back(static_cast<std::uint8_t>(credentials.username().size()));
            request.insert(request.end(), credentials.username().begin(), credentials.username().end());
            request.push_back(static_cast<std::uint8_t>(credentials.password().size()));
            request.insert(request.end(), credentials.password().begin(), credentials.password().end());
            return send(request, Step::Password, 2U);
        }
        case Step::Password:
            if (input_[0] != kPasswordVersion) return protocol_error();
            if (input_[1] != 0x00U) {
                return fail(status_of(StatusCode::PermissionDenied, "proxy refused the SOCKS5 credentials"));
            }
            return send(settings_->connect, Step::ReplyHead, 4U);
        case Step::ReplyHead:
            if (input_[0] != kVersion || input_[2] != 0x00U) return protocol_error();
            if (input_[1] != 0x00U) {
                try {
                    return fail(Status(StatusCode::Closed,
                                       "proxy refused CONNECT: " + std::string(refusal(input_[1]))));
                } catch (...) {
                    return fail(Status(StatusCode::Closed));
                }
            }
            if (input_[3] == kIpv4) return expect(Step::ReplyRest, 4U + 2U);
            if (input_[3] == kIpv6) return expect(Step::ReplyRest, 16U + 2U);
            if (input_[3] == kName) return expect(Step::ReplyName, 1U);
            return protocol_error();
        case Step::ReplyName:
            return expect(Step::ReplyRest, std::size_t{input_[0]} + 2U);
        case Step::ReplyRest:
            return succeed();
        }
    }

    void protocol_error() { fail(status_of(StatusCode::Closed, "proxy did not answer as SOCKS5")); }

    void settle() noexcept {
        timer_.cancel();
        registration_.unregister();
    }

    void succeed() {
        settle();
        auto done = std::move(completion_);
        completion_ = nullptr;
        try {
            done(Result<std::unique_ptr<ByteChannel>>(std::move(channel_)));
        } catch (...) {
            // The owner's failure stays the owner's.
        }
    }

    void fail(Status status) {
        if (!completion_) return;
        if (timed_out_) status = status_of(StatusCode::Closed, "proxy handshake timed out");
        settle();
        if (channel_) {
            channel_->close();
            channel_.reset();
        }
        auto done = std::move(completion_);
        completion_ = nullptr;
        try {
            done(Result<std::unique_ptr<ByteChannel>>(std::move(status)));
        } catch (...) {
            // The owner's failure stays the owner's.
        }
    }

    std::shared_ptr<AsioExecutionContext> context_;
    std::shared_ptr<engine::ByteChannelProvider> proxy_;
    std::shared_ptr<const Settings> settings_;
    boost::asio::steady_timer timer_;
    Completion completion_;
    CancellationSource source_;
    CancellationRegistration registration_;
    std::unique_ptr<ByteChannel> channel_;
    std::vector<std::uint8_t> input_;
    std::size_t wanted_{0U};
    Step step_{Step::Method};
    bool timed_out_{false};
};

}  // namespace

Socks5UpstreamProvider::Socks5UpstreamProvider(std::shared_ptr<AsioExecutionContext> context,
                                               std::shared_ptr<engine::ByteChannelProvider> proxy,
                                               std::shared_ptr<const Settings> settings) noexcept
    : context_(std::move(context)), proxy_(std::move(proxy)), settings_(std::move(settings)) {}

Socks5UpstreamProvider::~Socks5UpstreamProvider() noexcept = default;

Result<std::shared_ptr<Socks5UpstreamProvider>> Socks5UpstreamProvider::create(
    std::shared_ptr<AsioExecutionContext> context, std::shared_ptr<engine::ByteChannelProvider> proxy,
    std::string target_host, std::uint16_t target_port, std::optional<common::Socks5Credentials> credentials,
    Socks5UpstreamLimits limits) {
    using Created = Result<std::shared_ptr<Socks5UpstreamProvider>>;
    if (!context || !proxy) {
        return Created(status_of(StatusCode::InvalidArgument, "SOCKS5 upstream needs a context and a proxy"));
    }
    if (target_host.empty() || target_host.size() > kMaxField) {
        return Created(status_of(StatusCode::InvalidArgument, "SOCKS5 target needs 1 to 255 bytes"));
    }
    if (target_port == 0U) return Created(status_of(StatusCode::InvalidArgument, "SOCKS5 target port is 0"));
    if (limits.handshake_timeout <= std::chrono::milliseconds::zero()) {
        return Created(status_of(StatusCode::InvalidArgument, "SOCKS5 handshake needs a deadline"));
    }
    try {
        auto settings = std::make_shared<Settings>(
            Settings{connect_request(target_host, target_port), std::move(credentials), limits});
        return Created(std::shared_ptr<Socks5UpstreamProvider>(
            new Socks5UpstreamProvider(std::move(context), std::move(proxy), std::move(settings))));
    } catch (const std::bad_alloc&) {
        return Created(Status(StatusCode::ResourceExhausted));
    }
}

const engine::ProviderDescriptor& Socks5UpstreamProvider::descriptor() const noexcept {
    return proxy_->descriptor();
}

void Socks5UpstreamProvider::async_create(engine::EndpointRole role,
                                          engine::CancellationToken cancellation,
                                          Completion completion) {
    context_->require_context();
    if (!completion) return;
    std::shared_ptr<Handshake> handshake;
    try {
        handshake = std::make_shared<Handshake>(context_, proxy_, settings_, std::move(completion));
    } catch (const std::bad_alloc&) {
        if (completion) {
            try {
                completion(Result<std::unique_ptr<ByteChannel>>(Status(StatusCode::ResourceExhausted)));
            } catch (...) {
            }
        }
        return;
    }
    handshake->start(role, cancellation);
}

}  // namespace yume::providers
