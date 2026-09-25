/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/asio/ip/address.hpp>

#include "engine/status.hpp"
#include "providers/asio_execution_context.hpp"

namespace yume::providers {

struct LoopbackHttpLimits final {
    std::size_t response_headers{64U * 1024U};
    std::size_t response_body{8U * 1024U * 1024U};
    std::chrono::milliseconds connect_timeout{2000};
    std::chrono::milliseconds response_timeout{5000};
};

struct LoopbackHttpResponse final {
    unsigned status{0};
    // Lower-case names in the backend's order, without hop-by-hop fields.
    // content-length is the size of body, or for HEAD the size the backend
    // reported for the matching GET.
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<std::uint8_t> body;
};

// One GET or HEAD to an HTTP/1.1 server on a loopback address, for a cover
// site that a local web server provides. Nothing in the request comes from a
// client except the method and target: the Host is the backend's own address,
// and there is no resolver, redirect or proxy step, so a peer cannot choose
// the upstream. The response is buffered whole within the limits.
//
// start() and cancel() require the context. The completion runs on the
// context exactly once and never inside start() or cancel(). Exceptions from
// it are contained.
class LoopbackHttpFetch final {
public:
    using Completion = std::function<void(engine::Result<LoopbackHttpResponse>)>;

    // InvalidArgument for an address that is not loopback, port 0, a method
    // other than GET or HEAD, or a target that is not an origin-form path of
    // at most 8 KiB visible ASCII. Later failures reach the completion:
    // Closed when the backend cannot be reached, times out or ends before a
    // complete final response, ResourceExhausted when a response limit is
    // exceeded, Cancelled after cancel().
    static engine::Result<std::shared_ptr<LoopbackHttpFetch>> start(
        const std::shared_ptr<AsioExecutionContext>& context,
        const boost::asio::ip::address& address, std::uint16_t port,
        std::string_view method, std::string_view target,
        LoopbackHttpLimits limits, Completion completion);

    LoopbackHttpFetch(const LoopbackHttpFetch&) = delete;
    LoopbackHttpFetch& operator=(const LoopbackHttpFetch&) = delete;
    // Dropping the handle does not cancel the fetch.
    ~LoopbackHttpFetch();

    // Ends the fetch and closes its connection. The completion then receives
    // Cancelled, unless it already ran. Repeated calls do nothing.
    void cancel() noexcept;

    struct State;

private:
    explicit LoopbackHttpFetch(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

// A blocking HEAD / on a private context, for checking a backend at startup.
// A status from 200 to 499 succeeds. A 5xx status is FailedPrecondition, and
// other failures keep the fetch's code.
engine::Status probe_loopback_http(const boost::asio::ip::address& address,
                                   std::uint16_t port,
                                   LoopbackHttpLimits limits = {});

}  // namespace yume::providers
