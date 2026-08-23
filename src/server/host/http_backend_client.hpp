/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/any_io_executor.hpp>

namespace yume::server::host {

struct BackendHttpResponse {
    unsigned status{502};
    std::vector<std::pair<std::string, std::string>> headers;
    std::vector<std::uint8_t> body;
};

struct BackendHttpLimits {
    std::size_t request_headers{32U * 1024U};
    std::size_t response_headers{64U * 1024U};
    std::size_t response_body{8U * 1024U * 1024U};
    std::chrono::milliseconds connect_timeout{2000};
    std::chrono::milliseconds response_timeout{5000};
};

using BackendFetchHandler =
    std::function<void(std::string error, BackendHttpResponse response)>;

class BackendFetch {
public:
    virtual ~BackendFetch() = default;
    virtual void cancel() = 0;
};

// Fetch one ordinary GET/HEAD from a prevalidated loopback IP literal. There is
// no resolver, redirect following, proxy auth, or peer-selected upstream host.
// The returned operation may be cancelled from its executor. Completion is
// delivered exactly once, including cancellation; starting is posted so the
// handler cannot run before this function returns.
std::shared_ptr<BackendFetch> fetch_loopback_http(
    boost::asio::any_io_executor executor,
    std::string loopback_ip,
    int port,
    std::string method,
    std::string target,
    BackendHttpLimits limits,
    BackendFetchHandler handler);

// Startup-only health probe. Uses the same bounded fetcher and returns only
// after success or the configured timeout.
bool probe_loopback_http(const std::string& loopback_ip,
                         int port,
                         std::string* error,
                         BackendHttpLimits limits = {});

}  // namespace yume::server::host
