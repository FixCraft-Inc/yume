/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace yume::client {

struct ClientConfig;
class Tunnel;

struct EndpointBenchOptions {
    int bench_mib{256};
    int bench_chunk_kib{64};
    int bench_streams{1};
    std::string bench_direction{"both"};
    bool full_profile{false};
    bool matched_message_echo{false};
};

enum class EndpointBenchWorkload {
    SequentialDirections,
    MatchedMessageEcho,
};

class EndpointEchoReplyContract final {
public:
    // Exact capture geometry: no byte-stream splitting or coalescing.
    EndpointEchoReplyContract(
        std::uint64_t total_bytes, std::size_t message_bytes) noexcept
        : total_bytes_(total_bytes), message_bytes_(message_bytes) {}

    bool Accept(const std::vector<std::uint8_t>& data) noexcept;
    bool complete() const noexcept {
        return message_bytes_ != 0 && total_bytes_ != 0 &&
            total_bytes_ % message_bytes_ == 0 &&
            received_bytes_ == total_bytes_ &&
            received_messages_ == total_bytes_ / message_bytes_;
    }
    std::uint64_t received_bytes() const noexcept { return received_bytes_; }
    std::uint64_t received_messages() const noexcept {
        return received_messages_;
    }

private:
    std::uint64_t total_bytes_{0};
    std::size_t message_bytes_{0};
    std::uint64_t received_bytes_{0};
    std::uint64_t received_messages_{0};
};

EndpointBenchWorkload select_endpoint_bench_workload(
    const EndpointBenchOptions& options) noexcept;

int run_endpoint_benchmark(const std::shared_ptr<Tunnel>& tunnel,
                           const ClientConfig& cfg,
                           const EndpointBenchOptions& options);

}  // namespace yume::client
