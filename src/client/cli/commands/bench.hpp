/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <memory>
#include <string>

namespace yume::client {

struct ClientConfig;
class Tunnel;

struct EndpointBenchOptions {
    int bench_mib{256};
    int bench_chunk_kib{1024};
    int bench_streams{1};
    std::string bench_direction{"both"};
};

int run_endpoint_benchmark(const std::shared_ptr<Tunnel>& tunnel,
                           const ClientConfig& cfg,
                           const EndpointBenchOptions& options);

}  // namespace yume::client
