/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>

#include "core/stealth/outer_carrier_observer.hpp"

namespace yume::client {

struct OuterCarrierCapturePolicy {
    bool endpoint_bench{false};
    bool full_bench{false};
    int bench_mib{0};
    int bench_chunk_kib{0};
    int bench_streams{0};
    std::string bench_direction;
    int tunnel_count{0};
    std::string transport_profile;
    std::string tls_backend;
    std::string required_tls_backend;
    bool obfuscation{false};
    bool non_interactive{false};
    bool conflicting_mode{false};
    bool outbound_proxy{false};
    std::uint16_t obfs_pad_multiple{0};
    std::uint32_t obfs_jitter_ms{0};
};

// Empty means the policy is valid. The capture is deliberately restricted to
// the frozen one-shot 1-MiB bidirectional endpoint workload.
std::string ValidateOuterCarrierCapturePolicy(
    const OuterCarrierCapturePolicy& policy);

class OuterCarrierCapture final {
public:
    static constexpr std::size_t kMaxSerializedBytes = 1024U * 1024U;

    static std::unique_ptr<OuterCarrierCapture> Reserve(
        const std::filesystem::path& path, std::string* error);

    OuterCarrierCapture(const OuterCarrierCapture&) = delete;
    OuterCarrierCapture& operator=(const OuterCarrierCapture&) = delete;
    ~OuterCarrierCapture();

    std::shared_ptr<obfs::OuterCarrierTrace> trace() const noexcept {
        return trace_;
    }

    // Writes exactly one terminal document. A complete capture is not a
    // parity verdict: its actual event-derived behavior may still be DRIFT.
    // False means the evidence was incomplete or could not be durably written.
    bool Finalize(bool operation_succeeded, std::string* error = nullptr);

private:
    OuterCarrierCapture(
        int parent_fd, int file_fd,
        std::shared_ptr<obfs::OuterCarrierTrace> trace) noexcept;

    bool WriteTerminalDocument(bool operation_succeeded,
                               std::string* error) noexcept;
    bool WritePayload(const std::string& payload,
                      std::string* error) noexcept;

    int parent_fd_{-1};
    int file_fd_{-1};
    bool finalized_{false};
    std::shared_ptr<obfs::OuterCarrierTrace> trace_;
};

}  // namespace yume::client
