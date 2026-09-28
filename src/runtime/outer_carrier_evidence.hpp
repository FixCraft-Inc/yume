/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <filesystem>
#include <memory>
#include <string>

#include "stealth/outer_carrier_observer.hpp"

namespace yume::runtime {

// Writes one payload-free behavior report about the client's first outer
// carrier, for comparison with the captured browser (schema 2 of
// scripts/yume_classifier_evidence.py). The report describes only what the
// carrier did. yume runs no workload of its own, so application volume is left
// to whatever drove the session, and the idle interval is the quiet time the
// carrier observed before its close began.
//
// The file is reserved when the run starts: an absolute path whose parent is
// owned by this user, not group or world writable and outside every Git
// worktree, created exclusively with mode 0600. A report is complete only
// when the run succeeded and every lifecycle stage was observed. A complete
// report is not a parity verdict.
class OuterCarrierEvidence final {
public:
    static constexpr std::size_t kMaxSerializedBytes = 1024U * 1024U;

    static std::unique_ptr<OuterCarrierEvidence> reserve(
        const std::filesystem::path& path, std::string& error);

    OuterCarrierEvidence(const OuterCarrierEvidence&) = delete;
    OuterCarrierEvidence& operator=(const OuterCarrierEvidence&) = delete;
    // Writes an incomplete report if finalize() was never called.
    ~OuterCarrierEvidence();

    std::shared_ptr<obfs::OuterCarrierTrace> trace() const noexcept {
        return trace_;
    }

    // Writes the one report. False means it is incomplete or could not be
    // durably written, with the reason in error.
    bool finalize(bool run_succeeded, std::string& error);

private:
    OuterCarrierEvidence(
        int parent_fd, int file_fd,
        std::shared_ptr<obfs::OuterCarrierTrace> trace) noexcept;

    bool write_report(bool run_succeeded, std::string& error) noexcept;
    bool write_payload(const std::string& payload, std::string& error) noexcept;

    int parent_fd_{-1};
    int file_fd_{-1};
    bool finalized_{false};
    std::shared_ptr<obfs::OuterCarrierTrace> trace_;
};

}  // namespace yume::runtime
