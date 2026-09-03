/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <span>

namespace yume::engine {

// A volatile byte loop keeps secret erasure dependency-free and observable to
// the compiler. The caller must keep the referenced storage alive and stable
// until this guard is destroyed.
class ScopedByteWipe final {
public:
    explicit ScopedByteWipe(std::span<std::byte> bytes) noexcept
        : bytes_(bytes) {}

    ScopedByteWipe(const ScopedByteWipe&) = delete;
    ScopedByteWipe& operator=(const ScopedByteWipe&) = delete;
    ScopedByteWipe(ScopedByteWipe&&) = delete;
    ScopedByteWipe& operator=(ScopedByteWipe&&) = delete;

    ~ScopedByteWipe() noexcept {
        auto* output = reinterpret_cast<volatile unsigned char*>(
            bytes_.data());
        for (std::size_t index = 0U; index < bytes_.size(); ++index) {
            output[index] = 0U;
        }
    }

private:
    std::span<std::byte> bytes_;
};

}  // namespace yume::engine
