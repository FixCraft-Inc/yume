/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "engine/carrier.hpp"

#include <utility>

namespace yume::engine {

CarrierCredit::CarrierCredit(std::size_t bytes,
                             ReleaseHandler release) noexcept
    : bytes_(bytes), release_(std::move(release)) {}

// A moved-from std::function need not be empty (libc++ leaves a small
// target in place), so the source is emptied explicitly.
CarrierCredit::CarrierCredit(CarrierCredit&& other) noexcept
    : bytes_(std::exchange(other.bytes_, 0U)),
      release_(std::exchange(other.release_, nullptr)) {}

CarrierCredit& CarrierCredit::operator=(CarrierCredit&& other) noexcept {
    if (this != &other) {
        release_now();
        bytes_ = std::exchange(other.bytes_, 0U);
        release_ = std::exchange(other.release_, nullptr);
    }
    return *this;
}

CarrierCredit::~CarrierCredit() noexcept {
    release_now();
}

void CarrierCredit::release_now() noexcept {
    const std::size_t bytes = std::exchange(bytes_, 0U);
    ReleaseHandler release = std::exchange(release_, nullptr);
    if (bytes == 0U || !release) {
        return;
    }
    try {
        release(bytes);
    } catch (...) {
        // Receive credit is cleanup state and must be safe in destructors.
    }
}

}  // namespace yume::engine
