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

CarrierCredit::CarrierCredit(CarrierCredit&& other) noexcept
    : bytes_(std::exchange(other.bytes_, 0U)),
      release_(std::move(other.release_)) {}

CarrierCredit& CarrierCredit::operator=(CarrierCredit&& other) noexcept {
    if (this != &other) {
        release_now();
        bytes_ = std::exchange(other.bytes_, 0U);
        release_ = std::move(other.release_);
    }
    return *this;
}

CarrierCredit::~CarrierCredit() noexcept {
    release_now();
}

void CarrierCredit::release_now() noexcept {
    const std::size_t bytes = std::exchange(bytes_, 0U);
    ReleaseHandler release = std::move(release_);
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
