/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/stealth/outer_carrier_observer.hpp"

#include <limits>

namespace yume::obfs {

namespace {
std::size_t SaturatingAdd(std::size_t left, std::size_t right) noexcept {
    return right > std::numeric_limits<std::size_t>::max() - left
        ? std::numeric_limits<std::size_t>::max()
        : left + right;
}

}  // namespace

OuterCarrierTrace::OuterCarrierTrace() {
    try {
        events_.reserve(512);
    } catch (...) {
        truncated_.store(true, std::memory_order_release);
    }
}

std::size_t OuterCarrierTrace::EstimateBytes(
    const OuterCarrierEvent& event) const noexcept {
    std::size_t total = sizeof(event);
    total = SaturatingAdd(
        total, event.settings.size() * sizeof(OuterCarrierSetting));
    total = SaturatingAdd(
        total, event.headers.size() * sizeof(OuterCarrierHeader));
    for (const auto& header : event.headers) {
        total = SaturatingAdd(total, header.name.size());
        total = SaturatingAdd(total, header.value.size());
    }
    return total;
}

void OuterCarrierTrace::Record(OuterCarrierEvent event) noexcept {
    if (truncated()) return;
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        if (truncated()) return;
        const std::size_t estimated = EstimateBytes(event);
        if (events_.size() >= kMaxEvents ||
            estimated > kMaxRetainedBytes -
                (retained_bytes_ < kMaxRetainedBytes
                     ? retained_bytes_
                     : kMaxRetainedBytes)) {
            truncated_.store(true, std::memory_order_release);
            return;
        }
        const auto now = std::chrono::steady_clock::now();
        if (!started_) {
            started_at_ = now;
            started_ = true;
        }
        event.elapsed_us = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(
                now - started_at_)
                .count());
        events_.push_back(std::move(event));
        retained_bytes_ += estimated;
    } catch (...) {
        truncated_.store(true, std::memory_order_release);
    }
}

void OuterCarrierTrace::MarkTruncated() noexcept {
    truncated_.store(true, std::memory_order_release);
}

void OuterCarrierTrace::SetTlsAlpn(std::string alpn) noexcept {
    try {
        if (alpn.size() > 16) {
            truncated_.store(true, std::memory_order_release);
            return;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        tls_alpn_ = std::move(alpn);
    } catch (...) {
        truncated_.store(true, std::memory_order_release);
    }
}

OuterCarrierSnapshot OuterCarrierTrace::Snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return OuterCarrierSnapshot{
        events_, truncated_.load(std::memory_order_acquire), tls_alpn_};
}

const char* OuterCarrierDirectionName(OuterCarrierDirection value) noexcept {
    switch (value) {
        case OuterCarrierDirection::Sent: return "sent";
        case OuterCarrierDirection::Received: return "received";
    }
    return "unknown";
}

const char* OuterCarrierStreamClassName(
    OuterCarrierStreamClass value) noexcept {
    switch (value) {
        case OuterCarrierStreamClass::Connection: return "connection";
        case OuterCarrierStreamClass::Priming: return "priming";
        case OuterCarrierStreamClass::AssetCss: return "asset-css";
        case OuterCarrierStreamClass::AssetJs: return "asset-js";
        case OuterCarrierStreamClass::Carrier: return "carrier";
        case OuterCarrierStreamClass::Other: return "other";
    }
    return "unknown";
}

const char* OuterCarrierEventKindName(OuterCarrierEventKind value) noexcept {
    switch (value) {
        case OuterCarrierEventKind::H2Frame: return "h2-frame";
        case OuterCarrierEventKind::WebSocketFrame: return "websocket-frame";
        case OuterCarrierEventKind::FlowWindowStalled:
            return "flow-window-stalled";
        case OuterCarrierEventKind::FlowWindowRecovered:
            return "flow-window-recovered";
        case OuterCarrierEventKind::StreamClose: return "stream-close";
        case OuterCarrierEventKind::H2HeadersDecoded:
            return "h2-headers-decoded";
        case OuterCarrierEventKind::IdleInterval: return "idle-interval";
        case OuterCarrierEventKind::CloseWire: return "close-wire";
    }
    return "unknown";
}

}  // namespace yume::obfs
