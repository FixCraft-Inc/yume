/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace yume::obfs {

enum class OuterCarrierDirection : std::uint8_t {
    Sent,
    Received,
};

enum class OuterCarrierStreamClass : std::uint8_t {
    Connection,
    Priming,
    AssetCss,
    AssetJs,
    Carrier,
    Other,
};

enum class OuterCarrierEventKind : std::uint8_t {
    H2Frame,
    WebSocketFrame,
    FlowWindowStalled,
    FlowWindowRecovered,
    StreamClose,
    H2HeadersDecoded,
    IdleInterval,
    CloseWire,
};

struct OuterCarrierSetting {
    std::uint32_t id{0};
    std::uint32_t value{0};
};

struct OuterCarrierHeader {
    std::string name;
    std::string value;
};

struct OuterCarrierEvent {
    OuterCarrierEventKind kind{OuterCarrierEventKind::H2Frame};
    OuterCarrierDirection direction{OuterCarrierDirection::Sent};
    OuterCarrierStreamClass stream_class{OuterCarrierStreamClass::Other};
    std::uint64_t elapsed_us{0};

    std::uint8_t h2_type{0};
    std::uint8_t flags{0};
    std::int32_t h2_stream_id{-1};
    std::uint32_t length{0};
    std::uint32_t value{0};
    std::uint32_t error_code{0};
    std::uint64_t ping_id{0};
    std::vector<OuterCarrierSetting> settings;
    std::vector<OuterCarrierHeader> headers;
    bool priority_present{false};
    bool priority_exclusive{false};
    std::int32_t priority_parent_stream_id{0};
    std::int32_t priority_weight{0};

    std::uint8_t websocket_opcode{0};
    bool websocket_final{false};
    bool websocket_masked{false};
    std::uint64_t websocket_payload_bytes{0};
    bool h2_ping_immediately_before{false};

    bool completed{false};
};

struct OuterCarrierSnapshot {
    std::vector<OuterCarrierEvent> events;
    bool truncated{false};
    std::string tls_alpn;
};

// Payload-free, opt-in observation of one live outer carrier. Transport code
// supplies only already-sanitized metadata; the event model has no payload-byte,
// TLS-secret, or peer-address field. Header metadata is accepted only from the
// trusted carrier producer, which replaces dynamic values before recording.
// Recording is fail-open for the carrier: allocation/cap failures mark the
// evidence truncated and permanently stop collection.
class OuterCarrierTrace final {
public:
    static constexpr std::size_t kMaxEvents = 4096;
    static constexpr std::size_t kMaxRetainedBytes = 768U * 1024U;

    OuterCarrierTrace();
    OuterCarrierTrace(const OuterCarrierTrace&) = delete;
    OuterCarrierTrace& operator=(const OuterCarrierTrace&) = delete;

    void Record(OuterCarrierEvent event) noexcept;
    void MarkTruncated() noexcept;
    void SetTlsAlpn(std::string alpn) noexcept;

    OuterCarrierSnapshot Snapshot() const;
    bool truncated() const noexcept {
        return truncated_.load(std::memory_order_acquire);
    }

private:
    std::size_t EstimateBytes(const OuterCarrierEvent& event) const noexcept;

    std::chrono::steady_clock::time_point started_at_;
    bool started_{false};
    mutable std::mutex mutex_;
    std::vector<OuterCarrierEvent> events_;
    std::size_t retained_bytes_{0};
    std::atomic<bool> truncated_{false};
    std::string tls_alpn_;
};

const char* OuterCarrierDirectionName(OuterCarrierDirection value) noexcept;
const char* OuterCarrierStreamClassName(OuterCarrierStreamClass value) noexcept;
const char* OuterCarrierEventKindName(OuterCarrierEventKind value) noexcept;

}  // namespace yume::obfs
