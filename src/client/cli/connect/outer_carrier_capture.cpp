/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/connect/outer_carrier_capture.hpp"

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "core/stealth/cover_profile.hpp"

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace yume::client {
namespace {

using nlohmann::json;
using obfs::OuterCarrierDirection;
using obfs::OuterCarrierEvent;
using obfs::OuterCarrierEventKind;
using obfs::OuterCarrierStreamClass;

constexpr std::uint8_t kH2Data = 0x00;
constexpr std::uint8_t kH2Headers = 0x01;
constexpr std::uint8_t kH2Settings = 0x04;
constexpr std::uint8_t kH2Ping = 0x06;
constexpr std::uint8_t kH2Goaway = 0x07;
constexpr std::uint8_t kH2WindowUpdate = 0x08;
constexpr std::uint8_t kH2Ack = 0x01;

const char* SettingName(std::uint32_t id) noexcept {
    switch (id) {
        case 1: return "SETTINGS_HEADER_TABLE_SIZE";
        case 2: return "SETTINGS_ENABLE_PUSH";
        case 3: return "SETTINGS_MAX_CONCURRENT_STREAMS";
        case 4: return "SETTINGS_INITIAL_WINDOW_SIZE";
        case 5: return "SETTINGS_MAX_FRAME_SIZE";
        case 6: return "SETTINGS_MAX_HEADER_LIST_SIZE";
        case 8: return "SETTINGS_ENABLE_CONNECT_PROTOCOL";
        default: return "SETTINGS_UNKNOWN";
    }
}

json HeaderPairs(const std::vector<obfs::OuterCarrierHeader>& headers) {
    json result = json::array();
    for (const auto& header : headers) {
        result.push_back(json::array({header.name, header.value}));
    }
    return result;
}

json Settings(const std::vector<obfs::OuterCarrierSetting>& settings) {
    json result = json::array();
    for (const auto& setting : settings) {
        result.push_back(json::array(
            {setting.id, setting.value, SettingName(setting.id)}));
    }
    return result;
}

const OuterCarrierEvent* FindHeader(
    const std::vector<OuterCarrierEvent>& events,
    OuterCarrierDirection direction,
    OuterCarrierStreamClass stream_class) noexcept {
    for (const auto& event : events) {
        if ((event.kind == OuterCarrierEventKind::H2HeadersDecoded ||
             (event.kind == OuterCarrierEventKind::H2Frame &&
              event.h2_type == kH2Headers)) &&
            event.direction == direction &&
            event.stream_class == stream_class && !event.headers.empty()) {
            return &event;
        }
    }
    return nullptr;
}

json HeaderSummary(const OuterCarrierEvent* event) {
    if (!event) return nullptr;
    json result{
        {"stream_id", event->h2_stream_id},
        {"headers_in_order", HeaderPairs(event->headers)},
    };
    if (event->priority_present) {
        result["parent_stream_id"] = event->priority_parent_stream_id;
        result["exclusive"] = event->priority_exclusive;
        result["weight"] = event->priority_weight;
    }
    return result;
}

std::size_t EventIndex(
    const std::vector<OuterCarrierEvent>& events,
    const OuterCarrierEvent* target) noexcept {
    if (!target || events.empty()) return events.size();
    return static_cast<std::size_t>(target - events.data());
}

std::string HeaderValueOr(
    const OuterCarrierEvent* event, std::string_view name,
    std::string fallback) {
    if (event) {
        for (const auto& header : event->headers) {
            if (header.name == name) return header.value;
        }
    }
    return fallback;
}

json PayloadDistribution(
    const std::vector<const OuterCarrierEvent*>& frames) {
    std::map<std::uint64_t, std::size_t> counts;
    for (const auto* frame : frames) {
        ++counts[frame->websocket_payload_bytes];
    }
    if (counts.size() == 1) return counts.begin()->first;
    json result = json::array();
    for (const auto& [payload_bytes, count] : counts) {
        result.push_back({
            {"payload_bytes", payload_bytes}, {"count", count}});
    }
    return result;
}

json BinarySummary(
    const std::vector<const OuterCarrierEvent*>& frames,
    bool server) {
    json result{
        {server ? "unfragmented_count" : "count", frames.size()},
        {"payload_bytes", PayloadDistribution(frames)},
    };
    if (!frames.empty()) {
        const bool mask = frames.front()->websocket_masked;
        const bool uniform = std::all_of(
            frames.begin(), frames.end(), [mask](const auto* frame) {
                return frame->websocket_masked == mask;
            });
        result["masked"] = uniform ? json(mask) : json(nullptr);
    } else {
        result["masked"] = nullptr;
    }
    return result;
}

json EventJson(const OuterCarrierEvent& event) {
    json result{
        {"kind", obfs::OuterCarrierEventKindName(event.kind)},
        {"direction", obfs::OuterCarrierDirectionName(event.direction)},
        {"stream_class",
         obfs::OuterCarrierStreamClassName(event.stream_class)},
        {"milliseconds_after_session_start", event.elapsed_us / 1000U},
    };
    switch (event.kind) {
        case OuterCarrierEventKind::H2Frame:
            result["stream_id"] = event.h2_stream_id;
            result["h2_type"] = event.h2_type;
            result["flags"] = event.flags;
            result["length"] = event.length;
            if (!event.settings.empty()) {
                result["settings"] = Settings(event.settings);
            }
            if (!event.headers.empty()) {
                result["headers_in_order"] = HeaderPairs(event.headers);
            }
            if (event.h2_type == kH2WindowUpdate) {
                result["delta"] = event.value;
            }
            if (event.h2_type == kH2Ping) {
                result["is_ack"] = (event.flags & kH2Ack) != 0;
                result["unique_id"] = event.ping_id;
            }
            if (event.h2_type == kH2Goaway) {
                result["error_code"] = event.error_code;
            }
            if (event.priority_present) {
                result["priority"] = {
                    {"parent_stream_id", event.priority_parent_stream_id},
                    {"exclusive", event.priority_exclusive},
                    {"weight", event.priority_weight},
                };
            }
            break;
        case OuterCarrierEventKind::H2HeadersDecoded:
            result["stream_id"] = event.h2_stream_id;
            result["headers_in_order"] = HeaderPairs(event.headers);
            break;
        case OuterCarrierEventKind::WebSocketFrame:
            result["opcode"] = event.websocket_opcode;
            result["final"] = event.websocket_final;
            result["masked"] = event.websocket_masked;
            result["payload_bytes"] = event.websocket_payload_bytes;
            if (event.websocket_opcode == 0x8) {
                result["h2_ping_immediately_before"] =
                    event.h2_ping_immediately_before;
            }
            break;
        case OuterCarrierEventKind::StreamClose:
            result["stream_id"] = event.h2_stream_id;
            result["error_code"] = event.error_code;
            result["completed"] = event.completed;
            break;
        case OuterCarrierEventKind::IdleInterval:
            result["requested_ms"] = event.value;
            result["completed"] = event.completed;
            break;
        case OuterCarrierEventKind::CloseWire:
            result["completed"] = event.completed;
            break;
        case OuterCarrierEventKind::FlowWindowStalled:
        case OuterCarrierEventKind::FlowWindowRecovered:
            break;
    }
    return result;
}

struct CaptureAssessment {
    bool complete{true};
    std::vector<std::string> reasons;

    void Require(bool condition, std::string reason) {
        if (!condition) {
            complete = false;
            reasons.push_back(std::move(reason));
        }
    }
};

json BuildBehavior(const obfs::OuterCarrierTrace& trace,
                   bool operation_succeeded,
                   CaptureAssessment* assessment) {
    const auto snapshot = trace.Snapshot();
    const auto& events = snapshot.events;
    assessment->Require(operation_succeeded, "workload-failed");
    assessment->Require(!snapshot.truncated, "event-cap-reached");
    assessment->Require(snapshot.tls_alpn == "h2", "alpn-not-h2");

    const OuterCarrierEvent* client_settings = nullptr;
    const OuterCarrierEvent* server_settings = nullptr;
    const OuterCarrierEvent* connection_window = nullptr;
    bool window_recovery = false;
    bool sent_ping = false;
    bool sent_goaway = false;
    const OuterCarrierEvent* sent_close = nullptr;
    const OuterCarrierEvent* received_close = nullptr;
    bool close_wire = false;
    bool idle_complete = false;
    std::uint32_t requested_idle_ms = 0;
    std::size_t deferrals = 0;
    std::vector<const OuterCarrierEvent*> sent_binary;
    std::vector<const OuterCarrierEvent*> received_binary;
    std::vector<const OuterCarrierEvent*> received_fragmented;
    std::vector<const OuterCarrierEvent*> h2_pings;
    const OuterCarrierEvent* server_ping = nullptr;
    const OuterCarrierEvent* client_pong = nullptr;
    const OuterCarrierEvent* priming_close = nullptr;
    const OuterCarrierEvent* css_close = nullptr;
    const OuterCarrierEvent* js_close = nullptr;

    for (const auto& event : events) {
        if (event.kind == OuterCarrierEventKind::H2Frame) {
            if (event.h2_type == kH2Settings &&
                (event.flags & kH2Ack) == 0) {
                if (event.direction == OuterCarrierDirection::Sent &&
                    !client_settings) {
                    client_settings = &event;
                } else if (
                    event.direction == OuterCarrierDirection::Received &&
                    !server_settings) {
                    server_settings = &event;
                }
            }
            if (event.h2_type == kH2WindowUpdate) {
                if (event.direction == OuterCarrierDirection::Sent &&
                    event.stream_class == OuterCarrierStreamClass::Connection &&
                    !connection_window) {
                    connection_window = &event;
                }
                if (event.direction == OuterCarrierDirection::Received) {
                    window_recovery = true;
                }
            }
            if (event.h2_type == kH2Ping) {
                h2_pings.push_back(&event);
                if (event.direction == OuterCarrierDirection::Sent &&
                    (event.flags & kH2Ack) == 0) {
                    sent_ping = true;
                }
            }
            if (event.h2_type == kH2Goaway &&
                event.direction == OuterCarrierDirection::Sent) {
                sent_goaway = true;
            }
        } else if (event.kind == OuterCarrierEventKind::WebSocketFrame) {
            if (event.websocket_opcode == 0x2) {
                if (event.direction == OuterCarrierDirection::Sent) {
                    sent_binary.push_back(&event);
                } else if (event.websocket_final) {
                    received_binary.push_back(&event);
                } else {
                    received_fragmented.push_back(&event);
                }
            } else if (
                event.direction == OuterCarrierDirection::Received &&
                event.websocket_opcode == 0x0) {
                received_fragmented.push_back(&event);
            } else if (
                event.direction == OuterCarrierDirection::Received &&
                event.websocket_opcode == 0x9 && !server_ping) {
                server_ping = &event;
            } else if (
                event.direction == OuterCarrierDirection::Sent &&
                event.websocket_opcode == 0xA && !client_pong) {
                client_pong = &event;
            } else if (event.websocket_opcode == 0x8) {
                if (event.direction == OuterCarrierDirection::Sent) {
                    if (!sent_close) sent_close = &event;
                } else {
                    if (!received_close) received_close = &event;
                }
            }
        } else if (
            event.kind == OuterCarrierEventKind::FlowWindowStalled) {
            ++deferrals;
        } else if (event.kind == OuterCarrierEventKind::StreamClose &&
                   event.completed && event.error_code == 0) {
            switch (event.stream_class) {
                case OuterCarrierStreamClass::Priming:
                    if (!priming_close) priming_close = &event;
                    break;
                case OuterCarrierStreamClass::AssetCss:
                    if (!css_close) css_close = &event;
                    break;
                case OuterCarrierStreamClass::AssetJs:
                    if (!js_close) js_close = &event;
                    break;
                default: break;
            }
        } else if (event.kind == OuterCarrierEventKind::IdleInterval) {
            requested_idle_ms = event.value;
            idle_complete = event.completed;
        } else if (event.kind == OuterCarrierEventKind::CloseWire) {
            close_wire = event.completed;
        }
    }

    const auto* priming = FindHeader(
        events, OuterCarrierDirection::Sent,
        OuterCarrierStreamClass::Priming);
    const auto* css = FindHeader(
        events, OuterCarrierDirection::Sent,
        OuterCarrierStreamClass::AssetCss);
    const auto* js = FindHeader(
        events, OuterCarrierDirection::Sent,
        OuterCarrierStreamClass::AssetJs);
    const auto* connect = FindHeader(
        events, OuterCarrierDirection::Sent,
        OuterCarrierStreamClass::Carrier);
    const auto* connect_response = FindHeader(
        events, OuterCarrierDirection::Received,
        OuterCarrierStreamClass::Carrier);

    assessment->Require(client_settings != nullptr, "client-settings-missing");
    assessment->Require(server_settings != nullptr, "server-settings-missing");
    assessment->Require(connection_window != nullptr,
                        "connection-window-update-missing");
    assessment->Require(priming && css && js && connect,
                        "request-sequence-incomplete");
    const bool completed_priming_lifecycle =
        priming && css && js && connect && priming_close && css_close &&
        js_close && EventIndex(events, priming) < EventIndex(events, priming_close) &&
        EventIndex(events, priming_close) < EventIndex(events, css) &&
        EventIndex(events, priming_close) < EventIndex(events, js) &&
        EventIndex(events, css) < EventIndex(events, css_close) &&
        EventIndex(events, js) < EventIndex(events, js_close) &&
        EventIndex(events, css_close) < EventIndex(events, connect) &&
        EventIndex(events, js_close) < EventIndex(events, connect);
    assessment->Require(completed_priming_lifecycle,
                        "request-lifecycle-incomplete");
    assessment->Require(connect_response != nullptr,
                        "connect-response-missing");
    assessment->Require(!sent_binary.empty() &&
                            (!received_binary.empty() ||
                             !received_fragmented.empty()),
                        "bidirectional-websocket-missing");
    assessment->Require(idle_complete, "idle-interval-incomplete");
    assessment->Require(sent_ping && sent_close && sent_goaway && close_wire,
                        "terminal-sequence-incomplete");

    const auto& profile = cover_profile::active();
    json result{
        {"schema", 2},
        {"capture_status", assessment->complete ? "complete" : "incomplete"},
        {"capture_source", "live-production-carrier"},
        {"authority", HeaderValueOr(
            priming, ":authority", "<unobserved-authority>")},
        {"client",
         {{"name", profile.browser_name},
          {"version", profile.browser_version},
          {"os", profile.operating_system}}},
        {"tls_observation",
         {{"version", nullptr},
          {"alpn", snapshot.tls_alpn},
          {"resumed", nullptr},
          {"warning",
           "Live ALPN only; TLS version, resumption, and first-flight parity are evaluated from separate wire evidence."}}},
        {"client_settings_in_order",
         client_settings ? Settings(client_settings->settings) : json(nullptr)},
        {"client_connection_window_update",
         connection_window
             ? json{{"stream_id", connection_window->h2_stream_id},
                    {"delta", connection_window->value},
                    {"resulting_window", 65535U + connection_window->value}}
             : json(nullptr)},
        {"node_non_default_settings_in_order",
         server_settings ? Settings(server_settings->settings) : json(nullptr)},
        {"priming_get", HeaderSummary(priming)},
        {"asset_sequence", json::array()},
        {"extended_connect", HeaderSummary(connect)},
        {"websocket_fixture",
         {{"application_bytes_each_direction", 1024U * 1024U},
          {"client_binary_messages", BinarySummary(sent_binary, false)},
          {"server_binary_messages", BinarySummary(received_binary, true)},
          {"server_fragmented_binary_message", json::array()},
          {"ping_pong",
           {{"server_ping_payload_bytes",
             server_ping ? json(server_ping->websocket_payload_bytes)
                         : json(nullptr)},
            {"client_pong_payload_bytes",
             client_pong ? json(client_pong->websocket_payload_bytes)
                         : json(nullptr)},
            {"client_pong_masked",
             client_pong ? json(client_pong->websocket_masked)
                         : json(nullptr)}}},
          {"close",
           {{"payload_bytes", [&]() -> json {
                for (const auto& event : events) {
                    if (event.kind == OuterCarrierEventKind::WebSocketFrame &&
                        event.direction == OuterCarrierDirection::Sent &&
                        event.websocket_opcode == 0x8) {
                        return event.websocket_payload_bytes;
                    }
                }
                return nullptr;
            }()},
            {"client_masked",
             sent_close ? json(sent_close->websocket_masked) : json(nullptr)},
            {"server_masked",
             received_close ? json(received_close->websocket_masked)
                            : json(nullptr)},
            {"h2_ping_immediately_before_close",
             sent_close && sent_close->h2_ping_immediately_before},
            {"h2_ping_originator", sent_ping ? "client" : "unobserved"}}}}},
        {"flow_control_fixture",
         {{"client_stream_send_stalls", deferrals},
          {"window_update_recovery_observed", window_recovery}}},
        {"idle_and_close",
         {{"requested_idle_ms", requested_idle_ms},
          {"h2_pings", json::array()},
          {"graceful_websocket_close_observed",
           sent_close && received_close && close_wire}}},
        {"shaping_policy",
         {{"synthetic_idle_keepalive", false},
          {"random_padding", false},
          {"random_timing_jitter", false},
          {"bulk_websocket_message_bytes",
           profile.websocket_message_bytes}}},
        {"observations", {{"outer_events", json::array()}}},
    };

    if (css) {
        json summary = HeaderSummary(css);
        summary["path"] = HeaderValueOr(css, ":path", "<unobserved-path>");
        result["asset_sequence"].push_back(std::move(summary));
    }
    if (js) {
        json summary = HeaderSummary(js);
        summary["path"] = HeaderValueOr(js, ":path", "<unobserved-path>");
        result["asset_sequence"].push_back(std::move(summary));
    }
    if (connect) {
        result["extended_connect"]["requires_completed_priming_get"] =
            completed_priming_lifecycle;
        result["extended_connect"]["node_response_headers_in_order"] =
            connect_response ? HeaderPairs(connect_response->headers)
                             : json(nullptr);
    }
    for (std::size_t index = 0;
         index + 1 < received_fragmented.size(); ++index) {
        const auto* first = received_fragmented[index];
        const auto* second = received_fragmented[index + 1];
        if (first->websocket_opcode == 0x2 && !first->websocket_final &&
            second->websocket_opcode == 0x0 && second->websocket_final) {
            result["websocket_fixture"]["server_fragmented_binary_message"] =
                json::array({
                    {{"opcode", first->websocket_opcode},
                     {"final", first->websocket_final},
                     {"payload_bytes", first->websocket_payload_bytes},
                     {"masked", first->websocket_masked}},
                    {{"opcode", second->websocket_opcode},
                     {"final", second->websocket_final},
                     {"payload_bytes", second->websocket_payload_bytes},
                     {"masked", second->websocket_masked}},
                });
            break;
        }
    }
    for (const auto* ping : h2_pings) {
        result["idle_and_close"]["h2_pings"].push_back({
            {"milliseconds_after_session_start", ping->elapsed_us / 1000U},
            {"is_ack", (ping->flags & kH2Ack) != 0},
            {"type", ping->direction == OuterCarrierDirection::Sent
                         ? "sent"
                         : "received"},
            {"unique_id", ping->ping_id},
        });
    }
    for (const auto& event : events) {
        result["observations"]["outer_events"].push_back(EventJson(event));
    }
    if (!assessment->complete) {
        result["incomplete_reasons"] = assessment->reasons;
    }
    return result;
}

json MinimalIncomplete(std::string reason) {
    return {
        {"schema", 2},
        {"capture_status", "incomplete"},
        {"capture_source", "live-production-carrier"},
        {"incomplete_reasons", json::array({std::move(reason)})},
    };
}

#if !defined(_WIN32)

bool DirectoryContainsGitMarker(int directory_fd, std::string* error) {
    struct stat info {};
    if (::fstatat(directory_fd, ".git", &info, AT_SYMLINK_NOFOLLOW) == 0) {
        if (error) *error = "outer-carrier evidence must remain outside Git worktrees";
        return true;
    }
    if (errno != ENOENT) {
        if (error) *error = "cannot verify outer-carrier evidence ancestry";
        return true;
    }
    return false;
}

bool OpenSecureDestination(const std::filesystem::path& path,
                           int* parent_out, int* file_out,
                           std::string* error) {
    if (!path.is_absolute() || path.filename().empty()) {
        if (error) *error = "outer-carrier evidence path must be absolute";
        return false;
    }
    for (const auto& component : path) {
        if (component == "." || component == "..") {
            if (error) *error = "outer-carrier evidence path must not contain dot components";
            return false;
        }
    }

    int directory_flags = O_RDONLY | O_DIRECTORY | O_CLOEXEC;
#if defined(O_NOFOLLOW)
    directory_flags |= O_NOFOLLOW;
#endif
    int directory_fd = ::open("/", directory_flags);
    if (directory_fd < 0) {
        if (error) *error = "cannot anchor outer-carrier evidence path";
        return false;
    }
    auto fail = [&](std::string message) {
        if (error) *error = std::move(message);
        ::close(directory_fd);
        return false;
    };
    if (DirectoryContainsGitMarker(directory_fd, error)) {
        ::close(directory_fd);
        return false;
    }
    const auto relative_parent = path.parent_path().relative_path();
    for (const auto& component : relative_parent) {
        const std::string name = component.string();
        if (name.empty()) continue;
        const int next = ::openat(directory_fd, name.c_str(), directory_flags);
        if (next < 0) {
            return fail("cannot safely traverse outer-carrier evidence parent");
        }
        ::close(directory_fd);
        directory_fd = next;
        if (DirectoryContainsGitMarker(directory_fd, error)) {
            ::close(directory_fd);
            return false;
        }
    }

    struct stat parent_info {};
    if (::fstat(directory_fd, &parent_info) != 0 ||
        !S_ISDIR(parent_info.st_mode)) {
        return fail("outer-carrier evidence parent is not a directory");
    }
    if (parent_info.st_uid != ::geteuid()) {
        return fail("outer-carrier evidence parent must be owned by the current user");
    }
    if ((parent_info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        return fail("outer-carrier evidence parent must not be group/world writable");
    }

    int file_flags = O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC;
#if defined(O_NOFOLLOW)
    file_flags |= O_NOFOLLOW;
#endif
    const std::string filename = path.filename().string();
    const int file_fd = ::openat(
        directory_fd, filename.c_str(), file_flags, S_IRUSR | S_IWUSR);
    if (file_fd < 0) {
        return fail("cannot exclusively reserve outer-carrier evidence file");
    }
    struct stat file_info {};
    if (::fchmod(file_fd, S_IRUSR | S_IWUSR) != 0 ||
        ::fstat(file_fd, &file_info) != 0 || !S_ISREG(file_info.st_mode) ||
        file_info.st_uid != ::geteuid() || file_info.st_nlink != 1 ||
        (file_info.st_mode & 0777) != (S_IRUSR | S_IWUSR)) {
        ::close(file_fd);
        ::unlinkat(directory_fd, filename.c_str(), 0);
        return fail("outer-carrier evidence reservation failed validation");
    }
    *parent_out = directory_fd;
    *file_out = file_fd;
    if (error) error->clear();
    return true;
}

#endif

}  // namespace

std::string ValidateOuterCarrierCapturePolicy(
    const OuterCarrierCapturePolicy& policy) {
    if (!policy.endpoint_bench || policy.full_bench ||
        policy.bench_mib != 1 || policy.bench_chunk_kib != 16 ||
        policy.bench_streams != 1 || policy.bench_direction != "both") {
        return "--outer-carrier-evidence requires --bench --bench-mib 1 "
               "--bench-chunk-kib 16 --bench-streams 1 --bench-direction both";
    }
    if (policy.tunnel_count != 1 || policy.conflicting_mode ||
        policy.outbound_proxy) {
        return "--outer-carrier-evidence requires one direct, exclusive endpoint tunnel";
    }
    if (!policy.obfuscation ||
        policy.transport_profile != cover_profile::active().id ||
        policy.tls_backend != policy.required_tls_backend) {
        return "--outer-carrier-evidence requires the pinned chrome151 H2 carrier "
               "and openssl-chrome151 backend";
    }
    if (!policy.non_interactive) {
        return "--outer-carrier-evidence requires non-interactive endpoint benchmark mode";
    }
    if (policy.obfs_pad_multiple != 0 || policy.obfs_jitter_ms != 0) {
        return "--outer-carrier-evidence requires disabled optional padding and jitter";
    }
    return {};
}

OuterCarrierCapture::OuterCarrierCapture(
    int parent_fd, int file_fd,
    std::shared_ptr<obfs::OuterCarrierTrace> trace) noexcept
    : parent_fd_(parent_fd),
      file_fd_(file_fd),
      trace_(std::move(trace)) {}

std::unique_ptr<OuterCarrierCapture> OuterCarrierCapture::Reserve(
    const std::filesystem::path& path, std::string* error) {
#if defined(_WIN32)
    (void)path;
    if (error) *error = "outer-carrier evidence is currently Linux/POSIX only";
    return {};
#else
    std::shared_ptr<obfs::OuterCarrierTrace> trace;
    try {
        trace = std::make_shared<obfs::OuterCarrierTrace>();
    } catch (...) {
        if (error) *error = "cannot allocate outer-carrier evidence observer";
        return {};
    }
    int parent_fd = -1;
    int file_fd = -1;
    if (!OpenSecureDestination(path, &parent_fd, &file_fd, error)) return {};
    try {
        return std::unique_ptr<OuterCarrierCapture>(
            new OuterCarrierCapture(parent_fd, file_fd, std::move(trace)));
    } catch (...) {
        const std::string filename = path.filename().string();
        ::close(file_fd);
        (void)::unlinkat(parent_fd, filename.c_str(), 0);
        ::close(parent_fd);
        if (error) *error = "cannot allocate outer-carrier evidence observer";
        return {};
    }
#endif
}

OuterCarrierCapture::~OuterCarrierCapture() {
    if (!finalized_) {
        std::string ignored;
        WriteTerminalDocument(false, &ignored);
    }
#if !defined(_WIN32)
    if (file_fd_ >= 0) ::close(file_fd_);
    if (parent_fd_ >= 0) ::close(parent_fd_);
#endif
}

bool OuterCarrierCapture::Finalize(bool operation_succeeded,
                                   std::string* error) {
    if (finalized_) {
        if (error) *error = "outer-carrier evidence was already finalized";
        return false;
    }
    return WriteTerminalDocument(operation_succeeded, error);
}

bool OuterCarrierCapture::WriteTerminalDocument(
    bool operation_succeeded, std::string* error) noexcept {
    finalized_ = true;
    try {
        CaptureAssessment assessment;
        json document = BuildBehavior(
            *trace_, operation_succeeded, &assessment);
        std::string payload = document.dump(2) + "\n";
        if (payload.size() > kMaxSerializedBytes) {
            assessment.complete = false;
            payload = MinimalIncomplete("serialized-evidence-limit").dump(2) + "\n";
        }
        const bool written = WritePayload(payload, error);
        return written && assessment.complete;
    } catch (...) {
        try {
            const std::string payload =
                MinimalIncomplete("serialization-failed").dump(2) + "\n";
            (void)WritePayload(payload, error);
        } catch (...) {
            if (error) *error = "cannot serialize outer-carrier evidence";
        }
        return false;
    }
}

bool OuterCarrierCapture::WritePayload(
    const std::string& payload, std::string* error) noexcept {
#if defined(_WIN32)
    (void)payload;
    if (error) *error = "outer-carrier evidence is unavailable on Windows";
    return false;
#else
    if (file_fd_ < 0 || parent_fd_ < 0 ||
        payload.size() > kMaxSerializedBytes) {
        if (error) *error = "invalid outer-carrier evidence writer state";
        return false;
    }
    struct stat before {};
    if (::fstat(file_fd_, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_uid != ::geteuid() || before.st_nlink != 1 ||
        (before.st_mode & 0777) != (S_IRUSR | S_IWUSR)) {
        if (error) *error = "outer-carrier evidence file changed before write";
        return false;
    }
    if (::ftruncate(file_fd_, 0) != 0 || ::lseek(file_fd_, 0, SEEK_SET) < 0) {
        if (error) *error = "cannot initialize outer-carrier evidence file";
        return false;
    }
    std::size_t offset = 0;
    while (offset < payload.size()) {
        const ssize_t count = ::write(
            file_fd_, payload.data() + offset, payload.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            if (error) *error = "cannot write outer-carrier evidence";
            return false;
        }
        offset += static_cast<std::size_t>(count);
    }
    if (::fsync(file_fd_) != 0) {
        if (error) *error = "cannot sync outer-carrier evidence";
        return false;
    }
    struct stat after {};
    if (::fstat(file_fd_, &after) != 0 || !S_ISREG(after.st_mode) ||
        after.st_uid != before.st_uid || after.st_ino != before.st_ino ||
        after.st_dev != before.st_dev || after.st_nlink != 1 ||
        static_cast<std::uintmax_t>(after.st_size) != payload.size() ||
        (after.st_mode & 0777) != (S_IRUSR | S_IWUSR)) {
        if (error) *error = "outer-carrier evidence file changed during write";
        return false;
    }
    if (::fsync(parent_fd_) != 0) {
        if (error) *error = "cannot sync outer-carrier evidence directory";
        return false;
    }
    if (error) error->clear();
    return true;
#endif
}

}  // namespace yume::client
