/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "yume/yume.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "facade/session/endpoint_backend.hpp"
#include "common/service_name.hpp"
#include "config/v1/config.hpp"
#include "core/compatibility_manifest.hpp"

#if !defined(YUME_ABI_TRANSPORT_V2) || !YUME_ABI_TRANSPORT_V2
// A build without a transport runtime still exports the identical surface.
// Defining the seam here rather than guarding every call site keeps the shell
// readable, and every dialect that would reach these is already refused.
namespace yume::embed {

std::unique_ptr<BackendConfig> parse_transport_v2_config(std::string_view,
                                                         bool,
                                                         std::string_view,
                                                         std::string& error) {
    error = "this build has no transport runtime linked into the ABI";
    return nullptr;
}

std::unique_ptr<EndpointBackend> make_transport_v2_backend(
    const BackendConfig&,
    std::string& error) {
    error = "this build has no transport runtime linked into the ABI";
    return nullptr;
}

}  // namespace yume::embed
#endif

namespace {

// "This build cannot do that" is a different answer from "that document is
// malformed", and an embedder debugging a config deserves the accurate one.
#if defined(YUME_ABI_TRANSPORT_V2) && YUME_ABI_TRANSPORT_V2
constexpr bool kTransportBackendLinked = true;
#else
constexpr bool kTransportBackendLinked = false;
#endif

constexpr std::uint64_t kHandleMagic = UINT64_C(0x59554d4530334142);
constexpr std::uint32_t kDefaultExecutorThreads = 1;
constexpr std::uint32_t kMaxExecutorThreads = 64;
constexpr std::uint32_t kDefaultPendingCallbacks = 1024;
constexpr std::uint32_t kMaxPendingCallbacks = 65536;
constexpr std::size_t kMaxRuntimeEndpoints = 65536;
constexpr std::uint64_t kMaxServiceQueuedBytes = UINT64_C(64) * 1024 * 1024;
constexpr std::uint32_t kMaxServiceConcurrency = 65536;
constexpr std::size_t kMaxPacketBatch = 256;
constexpr std::size_t kMaxPacketBytes = 65535;
constexpr std::size_t kMaxPacketBatchBytes =
    std::size_t{16} * 1024 * 1024;
constexpr std::size_t kMaxConfigBaseDirBytes = 4096;

static_assert(YUME_MAX_SERVICE_NAME == yume::common::kMaxServiceNameBytes);

enum class HandleKind : std::uint32_t {
    Runtime = 1,
    Config = 2,
    Endpoint = 3,
    Stream = 4,
    Packet = 5,
};

struct DiagnosticData {
    yume_status status{YUME_STATUS_OK};
    std::uint32_t flags{0};
    std::array<char, YUME_MAX_JSON_POINTER> json_pointer{};
    std::array<char, YUME_MAX_DIAGNOSTIC_TEXT> message{};
};

struct HandleHeader {
    explicit HandleHeader(HandleKind handle_kind) : kind(handle_kind) {}

    const std::uint64_t magic{kHandleMagic};
    const HandleKind kind;
    mutable std::mutex diagnostic_mutex;
    DiagnosticData diagnostic;
};

struct EndpointControl {
    explicit EndpointControl(std::uint64_t assigned_id) : id(assigned_id) {}

    const std::uint64_t id;
    // Serializes lifecycle calls and their event order. Callbacks may run while
    // this sequencing mutex is held, but never while the state or diagnostic
    // mutex is held; forbidden lifecycle re-entry fails before locking it.
    mutable std::mutex lifecycle_mutex;
    mutable std::mutex mutex;
    std::uint32_t state{YUME_ENDPOINT_CREATED};
    // Owned under lifecycle_mutex only. Constructed on the first successful
    // start and destroyed by endpoint destruction, so a stopped endpoint can
    // be restarted without reparsing its configuration.
    std::unique_ptr<yume::embed::EndpointBackend> backend;
};

struct RuntimeState {
    std::uint32_t executor_threads{kDefaultExecutorThreads};
    std::uint32_t max_pending_callbacks{kDefaultPendingCallbacks};
    yume_log_callback log_callback{nullptr};
    yume_event_callback event_callback{nullptr};
    void* callback_user_data{nullptr};
    std::string config_base_dir{"."};
    std::mutex callback_mutex;
    std::condition_variable callback_cv;
    std::size_t callbacks_in_flight{0};
    bool callbacks_enabled{true};
    std::atomic<std::uint64_t> next_endpoint_id{1};
    std::atomic<bool> stopping{false};
    std::mutex endpoints_mutex;
    std::vector<std::weak_ptr<EndpointControl>> endpoints;
};

struct ServiceRegistration {
    std::uint32_t kind{0};
    std::uint32_t max_concurrent{0};
    std::uint32_t max_pending_accepts{0};
    std::uint64_t max_queued_bytes{0};
};

struct ServiceKey {
    std::string name;
    std::uint32_t kind{0};

    friend bool operator==(const ServiceKey&, const ServiceKey&) = default;
};

struct ServiceKeyHash {
    std::size_t operator()(const ServiceKey& key) const noexcept {
        const std::size_t name_hash = std::hash<std::string>{}(key.name);
        const std::size_t kind_hash = std::hash<std::uint32_t>{}(key.kind);
        return name_hash ^ (kind_hash + 0x9e3779b9U +
                            (name_hash << 6U) + (name_hash >> 2U));
    }
};

thread_local bool g_in_callback = false;

class CallbackScope {
public:
    CallbackScope() noexcept : previous_(g_in_callback) {
        g_in_callback = true;
    }
    ~CallbackScope() noexcept { g_in_callback = previous_; }

    CallbackScope(const CallbackScope&) = delete;
    CallbackScope& operator=(const CallbackScope&) = delete;

private:
    bool previous_;
};

const char* status_name(yume_status status) noexcept {
    switch (status) {
        case YUME_STATUS_OK: return "ok";
        case YUME_STATUS_EOF: return "eof";
        case YUME_STATUS_INVALID_ARGUMENT: return "invalid_argument";
        case YUME_STATUS_BUFFER_TOO_SMALL: return "buffer_too_small";
        case YUME_STATUS_INTERNAL_ERROR: return "internal_error";
        case YUME_STATUS_INVALID_STATE: return "invalid_state";
        case YUME_STATUS_TIMEOUT: return "timeout";
        case YUME_STATUS_WOULD_BLOCK: return "would_block";
        case YUME_STATUS_NOT_FOUND: return "not_found";
        case YUME_STATUS_PERMISSION_DENIED: return "permission_denied";
        case YUME_STATUS_PARSE_ERROR: return "parse_error";
        case YUME_STATUS_RESOURCE_EXHAUSTED: return "resource_exhausted";
        case YUME_STATUS_CANCELLED: return "cancelled";
        case YUME_STATUS_CLOSED: return "closed";
        case YUME_STATUS_INCOMPATIBLE: return "incompatible";
        case YUME_STATUS_UNSUPPORTED: return "unsupported";
        case YUME_STATUS_IO_ERROR: return "io_error";
        default: return nullptr;
    }
}

bool copy_text(char* destination,
               std::size_t capacity,
               std::string_view value) noexcept {
    if (!destination || capacity == 0) return !value.empty();
    const std::size_t length = std::min(capacity - 1, value.size());
    if (length != 0) {
        std::memcpy(destination, value.data(), length);
    }
    destination[length] = '\0';
    return length != value.size();
}

template <typename T>
yume_status copy_sized(T* out,
                       std::size_t out_size,
                       std::size_t minimum,
                       const T& value,
                       std::span<const std::size_t> complete_fields) noexcept {
    if (!out || out_size < minimum || out->struct_size < minimum ||
        out->struct_size > out_size || out->abi_version != YUME_ABI_VERSION) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    const std::size_t supplied = std::min(out_size, out->struct_size);
    std::size_t complete_prefix = 0;
    for (const std::size_t field_end : complete_fields) {
        if (field_end > supplied) break;
        complete_prefix = field_end;
    }
    if (complete_prefix < minimum) return YUME_STATUS_INVALID_ARGUMENT;
    std::memcpy(out, &value, complete_prefix);
    return supplied < sizeof(T) ? YUME_STATUS_BUFFER_TOO_SMALL
                                : YUME_STATUS_OK;
}

template <typename T, typename Field>
constexpr std::size_t field_end(std::size_t offset, Field T::*) noexcept {
    return offset + sizeof(Field);
}

template <typename T>
bool contains_field(const T& value,
                    std::size_t offset,
                    std::size_t field_size) noexcept {
    return value.struct_size >= offset &&
           field_size <= value.struct_size - offset;
}

#define YUME_FIELD_END(type, field) \
    field_end(offsetof(type, field), &type::field)

constexpr std::array kBuildInfoFields{
    YUME_FIELD_END(yume_build_info, struct_size),
    YUME_FIELD_END(yume_build_info, abi_version),
    YUME_FIELD_END(yume_build_info, feature_flags),
    YUME_FIELD_END(yume_build_info, product_version),
    YUME_FIELD_END(yume_build_info, crypto_backend),
    YUME_FIELD_END(yume_build_info, compiler),
};

constexpr std::array kCompatibilityFields{
    YUME_FIELD_END(yume_compatibility, struct_size),
    YUME_FIELD_END(yume_compatibility, abi_version),
    YUME_FIELD_END(yume_compatibility, ytp_version),
    YUME_FIELD_END(yume_compatibility, config_schema),
    YUME_FIELD_END(yume_compatibility, evidence_profile_version),
    YUME_FIELD_END(yume_compatibility, product_version),
    YUME_FIELD_END(yume_compatibility, ytp_name),
    YUME_FIELD_END(yume_compatibility, suite),
    YUME_FIELD_END(yume_compatibility, crypto_backend),
    YUME_FIELD_END(yume_compatibility, secure_channel_provider),
    YUME_FIELD_END(yume_compatibility, front_door_provider),
    YUME_FIELD_END(yume_compatibility, carrier_provider),
    YUME_FIELD_END(yume_compatibility, session_component),
    YUME_FIELD_END(yume_compatibility, session_security_provider),
    YUME_FIELD_END(yume_compatibility, evidence_profile),
};

constexpr std::array kStatusInfoFields{
    YUME_FIELD_END(yume_status_info, struct_size),
    YUME_FIELD_END(yume_status_info, abi_version),
    YUME_FIELD_END(yume_status_info, code),
    YUME_FIELD_END(yume_status_info, name),
};

constexpr std::array kDiagnosticFields{
    YUME_FIELD_END(yume_diagnostic, struct_size),
    YUME_FIELD_END(yume_diagnostic, abi_version),
    YUME_FIELD_END(yume_diagnostic, status),
    YUME_FIELD_END(yume_diagnostic, flags),
    YUME_FIELD_END(yume_diagnostic, json_pointer),
    YUME_FIELD_END(yume_diagnostic, message),
};

constexpr std::array kPeerIdentityFields{
    YUME_FIELD_END(yume_peer_identity, struct_size),
    YUME_FIELD_END(yume_peer_identity, abi_version),
    YUME_FIELD_END(yume_peer_identity, authenticated),
    YUME_FIELD_END(yume_peer_identity, role),
    YUME_FIELD_END(yume_peer_identity, capability_flags),
    YUME_FIELD_END(yume_peer_identity, composite_fingerprint_sha256),
    YUME_FIELD_END(yume_peer_identity, peer_label),
    YUME_FIELD_END(yume_peer_identity, service),
};

#undef YUME_FIELD_END

void set_diagnostic(HandleHeader* header,
                    yume_status status,
                    std::string_view json_pointer,
                    std::string_view message) noexcept {
    if (!header) return;
    try {
        std::lock_guard<std::mutex> lock(header->diagnostic_mutex);
        header->diagnostic.status = status;
        header->diagnostic.flags = 0;
        header->diagnostic.json_pointer.fill('\0');
        header->diagnostic.message.fill('\0');
        if (copy_text(header->diagnostic.json_pointer.data(),
                      header->diagnostic.json_pointer.size(), json_pointer)) {
            header->diagnostic.flags |=
                YUME_DIAGNOSTIC_JSON_POINTER_TRUNCATED;
        }
        if (copy_text(header->diagnostic.message.data(),
                      header->diagnostic.message.size(), message)) {
            header->diagnostic.flags |= YUME_DIAGNOSTIC_MESSAGE_TRUNCATED;
        }
    } catch (...) {
        // Diagnostics are secondary. A platform mutex failure must not disturb
        // the already-settled protocol or lifecycle result.
    }
}

void clear_diagnostic(HandleHeader* header) noexcept {
    set_diagnostic(header, YUME_STATUS_OK, {}, {});
}

yume_status fail_with_diagnostic(HandleHeader* header,
                                 yume_status status,
                                 std::string_view message,
                                 std::string_view json_pointer = {}) noexcept {
    set_diagnostic(header, status, json_pointer, message);
    return status;
}

template <typename Function>
yume_status guard(HandleHeader* diagnostic_owner, Function&& function) noexcept {
    try {
        return function();
    } catch (const std::bad_alloc&) {
        set_diagnostic(diagnostic_owner, YUME_STATUS_RESOURCE_EXHAUSTED, {},
                       "allocation failed");
        return YUME_STATUS_RESOURCE_EXHAUSTED;
    } catch (const std::exception& error) {
        set_diagnostic(diagnostic_owner, YUME_STATUS_INTERNAL_ERROR, {},
                       error.what());
        return YUME_STATUS_INTERNAL_ERROR;
    } catch (...) {
        set_diagnostic(diagnostic_owner, YUME_STATUS_INTERNAL_ERROR, {},
                       "unexpected internal failure");
        return YUME_STATUS_INTERNAL_ERROR;
    }
}

bool valid_header(const HandleHeader* header, HandleKind kind) noexcept {
    return header && header->magic == kHandleMagic && header->kind == kind;
}

bool valid_any_header(const HandleHeader* header) noexcept {
    if (!header || header->magic != kHandleMagic) return false;
    switch (header->kind) {
        case HandleKind::Runtime:
        case HandleKind::Config:
        case HandleKind::Endpoint:
        case HandleKind::Stream:
        case HandleKind::Packet:
            return true;
    }
    return false;
}

bool valid_utf8(std::string_view text) noexcept {
    std::size_t offset = 0;
    while (offset < text.size()) {
        const auto first = static_cast<unsigned char>(text[offset]);
        std::size_t continuation_count = 0;
        std::uint32_t code_point = 0;
        std::uint32_t minimum = 0;
        if (first <= 0x7fU) {
            if (first <= 0x1fU || first == 0x7fU) return false;
            ++offset;
            continue;
        }
        if ((first & 0xe0U) == 0xc0U) {
            continuation_count = 1;
            code_point = first & 0x1fU;
            minimum = 0x80U;
        } else if ((first & 0xf0U) == 0xe0U) {
            continuation_count = 2;
            code_point = first & 0x0fU;
            minimum = 0x800U;
        } else if ((first & 0xf8U) == 0xf0U) {
            continuation_count = 3;
            code_point = first & 0x07U;
            minimum = 0x10000U;
        } else {
            return false;
        }
        if (continuation_count > text.size() - offset - 1U) return false;
        for (std::size_t index = 0; index < continuation_count; ++index) {
            const auto byte = static_cast<unsigned char>(text[offset + index + 1U]);
            if ((byte & 0xc0U) != 0x80U) return false;
            code_point = (code_point << 6U) | (byte & 0x3fU);
        }
        if (code_point < minimum || code_point > 0x10ffffU ||
            (code_point >= 0xd800U && code_point <= 0xdfffU) ||
            (code_point >= 0x7fU && code_point <= 0x9fU)) {
            return false;
        }
        offset += continuation_count + 1U;
    }
    return true;
}

std::string checked_string(yume_string_view view,
                           std::size_t maximum,
                           const char* field) {
    if ((view.size != 0 && !view.data) || view.size == 0 ||
        view.size > maximum) {
        throw std::invalid_argument(std::string(field) + " size is invalid");
    }
    if (std::memchr(view.data, 0, view.size) != nullptr) {
        throw std::invalid_argument(std::string(field) + " contains NUL");
    }
    if (!valid_utf8(std::string_view(view.data, view.size))) {
        throw std::invalid_argument(std::string(field) + " is not valid UTF-8");
    }
    return std::string(view.data, view.size);
}

std::string checked_service_name(yume_string_view view) {
    std::string name = checked_string(
        view, YUME_MAX_SERVICE_NAME, "service name");
    if (!yume::common::valid_service_name(name)) {
        throw std::invalid_argument(
            "service name is not a canonical lowercase ASCII namespace");
    }
    return name;
}

bool valid_service_kind(std::uint32_t kind) noexcept {
    return kind == YUME_SERVICE_BYTE_STREAM || kind == YUME_SERVICE_PACKET;
}

bool valid_destination_kind(std::uint32_t kind) noexcept {
    return kind == YUME_DESTINATION_NONE ||
           kind == YUME_DESTINATION_HOSTNAME ||
           kind == YUME_DESTINATION_IPV4 ||
           kind == YUME_DESTINATION_IPV6;
}

bool valid_ipv4(std::string_view value) noexcept {
    std::size_t start = 0;
    unsigned parts = 0;
    while (start <= value.size()) {
        const std::size_t end = value.find('.', start);
        const std::string_view part = value.substr(
            start, end == std::string_view::npos ? value.size() - start
                                                 : end - start);
        if (part.empty() || part.size() > 3 ||
            (part.size() > 1 && part.front() == '0')) {
            return false;
        }
        unsigned parsed = 0;
        const auto conversion =
            std::from_chars(part.data(), part.data() + part.size(), parsed);
        if (conversion.ec != std::errc{} ||
            conversion.ptr != part.data() + part.size() || parsed > 255) {
            return false;
        }
        ++parts;
        if (end == std::string_view::npos) break;
        start = end + 1U;
    }
    return parts == 4;
}

bool count_ipv6_units(std::string_view part,
                      bool allow_embedded_ipv4,
                      unsigned& units) noexcept {
    units = 0;
    if (part.empty()) return true;
    std::size_t start = 0;
    while (start <= part.size()) {
        const std::size_t end = part.find(':', start);
        const std::string_view group = part.substr(
            start, end == std::string_view::npos ? part.size() - start
                                                 : end - start);
        if (group.empty()) return false;
        if (group.find('.') != std::string_view::npos) {
            if (!allow_embedded_ipv4 || end != std::string_view::npos ||
                !valid_ipv4(group)) {
                return false;
            }
            units += 2;
        } else {
            if (group.size() > 4 ||
                !std::all_of(group.begin(), group.end(), [](char value) {
                    return (value >= '0' && value <= '9') ||
                           (value >= 'a' && value <= 'f') ||
                           (value >= 'A' && value <= 'F');
                })) {
                return false;
            }
            ++units;
        }
        if (end == std::string_view::npos) break;
        start = end + 1U;
    }
    return true;
}

bool valid_ipv6(std::string_view value) noexcept {
    if (value.empty() || value.find(':') == std::string_view::npos) return false;
    const std::size_t compression = value.find("::");
    if (compression == std::string_view::npos) {
        unsigned units = 0;
        return count_ipv6_units(value, true, units) && units == 8;
    }
    if (value.find("::", compression + 2U) != std::string_view::npos) {
        return false;
    }
    unsigned left_units = 0;
    unsigned right_units = 0;
    return count_ipv6_units(value.substr(0, compression), false, left_units) &&
           count_ipv6_units(value.substr(compression + 2U), true,
                            right_units) &&
           left_units + right_units < 8;
}

bool valid_dns_name(std::string_view value) noexcept {
    if (value.empty() || value.size() > 253 || value.front() == '.' ||
        value.back() == '.') {
        return false;
    }
    std::size_t start = 0;
    while (start <= value.size()) {
        const std::size_t end = value.find('.', start);
        const std::string_view label = value.substr(
            start, end == std::string_view::npos ? value.size() - start
                                                 : end - start);
        if (label.empty() || label.size() > 63 || label.front() == '-' ||
            label.back() == '-' ||
            !std::all_of(label.begin(), label.end(), [](char byte) {
                return (byte >= 'a' && byte <= 'z') ||
                       (byte >= '0' && byte <= '9') || byte == '-';
            })) {
            return false;
        }
        if (end == std::string_view::npos) break;
        start = end + 1U;
    }
    return true;
}

template <typename T, typename Field>
bool contains_input_field(const T& value,
                          std::size_t offset,
                          Field T::*) noexcept {
    return contains_field(value, offset, sizeof(Field));
}

yume_status validate_destination(HandleHeader* diagnostic_owner,
                                 const yume_destination& destination) {
    if (destination.struct_size < YUME_DESTINATION_MIN_SIZE ||
        destination.abi_version != YUME_ABI_VERSION ||
        !valid_destination_kind(destination.kind) ||
        destination.reserved != 0) {
        return fail_with_diagnostic(diagnostic_owner,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "destination descriptor is invalid or truncated");
    }

    constexpr std::size_t kHostOffset = offsetof(yume_destination, host);
    constexpr std::size_t kPortOffset = offsetof(yume_destination, port);
    constexpr std::size_t kReserved2Offset =
        offsetof(yume_destination, reserved2);
    const bool has_host = contains_input_field(
        destination, kHostOffset, &yume_destination::host);
    const bool has_port = contains_input_field(
        destination, kPortOffset, &yume_destination::port);
    const bool has_reserved2 = contains_input_field(
        destination, kReserved2Offset, &yume_destination::reserved2);
    if (destination.struct_size > YUME_DESTINATION_MIN_SIZE && !has_host) {
        return fail_with_diagnostic(diagnostic_owner,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "destination ends inside the host field");
    }
    if (has_host && !has_port &&
        destination.struct_size > kPortOffset) {
        return fail_with_diagnostic(diagnostic_owner,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "destination ends inside the port field");
    }
    if (has_port && !has_reserved2 &&
        destination.struct_size > kReserved2Offset) {
        return fail_with_diagnostic(diagnostic_owner,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "destination ends inside a reserved field");
    }
    if (has_reserved2 && destination.reserved2 != 0) {
        return fail_with_diagnostic(diagnostic_owner,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "destination reserved fields must be zero");
    }

    if (destination.kind == YUME_DESTINATION_NONE) {
        if ((has_host && (destination.host.data || destination.host.size != 0)) ||
            (has_port && destination.port != 0)) {
            return fail_with_diagnostic(diagnostic_owner,
                                        YUME_STATUS_INVALID_ARGUMENT,
                                        "destination NONE must not carry a host or port");
        }
        return YUME_STATUS_OK;
    }
    if (!has_host || !has_port || destination.port == 0) {
        return fail_with_diagnostic(diagnostic_owner,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "network destination requires a host and nonzero port");
    }
    const std::size_t maximum =
        destination.kind == YUME_DESTINATION_HOSTNAME ? 253U :
        destination.kind == YUME_DESTINATION_IPV4 ? 15U : 45U;
    std::string host;
    try {
        host = checked_string(destination.host, maximum, "destination host");
    } catch (const std::invalid_argument& error) {
        return fail_with_diagnostic(diagnostic_owner,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    error.what());
    }
    const bool host_valid =
        destination.kind == YUME_DESTINATION_HOSTNAME ? valid_dns_name(host) :
        destination.kind == YUME_DESTINATION_IPV4 ? valid_ipv4(host) :
                                                    valid_ipv6(host);
    if (!host_valid) {
        return fail_with_diagnostic(diagnostic_owner,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "destination host does not match its declared kind");
    }
    return YUME_STATUS_OK;
}

yume_status validate_open_options(HandleHeader* diagnostic_owner,
                                  const yume_open_options& options,
                                  std::uint32_t expected_kind) {
    if (options.struct_size < YUME_OPEN_OPTIONS_MIN_SIZE ||
        options.abi_version != YUME_ABI_VERSION ||
        options.kind != expected_kind || options.reserved != 0) {
        return fail_with_diagnostic(diagnostic_owner,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "open options are invalid or truncated");
    }
    try {
        (void)checked_service_name(options.service);
    } catch (const std::invalid_argument& error) {
        return fail_with_diagnostic(diagnostic_owner,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    error.what());
    }
    constexpr std::size_t kDestinationOffset =
        offsetof(yume_open_options, destination);
    const bool has_destination = contains_input_field(
        options, kDestinationOffset, &yume_open_options::destination);
    if (!has_destination) {
        if (options.struct_size != YUME_OPEN_OPTIONS_MIN_SIZE) {
            return fail_with_diagnostic(
                diagnostic_owner, YUME_STATUS_INVALID_ARGUMENT,
                "open options end inside the destination field");
        }
        return YUME_STATUS_OK;
    }
    return validate_destination(diagnostic_owner, options.destination);
}

yume_status validate_accept_options(HandleHeader* diagnostic_owner,
                                    const yume_accept_options& options,
                                    std::uint32_t expected_kind) {
    if (options.struct_size < YUME_ACCEPT_OPTIONS_MIN_SIZE ||
        options.abi_version != YUME_ABI_VERSION ||
        options.kind != expected_kind) {
        return fail_with_diagnostic(diagnostic_owner,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "accept options are invalid or truncated");
    }
    if (contains_input_field(options,
                             offsetof(yume_accept_options, reserved),
                             &yume_accept_options::reserved) &&
        options.reserved != 0) {
        return fail_with_diagnostic(diagnostic_owner,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "accept options reserved fields must be zero");
    }
    try {
        (void)checked_service_name(options.service);
    } catch (const std::invalid_argument& error) {
        return fail_with_diagnostic(diagnostic_owner,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    error.what());
    }
    return YUME_STATUS_OK;
}

void emit_endpoint_event(const std::shared_ptr<RuntimeState>& runtime,
                         std::uint64_t endpoint_id,
                         std::uint32_t endpoint_state,
                         yume_status status) noexcept {
    if (!runtime) return;
    yume_event_callback callback = nullptr;
    void* callback_data = nullptr;
    try {
        std::lock_guard<std::mutex> lock(runtime->callback_mutex);
        if (!runtime->callbacks_enabled || !runtime->event_callback) return;
        if (runtime->callbacks_in_flight >= runtime->max_pending_callbacks) {
            return;
        }
        callback = runtime->event_callback;
        callback_data = runtime->callback_user_data;
        ++runtime->callbacks_in_flight;
    } catch (...) {
        return;
    }
    yume_event event{};
    event.struct_size = sizeof(event);
    event.abi_version = YUME_ABI_VERSION;
    event.type = YUME_EVENT_ENDPOINT_STATE;
    event.endpoint_state = endpoint_state;
    event.endpoint_id = endpoint_id;
    event.status = status;
    try {
        CallbackScope callback_scope;
        callback(&event, callback_data);
    } catch (...) {
        // A callback is outside the ABI trust boundary. It cannot unwind into
        // endpoint state settlement.
    }
    try {
        std::lock_guard<std::mutex> lock(runtime->callback_mutex);
        if (runtime->callbacks_in_flight != 0) {
            --runtime->callbacks_in_flight;
        }
        if (runtime->callbacks_in_flight == 0) runtime->callback_cv.notify_all();
    } catch (...) {
        // The runtime remains fail-closed. A platform mutex failure is not
        // recoverable through a callback or C ABI diagnostic path.
    }
}

yume_status stop_endpoint_control(
    const std::shared_ptr<RuntimeState>& runtime,
    const std::shared_ptr<EndpointControl>& control) noexcept {
    if (!control) return YUME_STATUS_INVALID_ARGUMENT;
    try {
        std::lock_guard<std::mutex> lifecycle_lock(control->lifecycle_mutex);
        {
            std::lock_guard<std::mutex> state_lock(control->mutex);
            if (control->state == YUME_ENDPOINT_STOPPED) {
                return YUME_STATUS_OK;
            }
            control->state = YUME_ENDPOINT_STOPPING;
        }
        emit_endpoint_event(runtime, control->id, YUME_ENDPOINT_STOPPING,
                            YUME_STATUS_OK);
        // Tear the runtime down between the two published states so a caller
        // that observes STOPPED has already had its worker threads joined.
        // stop() is idempotent, so a never-started endpoint is a no-op.
        if (control->backend) {
            control->backend->stop();
        }
        {
            std::lock_guard<std::mutex> state_lock(control->mutex);
            control->state = YUME_ENDPOINT_STOPPED;
        }
        emit_endpoint_event(runtime, control->id, YUME_ENDPOINT_STOPPED,
                            YUME_STATUS_OK);
        return YUME_STATUS_OK;
    } catch (...) {
        return YUME_STATUS_INTERNAL_ERROR;
    }
}

std::uint64_t allocate_endpoint_id(RuntimeState& runtime) noexcept {
    std::uint64_t candidate = runtime.next_endpoint_id.load();
    const std::uint64_t exhausted = std::numeric_limits<std::uint64_t>::max();
    while (candidate != 0 && candidate != exhausted) {
        if (runtime.next_endpoint_id.compare_exchange_weak(candidate,
                                                           candidate + 1U)) {
            return candidate;
        }
    }
    return 0;
}

}  // namespace

// Public identity fields are fixed-size and NUL-terminated. Truncation is
// preferred over failing an otherwise valid stream, because these strings are
// diagnostic labels rather than authorization inputs.
void copy_bounded(char* destination,
                  std::size_t capacity,
                  std::string_view value) noexcept {
    if (destination == nullptr || capacity == 0) return;
    const std::size_t copied = std::min(value.size(), capacity - 1U);
    std::memcpy(destination, value.data(), copied);
    destination[copied] = '\0';
}

// The transport publishes the composite fingerprint as lowercase hex. A value
// that is not exactly 32 decoded bytes is dropped rather than partially
// copied, so a caller can never read a half-populated fingerprint.
void copy_fingerprint(std::uint8_t (&destination)[32],
                      std::string_view hex) noexcept {
    std::memset(destination, 0, sizeof(destination));
    if (hex.size() != sizeof(destination) * 2U) return;
    for (std::size_t index = 0; index < sizeof(destination); ++index) {
        std::uint8_t byte = 0;
        for (std::size_t nibble = 0; nibble < 2U; ++nibble) {
            const char character = hex[index * 2U + nibble];
            std::uint8_t value = 0;
            if (character >= '0' && character <= '9') {
                value = static_cast<std::uint8_t>(character - '0');
            } else if (character >= 'a' && character <= 'f') {
                value = static_cast<std::uint8_t>(character - 'a' + 10);
            } else if (character >= 'A' && character <= 'F') {
                value = static_cast<std::uint8_t>(character - 'A' + 10);
            } else {
                std::memset(destination, 0, sizeof(destination));
                return;
            }
            byte = static_cast<std::uint8_t>((byte << 4) | value);
        }
        destination[index] = byte;
    }
}

yume_status status_from_backend(yume::embed::BackendIo io) noexcept {
    switch (io) {
    case yume::embed::BackendIo::Ok:         return YUME_STATUS_OK;
    case yume::embed::BackendIo::Eof:        return YUME_STATUS_EOF;
    case yume::embed::BackendIo::Timeout:    return YUME_STATUS_TIMEOUT;
    case yume::embed::BackendIo::WouldBlock: return YUME_STATUS_WOULD_BLOCK;
    case yume::embed::BackendIo::Closed:     return YUME_STATUS_CLOSED;
    case yume::embed::BackendIo::Invalid:    return YUME_STATUS_INVALID_ARGUMENT;
    case yume::embed::BackendIo::NotRunning: return YUME_STATUS_INVALID_STATE;
    case yume::embed::BackendIo::Failed:     return YUME_STATUS_IO_ERROR;
    }
    return YUME_STATUS_INTERNAL_ERROR;
}

struct DocumentDialect {
    bool schema1{false};
    bool server{false};
    const char* error{nullptr};
    const char* json_pointer{""};
};

// Both configuration dialects must state their role. Schema 1 additionally
// carries "schema": 1. Anything else is rejected here rather than being fed
// to a parser that would ignore the keys it does not recognize.
//
// Deliberately not noexcept: this builds a DOM from a caller-sized buffer, so
// it can throw std::bad_alloc. Callers run it inside guard(), which turns that
// into YUME_STATUS_RESOURCE_EXHAUSTED. Marking it noexcept would terminate the
// embedder's process instead.
DocumentDialect classify_document(std::string_view text) {
    DocumentDialect dialect;
    nlohmann::json document =
        nlohmann::json::parse(text, nullptr, false, true);
    if (document.is_discarded() || !document.is_object()) {
        dialect.error = "configuration must be one JSON object";
        return dialect;
    }
    const auto role = document.find("role");
    if (role == document.end() || !role->is_string()) {
        dialect.error = "required string key is missing";
        dialect.json_pointer = "/role";
        return dialect;
    }
    const auto& role_text = role->get_ref<const std::string&>();
    if (role_text == "server") {
        dialect.server = true;
    } else if (role_text != "client") {
        dialect.error = "must be \"client\" or \"server\"";
        dialect.json_pointer = "/role";
        return dialect;
    }
    const auto schema = document.find("schema");
    if (schema != document.end()) {
        if (!schema->is_number_unsigned() ||
            schema->get<std::uint64_t>() != yume::config::v1::kSchema) {
            dialect.error = "unsupported configuration schema";
            dialect.json_pointer = "/schema";
            return dialect;
        }
        dialect.schema1 = true;
    }
    return dialect;
}

struct yume_runtime {
    HandleHeader header{HandleKind::Runtime};
    std::shared_ptr<RuntimeState> state;
};

// Two configuration dialects reach the same public entry point during the
// transition: strict schema 1 for the YTP/1 replacement, and the runnable
// transport-v2 document. Both must name their role explicitly so the ABI
// never has to guess which runtime a document was written for.
struct yume_config {
    yume_config(std::shared_ptr<RuntimeState> runtime_state,
                yume::config::v1::Config parsed)
        : runtime(std::move(runtime_state)),
          schema1(std::move(parsed)),
          server(schema1->role() == yume::config::v1::Role::Server) {}

    yume_config(std::shared_ptr<RuntimeState> runtime_state,
                std::unique_ptr<yume::embed::BackendConfig> parsed)
        : runtime(std::move(runtime_state)),
          transport_v2(std::move(parsed)),
          server(transport_v2->is_server()) {}

    HandleHeader header{HandleKind::Config};
    std::shared_ptr<RuntimeState> runtime;
    std::optional<yume::config::v1::Config> schema1;
    std::shared_ptr<yume::embed::BackendConfig> transport_v2;
    bool server{false};
};

struct yume_endpoint {
    yume_endpoint(std::shared_ptr<RuntimeState> runtime_state,
                  const yume_config& source,
                  std::uint64_t assigned_id)
        : runtime(std::move(runtime_state)),
          config(source.schema1),
          transport_v2(source.transport_v2),
          control(std::make_shared<EndpointControl>(assigned_id)) {}

    HandleHeader header{HandleKind::Endpoint};
    std::shared_ptr<RuntimeState> runtime;
    std::optional<yume::config::v1::Config> config;
    std::shared_ptr<yume::embed::BackendConfig> transport_v2;
    std::shared_ptr<EndpointControl> control;
    mutable std::mutex mutex;
    std::unordered_map<ServiceKey, ServiceRegistration, ServiceKeyHash>
        services;
    yume_socket_protect_callback socket_protector{nullptr};
    void* socket_protector_data{nullptr};
};

struct yume_stream {
    yume_stream() noexcept {
        peer.struct_size = sizeof(peer);
        peer.abi_version = YUME_ABI_VERSION;
    }

    explicit yume_stream(std::unique_ptr<yume::embed::BackendStream> backing)
        : backend(std::move(backing)) {
        peer.struct_size = sizeof(peer);
        peer.abi_version = YUME_ABI_VERSION;
        closed = false;
        const yume::embed::BackendPeerIdentity identity =
            backend->peer_identity();
        peer.authenticated = identity.authenticated ? 1U : 0U;
        copy_bounded(peer.peer_label, sizeof(peer.peer_label),
                     identity.peer_label);
        copy_bounded(peer.service, sizeof(peer.service), identity.service);
        copy_fingerprint(peer.composite_fingerprint_sha256,
                         identity.fingerprint_sha256);
    }

    HandleHeader header{HandleKind::Stream};
    mutable std::mutex mutex;
    yume_peer_identity peer{};
    bool closed{true};
    std::unique_ptr<yume::embed::BackendStream> backend;
};

struct yume_packet {
    yume_packet() noexcept {
        peer.struct_size = sizeof(peer);
        peer.abi_version = YUME_ABI_VERSION;
    }

    HandleHeader header{HandleKind::Packet};
    mutable std::mutex mutex;
    yume_peer_identity peer{};
    bool closed{true};
};

static_assert(std::is_standard_layout_v<yume_runtime> &&
              offsetof(yume_runtime, header) == 0);
static_assert(std::is_standard_layout_v<yume_config> &&
              offsetof(yume_config, header) == 0);
static_assert(std::is_standard_layout_v<yume_endpoint> &&
              offsetof(yume_endpoint, header) == 0);
static_assert(std::is_standard_layout_v<yume_stream> &&
              offsetof(yume_stream, header) == 0);
static_assert(std::is_standard_layout_v<yume_packet> &&
              offsetof(yume_packet, header) == 0);

extern "C" {

uint32_t yume_abi_version(void) noexcept {
    return YUME_ABI_VERSION;
}

yume_status yume_get_build_info(yume_build_info* out,
                                size_t out_size) noexcept {
    yume_build_info value{};
    value.struct_size = sizeof(value);
    value.abi_version = YUME_ABI_VERSION;
    value.feature_flags = 0;
    copy_text(value.product_version, sizeof(value.product_version),
              yume::kCompatibilityManifest.product_version);
    copy_text(value.crypto_backend, sizeof(value.crypto_backend),
              yume::kCompatibilityManifest.crypto_backend);
#if defined(__clang__)
    copy_text(value.compiler, sizeof(value.compiler), "clang");
#elif defined(__GNUC__)
    copy_text(value.compiler, sizeof(value.compiler), "gcc");
#elif defined(_MSC_VER)
    copy_text(value.compiler, sizeof(value.compiler), "msvc");
#else
    copy_text(value.compiler, sizeof(value.compiler), "unknown");
#endif
    return copy_sized(out, out_size, YUME_BUILD_INFO_MIN_SIZE, value,
                      kBuildInfoFields);
}

yume_status yume_get_compatibility(yume_compatibility* out,
                                   size_t out_size) noexcept {
    yume_compatibility value{};
    value.struct_size = sizeof(value);
    value.abi_version = YUME_ABI_VERSION;
    value.ytp_version = yume::kYtpVersionNumber;
    value.config_schema = yume::kConfigSchema;
    value.evidence_profile_version = yume::kEvidenceProfileVersion;
    copy_text(value.product_version, sizeof(value.product_version),
              yume::kCompatibilityManifest.product_version);
    copy_text(value.ytp_name, sizeof(value.ytp_name),
              yume::kCompatibilityManifest.ytp_version);
    copy_text(value.suite, sizeof(value.suite),
              yume::kCompatibilityManifest.transport_suite);
    copy_text(value.crypto_backend, sizeof(value.crypto_backend),
              yume::kCompatibilityManifest.crypto_backend);
    copy_text(value.secure_channel_provider,
              sizeof(value.secure_channel_provider),
              yume::kCompatibilityManifest.secure_channel_provider);
    copy_text(value.front_door_provider, sizeof(value.front_door_provider),
              yume::kCompatibilityManifest.front_door_provider);
    copy_text(value.carrier_provider, sizeof(value.carrier_provider),
              yume::kCompatibilityManifest.carrier_provider);
    copy_text(value.session_component, sizeof(value.session_component),
              yume::kCompatibilityManifest.session_component);
    copy_text(value.session_security_provider,
              sizeof(value.session_security_provider),
              yume::kCompatibilityManifest.session_security_provider);
    copy_text(value.evidence_profile, sizeof(value.evidence_profile),
              yume::kCompatibilityManifest.evidence_profile);
    return copy_sized(out, out_size, YUME_COMPATIBILITY_MIN_SIZE, value,
                      kCompatibilityFields);
}

yume_status yume_get_status_info(yume_status code,
                                 yume_status_info* out,
                                 size_t out_size) noexcept {
    const char* name = status_name(code);
    if (!name) return YUME_STATUS_INVALID_ARGUMENT;
    yume_status_info value{};
    value.struct_size = sizeof(value);
    value.abi_version = YUME_ABI_VERSION;
    value.code = code;
    copy_text(value.name, sizeof(value.name), name);
    return copy_sized(out, out_size, YUME_STATUS_INFO_MIN_SIZE, value,
                      kStatusInfoFields);
}

yume_status yume_runtime_create(const yume_runtime_options* options,
                                yume_runtime** out_runtime) noexcept {
    if (out_runtime) *out_runtime = nullptr;
    if (g_in_callback) return YUME_STATUS_INVALID_STATE;
    if (!options || !out_runtime ||
        options->struct_size < YUME_RUNTIME_OPTIONS_MIN_SIZE ||
        options->abi_version != YUME_ABI_VERSION) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    return guard(nullptr, [&]() -> yume_status {
        const std::uint32_t threads = options->executor_threads == 0
            ? kDefaultExecutorThreads : options->executor_threads;
        const std::uint32_t pending = options->max_pending_callbacks == 0
            ? kDefaultPendingCallbacks : options->max_pending_callbacks;
        if (threads > kMaxExecutorThreads || pending > kMaxPendingCallbacks) {
            return YUME_STATUS_RESOURCE_EXHAUSTED;
        }
        auto runtime = std::make_unique<yume_runtime>();
        runtime->state = std::make_shared<RuntimeState>();
        runtime->state->executor_threads = threads;
        runtime->state->max_pending_callbacks = pending;
        runtime->state->log_callback = options->log_callback;
        if (contains_field(*options,
                           offsetof(yume_runtime_options, event_callback),
                           sizeof(options->event_callback))) {
            runtime->state->event_callback = options->event_callback;
        }
        if (contains_field(*options,
                           offsetof(yume_runtime_options, callback_user_data),
                           sizeof(options->callback_user_data))) {
            runtime->state->callback_user_data = options->callback_user_data;
        }
        if (contains_field(*options,
                           offsetof(yume_runtime_options, config_base_dir),
                           sizeof(options->config_base_dir)) &&
            options->config_base_dir != nullptr) {
            const std::string_view base(options->config_base_dir);
            if (base.empty() || base.size() > kMaxConfigBaseDirBytes) {
                return YUME_STATUS_INVALID_ARGUMENT;
            }
            runtime->state->config_base_dir = std::string(base);
        }
        *out_runtime = runtime.release();
        return YUME_STATUS_OK;
    });
}

void yume_runtime_destroy(yume_runtime* runtime) noexcept {
    if (!runtime || !valid_header(&runtime->header, HandleKind::Runtime)) return;
    if (g_in_callback) return;
    const std::shared_ptr<RuntimeState> state = runtime->state;
    try {
        if (state) {
            state->stopping.store(true);
            std::vector<std::weak_ptr<EndpointControl>> endpoints;
            {
                std::lock_guard<std::mutex> lock(state->endpoints_mutex);
                endpoints.swap(state->endpoints);
            }
            for (const auto& weak_endpoint : endpoints) {
                if (auto endpoint = weak_endpoint.lock()) {
                    (void)stop_endpoint_control(state, endpoint);
                }
            }
        }
    } catch (...) {
        // Continue disabling callbacks and releasing the runtime handle. The
        // shared state remains fail-closed through stopping=true.
    }
    try {
        if (state) {
            std::unique_lock<std::mutex> callback_lock(state->callback_mutex);
            state->callbacks_enabled = false;
            state->callback_cv.wait(callback_lock, [&state] {
                return state->callbacks_in_flight == 0;
            });
            state->log_callback = nullptr;
            state->event_callback = nullptr;
            state->callback_user_data = nullptr;
        }
    } catch (...) {
        // Mutex/condition-variable failure is not recoverable through a void C
        // destructor. stopping=true still prevents further endpoint work.
    }
    delete runtime;
}

yume_status yume_config_parse_json(yume_runtime* runtime,
                                   const void* json,
                                   size_t json_size,
                                   yume_config** out_config) noexcept {
    if (out_config) *out_config = nullptr;
    if (!runtime || !valid_header(&runtime->header, HandleKind::Runtime)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(&runtime->header,
                                    YUME_STATUS_INVALID_STATE,
                                    "configuration parsing is forbidden from callbacks");
    }
    if (!json || json_size == 0 || !out_config) {
        return fail_with_diagnostic(&runtime->header,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "JSON input and output handle are required");
    }
    return guard(&runtime->header, [&]() -> yume_status {
        const auto* data = static_cast<const char*>(json);
        const std::string_view text(data, json_size);

        // Dialect selection is explicit, never inferred from which parser
        // happens to accept the bytes. Both dialects ignore unknown keys, so
        // guessing would silently load a document against the wrong runtime.
        const DocumentDialect dialect = classify_document(text);
        if (dialect.error != nullptr) {
            set_diagnostic(&runtime->header, YUME_STATUS_PARSE_ERROR,
                           dialect.json_pointer, dialect.error);
            return YUME_STATUS_PARSE_ERROR;
        }

        if (dialect.schema1) {
            try {
                auto parsed = yume::config::v1::ParseJson(text);
                auto config = std::make_unique<yume_config>(runtime->state,
                                                            std::move(parsed));
                clear_diagnostic(&runtime->header);
                *out_config = config.release();
                return YUME_STATUS_OK;
            } catch (const yume::config::v1::ValidationError& error) {
                set_diagnostic(&runtime->header, YUME_STATUS_PARSE_ERROR,
                               error.json_pointer(), error.detail());
                return YUME_STATUS_PARSE_ERROR;
            }
        }

        std::string error;
        auto parsed = yume::embed::parse_transport_v2_config(
            text, dialect.server, runtime->state->config_base_dir, error);
        if (!parsed) {
            const yume_status status = kTransportBackendLinked
                ? YUME_STATUS_PARSE_ERROR : YUME_STATUS_UNSUPPORTED;
            set_diagnostic(&runtime->header, status, {}, error);
            return status;
        }
        auto config = std::make_unique<yume_config>(runtime->state,
                                                    std::move(parsed));
        clear_diagnostic(&runtime->header);
        *out_config = config.release();
        return YUME_STATUS_OK;
    });
}

uint32_t yume_config_role(const yume_config* config) noexcept {
    if (!config || !valid_header(&config->header, HandleKind::Config)) return 0;
    if (g_in_callback) return 0;
    return config->server ? YUME_ROLE_SERVER : YUME_ROLE_CLIENT;
}

void yume_config_destroy(yume_config* config) noexcept {
    if (!config || !valid_header(&config->header, HandleKind::Config)) return;
    if (g_in_callback) return;
    delete config;
}

yume_status yume_endpoint_create(yume_runtime* runtime,
                                 const yume_config* config,
                                 yume_endpoint** out_endpoint) noexcept {
    if (out_endpoint) *out_endpoint = nullptr;
    if (!runtime || !valid_header(&runtime->header, HandleKind::Runtime)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(&runtime->header,
                                    YUME_STATUS_INVALID_STATE,
                                    "endpoint creation is forbidden from callbacks");
    }
    if (!config || !valid_header(&config->header, HandleKind::Config) ||
        !out_endpoint) {
        return fail_with_diagnostic(&runtime->header,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "config and output endpoint are required");
    }
    return guard(&runtime->header, [&]() -> yume_status {
        if (runtime->state->stopping.load()) {
            return fail_with_diagnostic(&runtime->header,
                                        YUME_STATUS_CANCELLED,
                                        "runtime is stopping");
        }
        if (config->runtime.get() != runtime->state.get()) {
            return fail_with_diagnostic(&runtime->header,
                                        YUME_STATUS_INVALID_ARGUMENT,
                                        "config belongs to a different runtime");
        }
        const std::uint64_t id = allocate_endpoint_id(*runtime->state);
        if (id == 0) {
            return fail_with_diagnostic(&runtime->header,
                                        YUME_STATUS_RESOURCE_EXHAUSTED,
                                        "endpoint identifier space is exhausted");
        }
        auto endpoint = std::make_unique<yume_endpoint>(
            runtime->state, *config, id);
        {
            std::lock_guard<std::mutex> lock(runtime->state->endpoints_mutex);
            if (runtime->state->stopping.load()) {
                return fail_with_diagnostic(&runtime->header,
                                            YUME_STATUS_CANCELLED,
                                            "runtime is stopping");
            }
            auto& endpoints = runtime->state->endpoints;
            endpoints.erase(
                std::remove_if(endpoints.begin(), endpoints.end(),
                               [](const auto& item) { return item.expired(); }),
                endpoints.end());
            if (endpoints.size() >= kMaxRuntimeEndpoints) {
                return fail_with_diagnostic(
                    &runtime->header, YUME_STATUS_RESOURCE_EXHAUSTED,
                    "runtime endpoint limit is exhausted");
            }
            endpoints.emplace_back(endpoint->control);
        }
        clear_diagnostic(&runtime->header);
        *out_endpoint = endpoint.release();
        return YUME_STATUS_OK;
    });
}

yume_status yume_endpoint_set_socket_protector(
    yume_endpoint* endpoint,
    yume_socket_protect_callback callback,
    void* user_data) noexcept {
    if (!endpoint || !valid_header(&endpoint->header, HandleKind::Endpoint)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(&endpoint->header,
                                    YUME_STATUS_INVALID_STATE,
                                    "socket protector changes are forbidden from callbacks");
    }
    if (!callback && user_data) {
        return fail_with_diagnostic(
            &endpoint->header, YUME_STATUS_INVALID_ARGUMENT,
            "socket protector user data requires a callback");
    }
    return guard(&endpoint->header, [&]() -> yume_status {
        std::lock_guard<std::mutex> lifecycle_lock(
            endpoint->control->lifecycle_mutex);
        std::lock_guard<std::mutex> state_lock(endpoint->control->mutex);
        if (endpoint->runtime->stopping.load()) {
            return fail_with_diagnostic(&endpoint->header,
                                        YUME_STATUS_CANCELLED,
                                        "runtime is stopping");
        }
        if (endpoint->control->state == YUME_ENDPOINT_STARTING ||
            endpoint->control->state == YUME_ENDPOINT_RUNNING ||
            endpoint->control->state == YUME_ENDPOINT_STOPPING) {
            return fail_with_diagnostic(
                &endpoint->header, YUME_STATUS_INVALID_STATE,
                "socket protector cannot change while the endpoint is active");
        }
        std::lock_guard<std::mutex> lock(endpoint->mutex);
        endpoint->socket_protector = callback;
        endpoint->socket_protector_data = user_data;
        clear_diagnostic(&endpoint->header);
        return YUME_STATUS_OK;
    });
}

yume_status yume_endpoint_register_service(
    yume_endpoint* endpoint,
    const yume_service_descriptor* service) noexcept {
    if (!endpoint || !valid_header(&endpoint->header, HandleKind::Endpoint)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(&endpoint->header,
                                    YUME_STATUS_INVALID_STATE,
                                    "service registration is forbidden from callbacks");
    }
    if (!service || service->struct_size < YUME_SERVICE_DESCRIPTOR_MIN_SIZE ||
        service->abi_version != YUME_ABI_VERSION ||
        !valid_service_kind(service->kind)) {
        return fail_with_diagnostic(&endpoint->header,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "service descriptor is invalid or truncated");
    }
    return guard(&endpoint->header, [&]() -> yume_status {
        if (endpoint->runtime->stopping.load()) {
            return fail_with_diagnostic(&endpoint->header,
                                        YUME_STATUS_CANCELLED,
                                        "runtime is stopping");
        }
        std::string name;
        try {
            name = checked_service_name(service->name);
        } catch (const std::invalid_argument& error) {
            set_diagnostic(&endpoint->header, YUME_STATUS_INVALID_ARGUMENT, {},
                           error.what());
            return YUME_STATUS_INVALID_ARGUMENT;
        }
        if (service->max_concurrent == 0 ||
            service->max_concurrent > kMaxServiceConcurrency ||
            service->max_pending_accepts == 0 ||
            service->max_pending_accepts > kMaxServiceConcurrency ||
            service->max_queued_bytes == 0 ||
            service->max_queued_bytes > kMaxServiceQueuedBytes) {
            return fail_with_diagnostic(
                &endpoint->header, YUME_STATUS_RESOURCE_EXHAUSTED,
                "service resource policy is outside supported bounds");
        }
        if (!endpoint->config.has_value()) {
            // A transport-v2 endpoint has no schema-1 service table to check
            // a registration against, so the runtime itself is the authority.
            // Registration is a server capability and the runtime must already
            // be listening, which is why this runs after start rather than
            // before it.
            if (service->kind != YUME_SERVICE_BYTE_STREAM) {
                return fail_with_diagnostic(
                    &endpoint->header, YUME_STATUS_UNSUPPORTED,
                    "packet services are not implemented yet");
            }
            yume::embed::EndpointBackend* backend =
                endpoint->control->backend.get();
            if (backend == nullptr) {
                return fail_with_diagnostic(
                    &endpoint->header, YUME_STATUS_INVALID_STATE,
                    "endpoint must be started before registering a service");
            }
            std::string backend_error;
            const yume::embed::BackendIo io =
                backend->register_service(name, backend_error);
            if (io != yume::embed::BackendIo::Ok) {
                return fail_with_diagnostic(
                    &endpoint->header, status_from_backend(io),
                    backend_error.empty() ? "service registration failed"
                                          : backend_error);
            }
            std::lock_guard<std::mutex> lock(endpoint->mutex);
            endpoint->services.insert_or_assign(
                ServiceKey{name, service->kind},
                ServiceRegistration{service->kind, service->max_concurrent,
                                    service->max_pending_accepts,
                                    service->max_queued_bytes});
            clear_diagnostic(&endpoint->header);
            return YUME_STATUS_OK;
        }
        const auto configured_service = std::find_if(
            endpoint->config->services().begin(),
            endpoint->config->services().end(),
            [&](const yume::config::v1::Service& configured) {
                const bool kind_matches =
                    (configured.kind() == yume::config::v1::ServiceKind::Stream &&
                     service->kind == YUME_SERVICE_BYTE_STREAM) ||
                    (configured.kind() == yume::config::v1::ServiceKind::Packet &&
                     service->kind == YUME_SERVICE_PACKET);
                return configured.name() == name && kind_matches;
            });
        if (configured_service == endpoint->config->services().end()) {
            return fail_with_diagnostic(
                &endpoint->header, YUME_STATUS_PERMISSION_DENIED,
                "service is not enabled by the immutable endpoint config");
        }
        if (service->max_concurrent == 0 ||
            service->max_concurrent > kMaxServiceConcurrency ||
            service->max_pending_accepts == 0 ||
            service->max_pending_accepts > kMaxServiceConcurrency ||
            service->max_queued_bytes == 0 ||
            service->max_queued_bytes > kMaxServiceQueuedBytes) {
            return fail_with_diagnostic(
                &endpoint->header, YUME_STATUS_RESOURCE_EXHAUSTED,
                "service resource policy is outside supported bounds");
        }
        const auto& endpoint_limits = endpoint->config->limits();
        if (service->max_concurrent >
                configured_service->max_concurrent_streams() ||
            service->max_concurrent > endpoint_limits.max_streams() ||
            service->max_pending_accepts >
                endpoint_limits.max_pending_opens() ||
            service->max_queued_bytes > endpoint_limits.max_queued_bytes()) {
            return fail_with_diagnostic(
                &endpoint->header, YUME_STATUS_PERMISSION_DENIED,
                "service policy exceeds immutable endpoint config limits");
        }
        {
            std::lock_guard<std::mutex> lifecycle_lock(
                endpoint->control->lifecycle_mutex);
            std::lock_guard<std::mutex> state_lock(endpoint->control->mutex);
            if (endpoint->runtime->stopping.load()) {
                return fail_with_diagnostic(&endpoint->header,
                                            YUME_STATUS_CANCELLED,
                                            "runtime is stopping");
            }
            if (endpoint->control->state != YUME_ENDPOINT_CREATED &&
                endpoint->control->state != YUME_ENDPOINT_STOPPED) {
                return fail_with_diagnostic(
                    &endpoint->header, YUME_STATUS_INVALID_STATE,
                    "services cannot change while the endpoint is active");
            }
            std::lock_guard<std::mutex> lock(endpoint->mutex);
            const auto [_, inserted] = endpoint->services.emplace(
                ServiceKey{std::move(name), service->kind},
                ServiceRegistration{
                    service->kind, service->max_concurrent,
                    service->max_pending_accepts, service->max_queued_bytes});
            if (!inserted) {
                return fail_with_diagnostic(&endpoint->header,
                                            YUME_STATUS_INVALID_ARGUMENT,
                                            "service name and kind are already registered");
            }
        }
        clear_diagnostic(&endpoint->header);
        return YUME_STATUS_OK;
    });
}

yume_status yume_endpoint_start(yume_endpoint* endpoint,
                                uint32_t timeout_ms) noexcept {
    if (!endpoint || !valid_header(&endpoint->header, HandleKind::Endpoint)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(&endpoint->header,
                                    YUME_STATUS_INVALID_STATE,
                                    "endpoint start is forbidden from callbacks");
    }
    return guard(&endpoint->header, [&]() -> yume_status {
        std::lock_guard<std::mutex> lifecycle_lock(
            endpoint->control->lifecycle_mutex);
        {
            std::lock_guard<std::mutex> lock(endpoint->control->mutex);
            if (endpoint->runtime->stopping.load()) {
                return fail_with_diagnostic(&endpoint->header,
                                            YUME_STATUS_CANCELLED,
                                            "runtime is stopping");
            }
            if (endpoint->control->state != YUME_ENDPOINT_CREATED &&
                endpoint->control->state != YUME_ENDPOINT_STOPPED) {
                return fail_with_diagnostic(
                    &endpoint->header, YUME_STATUS_INVALID_STATE,
                    "endpoint cannot start from its current state");
            }
            endpoint->control->state = YUME_ENDPOINT_STARTING;
        }
        clear_diagnostic(&endpoint->header);
        emit_endpoint_event(endpoint->runtime, endpoint->control->id,
                            YUME_ENDPOINT_STARTING, YUME_STATUS_OK);

        // A schema-1 endpoint targets the YTP/1 provider graph, which has no
        // live TLS/H2 front door yet. Never substitute a test or in-memory
        // channel for the configured mandatory suite to make this path look
        // like it works.
        yume_status failure = YUME_STATUS_UNSUPPORTED;
        std::string detail =
            "native ytp1-tls13-h2 endpoint provider is not linked";
        bool started = false;

        if (endpoint->transport_v2) {
            std::string error;
            if (!endpoint->control->backend) {
                endpoint->control->backend =
                    yume::embed::make_transport_v2_backend(
                        *endpoint->transport_v2, error);
            }
            if (!endpoint->control->backend) {
                failure = YUME_STATUS_INTERNAL_ERROR;
                detail = error.empty() ? "endpoint backend unavailable" : error;
            } else if (endpoint->control->backend->start(timeout_ms, error)) {
                started = true;
            } else {
                // A failed start leaves no half-open runtime behind: the
                // backend is torn down so a retry re-runs the whole sequence.
                endpoint->control->backend->stop();
                failure = YUME_STATUS_IO_ERROR;
                detail = error.empty() ? "endpoint failed to start" : error;
            }
        }

        {
            std::lock_guard<std::mutex> lock(endpoint->control->mutex);
            const bool cancelled =
                endpoint->runtime->stopping.load() ||
                endpoint->control->state != YUME_ENDPOINT_STARTING;
            if (cancelled) {
                if (started && endpoint->control->backend) {
                    endpoint->control->backend->stop();
                }
                return fail_with_diagnostic(&endpoint->header,
                                            YUME_STATUS_CANCELLED,
                                            "endpoint start was cancelled");
            }
            endpoint->control->state =
                started ? YUME_ENDPOINT_RUNNING : YUME_ENDPOINT_FAILED;
        }

        if (started) {
            emit_endpoint_event(endpoint->runtime, endpoint->control->id,
                                YUME_ENDPOINT_RUNNING, YUME_STATUS_OK);
            clear_diagnostic(&endpoint->header);
            return YUME_STATUS_OK;
        }

        emit_endpoint_event(endpoint->runtime, endpoint->control->id,
                            YUME_ENDPOINT_FAILED, failure);
        // A callback may make a forbidden re-entrant call which records its
        // own INVALID_STATE diagnostic. Publish this operation's final result
        // after callbacks return so the caller observes the start failure.
        set_diagnostic(&endpoint->header, failure, {}, detail);
        return failure;
    });
}

yume_status yume_endpoint_stop(yume_endpoint* endpoint,
                               uint32_t /*timeout_ms*/) noexcept {
    if (!endpoint || !valid_header(&endpoint->header, HandleKind::Endpoint)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(&endpoint->header,
                                    YUME_STATUS_INVALID_STATE,
                                    "endpoint stop is forbidden from callbacks");
    }
    const yume_status status =
        stop_endpoint_control(endpoint->runtime, endpoint->control);
    if (status == YUME_STATUS_OK) {
        clear_diagnostic(&endpoint->header);
    } else {
        set_diagnostic(&endpoint->header, status, {},
                       "endpoint stop failed during state settlement");
    }
    return status;
}

uint32_t yume_endpoint_state(const yume_endpoint* endpoint) noexcept {
    if (!endpoint || !valid_header(&endpoint->header, HandleKind::Endpoint)) {
        return 0;
    }
    if (g_in_callback) return 0;
    try {
        std::lock_guard<std::mutex> lock(endpoint->control->mutex);
        return endpoint->control->state;
    } catch (...) {
        return 0;
    }
}

namespace {

yume_status unavailable_endpoint_io(yume_endpoint* endpoint,
                                    std::uint32_t kind) noexcept {
    if (!endpoint || !valid_header(&endpoint->header, HandleKind::Endpoint) ||
        !valid_service_kind(kind)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(&endpoint->header,
                                    YUME_STATUS_INVALID_STATE,
                                    "endpoint I/O is forbidden from callbacks");
    }
    return guard(&endpoint->header, [&]() -> yume_status {
        if (endpoint->runtime->stopping.load()) {
            return fail_with_diagnostic(&endpoint->header,
                                        YUME_STATUS_CANCELLED,
                                        "runtime is stopping");
        }
        std::lock_guard<std::mutex> lock(endpoint->control->mutex);
        if (endpoint->control->state != YUME_ENDPOINT_RUNNING) {
            return fail_with_diagnostic(&endpoint->header,
                                        YUME_STATUS_INVALID_STATE,
                                        "endpoint is not running");
        }
        return fail_with_diagnostic(
            &endpoint->header, YUME_STATUS_UNSUPPORTED,
            "native ytp1-tls13-h2 endpoint provider is not linked");
    });
}

// Streams are opened by the client role and accepted by the server role. The
// backend refuses the direction it does not own, so this shared entry point
// never has to know which role it is serving.
yume_status backend_stream_io(yume_endpoint* endpoint,
                              std::uint32_t kind,
                              std::string_view service,
                              std::uint32_t timeout_ms,
                              bool accept,
                              yume_stream** out_stream) noexcept {
    if (!endpoint || !valid_header(&endpoint->header, HandleKind::Endpoint) ||
        !valid_service_kind(kind) || out_stream == nullptr) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(&endpoint->header,
                                    YUME_STATUS_INVALID_STATE,
                                    "endpoint I/O is forbidden from callbacks");
    }
    if (kind != YUME_SERVICE_BYTE_STREAM) {
        return fail_with_diagnostic(&endpoint->header, YUME_STATUS_UNSUPPORTED,
                                    "packet channels are not implemented yet");
    }
    return guard(&endpoint->header, [&]() -> yume_status {
        if (endpoint->runtime->stopping.load()) {
            return fail_with_diagnostic(&endpoint->header,
                                        YUME_STATUS_CANCELLED,
                                        "runtime is stopping");
        }
        {
            std::lock_guard<std::mutex> lock(endpoint->control->mutex);
            if (endpoint->control->state != YUME_ENDPOINT_RUNNING) {
                return fail_with_diagnostic(&endpoint->header,
                                            YUME_STATUS_INVALID_STATE,
                                            "endpoint is not running");
            }
        }
        // The backend pointer is only written under lifecycle_mutex during
        // start, and start must have completed for the state check above to
        // pass, so reading it here needs no lifecycle lock.
        yume::embed::EndpointBackend* backend = endpoint->control->backend.get();
        if (backend == nullptr) {
            return fail_with_diagnostic(
                &endpoint->header, YUME_STATUS_UNSUPPORTED,
                "native ytp1-tls13-h2 endpoint provider is not linked");
        }

        std::unique_ptr<yume::embed::BackendStream> opened;
        std::string error;
        const std::string service_name(service);
        const yume::embed::BackendIo io = accept
            ? backend->accept_stream(service_name, timeout_ms, opened, error)
            : backend->open_stream(service_name, timeout_ms, opened, error);
        if (io != yume::embed::BackendIo::Ok || !opened) {
            const yume_status status = io == yume::embed::BackendIo::Ok
                ? YUME_STATUS_INTERNAL_ERROR
                : status_from_backend(io);
            return fail_with_diagnostic(
                &endpoint->header, status,
                error.empty() ? "stream operation failed" : error);
        }
        auto published = std::make_unique<yume_stream>(std::move(opened));
        clear_diagnostic(&endpoint->header);
        *out_stream = published.release();
        return YUME_STATUS_OK;
    });
}

}  // namespace

yume_status yume_endpoint_open_stream(yume_endpoint* endpoint,
                                      const yume_open_options* options,
                                      uint32_t timeout_ms,
                                      yume_stream** out_stream) noexcept {
    if (out_stream) *out_stream = nullptr;
    if (!endpoint || !valid_header(&endpoint->header, HandleKind::Endpoint)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(&endpoint->header,
                                    YUME_STATUS_INVALID_STATE,
                                    "endpoint I/O is forbidden from callbacks");
    }
    if (!options || !out_stream) {
        return fail_with_diagnostic(&endpoint->header,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "open options and output handle are required");
    }
    return guard(&endpoint->header, [&]() -> yume_status {
        const yume_status status = validate_open_options(
            &endpoint->header, *options, YUME_SERVICE_BYTE_STREAM);
        if (status != YUME_STATUS_OK) return status;
        return backend_stream_io(
            endpoint, options->kind,
            std::string_view(options->service.data, options->service.size),
            timeout_ms, false, out_stream);
    });
}

yume_status yume_endpoint_accept_stream(yume_endpoint* endpoint,
                                        const yume_accept_options* options,
                                        uint32_t timeout_ms,
                                        yume_stream** out_stream) noexcept {
    if (out_stream) *out_stream = nullptr;
    if (!endpoint || !valid_header(&endpoint->header, HandleKind::Endpoint)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(&endpoint->header,
                                    YUME_STATUS_INVALID_STATE,
                                    "endpoint I/O is forbidden from callbacks");
    }
    if (!options || !out_stream) {
        return fail_with_diagnostic(&endpoint->header,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "accept options and output handle are required");
    }
    return guard(&endpoint->header, [&]() -> yume_status {
        const yume_status status = validate_accept_options(
            &endpoint->header, *options, YUME_SERVICE_BYTE_STREAM);
        if (status != YUME_STATUS_OK) return status;
        return backend_stream_io(
            endpoint, options->kind,
            std::string_view(options->service.data, options->service.size),
            timeout_ms, true, out_stream);
    });
}

yume_status yume_endpoint_open_packet(yume_endpoint* endpoint,
                                      const yume_open_options* options,
                                      uint32_t /*timeout_ms*/,
                                      yume_packet** out_packet) noexcept {
    if (out_packet) *out_packet = nullptr;
    if (!endpoint || !valid_header(&endpoint->header, HandleKind::Endpoint)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(&endpoint->header,
                                    YUME_STATUS_INVALID_STATE,
                                    "endpoint I/O is forbidden from callbacks");
    }
    if (!options || !out_packet) {
        return fail_with_diagnostic(&endpoint->header,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "open options and output handle are required");
    }
    return guard(&endpoint->header, [&]() -> yume_status {
        const yume_status status = validate_open_options(
            &endpoint->header, *options, YUME_SERVICE_PACKET);
        if (status != YUME_STATUS_OK) return status;
        return unavailable_endpoint_io(endpoint, options->kind);
    });
}

yume_status yume_endpoint_accept_packet(yume_endpoint* endpoint,
                                        const yume_accept_options* options,
                                        uint32_t /*timeout_ms*/,
                                        yume_packet** out_packet) noexcept {
    if (out_packet) *out_packet = nullptr;
    if (!endpoint || !valid_header(&endpoint->header, HandleKind::Endpoint)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(&endpoint->header,
                                    YUME_STATUS_INVALID_STATE,
                                    "endpoint I/O is forbidden from callbacks");
    }
    if (!options || !out_packet) {
        return fail_with_diagnostic(&endpoint->header,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "accept options and output handle are required");
    }
    return guard(&endpoint->header, [&]() -> yume_status {
        const yume_status status = validate_accept_options(
            &endpoint->header, *options, YUME_SERVICE_PACKET);
        if (status != YUME_STATUS_OK) return status;
        return unavailable_endpoint_io(endpoint, options->kind);
    });
}

void yume_endpoint_destroy(yume_endpoint* endpoint) noexcept {
    if (!endpoint || !valid_header(&endpoint->header, HandleKind::Endpoint)) {
        return;
    }
    if (g_in_callback) return;
    (void)yume_endpoint_stop(endpoint, YUME_TIMEOUT_INFINITE);
    delete endpoint;
}

yume_status yume_stream_get_peer_identity(const yume_stream* stream,
                                          yume_peer_identity* out,
                                          size_t out_size) noexcept {
    if (!stream || !valid_header(&stream->header, HandleKind::Stream)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(
            const_cast<HandleHeader*>(&stream->header),
            YUME_STATUS_INVALID_STATE,
            "stream identity queries are forbidden from callbacks");
    }
    auto* diagnostic_owner = const_cast<HandleHeader*>(&stream->header);
    if (!out) {
        return fail_with_diagnostic(diagnostic_owner,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "peer identity output is required");
    }
    return guard(diagnostic_owner, [&]() -> yume_status {
        std::lock_guard<std::mutex> lock(stream->mutex);
        const yume_status status = copy_sized(
            out, out_size, YUME_PEER_IDENTITY_MIN_SIZE, stream->peer,
            kPeerIdentityFields);
        if (status == YUME_STATUS_OK) {
            clear_diagnostic(diagnostic_owner);
        } else {
            set_diagnostic(diagnostic_owner, status, {},
                           status == YUME_STATUS_BUFFER_TOO_SMALL
                               ? "peer identity output is too small"
                               : "peer identity output layout is invalid");
        }
        return status;
    });
}

yume_status yume_stream_read(yume_stream* stream,
                             void* out,
                             size_t out_size,
                             size_t* bytes_read,
                             uint32_t timeout_ms) noexcept {
    if (bytes_read) *bytes_read = 0;
    if (!stream || !valid_header(&stream->header, HandleKind::Stream)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(&stream->header,
                                    YUME_STATUS_INVALID_STATE,
                                    "stream reads are forbidden from callbacks");
    }
    if (!bytes_read || !out || out_size == 0) {
        return fail_with_diagnostic(&stream->header,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "stream read requires nonempty output storage");
    }
    return guard(&stream->header, [&]() -> yume_status {
        std::lock_guard<std::mutex> lock(stream->mutex);
        if (stream->closed || !stream->backend) {
            return fail_with_diagnostic(&stream->header, YUME_STATUS_CLOSED,
                                        "stream is closed");
        }
        std::string error;
        std::size_t received = 0;
        const yume::embed::BackendIo io =
            stream->backend->read(out, out_size, timeout_ms, received, error);
        if (io == yume::embed::BackendIo::Ok) {
            *bytes_read = received;
            clear_diagnostic(&stream->header);
            return YUME_STATUS_OK;
        }
        if (io == yume::embed::BackendIo::Eof) {
            clear_diagnostic(&stream->header);
            return YUME_STATUS_EOF;
        }
        return fail_with_diagnostic(
            &stream->header, status_from_backend(io),
            error.empty() ? "stream read failed" : error);
    });
}

yume_status yume_stream_write(yume_stream* stream,
                              const void* data,
                              size_t size,
                              size_t* bytes_written,
                              uint32_t timeout_ms) noexcept {
    if (bytes_written) *bytes_written = 0;
    if (!stream || !valid_header(&stream->header, HandleKind::Stream)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(&stream->header,
                                    YUME_STATUS_INVALID_STATE,
                                    "stream writes are forbidden from callbacks");
    }
    if (!bytes_written || (size != 0 && !data)) {
        return fail_with_diagnostic(&stream->header,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "stream write input is invalid");
    }
    return guard(&stream->header, [&]() -> yume_status {
        std::lock_guard<std::mutex> lock(stream->mutex);
        if (stream->closed || !stream->backend) {
            return fail_with_diagnostic(&stream->header, YUME_STATUS_CLOSED,
                                        "stream is closed");
        }
        if (size == 0) {
            clear_diagnostic(&stream->header);
            return YUME_STATUS_OK;
        }
        std::string error;
        const yume::embed::BackendIo io =
            stream->backend->write(data, size, timeout_ms, error);
        if (io == yume::embed::BackendIo::Ok) {
            // Admission is all or none, so a successful write always consumed
            // the complete input.
            *bytes_written = size;
            clear_diagnostic(&stream->header);
            return YUME_STATUS_OK;
        }
        return fail_with_diagnostic(
            &stream->header, status_from_backend(io),
            error.empty() ? "stream write failed" : error);
    });
}

yume_status yume_stream_shutdown_write(yume_stream* stream,
                                       uint32_t timeout_ms) noexcept {
    if (!stream || !valid_header(&stream->header, HandleKind::Stream)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(&stream->header,
                                    YUME_STATUS_INVALID_STATE,
                                    "stream shutdown is forbidden from callbacks");
    }
    return guard(&stream->header, [&]() -> yume_status {
        std::lock_guard<std::mutex> lock(stream->mutex);
        if (stream->closed || !stream->backend) {
            return fail_with_diagnostic(&stream->header, YUME_STATUS_CLOSED,
                                        "stream is closed");
        }
        std::string error;
        const yume::embed::BackendIo io =
            stream->backend->shutdown_write(timeout_ms, error);
        if (io == yume::embed::BackendIo::Ok) {
            clear_diagnostic(&stream->header);
            return YUME_STATUS_OK;
        }
        return fail_with_diagnostic(
            &stream->header, status_from_backend(io),
            error.empty() ? "stream write shutdown failed" : error);
    });
}

yume_status yume_stream_close(yume_stream* stream,
                              uint32_t /*timeout_ms*/) noexcept {
    if (!stream || !valid_header(&stream->header, HandleKind::Stream)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(&stream->header,
                                    YUME_STATUS_INVALID_STATE,
                                    "stream close is forbidden from callbacks");
    }
    return guard(&stream->header, [&]() -> yume_status {
        std::lock_guard<std::mutex> lock(stream->mutex);
        // Close is the promised logical close, and it must happen here rather
        // than at destroy so a caller that closes and then inspects the handle
        // sees a settled stream. It is idempotent.
        if (!stream->closed && stream->backend) {
            stream->backend->close();
        }
        stream->closed = true;
        clear_diagnostic(&stream->header);
        return YUME_STATUS_OK;
    });
}

void yume_stream_destroy(yume_stream* stream) noexcept {
    if (!stream || !valid_header(&stream->header, HandleKind::Stream)) return;
    if (g_in_callback) return;
    delete stream;
}

yume_status yume_packet_get_peer_identity(const yume_packet* packet,
                                          yume_peer_identity* out,
                                          size_t out_size) noexcept {
    if (!packet || !valid_header(&packet->header, HandleKind::Packet)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(
            const_cast<HandleHeader*>(&packet->header),
            YUME_STATUS_INVALID_STATE,
            "packet identity queries are forbidden from callbacks");
    }
    auto* diagnostic_owner = const_cast<HandleHeader*>(&packet->header);
    if (!out) {
        return fail_with_diagnostic(diagnostic_owner,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "peer identity output is required");
    }
    return guard(diagnostic_owner, [&]() -> yume_status {
        std::lock_guard<std::mutex> lock(packet->mutex);
        const yume_status status = copy_sized(
            out, out_size, YUME_PEER_IDENTITY_MIN_SIZE, packet->peer,
            kPeerIdentityFields);
        if (status == YUME_STATUS_OK) {
            clear_diagnostic(diagnostic_owner);
        } else {
            set_diagnostic(diagnostic_owner, status, {},
                           status == YUME_STATUS_BUFFER_TOO_SMALL
                               ? "peer identity output is too small"
                               : "peer identity output layout is invalid");
        }
        return status;
    });
}

yume_status yume_packet_write_batch(yume_packet* packet,
                                    const yume_packet_view* packets,
                                    size_t packet_count,
                                    size_t* packets_written,
                                    uint32_t /*timeout_ms*/) noexcept {
    if (packets_written) *packets_written = 0;
    if (!packet || !valid_header(&packet->header, HandleKind::Packet)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(&packet->header,
                                    YUME_STATUS_INVALID_STATE,
                                    "packet writes are forbidden from callbacks");
    }
    if (!packets_written || packet_count == 0 || !packets) {
        return fail_with_diagnostic(&packet->header,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "packet batch and output count are required");
    }
    if (packet_count > kMaxPacketBatch) {
        return fail_with_diagnostic(&packet->header,
                                    YUME_STATUS_RESOURCE_EXHAUSTED,
                                    "packet batch count exceeds the ABI bound");
    }
    std::size_t total_bytes = 0;
    for (std::size_t index = 0; index < packet_count; ++index) {
        if (!packets[index].data || packets[index].size == 0 ||
            packets[index].size > kMaxPacketBytes) {
            return fail_with_diagnostic(&packet->header,
                                        YUME_STATUS_INVALID_ARGUMENT,
                                        "packet batch contains an invalid data view");
        }
        if (packets[index].size > kMaxPacketBatchBytes - total_bytes) {
            return fail_with_diagnostic(&packet->header,
                                        YUME_STATUS_RESOURCE_EXHAUSTED,
                                        "packet batch byte total exceeds the ABI bound");
        }
        total_bytes += packets[index].size;
    }
    return guard(&packet->header, [&]() -> yume_status {
        std::lock_guard<std::mutex> lock(packet->mutex);
        return fail_with_diagnostic(
            &packet->header,
            packet->closed ? YUME_STATUS_CLOSED : YUME_STATUS_UNSUPPORTED,
            packet->closed ? "packet channel is closed"
                           : "packet provider is not linked");
    });
}

yume_status yume_packet_read_batch(yume_packet* packet,
                                   void* storage,
                                   size_t storage_size,
                                   yume_packet_slot* slots,
                                   size_t slot_count,
                                   size_t* packets_read,
                                   size_t* required_storage,
                                   uint32_t /*timeout_ms*/) noexcept {
    if (packets_read) *packets_read = 0;
    if (required_storage) *required_storage = 0;
    if (!packet || !valid_header(&packet->header, HandleKind::Packet)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(&packet->header,
                                    YUME_STATUS_INVALID_STATE,
                                    "packet reads are forbidden from callbacks");
    }
    if (!packets_read || !required_storage || slot_count == 0 || !slots ||
        (storage_size != 0 && !storage)) {
        return fail_with_diagnostic(&packet->header,
                                    YUME_STATUS_INVALID_ARGUMENT,
                                    "packet read buffers and output counts are required");
    }
    if (slot_count > kMaxPacketBatch ||
        storage_size > kMaxPacketBatchBytes) {
        return fail_with_diagnostic(&packet->header,
                                    YUME_STATUS_RESOURCE_EXHAUSTED,
                                    "packet read buffers exceed ABI bounds");
    }
    return guard(&packet->header, [&]() -> yume_status {
        std::lock_guard<std::mutex> lock(packet->mutex);
        return fail_with_diagnostic(
            &packet->header,
            packet->closed ? YUME_STATUS_CLOSED : YUME_STATUS_UNSUPPORTED,
            packet->closed ? "packet channel is closed"
                           : "packet provider is not linked");
    });
}

yume_status yume_packet_close(yume_packet* packet,
                              uint32_t /*timeout_ms*/) noexcept {
    if (!packet || !valid_header(&packet->header, HandleKind::Packet)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (g_in_callback) {
        return fail_with_diagnostic(&packet->header,
                                    YUME_STATUS_INVALID_STATE,
                                    "packet close is forbidden from callbacks");
    }
    return guard(&packet->header, [&]() -> yume_status {
        std::lock_guard<std::mutex> lock(packet->mutex);
        packet->closed = true;
        clear_diagnostic(&packet->header);
        return YUME_STATUS_OK;
    });
}

void yume_packet_destroy(yume_packet* packet) noexcept {
    if (!packet || !valid_header(&packet->header, HandleKind::Packet)) return;
    if (g_in_callback) return;
    delete packet;
}

yume_status yume_handle_get_diagnostic(const void* handle,
                                       yume_diagnostic* out,
                                       size_t out_size) noexcept {
    if (!handle || !out) return YUME_STATUS_INVALID_ARGUMENT;
    const auto* header = static_cast<const HandleHeader*>(handle);
    if (!valid_any_header(header)) return YUME_STATUS_INVALID_ARGUMENT;
    DiagnosticData diagnostic;
    try {
        std::lock_guard<std::mutex> lock(header->diagnostic_mutex);
        diagnostic = header->diagnostic;
    } catch (...) {
        return YUME_STATUS_INTERNAL_ERROR;
    }
    yume_diagnostic value{};
    value.struct_size = sizeof(value);
    value.abi_version = YUME_ABI_VERSION;
    value.status = diagnostic.status;
    value.flags = diagnostic.flags;
    copy_text(value.json_pointer, sizeof(value.json_pointer),
              diagnostic.json_pointer.data());
    copy_text(value.message, sizeof(value.message), diagnostic.message.data());
    return copy_sized(out, out_size, YUME_DIAGNOSTIC_MIN_SIZE, value,
                      kDiagnosticFields);
}

}  // extern "C"
