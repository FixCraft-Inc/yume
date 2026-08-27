/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "yume/yume.h"

#include "abi/service_open_wait.hpp"
#include "abi/service_status.hpp"
#include "client/packet/channel.hpp"
#include "client/relay/secret.hpp"
#include "client/transport/tunnel.hpp"
#include "core/runtime/service_stream.hpp"
#include "core/runtime/operation_status.hpp"
#include "core/security/crypto.hpp"
#include "core/security/inner_crypto.hpp"
#include "core/security/secure_erase.hpp"
#include "core/version.hpp"
#include "facade/config/config_io.hpp"
#include "facade/session/inproc_client.hpp"
#if !defined(YUME_ABI_CLIENT_ONLY) || !YUME_ABI_CLIENT_ONLY
#include "server/runtime/controller.hpp"
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include <nlohmann/json.hpp>

namespace {

constexpr std::size_t kRequestReplayKeyBytes = 32;
constexpr std::size_t kMaxRequestOperationBytes = 128;
constexpr std::size_t kMaxRequestArgsJsonBytes = 1024U * 1024U;
constexpr std::string_view kRequestReplayDomain =
    "yume-abi-request-replay-v1";

using RequestReplayKey = yume::crypto::Bytes;

class RequestReplayKeyWiper {
public:
    explicit RequestReplayKeyWiper(RequestReplayKey& key) noexcept
        : key_(key) {}
    RequestReplayKeyWiper(const RequestReplayKeyWiper&) = delete;
    RequestReplayKeyWiper& operator=(const RequestReplayKeyWiper&) = delete;
    ~RequestReplayKeyWiper() { yume::security::secure_erase(key_); }

private:
    RequestReplayKey& key_;
};

// A request sizing call has already executed the operation. Retaining exactly
// one serialized response lets its immediate retry deliver that result without
// repeating a mutation. The request itself is represented only by a fixed-size
// digest; no plaintext argument JSON is retained here.
struct RequestReplayCache {
    std::mutex mutex;
    RequestReplayKey key;
    std::string response;
    bool valid{false};

    RequestReplayCache() = default;
    RequestReplayCache(const RequestReplayCache&) = delete;
    RequestReplayCache& operator=(const RequestReplayCache&) = delete;

    ~RequestReplayCache() { clear(); }

    bool matches(const RequestReplayKey& candidate) const noexcept {
        return valid && key.size() == kRequestReplayKeyBytes &&
               candidate.size() == kRequestReplayKeyBytes && key == candidate;
    }

    void clear() noexcept {
        valid = false;
        yume::security::secure_erase(key);
        yume::client::wipe_relay_secret(response);
    }

    void replace(RequestReplayKey& candidate,
                 std::string& completed_response) noexcept {
        clear();
        key.swap(candidate);
        response.swap(completed_response);
        valid = true;
    }
};

struct HandleBase {
    mutable std::mutex error_mu;
    std::string last_error;
};

thread_local std::string abi_last_error;

int set_abi_error(int status, std::string_view message) noexcept {
    try {
        abi_last_error.assign(message);
    } catch (...) {
        // Never let allocation failure cross the C boundary. The status still
        // carries the failure even if the optional detail cannot be retained.
        abi_last_error.clear();
    }
    return status;
}

void clear_abi_error() noexcept {
    abi_last_error.clear();
}

int set_error(HandleBase* handle,
              int status,
              std::string_view message) noexcept {
    if (!handle) {
        return status;
    }
    try {
        std::lock_guard<std::mutex> lock(handle->error_mu);
        handle->last_error.assign(message);
    } catch (...) {
        // Error reporting is frequently called from an exception handler.
        // Allocation or locking failure here must never replace the original
        // status with an exception crossing the C boundary.
        try {
            std::lock_guard<std::mutex> lock(handle->error_mu);
            handle->last_error.clear();
        } catch (...) {
        }
    }
    return status;
}

int clear_error(HandleBase* handle) noexcept {
    try {
        if (!handle) {
            return YUME_STATUS_OK;
        }
        std::lock_guard<std::mutex> lock(handle->error_mu);
        handle->last_error.clear();
    } catch (...) {
        // Clearing an optional diagnostic must not make an otherwise
        // successful C call throw.
    }
    return YUME_STATUS_OK;
}

static_assert(noexcept(set_error(nullptr, 0, std::string_view{})));
static_assert(noexcept(clear_error(nullptr)));

bool bounded_c_string_length(const char* value,
                             std::size_t maximum,
                             std::size_t* length) noexcept {
    if (!value || !length) return false;
    for (std::size_t index = 0;; ++index) {
        if (value[index] == '\0') {
            *length = index;
            return true;
        }
        // Index maximum is the terminator slot for a maximum-length payload.
        // Stop after inspecting it so even a future SIZE_MAX bound cannot
        // wrap index.
        if (index == maximum) return false;
    }
}

int parse_request_operation(HandleBase* handle,
                            const char* operation,
                            std::string* parsed) noexcept {
    if (!operation || !parsed) {
        return set_error(handle, YUME_STATUS_INVALID_ARGUMENT,
                         "request operation is null");
    }
    std::size_t length = 0;
    if (!bounded_c_string_length(
            operation, kMaxRequestOperationBytes, &length)) {
        return set_error(handle, YUME_STATUS_RESOURCE_EXHAUSTED,
                         "request operation exceeds 128 bytes");
    }
    if (length == 0U) {
        return set_error(handle, YUME_STATUS_INVALID_ARGUMENT,
                         "request operation is empty");
    }
    try {
        parsed->assign(operation, length);
        return YUME_STATUS_OK;
    } catch (const std::bad_alloc&) {
        return set_error(handle, YUME_STATUS_RESOURCE_EXHAUSTED,
                         "request operation allocation failed");
    } catch (const std::exception& ex) {
        return set_error(handle, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(handle, YUME_STATUS_INTERNAL_ERROR,
                         "unknown request operation error");
    }
}

int parse_request_args(HandleBase* handle,
                       const char* args_json,
                       nlohmann::json* args) noexcept {
    if (!args) {
        return set_error(handle, YUME_STATUS_INTERNAL_ERROR,
                         "request argument output is unavailable");
    }
    try {
        *args = nlohmann::json::object();
        if (args_json) {
            std::size_t length = 0;
            if (!bounded_c_string_length(
                    args_json, kMaxRequestArgsJsonBytes, &length)) {
                return set_error(
                    handle, YUME_STATUS_RESOURCE_EXHAUSTED,
                    "args_json exceeds the 1 MiB request limit");
            }
            if (length != 0U) {
                *args = nlohmann::json::parse(
                    args_json, args_json + length);
            }
        }
        if (!args->is_object()) {
            return set_error(handle, YUME_STATUS_INVALID_ARGUMENT,
                             "args_json must encode a JSON object");
        }
        return YUME_STATUS_OK;
    } catch (const nlohmann::json::parse_error& ex) {
        return set_error(handle, YUME_STATUS_PARSE_ERROR, ex.what());
    } catch (const nlohmann::json::out_of_range& ex) {
        // A syntactically valid numeric token that cannot be represented by
        // nlohmann::json is still caller-controlled JSON parse input, not an
        // internal runtime failure.
        return set_error(handle, YUME_STATUS_PARSE_ERROR, ex.what());
    } catch (const std::bad_alloc&) {
        return set_error(handle, YUME_STATUS_RESOURCE_EXHAUSTED,
                         "request argument allocation failed");
    } catch (const std::exception& ex) {
        return set_error(handle, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(handle, YUME_STATUS_INTERNAL_ERROR,
                         "unknown request argument error");
    }
}

void update_request_replay_digest(yume::crypto::Sha256Stream& digest,
                                  std::string_view field) {
    static_assert(sizeof(std::size_t) <= sizeof(std::uint64_t));
    std::array<std::uint8_t, sizeof(std::uint64_t)> encoded_size{};
    std::uint64_t size = static_cast<std::uint64_t>(field.size());
    for (std::size_t i = 0; i < encoded_size.size(); ++i) {
        encoded_size[encoded_size.size() - i - 1] =
            static_cast<std::uint8_t>(size & 0xffU);
        size >>= 8U;
    }
    digest.Update(encoded_size);
    if (!field.empty()) {
        digest.Update(std::span<const std::uint8_t>(
            reinterpret_cast<const std::uint8_t*>(field.data()),
            field.size()));
    }
}

RequestReplayKey make_request_replay_key(std::string_view op,
                                         const nlohmann::json& args) {
    std::string canonical_args = args.dump();
    yume::client::RelaySecretWiper canonical_args_wiper(canonical_args);

    yume::crypto::Sha256Stream digest;
    update_request_replay_digest(digest, kRequestReplayDomain);
    update_request_replay_digest(digest, op);
    update_request_replay_digest(digest, canonical_args);
    auto key = digest.Finish();
    if (key.size() != kRequestReplayKeyBytes) {
        yume::security::secure_erase(key);
        throw std::runtime_error("unexpected request replay digest size");
    }
    return key;
}

std::size_t request_response_size(const std::string& response) {
    if (response.size() == std::numeric_limits<std::size_t>::max()) {
        throw std::length_error("request response is too large");
    }
    return response.size() + 1;
}

int copy_cached_request_response(HandleBase* handle,
                                 RequestReplayCache* cache,
                                 char* out,
                                 std::size_t out_size,
                                 std::size_t* needed) {
    const std::size_t required = request_response_size(cache->response);
    if (needed) {
        *needed = required;
    }
    if (!out || out_size < required) {
        return set_error(handle,
                         YUME_STATUS_BUFFER_TOO_SMALL,
                         "output buffer is too small");
    }
    std::memcpy(out, cache->response.c_str(), required);
    cache->clear();
    return clear_error(handle);
}

int write_completed_request_response(HandleBase* handle,
                                     RequestReplayCache* cache,
                                     RequestReplayKey* key,
                                     const nlohmann::json& response,
                                     char* out,
                                     std::size_t out_size,
                                     std::size_t* needed) {
    std::string text = response.dump();
    yume::client::RelaySecretWiper text_wiper(text);
    const std::size_t required = request_response_size(text);
    if (needed) {
        *needed = required;
    }
    if (!out || out_size < required) {
        cache->replace(*key, text);
        return set_error(handle,
                         YUME_STATUS_BUFFER_TOO_SMALL,
                         "output buffer is too small");
    }
    std::memcpy(out, text.c_str(), required);
    cache->clear();
    return clear_error(handle);
}

template <typename T>
void write_complete_abi_field(void* out,
                              std::size_t out_size,
                              std::size_t offset,
                              const T& value) noexcept {
    if (offset <= out_size && sizeof(T) <= out_size - offset) {
        std::memcpy(static_cast<unsigned char*>(out) + offset,
                    &value,
                    sizeof(T));
    }
}

std::string basefwx_version_string() {
    return std::string(yume::kBasefwxVersion);
}

std::string pq_backend_string() {
    return yume::inner::pq_backend_version();
}

std::string argon2_backend_string() {
    return yume::inner::argon2_backend_version();
}

std::filesystem::path abi_base_dir(const char* base_dir) {
    if (base_dir && *base_dir) {
        return std::filesystem::path(base_dir);
    }
    std::error_code ec;
    auto cwd = std::filesystem::current_path(ec);
    return ec ? std::filesystem::path{} : cwd;
}

std::chrono::milliseconds start_timeout(uint32_t timeout_ms) {
    return std::chrono::milliseconds{timeout_ms};
}

int timeout_as_int(uint32_t timeout_ms) {
    return static_cast<int>(std::min<std::uint32_t>(
        timeout_ms,
        static_cast<std::uint32_t>(std::numeric_limits<int>::max())));
}

std::int64_t unix_ms(std::chrono::system_clock::time_point tp) {
    if (tp == std::chrono::system_clock::time_point{}) {
        return 0;
    }
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        tp.time_since_epoch()).count();
}

int write_json_buffer(HandleBase* handle,
                      nlohmann::json const& json,
                      char* out,
                      std::size_t out_size,
                      std::size_t* needed) {
    const std::string text = json.dump();
    const std::size_t required = text.size() + 1;
    if (needed) {
        *needed = required;
    }
    if (!out || out_size < required) {
        return set_error(handle,
                         YUME_STATUS_BUFFER_TOO_SMALL,
                         "output buffer is too small");
    }
    std::memcpy(out, text.c_str(), required);
    return clear_error(handle);
}

bool valid_service_name(std::string_view service) {
    if (service.empty() || service.size() > 128) {
        return false;
    }
    return std::all_of(service.begin(), service.end(), [](unsigned char ch) {
        return (ch >= 'a' && ch <= 'z') ||
               (ch >= 'A' && ch <= 'Z') ||
               (ch >= '0' && ch <= '9') ||
               ch == '-' || ch == '_' || ch == '.' || ch == ':';
    });
}

int status_from_packet_result(yume::client::packet::QueueResult result) {
    using Result = yume::client::packet::QueueResult;
    switch (result) {
    case Result::ok: return YUME_STATUS_OK;
    case Result::would_block: return YUME_STATUS_WOULD_BLOCK;
    case Result::timeout: return YUME_STATUS_TIMEOUT;
    case Result::stopped: return YUME_STATUS_NOT_RUNNING;
    case Result::buffer_too_small: return YUME_STATUS_BUFFER_TOO_SMALL;
    case Result::invalid: return YUME_STATUS_INVALID_ARGUMENT;
    }
    return YUME_STATUS_INTERNAL_ERROR;
}

int status_from_config_load_error(
    yume::facade::config_io::ConfigLoadError error) {
    using Error = yume::facade::config_io::ConfigLoadError;
    switch (error) {
    case Error::NotFound: return YUME_STATUS_NOT_FOUND;
    case Error::PermissionDenied: return YUME_STATUS_PERMISSION_DENIED;
    case Error::Parse: return YUME_STATUS_PARSE_ERROR;
    case Error::Io:
    case Error::None:
        return YUME_STATUS_INTERNAL_ERROR;
    }
    return YUME_STATUS_INTERNAL_ERROR;
}

int status_from_operation_status(yume::runtime::OperationStatus status) {
    using Status = yume::runtime::OperationStatus;
    switch (status) {
    case Status::Success: return YUME_STATUS_OK;
    case Status::InvalidArgument: return YUME_STATUS_INVALID_ARGUMENT;
    case Status::NotRunning: return YUME_STATUS_NOT_RUNNING;
    case Status::AlreadyRunning: return YUME_STATUS_ALREADY_RUNNING;
    case Status::Timeout: return YUME_STATUS_TIMEOUT;
    case Status::NotFound: return YUME_STATUS_NOT_FOUND;
    case Status::PermissionDenied: return YUME_STATUS_PERMISSION_DENIED;
    case Status::WouldBlock: return YUME_STATUS_WOULD_BLOCK;
    case Status::ResourceExhausted:
        return YUME_STATUS_RESOURCE_EXHAUSTED;
    case Status::ParseError: return YUME_STATUS_PARSE_ERROR;
    case Status::InternalError: return YUME_STATUS_INTERNAL_ERROR;
    }
    return YUME_STATUS_INTERNAL_ERROR;
}

int status_from_packet_open_result(
    yume::client::packet::OpenStatus status) {
    using Status = yume::client::packet::OpenStatus;
    switch (status) {
    case Status::success: return YUME_STATUS_OK;
    case Status::invalid_argument: return YUME_STATUS_INVALID_ARGUMENT;
    case Status::not_running: return YUME_STATUS_NOT_RUNNING;
    case Status::capability_unavailable:
    case Status::peer_rejected:
        return YUME_STATUS_PERMISSION_DENIED;
    case Status::timeout: return YUME_STATUS_TIMEOUT;
    case Status::resource_exhausted:
        return YUME_STATUS_RESOURCE_EXHAUSTED;
    case Status::protocol_error: return YUME_STATUS_PARSE_ERROR;
    }
    return YUME_STATUS_INTERNAL_ERROR;
}

std::string validation_error(yume::facade::config_io::ValidationReport const& report) {
    std::string out;
    for (const auto& error : report.errors) {
        if (!out.empty()) {
            out += "; ";
        }
        out += error;
    }
    return out;
}

}  // namespace

struct yume_client {
    HandleBase base{};
    RequestReplayCache request_replay{};
    std::mutex mu;
    yume::facade::InProcClient runtime;
    yume_socket_protect_fn socket_protect{nullptr};
    void* socket_protect_user_data{nullptr};
    bool start_in_progress{false};
    std::shared_ptr<std::atomic<bool>> start_cancel_requested;
};

namespace {

class ClientStartGuard {
public:
    ClientStartGuard(
        yume_client* client,
        std::shared_ptr<std::atomic<bool>> cancel_requested) noexcept
        : client_(client), cancel_requested_(std::move(cancel_requested)) {}

    ClientStartGuard(const ClientStartGuard&) = delete;
    ClientStartGuard& operator=(const ClientStartGuard&) = delete;

    ~ClientStartGuard() noexcept {
        try {
            std::lock_guard<std::mutex> lock(client_->mu);
            if (client_->start_cancel_requested == cancel_requested_) {
                client_->start_cancel_requested.reset();
                client_->start_in_progress = false;
            }
        } catch (...) {
            // The ABI requires callers to keep the handle alive while an
            // operation is in flight. Clearing this admission flag must not
            // let an exception cross the C boundary during cleanup.
        }
    }

private:
    yume_client* client_;
    std::shared_ptr<std::atomic<bool>> cancel_requested_;
};

}  // namespace

struct yume_server {
    HandleBase base{};
    RequestReplayCache request_replay{};
    std::mutex mu;
#if !defined(YUME_ABI_CLIENT_ONLY) || !YUME_ABI_CLIENT_ONLY
    yume::server::RuntimeController runtime;
#endif
};

struct yume_stream {
    explicit yume_stream(std::shared_ptr<yume::runtime::ServiceStream> stream_in)
        : stream(std::move(stream_in)) {}

    ~yume_stream() noexcept {
        try {
            if (stream) {
                stream->close("stream destroyed");
            }
        } catch (...) {
            // Destruction is a C ABI operation. Cleanup is best-effort and
            // must not terminate the caller if the transport close path fails.
        }
    }

    HandleBase base{};
    std::shared_ptr<yume::runtime::ServiceStream> stream;
};

struct yume_packet {
    explicit yume_packet(
        std::shared_ptr<yume::client::packet::PacketChannel> channel_in)
        : channel(std::move(channel_in)) {}

    ~yume_packet() noexcept {
        try {
            if (channel) channel->close("ABI packet destroyed");
        } catch (...) {
            // See yume_stream: destroy functions cannot report a status and
            // are required to stay inside the C exception boundary.
        }
    }

    HandleBase base{};
    std::mutex mu;
    std::shared_ptr<yume::client::packet::PacketChannel> channel;
};

// yume_handle_last_error receives an opaque handle pointer and relies on the
// common HandleBase being pointer-interconvertible with every public handle.
// Keep this invariant compile-time enforced as handle implementations evolve.
static_assert(std::is_standard_layout_v<yume_client>);
static_assert(std::is_standard_layout_v<yume_server>);
static_assert(std::is_standard_layout_v<yume_stream>);
static_assert(std::is_standard_layout_v<yume_packet>);
static_assert(offsetof(yume_client, base) == 0);
static_assert(offsetof(yume_server, base) == 0);
static_assert(offsetof(yume_stream, base) == 0);
static_assert(offsetof(yume_packet, base) == 0);

extern "C" {

uint32_t yume_abi_version(void) {
    return YUME_ABI_VERSION;
}

const char* yume_version(void) {
    return yume::kVersion;
}

uint32_t yume_feature_flags(void) {
    uint32_t flags = YUME_FEATURE_PBKDF2_HKDF | YUME_FEATURE_PACKET_BULK;
#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
    flags |= YUME_FEATURE_BASEFWX;
#endif
    try {
        if (yume::inner::pq_supported()) {
            flags |= YUME_FEATURE_PQ_MLKEM768;
            flags |= YUME_FEATURE_PQ_MLKEM1024;
        }
        if (yume::inner::argon2_supported()) {
            flags |= YUME_FEATURE_ARGON2ID;
        }
    } catch (...) {
        return flags;
    }
    return flags;
}

const char* yume_basefwx_version(void) {
    try {
        static const std::string value = basefwx_version_string();
        return value.c_str();
    } catch (...) {
        return "unknown";
    }
}

const char* yume_pq_backend(void) {
    try {
        static const std::string value = pq_backend_string();
        return value.c_str();
    } catch (...) {
        return "unavailable";
    }
}

const char* yume_argon2_backend(void) {
    try {
        static const std::string value = argon2_backend_string();
        return value.c_str();
    } catch (...) {
        return "unavailable";
    }
}

int yume_get_build_info(yume_build_info* out, size_t out_size) {
    if (!out) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (out_size < YUME_BUILD_INFO_MIN_SIZE) {
        return YUME_STATUS_BUFFER_TOO_SMALL;
    }

    try {
        const yume_build_info value{
            sizeof(yume_build_info),
            yume_abi_version(),
            yume_feature_flags(),
            yume_version(),
            yume_basefwx_version(),
            yume_pq_backend(),
            yume_argon2_backend(),
        };
        write_complete_abi_field(
            out, out_size, offsetof(yume_build_info, struct_size),
            value.struct_size);
        write_complete_abi_field(
            out, out_size, offsetof(yume_build_info, abi_version),
            value.abi_version);
        write_complete_abi_field(
            out, out_size, offsetof(yume_build_info, feature_flags),
            value.feature_flags);
        write_complete_abi_field(
            out, out_size, offsetof(yume_build_info, yume_version),
            value.yume_version);
        write_complete_abi_field(
            out, out_size, offsetof(yume_build_info, basefwx_version),
            value.basefwx_version);
        write_complete_abi_field(
            out, out_size, offsetof(yume_build_info, pq_backend),
            value.pq_backend);
        write_complete_abi_field(
            out, out_size, offsetof(yume_build_info, argon2_backend),
            value.argon2_backend);
        return YUME_STATUS_OK;
    } catch (...) {
        return YUME_STATUS_INTERNAL_ERROR;
    }
}

const char* yume_strerror(int status) {
    switch (status) {
    case YUME_STATUS_OK: return "ok";
    case YUME_STATUS_INVALID_ARGUMENT: return "invalid argument";
    case YUME_STATUS_BUFFER_TOO_SMALL: return "buffer too small";
    case YUME_STATUS_INTERNAL_ERROR: return "internal error";
    case YUME_STATUS_NOT_RUNNING: return "not running";
    case YUME_STATUS_ALREADY_RUNNING: return "already running";
    case YUME_STATUS_TIMEOUT: return "timeout";
    case YUME_STATUS_NOT_FOUND: return "not found";
    case YUME_STATUS_PERMISSION_DENIED: return "permission denied";
    case YUME_STATUS_PARSE_ERROR: return "parse error";
    case YUME_STATUS_WOULD_BLOCK: return "would block";
    case YUME_STATUS_RESOURCE_EXHAUSTED: return "resource exhausted";
    default: return "unknown status";
    }
}

int yume_generate_pq_keypair(const char* private_path,
                             const char* public_path) {
    if (!private_path || !*private_path || !public_path || !*public_path) {
        return set_abi_error(
            YUME_STATUS_INVALID_ARGUMENT,
            "private_path and public_path must both be non-empty");
    }
    try {
        std::string error;
        if (!yume::inner::generate_pq_keypair(private_path, public_path, &error)) {
            return set_abi_error(
                YUME_STATUS_INTERNAL_ERROR,
                error.empty() ? std::string_view("PQ keypair generation failed")
                              : std::string_view(error));
        }
        clear_abi_error();
        return YUME_STATUS_OK;
    } catch (std::exception const& ex) {
        return set_abi_error(YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_abi_error(
            YUME_STATUS_INTERNAL_ERROR, "unknown PQ keypair generation error");
    }
}

const char* yume_last_error(void) {
    return abi_last_error.c_str();
}

yume_client* yume_client_create(void) {
    try {
        return new yume_client();
    } catch (...) {
        return nullptr;
    }
}

void yume_client_destroy(yume_client* client) {
    delete client;
}

int yume_client_set_socket_protector(yume_client* client,
                                     yume_socket_protect_fn callback,
                                     void* user_data) {
    if (!client) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    try {
        std::lock_guard<std::mutex> lock(client->mu);
        if (client->start_in_progress || client->runtime.status().running) {
            return set_error(&client->base, YUME_STATUS_ALREADY_RUNNING,
                             "socket protector must be configured before start");
        }
        client->socket_protect = callback;
        client->socket_protect_user_data = user_data;
        return clear_error(&client->base);
    } catch (std::exception const& ex) {
        return set_error(&client->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&client->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_client_start_json(yume_client* client,
                           const char* config_json,
                           const char* base_dir,
                           uint32_t timeout_ms) {
    if (!client || !config_json) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    try {
        auto start_cancel_requested =
            std::make_shared<std::atomic<bool>>(false);
        yume_socket_protect_fn callback = nullptr;
        void* user_data = nullptr;
        {
            std::lock_guard<std::mutex> lock(client->mu);
            const bool start_in_progress = client->start_in_progress;
            if (start_in_progress || client->runtime.running()) {
                return set_error(&client->base,
                                 YUME_STATUS_ALREADY_RUNNING,
                                 start_in_progress
                                     ? "client start is already in progress"
                                     : "client is already running");
            }
            client->start_in_progress = true;
            client->start_cancel_requested = start_cancel_requested;
            callback = client->socket_protect;
            user_data = client->socket_protect_user_data;
        }
        ClientStartGuard start_guard(client, start_cancel_requested);

        std::string parse_error;
        auto cfg = yume::facade::config_io::parse_client_json(
            config_json,
            abi_base_dir(base_dir),
            &parse_error);
        if (!cfg) {
            return set_error(&client->base, YUME_STATUS_PARSE_ERROR, parse_error);
        }
        auto validation = yume::facade::config_io::validate(*cfg);
        if (!validation.ok()) {
            return set_error(&client->base,
                             YUME_STATUS_INVALID_ARGUMENT,
                             validation_error(validation));
        }
        if (callback) {
            cfg->socket_protect = [callback, user_data](std::intptr_t handle) {
                return callback(handle, user_data) != 0;
            };
        }
        std::string error;
        yume::runtime::OperationStatus operation_status{};
        if (!client->runtime.start(std::move(*cfg), &error,
                                   start_timeout(timeout_ms),
                                   &operation_status,
                                   start_cancel_requested)) {
            return set_error(&client->base,
                             status_from_operation_status(operation_status),
                             error);
        }
        return clear_error(&client->base);
    } catch (std::exception const& ex) {
        return set_error(&client->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&client->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_client_start_file(yume_client* client,
                           const char* config_path,
                           uint32_t timeout_ms) {
    if (!client || !config_path || !*config_path) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    try {
        auto start_cancel_requested =
            std::make_shared<std::atomic<bool>>(false);
        yume_socket_protect_fn callback = nullptr;
        void* user_data = nullptr;
        {
            std::lock_guard<std::mutex> lock(client->mu);
            const bool start_in_progress = client->start_in_progress;
            if (start_in_progress || client->runtime.running()) {
                return set_error(&client->base,
                                 YUME_STATUS_ALREADY_RUNNING,
                                 start_in_progress
                                     ? "client start is already in progress"
                                     : "client is already running");
            }
            client->start_in_progress = true;
            client->start_cancel_requested = start_cancel_requested;
            callback = client->socket_protect;
            user_data = client->socket_protect_user_data;
        }
        ClientStartGuard start_guard(client, start_cancel_requested);

        std::string error;
        yume::facade::config_io::ConfigLoadError load_error{};
        auto cfg = yume::facade::config_io::load_client(
            config_path, &error, &load_error);
        if (!cfg) {
            return set_error(&client->base,
                             status_from_config_load_error(load_error),
                             error);
        }
        auto validation = yume::facade::config_io::validate(*cfg);
        if (!validation.ok()) {
            return set_error(&client->base,
                             YUME_STATUS_INVALID_ARGUMENT,
                             validation_error(validation));
        }
        if (callback) {
            cfg->socket_protect = [callback, user_data](std::intptr_t handle) {
                return callback(handle, user_data) != 0;
            };
        }
        yume::runtime::OperationStatus operation_status{};
        if (!client->runtime.start(std::move(*cfg), &error,
                                   start_timeout(timeout_ms),
                                   &operation_status,
                                   start_cancel_requested)) {
            return set_error(&client->base,
                             status_from_operation_status(operation_status),
                             error);
        }
        return clear_error(&client->base);
    } catch (std::exception const& ex) {
        return set_error(&client->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&client->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_client_stop(yume_client* client) {
    if (!client) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    try {
        std::shared_ptr<std::atomic<bool>> start_cancel_requested;
        {
            std::lock_guard<std::mutex> lock(client->mu);
            start_cancel_requested = client->start_cancel_requested;
        }
        if (start_cancel_requested) {
            start_cancel_requested->store(true, std::memory_order_release);
        }
        std::string error;
        client->runtime.stop(&error, "ABI client stop");
        if (!error.empty()) {
            return set_error(&client->base, YUME_STATUS_INTERNAL_ERROR, error);
        }
        return clear_error(&client->base);
    } catch (std::exception const& ex) {
        return set_error(&client->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&client->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_client_status_json(yume_client* client,
                            char* out,
                            size_t out_size,
                            size_t* needed) {
    if (!client) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    try {
        const auto status = client->runtime.status();
        const auto& server_capabilities = status.server_capabilities;
        const bool packet_bulk_supported =
            (yume_feature_flags() & YUME_FEATURE_PACKET_BULK) != 0 &&
            yume::client::packet::has_packet_bulk_capability(
                server_capabilities);
        nlohmann::json json = {
            {"running", status.running},
            {"ready", status.ipc_available},
            {"message", status.message},
            {"socket_path", status.socket_path},
            {"exit_code", status.exit_code},
            {"server_tls_fingerprint_sha256", status.server_tls_fingerprint_sha256},
            {"started_unix_ms", unix_ms(status.started)},
            {"server_capabilities", server_capabilities},
            {"packet_bulk_supported", packet_bulk_supported}
        };
        return write_json_buffer(&client->base, json, out, out_size, needed);
    } catch (std::exception const& ex) {
        return set_error(&client->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&client->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_client_request_json(yume_client* client,
                             const char* op,
                             const char* args_json,
                             char* out,
                             size_t out_size,
                             size_t* needed,
                             uint32_t timeout_ms) {
    if (!client || !op) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    try {
        std::lock_guard<std::mutex> request_lock(
            client->request_replay.mutex);
        std::string operation;
        const int operation_parse_status =
            parse_request_operation(&client->base, op, &operation);
        if (operation_parse_status != YUME_STATUS_OK) {
            return operation_parse_status;
        }
        nlohmann::json args;
        const int args_status =
            parse_request_args(&client->base, args_json, &args);
        if (args_status != YUME_STATUS_OK) {
            return args_status;
        }
        yume::client::RelayRequestSecretsWiper args_wiper(args);
        auto request_key = make_request_replay_key(operation, args);
        RequestReplayKeyWiper request_key_wiper(request_key);
        if (client->request_replay.matches(request_key)) {
            return copy_cached_request_response(
                &client->base, &client->request_replay,
                out, out_size, needed);
        }
        client->request_replay.clear();

        std::string error;
        yume::runtime::OperationStatus operation_status{};
        auto response = client->runtime.request(
            operation, args, &error, timeout_as_int(timeout_ms),
            &operation_status);
        if (operation_status != yume::runtime::OperationStatus::Success) {
            return set_error(&client->base,
                             status_from_operation_status(operation_status),
                             error.empty() ? "client request failed" : error);
        }
        return write_completed_request_response(
            &client->base, &client->request_replay, &request_key,
            response, out, out_size, needed);
    } catch (std::exception const& ex) {
        return set_error(&client->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&client->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_client_open_stream(yume_client* client,
                            const char* service,
                            uint32_t timeout_ms,
                            yume_stream** out_stream) {
    if (!client || !service || !out_stream) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    *out_stream = nullptr;
    if (!valid_service_name(service)) {
        return set_error(&client->base,
                         YUME_STATUS_INVALID_ARGUMENT,
                         "invalid service name");
    }
    if (timeout_ms == 0) {
        return set_error(&client->base,
                         YUME_STATUS_WOULD_BLOCK,
                         "stream OPEN requires a positive deadline");
    }

    try {
        const std::string service_name(service);
        auto runtime_access = client->runtime.acquire_runtime();
        if (!runtime_access) {
            return set_error(&client->base,
                             YUME_STATUS_NOT_RUNNING,
                             "client runtime is not running");
        }
        const auto lifetime_gate = runtime_access->gate();
        auto tunnel = runtime_access->tunnel();
        if (!tunnel || !tunnel->is_alive()) {
            return set_error(&client->base,
                             YUME_STATUS_NOT_RUNNING,
                             "client tunnel is not running");
        }

        const uint8_t stream_id = tunnel->reserve_stream_id();
        if (stream_id == 0) {
            return set_error(&client->base,
                             YUME_STATUS_RESOURCE_EXHAUSTED,
                             "no stream ids available");
        }

        auto stream = std::make_shared<yume::runtime::ServiceStream>(
            service_name,
            "server");
        auto open_wait = std::make_shared<yume::abi::detail::ServiceOpenWait>();
        std::weak_ptr<yume::abi::detail::ServiceOpenWait> weak_open_wait =
            open_wait;
        std::weak_ptr<yume::client::Tunnel> weak_tunnel = tunnel;

        stream->set_callbacks(
            [weak_tunnel, lifetime_gate, stream_id](
                yume::runtime::ServiceStream::Bytes data,
                std::uint32_t timeout_ms,
                yume::runtime::ServiceStream::WriteCompletion completion,
                std::string* error) {
                using Admission =
                    yume::client::TransportCore::DataWriteAdmission;
                using Result = yume::runtime::ServiceStream::WriteResult;
                yume::client::RuntimeLifetimeGate::Lease runtime_lease;
                if (lifetime_gate) {
                    runtime_lease = lifetime_gate->try_acquire();
                    if (!runtime_lease) {
                        if (error) *error = "client runtime is stopping";
                        return Result::Closed;
                    }
                }
                auto locked = weak_tunnel.lock();
                if (!locked || !locked->is_alive()) {
                    if (error) *error = "client tunnel is closed";
                    return Result::Closed;
                }
                const auto admission = locked->wait_send_data(
                    stream_id, std::move(data),
                    std::chrono::milliseconds(timeout_ms),
                    [completion = std::move(completion)](
                        bool ok, std::size_t, const std::string& reason) mutable {
                        if (completion) completion(ok, reason);
                    });
                switch (admission) {
                case Admission::accepted:
                    return Result::Accepted;
                case Admission::would_block:
                    if (error) *error = "service write would block";
                    return Result::WouldBlock;
                case Admission::timeout:
                    if (error) *error = "service write deadline expired";
                    return Result::Timeout;
                case Admission::stopped:
                    if (error) *error = "client transport stopped";
                    return Result::Closed;
                case Admission::invalid:
                    if (error) *error = "service write is too large";
                    return Result::Invalid;
                }
                if (error) *error = "unknown service write admission result";
                return Result::Failed;
            },
            [weak_tunnel, lifetime_gate, stream_id](std::string reason) {
                auto runtime_lease = lifetime_gate
                    ? lifetime_gate->try_acquire()
                    : yume::client::RuntimeLifetimeGate::Lease{};
                if (lifetime_gate && !runtime_lease) return;
                if (auto locked = weak_tunnel.lock()) {
                    locked->send_close(stream_id, reason);
                    locked->unregister_stream(stream_id);
                }
            },
            [weak_tunnel, lifetime_gate, stream_id](std::string reason) {
                auto runtime_lease = lifetime_gate
                    ? lifetime_gate->try_acquire()
                    : yume::client::RuntimeLifetimeGate::Lease{};
                if (lifetime_gate && !runtime_lease) return;
                if (auto locked = weak_tunnel.lock()) {
                    locked->send_stream_fin(stream_id, reason);
                }
            });

        tunnel->register_stream(
            stream_id,
            [stream, weak_tunnel, lifetime_gate, stream_id](
                const yume::client::Tunnel::Bytes& data,
                yume::client::Tunnel::InboundCredit inbound_credit) {
                std::string error;
                yume::client::Tunnel::Bytes owned(data.begin(), data.end());
                if (stream->receive_data(
                        std::move(owned), std::move(inbound_credit), &error)) {
                    return;
                }
                const std::string reason = error.empty() ? "service inbound queue overflow"
                                                         : "service inbound queue overflow: " + error;
                stream->receive_close(reason, true);
                auto runtime_lease = lifetime_gate
                    ? lifetime_gate->try_acquire()
                    : yume::client::RuntimeLifetimeGate::Lease{};
                if (lifetime_gate && !runtime_lease) return;
                if (auto locked = weak_tunnel.lock()) {
                    locked->send_close(stream_id, reason);
                    locked->unregister_stream(stream_id);
                }
            },
            [stream, weak_tunnel, weak_open_wait, lifetime_gate, stream_id](
                const std::string& reason) {
                // Tunnel shutdown clears pending OPEN handlers, but it invokes
                // registered stream-close handlers. Settle the waiter here so
                // both yume_client_stop() and a natural disconnect wake it.
                if (auto wait = weak_open_wait.lock()) {
                    wait->cancel(reason);
                }
                stream->receive_close(reason);
                auto runtime_lease = lifetime_gate
                    ? lifetime_gate->try_acquire()
                    : yume::client::RuntimeLifetimeGate::Lease{};
                if (lifetime_gate && !runtime_lease) return;
                if (auto locked = weak_tunnel.lock()) {
                    locked->unregister_stream(stream_id);
                }
            },
            [stream](const std::string& reason) {
                stream->receive_fin(reason);
            });

        tunnel->open_relay_stream(
            stream_id,
            nlohmann::json{{"proto", "service.v1"}, {"service", service_name}},
            [open_wait](bool ok, const std::string& reason) {
                open_wait->complete(ok, reason);
            });

        const auto open_result = open_wait->wait_for(
            std::chrono::milliseconds(timeout_ms));
        if (open_result.outcome !=
            yume::abi::detail::ServiceOpenWait::Outcome::accepted) {
            using Outcome = yume::abi::detail::ServiceOpenWait::Outcome;
            if (open_result.outcome == Outcome::timed_out) {
                // OPEN was already admitted to the ordered transport. Send a
                // matching CLOSE before removing local state, and never reuse
                // this id on the connection: a late OPEN_ACK or DATA frame
                // otherwise could be mistaken for a subsequent stream.
                tunnel->send_close(stream_id, "stream open timed out");
                tunnel->retire_stream_id(stream_id);
                stream->set_callbacks({}, {}, {});
                stream->receive_close("stream open timed out");
                return set_error(&client->base,
                                 YUME_STATUS_TIMEOUT,
                                 "stream open timed out");
            }
            tunnel->unregister_stream(stream_id);
            stream->set_callbacks({}, {}, {});
            if (open_result.outcome == Outcome::cancelled) {
                const std::string reason = open_result.reason.empty()
                    ? "client tunnel closed while opening stream"
                    : open_result.reason;
                stream->receive_close(reason);
                return set_error(&client->base, YUME_STATUS_NOT_RUNNING, reason);
            }

            const std::string reason = open_result.reason.empty()
                ? "stream open rejected"
                : open_result.reason;
            stream->receive_close(reason);
            return set_error(&client->base,
                             YUME_STATUS_PERMISSION_DENIED,
                             reason);
        }

        *out_stream = new yume_stream(std::move(stream));
        return clear_error(&client->base);
    } catch (std::bad_alloc const&) {
        return set_error(&client->base, YUME_STATUS_INTERNAL_ERROR, "out of memory");
    } catch (std::exception const& ex) {
        return set_error(&client->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&client->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_client_open_packet(yume_client* client,
                            uint32_t timeout_ms,
                            yume_packet** out_packet) {
    if (!client || !out_packet) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    *out_packet = nullptr;
    if (timeout_ms == 0) {
        return set_error(&client->base, YUME_STATUS_WOULD_BLOCK,
                         "packet OPEN requires a positive deadline");
    }
    try {
        auto runtime_access = client->runtime.acquire_runtime();
        if (!runtime_access) {
            return set_error(&client->base, YUME_STATUS_NOT_RUNNING,
                             "client runtime is not running");
        }
        auto tunnel = runtime_access->tunnel();
        if (!tunnel || !tunnel->is_alive()) {
            return set_error(&client->base, YUME_STATUS_NOT_RUNNING,
                             "client tunnel is not running");
        }
        std::string error;
        yume::client::packet::OpenResult open_result;
        auto channel = yume::client::packet::PacketChannel::open(
            std::move(tunnel), runtime_access->server_capabilities(),
            std::chrono::milliseconds(timeout_ms), &error,
            runtime_access->gate(), &open_result);
        if (!channel) {
            return set_error(&client->base,
                             status_from_packet_open_result(open_result.status),
                             error.empty() ? open_result.detail : error);
        }
        *out_packet = new yume_packet(std::move(channel));
        return clear_error(&client->base);
    } catch (std::bad_alloc const&) {
        return set_error(&client->base, YUME_STATUS_INTERNAL_ERROR, "out of memory");
    } catch (std::exception const& ex) {
        return set_error(&client->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&client->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_packet_status_json(yume_packet* packet,
                            char* out,
                            size_t out_size,
                            size_t* needed) {
    if (!packet || !packet->channel) return YUME_STATUS_INVALID_ARGUMENT;
    try {
        const auto& assignment = packet->channel->assignment();
        const auto stats = packet->channel->stats();
        nlohmann::json json{
            {"protocol", "packet-bulk-v1"},
            {"capability", "packet_bulk_v1"},
            {"ipv4", assignment.ipv4},
            {"mtu", assignment.mtu},
            {"dns", assignment.dns_servers},
            {"stopped", stats.stopped},
            {"stop_reason", stats.stop_reason},
            {"outbound_batches", stats.outbound_batches},
            {"outbound_packets", stats.outbound_packets},
            {"outbound_bytes", stats.outbound_bytes},
            {"outbound_queue_packets", stats.outbound_queue_packets},
            {"outbound_queue_bytes", stats.outbound_queue_bytes},
            {"inbound_batches", stats.inbound_batches},
            {"inbound_packets", stats.inbound_packets},
            {"inbound_bytes", stats.inbound_bytes},
            {"inbound_queue_packets", stats.inbound_queue_packets},
            {"inbound_queue_bytes", stats.inbound_queue_bytes},
        };
        return write_json_buffer(&packet->base, json, out, out_size, needed);
    } catch (std::exception const& ex) {
        return set_error(&packet->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&packet->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_packet_write_batch(yume_packet* packet,
                            const void* const* packets,
                            const size_t* lengths,
                            size_t packet_count,
                            uint32_t timeout_ms) {
    if (!packet || !packet->channel || !packets || !lengths || packet_count == 0) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (packet_count >
        yume::client::packet::PacketBatchEngine::kDefaultMaxQueuePackets) {
        return set_error(&packet->base, YUME_STATUS_INVALID_ARGUMENT,
                         "packet batch exceeds the queue packet limit");
    }
    try {
        std::size_t total_bytes = 0;
        for (std::size_t i = 0; i < packet_count; ++i) {
            if (!packets[i] || lengths[i] == 0 ||
                lengths[i] > yume::protocol::packet_bulk::kMaxPacketBytes) {
                return set_error(&packet->base, YUME_STATUS_INVALID_ARGUMENT,
                                 "packet input is null, empty, or oversized");
            }
            if (lengths[i] >
                yume::client::packet::PacketBatchEngine::kDefaultMaxQueueBytes -
                    std::min(total_bytes,
                             yume::client::packet::PacketBatchEngine::kDefaultMaxQueueBytes)) {
                return set_error(&packet->base, YUME_STATUS_INVALID_ARGUMENT,
                                 "packet batch exceeds the queue byte limit");
            }
            total_bytes += lengths[i];
        }
        std::vector<yume::client::packet::Bytes> copied;
        copied.reserve(packet_count);
        for (std::size_t i = 0; i < packet_count; ++i) {
            const auto* begin = static_cast<const std::uint8_t*>(packets[i]);
            copied.emplace_back(begin, begin + lengths[i]);
        }
        std::string error;
        const auto result = packet->channel->write_packets(
            copied, std::chrono::milliseconds(timeout_ms), &error);
        if (result != yume::client::packet::QueueResult::ok) {
            return set_error(&packet->base,
                             status_from_packet_result(result),
                             error.empty() ? "packet write unavailable" : error);
        }
        return clear_error(&packet->base);
    } catch (std::bad_alloc const&) {
        return set_error(&packet->base, YUME_STATUS_INTERNAL_ERROR, "out of memory");
    } catch (std::exception const& ex) {
        return set_error(&packet->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&packet->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_packet_read_batch(yume_packet* packet,
                           void* storage,
                           size_t storage_size,
                           size_t* offsets,
                           size_t* lengths,
                           size_t array_capacity,
                           size_t* packet_count,
                           size_t* required_storage,
                           uint32_t timeout_ms) {
    if (!packet || !packet->channel || !packet_count ||
        array_capacity == 0 || !offsets || !lengths ||
        (!storage && storage_size != 0)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    *packet_count = 0;
    if (required_storage) *required_storage = 0;
    try {
        std::vector<yume::client::packet::Bytes> packets;
        std::size_t required = 0;
        const auto result = packet->channel->read_packets(
            array_capacity, storage_size, std::chrono::milliseconds(timeout_ms),
            &packets, &required);
        if (required_storage) *required_storage = required;
        if (result != yume::client::packet::QueueResult::ok) {
            return set_error(&packet->base, status_from_packet_result(result),
                             result == yume::client::packet::QueueResult::buffer_too_small
                                 ? "packet read storage is too small"
                                 : "packet read unavailable");
        }
        auto* bytes = static_cast<std::uint8_t*>(storage);
        std::size_t offset = 0;
        for (std::size_t i = 0; i < packets.size(); ++i) {
            offsets[i] = offset;
            lengths[i] = packets[i].size();
            std::memcpy(bytes + offset, packets[i].data(), packets[i].size());
            offset += packets[i].size();
        }
        *packet_count = packets.size();
        if (required_storage) *required_storage = offset;
        return clear_error(&packet->base);
    } catch (std::exception const& ex) {
        return set_error(&packet->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&packet->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_packet_close(yume_packet* packet) {
    if (!packet || !packet->channel) return YUME_STATUS_INVALID_ARGUMENT;
    try {
        packet->channel->close("ABI packet close");
        return clear_error(&packet->base);
    } catch (...) {
        return set_error(&packet->base, YUME_STATUS_INTERNAL_ERROR,
                         "packet close failed");
    }
}

void yume_packet_destroy(yume_packet* packet) {
    delete packet;
}

yume_server* yume_server_create(void) {
    try {
        return new yume_server();
    } catch (...) {
        return nullptr;
    }
}

void yume_server_destroy(yume_server* server) {
    delete server;
}

#if !defined(YUME_ABI_CLIENT_ONLY) || !YUME_ABI_CLIENT_ONLY

int yume_server_start_json(yume_server* server,
                           const char* config_json,
                           const char* base_dir) {
    if (!server || !config_json) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    try {
        std::string parse_error;
        auto cfg = yume::facade::config_io::parse_server_json(
            config_json,
            abi_base_dir(base_dir),
            &parse_error);
        if (!cfg) {
            return set_error(&server->base, YUME_STATUS_PARSE_ERROR, parse_error);
        }
        auto validation = yume::facade::config_io::validate(*cfg);
        if (!validation.ok()) {
            return set_error(&server->base,
                             YUME_STATUS_INVALID_ARGUMENT,
                             validation_error(validation));
        }

        std::lock_guard<std::mutex> lock(server->mu);
        std::string error;
        yume::runtime::OperationStatus operation_status{};
        const bool started = server->runtime.start(
            std::move(*cfg), &error, &operation_status);
        if (!started ||
            operation_status != yume::runtime::OperationStatus::Success) {
            return set_error(&server->base,
                             status_from_operation_status(operation_status),
                             error.empty() ? "server start failed" : error);
        }
        return clear_error(&server->base);
    } catch (std::exception const& ex) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_server_start_file(yume_server* server,
                           const char* config_path) {
    if (!server || !config_path || !*config_path) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    try {
        std::string error;
        yume::facade::config_io::ConfigLoadError load_error{};
        auto cfg = yume::facade::config_io::load_server(
            config_path, &error, &load_error);
        if (!cfg) {
            return set_error(&server->base,
                             status_from_config_load_error(load_error),
                             error);
        }
        auto validation = yume::facade::config_io::validate(*cfg);
        if (!validation.ok()) {
            return set_error(&server->base,
                             YUME_STATUS_INVALID_ARGUMENT,
                             validation_error(validation));
        }
        std::lock_guard<std::mutex> lock(server->mu);
        yume::runtime::OperationStatus operation_status{};
        const bool started = server->runtime.start(
            std::move(*cfg), &error, &operation_status);
        if (!started ||
            operation_status != yume::runtime::OperationStatus::Success) {
            return set_error(&server->base,
                             status_from_operation_status(operation_status),
                             error.empty() ? "server start failed" : error);
        }
        return clear_error(&server->base);
    } catch (std::exception const& ex) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_server_stop(yume_server* server) {
    if (!server) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    try {
        std::lock_guard<std::mutex> lock(server->mu);
        server->runtime.stop();
        return clear_error(&server->base);
    } catch (std::exception const& ex) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_server_reload_auth(yume_server* server) {
    if (!server) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    try {
        std::string error;
        yume::runtime::OperationStatus operation_status{};
        if (!server->runtime.reload_auth(&error, &operation_status)) {
            return set_error(&server->base,
                             status_from_operation_status(operation_status),
                             error);
        }
        return clear_error(&server->base);
    } catch (std::exception const& ex) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_server_status_json(yume_server* server,
                            char* out,
                            size_t out_size,
                            size_t* needed) {
    if (!server) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    try {
        const auto status = server->runtime.status();
        nlohmann::json json = {
            {"running", status.running},
            {"listen_endpoint", status.listen_endpoint},
            {"ipc_path", status.ipc_path},
            {"message", status.message},
            {"active_sessions", status.active_sessions},
            {"started_unix_ms", unix_ms(status.started)}
        };
        return write_json_buffer(&server->base, json, out, out_size, needed);
    } catch (std::exception const& ex) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_server_request_json(yume_server* server,
                             const char* op,
                             const char* args_json,
                             char* out,
                             size_t out_size,
                             size_t* needed) {
    if (!server || !op) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    try {
        std::lock_guard<std::mutex> request_lock(
            server->request_replay.mutex);
        std::string operation;
        const int operation_parse_status =
            parse_request_operation(&server->base, op, &operation);
        if (operation_parse_status != YUME_STATUS_OK) {
            return operation_parse_status;
        }
        nlohmann::json args;
        const int args_status =
            parse_request_args(&server->base, args_json, &args);
        if (args_status != YUME_STATUS_OK) {
            return args_status;
        }
        yume::client::RelayRequestSecretsWiper args_wiper(args);
        auto request_key = make_request_replay_key(operation, args);
        RequestReplayKeyWiper request_key_wiper(request_key);
        if (server->request_replay.matches(request_key)) {
            return copy_cached_request_response(
                &server->base, &server->request_replay,
                out, out_size, needed);
        }
        server->request_replay.clear();

        std::string error;
        yume::runtime::OperationStatus operation_status{};
        auto response = server->runtime.request(
            operation, args, &error, &operation_status);
        if (operation_status != yume::runtime::OperationStatus::Success) {
            return set_error(&server->base,
                             status_from_operation_status(operation_status),
                             error.empty() ? "server request failed" : error);
        }
        return write_completed_request_response(
            &server->base, &server->request_replay, &request_key,
            response, out, out_size, needed);
    } catch (std::exception const& ex) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_server_sessions_json(yume_server* server,
                              char* out,
                              size_t out_size,
                              size_t* needed) {
    if (!server) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    try {
        nlohmann::json sessions = nlohmann::json::array();
        for (const auto& session : server->runtime.sessions()) {
            sessions.push_back({
                {"endpoint_id", session.endpoint_id},
                {"display_name", session.display_name},
                {"state", session.state},
                {"client_platform", session.client_platform},
                {"client_version", session.client_version}
            });
        }
        return write_json_buffer(&server->base, sessions, out, out_size, needed);
    } catch (std::exception const& ex) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_server_register_service(yume_server* server,
                                 const char* service) {
    if (!server || !service) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (!valid_service_name(service)) {
        return set_error(&server->base,
                         YUME_STATUS_INVALID_ARGUMENT,
                         "invalid service name");
    }
    try {
        const std::string service_name(service);
        std::string error;
        yume::runtime::OperationStatus operation_status{};
        if (!server->runtime.register_service(
                service_name, &error, &operation_status)) {
            return set_error(&server->base,
                             status_from_operation_status(operation_status),
                             error);
        }
        return clear_error(&server->base);
    } catch (std::exception const& ex) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_server_accept_stream(yume_server* server,
                              const char* service,
                              uint32_t timeout_ms,
                              yume_stream** out_stream) {
    if (!server || !service || !out_stream) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    *out_stream = nullptr;
    if (!valid_service_name(service)) {
        return set_error(&server->base,
                         YUME_STATUS_INVALID_ARGUMENT,
                         "invalid service name");
    }
    try {
        const std::string service_name(service);
        std::string error;
        yume::runtime::OperationStatus operation_status{};
        auto stream = server->runtime.accept_service_stream(
            service_name, timeout_ms, &error, &operation_status);
        if (!stream) {
            return set_error(&server->base,
                             status_from_operation_status(operation_status),
                             error);
        }
        *out_stream = new yume_stream(std::move(stream));
        return clear_error(&server->base);
    } catch (std::bad_alloc const&) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, "out of memory");
    } catch (std::exception const& ex) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

#else

int yume_server_start_json(yume_server* server,
                           const char* config_json,
                           const char*) {
    if (!server || !config_json) return YUME_STATUS_INVALID_ARGUMENT;
    return set_error(&server->base, YUME_STATUS_PERMISSION_DENIED,
                     "server runtime is not included in this client-only build");
}

int yume_server_start_file(yume_server* server, const char* config_path) {
    if (!server || !config_path || !*config_path) return YUME_STATUS_INVALID_ARGUMENT;
    return set_error(&server->base, YUME_STATUS_PERMISSION_DENIED,
                     "server runtime is not included in this client-only build");
}

int yume_server_stop(yume_server* server) {
    if (!server) return YUME_STATUS_INVALID_ARGUMENT;
    return clear_error(&server->base);
}

int yume_server_reload_auth(yume_server* server) {
    if (!server) return YUME_STATUS_INVALID_ARGUMENT;
    return set_error(&server->base, YUME_STATUS_NOT_RUNNING,
                     "server runtime is not included in this client-only build");
}

int yume_server_status_json(yume_server* server, char*, size_t, size_t*) {
    if (!server) return YUME_STATUS_INVALID_ARGUMENT;
    return set_error(&server->base, YUME_STATUS_NOT_RUNNING,
                     "server runtime is not included in this client-only build");
}

int yume_server_sessions_json(yume_server* server, char*, size_t, size_t*) {
    if (!server) return YUME_STATUS_INVALID_ARGUMENT;
    return set_error(&server->base, YUME_STATUS_NOT_RUNNING,
                     "server runtime is not included in this client-only build");
}

int yume_server_request_json(yume_server* server, const char* op,
                             const char* args_json,
                             char*, size_t, size_t*) {
    if (!server || !op) return YUME_STATUS_INVALID_ARGUMENT;
    try {
        std::lock_guard<std::mutex> request_lock(
            server->request_replay.mutex);
        std::string operation;
        const int operation_parse_status =
            parse_request_operation(&server->base, op, &operation);
        if (operation_parse_status != YUME_STATUS_OK) {
            return operation_parse_status;
        }
        nlohmann::json args;
        const int args_status =
            parse_request_args(&server->base, args_json, &args);
        if (args_status != YUME_STATUS_OK) return args_status;
        yume::client::RelayRequestSecretsWiper args_wiper(args);
        server->request_replay.clear();
        return set_error(
            &server->base, YUME_STATUS_NOT_RUNNING,
            "server runtime is not included in this client-only build");
    } catch (std::exception const& ex) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&server->base, YUME_STATUS_INTERNAL_ERROR,
                         "unknown error");
    }
}

int yume_server_register_service(yume_server* server, const char* service) {
    if (!server || !service) return YUME_STATUS_INVALID_ARGUMENT;
    return set_error(&server->base, YUME_STATUS_NOT_RUNNING,
                     "server runtime is not included in this client-only build");
}

int yume_server_accept_stream(yume_server* server,
                              const char* service,
                              uint32_t,
                              yume_stream** out_stream) {
    if (!server || !service || !out_stream) return YUME_STATUS_INVALID_ARGUMENT;
    *out_stream = nullptr;
    return set_error(&server->base, YUME_STATUS_NOT_RUNNING,
                     "server runtime is not included in this client-only build");
}

#endif

int yume_stream_peer_json(yume_stream* stream,
                          char* out,
                          size_t out_size,
                          size_t* needed) {
    if (!stream || !stream->stream) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    try {
        const auto info = stream->stream->peer_info();
        nlohmann::json json = {
            {"service", info.service},
            {"peer", info.peer},
            {"auth_fingerprint_sha256", info.auth_fingerprint_sha256},
            {"session_id", info.session_id},
            {"server_session_id", info.server_session_id},
            {"remote_addr", info.remote_addr}
        };
        return write_json_buffer(&stream->base, json, out, out_size, needed);
    } catch (std::exception const& ex) {
        return set_error(&stream->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&stream->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_stream_read(yume_stream* stream,
                     void* out,
                     size_t out_size,
                     size_t* bytes_read,
                     uint32_t timeout_ms) {
    if (!stream || !out || out_size == 0) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (bytes_read) {
        *bytes_read = 0;
    }
    try {
        std::string reason;
        const auto result = stream->stream->read(out, out_size, timeout_ms, bytes_read, &reason);
        const int status = yume::abi::detail::service_read_status(
            result, timeout_ms);
        if (status == YUME_STATUS_OK) {
            return clear_error(&stream->base);
        }
        if (status == YUME_STATUS_WOULD_BLOCK) {
            return set_error(&stream->base, status, "stream read would block");
        }
        if (status == YUME_STATUS_TIMEOUT) {
            return set_error(&stream->base, status, "stream read timed out");
        }
        if (status == YUME_STATUS_NOT_RUNNING) {
            return set_error(&stream->base, status,
                             reason.empty() ? "stream is closed" : reason);
        }
        return set_error(&stream->base, status, "unknown read result");
    } catch (std::exception const& ex) {
        return set_error(&stream->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&stream->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_stream_write(yume_stream* stream,
                      const void* data,
                      size_t size,
                      size_t* bytes_written,
                      uint32_t timeout_ms) {
    if (!stream || (size > 0 && !data)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (bytes_written) {
        *bytes_written = 0;
    }
    try {
        std::string error;
        const auto result = stream->stream->write(
            data, size, timeout_ms, &error);
        using Result = yume::runtime::ServiceStream::WriteResult;
        if (result != Result::Accepted) {
            int status = YUME_STATUS_INTERNAL_ERROR;
            switch (result) {
            case Result::WouldBlock:
                status = YUME_STATUS_WOULD_BLOCK;
                break;
            case Result::Timeout:
                status = YUME_STATUS_TIMEOUT;
                break;
            case Result::Closed:
                status = YUME_STATUS_NOT_RUNNING;
                break;
            case Result::Invalid:
                status = YUME_STATUS_INVALID_ARGUMENT;
                break;
            case Result::Failed:
                status = YUME_STATUS_INTERNAL_ERROR;
                break;
            case Result::Accepted:
                break;
            }
            return set_error(&stream->base, status,
                             error.empty() ? "stream write failed" : error);
        }
        if (bytes_written) {
            *bytes_written = size;
        }
        return clear_error(&stream->base);
    } catch (std::exception const& ex) {
        return set_error(&stream->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&stream->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_stream_shutdown_write(yume_stream* stream) {
    if (!stream) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    try {
        std::string error;
        if (!stream->stream->shutdown_write(&error)) {
            return set_error(&stream->base, YUME_STATUS_NOT_RUNNING, error);
        }
        return clear_error(&stream->base);
    } catch (std::exception const& ex) {
        return set_error(&stream->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&stream->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

int yume_stream_close(yume_stream* stream) {
    if (!stream) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    try {
        stream->stream->close("ABI stream close");
        return clear_error(&stream->base);
    } catch (std::exception const& ex) {
        return set_error(&stream->base, YUME_STATUS_INTERNAL_ERROR, ex.what());
    } catch (...) {
        return set_error(&stream->base, YUME_STATUS_INTERNAL_ERROR, "unknown error");
    }
}

void yume_stream_destroy(yume_stream* stream) {
    delete stream;
}

const char* yume_handle_last_error(const void* handle) {
    if (!handle) {
        return "invalid handle";
    }
    try {
        const auto* base = static_cast<const HandleBase*>(handle);
        thread_local std::string copy;
        std::lock_guard<std::mutex> lock(base->error_mu);
        copy = base->last_error;
        return copy.c_str();
    } catch (...) {
        return "invalid handle";
    }
}

}  // extern "C"
