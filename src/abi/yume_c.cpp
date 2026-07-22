/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "yume/yume.h"

#include "client/packet/channel.hpp"
#include "client/transport/tunnel.hpp"
#include "core/runtime/service_stream.hpp"
#include "core/security/inner_crypto.hpp"
#include "core/version.hpp"
#include "facade/config/config_io.hpp"
#include "facade/session/inproc_client.hpp"
#if !defined(YUME_ABI_CLIENT_ONLY) || !YUME_ABI_CLIENT_ONLY
#include "server/runtime/controller.hpp"
#endif

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <limits>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <nlohmann/json.hpp>

namespace {

enum class HandleKind : std::uint32_t {
    Client = 0x59434c49u,  // YCLI
    Server = 0x59535256u,  // YSRV
    Stream = 0x59535452u,  // YSTR
    Packet = 0x59504b54u,  // YPKT
};

struct HandleBase {
    explicit HandleBase(HandleKind handle_kind)
        : kind(static_cast<std::uint32_t>(handle_kind)) {}

    std::uint32_t kind;
    mutable std::mutex error_mu;
    std::string last_error;
};

int set_error(HandleBase* handle, int status, std::string message) {
    if (handle) {
        std::lock_guard<std::mutex> lock(handle->error_mu);
        handle->last_error = std::move(message);
    }
    return status;
}

int clear_error(HandleBase* handle) {
    if (handle) {
        std::lock_guard<std::mutex> lock(handle->error_mu);
        handle->last_error.clear();
    }
    return YUME_STATUS_OK;
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

std::chrono::seconds start_timeout(uint32_t timeout_ms) {
    if (timeout_ms == 0) {
        return std::chrono::seconds{0};
    }
    return std::chrono::seconds{(timeout_ms + 999u) / 1000u};
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

bool contains_text(const std::string& haystack, const char* needle) {
    return haystack.find(needle) != std::string::npos;
}

int status_from_error(const std::string& error) {
    if (contains_text(error, "not running") ||
        contains_text(error, "stopping")) {
        return YUME_STATUS_NOT_RUNNING;
    }
    if (contains_text(error, "already running") ||
        contains_text(error, "already started")) {
        return YUME_STATUS_ALREADY_RUNNING;
    }
    if (contains_text(error, "timed out") ||
        contains_text(error, "timeout") ||
        contains_text(error, "no service stream is pending")) {
        return YUME_STATUS_TIMEOUT;
    }
    if (contains_text(error, "not registered") ||
        contains_text(error, "not found") ||
        contains_text(error, "does not advertise") ||
        contains_text(error, "unavailable")) {
        return YUME_STATUS_NOT_FOUND;
    }
    if (contains_text(error, "not enabled") ||
        contains_text(error, "not permitted") ||
        contains_text(error, "permission") ||
        contains_text(error, "denied")) {
        return YUME_STATUS_PERMISSION_DENIED;
    }
    return YUME_STATUS_INTERNAL_ERROR;
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
    yume_client()
        : base(HandleKind::Client) {}

    HandleBase base;
    std::mutex mu;
    yume::facade::InProcClient runtime;
    yume_socket_protect_fn socket_protect{nullptr};
    void* socket_protect_user_data{nullptr};
};

struct yume_server {
    yume_server()
        : base(HandleKind::Server) {}

    HandleBase base;
    std::mutex mu;
#if !defined(YUME_ABI_CLIENT_ONLY) || !YUME_ABI_CLIENT_ONLY
    yume::server::RuntimeController runtime;
#endif
};

struct yume_stream {
    explicit yume_stream(std::shared_ptr<yume::runtime::ServiceStream> stream_in)
        : base(HandleKind::Stream)
        , stream(std::move(stream_in)) {}

    ~yume_stream() {
        if (stream) {
            stream->close("stream destroyed");
        }
    }

    HandleBase base;
    std::shared_ptr<yume::runtime::ServiceStream> stream;
};

struct yume_packet {
    explicit yume_packet(
        std::shared_ptr<yume::client::packet::PacketChannel> channel_in)
        : base(HandleKind::Packet)
        , channel(std::move(channel_in)) {}

    ~yume_packet() {
        if (channel) channel->close("ABI packet destroyed");
    }

    HandleBase base;
    std::mutex mu;
    std::shared_ptr<yume::client::packet::PacketChannel> channel;
};

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
    if (out_size < sizeof(yume_build_info)) {
        return YUME_STATUS_BUFFER_TOO_SMALL;
    }

    try {
        std::memset(out, 0, sizeof(yume_build_info));
        out->struct_size = sizeof(yume_build_info);
        out->abi_version = yume_abi_version();
        out->feature_flags = yume_feature_flags();
        out->yume_version = yume_version();
        out->basefwx_version = yume_basefwx_version();
        out->pq_backend = yume_pq_backend();
        out->argon2_backend = yume_argon2_backend();
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
    default: return "unknown status";
    }
}

int yume_generate_pq_keypair(const char* private_path,
                             const char* public_path) {
    if (!private_path || !*private_path || !public_path || !*public_path) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    try {
        std::string error;
        if (!yume::inner::generate_pq_keypair(private_path, public_path, &error)) {
            return YUME_STATUS_INTERNAL_ERROR;
        }
        return YUME_STATUS_OK;
    } catch (...) {
        return YUME_STATUS_INTERNAL_ERROR;
    }
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
        if (client->runtime.status().running) {
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

        std::lock_guard<std::mutex> lock(client->mu);
        if (client->socket_protect) {
            auto callback = client->socket_protect;
            auto* user_data = client->socket_protect_user_data;
            cfg->socket_protect = [callback, user_data](std::intptr_t handle) {
                return callback(handle, user_data) != 0;
            };
        }
        std::string error;
        if (!client->runtime.start(std::move(*cfg), &error, start_timeout(timeout_ms))) {
            return set_error(&client->base, status_from_error(error), error);
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
        std::string error;
        auto cfg = yume::facade::config_io::load_client(config_path, &error);
        if (!cfg) {
            const int status = contains_text(error, "invalid JSON")
                ? YUME_STATUS_PARSE_ERROR
                : YUME_STATUS_NOT_FOUND;
            return set_error(&client->base, status, error);
        }
        auto validation = yume::facade::config_io::validate(*cfg);
        if (!validation.ok()) {
            return set_error(&client->base,
                             YUME_STATUS_INVALID_ARGUMENT,
                             validation_error(validation));
        }
        std::lock_guard<std::mutex> lock(client->mu);
        if (client->socket_protect) {
            auto callback = client->socket_protect;
            auto* user_data = client->socket_protect_user_data;
            cfg->socket_protect = [callback, user_data](std::intptr_t handle) {
                return callback(handle, user_data) != 0;
            };
        }
        if (!client->runtime.start(std::move(*cfg), &error, start_timeout(timeout_ms))) {
            return set_error(&client->base, status_from_error(error), error);
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
        std::lock_guard<std::mutex> lock(client->mu);
        std::string error;
        client->runtime.stop(&error, "ABI client stop");
        if (!error.empty()) {
            return set_error(&client->base, status_from_error(error), error);
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
        const auto server_capabilities = client->runtime.server_capabilities();
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
    if (!client || !op || !*op) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    try {
        nlohmann::json args = nlohmann::json::object();
        if (args_json && *args_json) {
            try {
                args = nlohmann::json::parse(args_json);
            } catch (std::exception const& ex) {
                return set_error(&client->base,
                                 YUME_STATUS_PARSE_ERROR,
                                 std::string("invalid args JSON: ") + ex.what());
            }
        }

        std::string error;
        auto response = client->runtime.request(op, args, &error, timeout_as_int(timeout_ms));
        if (!error.empty()) {
            return set_error(&client->base, status_from_error(error), error);
        }
        return write_json_buffer(&client->base, response, out, out_size, needed);
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
    const std::string service_name(service);
    if (!valid_service_name(service_name)) {
        return set_error(&client->base,
                         YUME_STATUS_INVALID_ARGUMENT,
                         "invalid service name");
    }

    try {
        auto tunnel = client->runtime.primary_tunnel();
        if (!tunnel || !tunnel->is_alive()) {
            return set_error(&client->base,
                             YUME_STATUS_NOT_RUNNING,
                             "client tunnel is not running");
        }

        const uint8_t stream_id = tunnel->reserve_stream_id();
        if (stream_id == 0) {
            return set_error(&client->base,
                             YUME_STATUS_NOT_FOUND,
                             "no stream ids available");
        }

        auto stream = std::make_shared<yume::runtime::ServiceStream>(
            service_name,
            "server");
        std::weak_ptr<yume::client::Tunnel> weak_tunnel = tunnel;

        stream->set_callbacks(
            [weak_tunnel, stream_id](yume::runtime::ServiceStream::Bytes data,
                                     std::string* error) {
                auto locked = weak_tunnel.lock();
                if (!locked || !locked->is_alive()) {
                    if (error) *error = "client tunnel is closed";
                    return false;
                }
                locked->send_data(stream_id, std::move(data));
                return true;
            },
            [weak_tunnel, stream_id](std::string reason) {
                if (auto locked = weak_tunnel.lock()) {
                    locked->send_close(stream_id, reason);
                    locked->unregister_stream(stream_id);
                }
            },
            [weak_tunnel, stream_id](std::string reason) {
                if (auto locked = weak_tunnel.lock()) {
                    locked->send_stream_fin(stream_id, reason);
                }
            });

        tunnel->register_stream(
            stream_id,
            [stream, weak_tunnel, stream_id](const yume::client::Tunnel::Bytes& data) {
                std::string error;
                if (stream->receive_data(data, &error)) {
                    return;
                }
                const std::string reason = error.empty() ? "service inbound queue overflow"
                                                         : "service inbound queue overflow: " + error;
                stream->receive_close(reason, true);
                if (auto locked = weak_tunnel.lock()) {
                    locked->send_close(stream_id, reason);
                    locked->unregister_stream(stream_id);
                }
            },
            [stream, weak_tunnel, stream_id](const std::string& reason) {
                stream->receive_close(reason);
                if (auto locked = weak_tunnel.lock()) {
                    locked->unregister_stream(stream_id);
                }
            },
            [stream](const std::string& reason) {
                stream->receive_fin(reason);
            });

        std::mutex open_mu;
        std::condition_variable open_cv;
        bool open_done = false;
        bool open_ok = false;
        std::string open_reason;

        tunnel->open_relay_stream(
            stream_id,
            nlohmann::json{{"proto", "service.v1"}, {"service", service_name}},
            [&](bool ok, const std::string& reason) {
                {
                    std::lock_guard<std::mutex> lock(open_mu);
                    open_done = true;
                    open_ok = ok;
                    open_reason = reason;
                }
                open_cv.notify_all();
            });

        {
            std::unique_lock<std::mutex> lock(open_mu);
            if (!open_cv.wait_for(lock,
                                  std::chrono::milliseconds(timeout_ms),
                                  [&] { return open_done; })) {
                tunnel->unregister_stream(stream_id);
                stream->set_callbacks({}, {}, {});
                stream->receive_close("stream open timed out");
                return set_error(&client->base,
                                 YUME_STATUS_TIMEOUT,
                                 "stream open timed out");
            }
        }

        if (!open_ok) {
            tunnel->unregister_stream(stream_id);
            stream->set_callbacks({}, {}, {});
            stream->receive_close(open_reason);
            return set_error(&client->base,
                             status_from_error(open_reason),
                             open_reason.empty() ? "stream open rejected" : open_reason);
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
        auto tunnel = client->runtime.primary_tunnel();
        if (!tunnel || !tunnel->is_alive()) {
            return set_error(&client->base, YUME_STATUS_NOT_RUNNING,
                             "client tunnel is not running");
        }
        std::string error;
        auto channel = yume::client::packet::PacketChannel::open(
            std::move(tunnel), client->runtime.server_capabilities(),
            std::chrono::milliseconds(timeout_ms), &error);
        if (!channel) {
            return set_error(&client->base, status_from_error(error), error);
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
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        while (true) {
            std::string error;
            const auto result = packet->channel->write_packets(copied, &error);
            if (result == yume::client::packet::QueueResult::ok) {
                return clear_error(&packet->base);
            }
            if (result != yume::client::packet::QueueResult::would_block) {
                return set_error(&packet->base, status_from_packet_result(result), error);
            }
            if (timeout_ms == 0) {
                return set_error(&packet->base, YUME_STATUS_WOULD_BLOCK, error);
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                return set_error(&packet->base, YUME_STATUS_TIMEOUT,
                                 "packet write deadline expired");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
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
        if (!server->runtime.start(std::move(*cfg), &error)) {
            return set_error(&server->base, status_from_error(error), error);
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
        auto cfg = yume::facade::config_io::load_server(config_path, &error);
        if (!cfg) {
            const int status = contains_text(error, "invalid JSON")
                ? YUME_STATUS_PARSE_ERROR
                : YUME_STATUS_NOT_FOUND;
            return set_error(&server->base, status, error);
        }
        auto validation = yume::facade::config_io::validate(*cfg);
        if (!validation.ok()) {
            return set_error(&server->base,
                             YUME_STATUS_INVALID_ARGUMENT,
                             validation_error(validation));
        }
        std::lock_guard<std::mutex> lock(server->mu);
        if (!server->runtime.start(std::move(*cfg), &error)) {
            return set_error(&server->base, status_from_error(error), error);
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
        if (!server->runtime.reload_auth(&error)) {
            return set_error(&server->base, status_from_error(error), error);
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
    const std::string service_name(service);
    if (!valid_service_name(service_name)) {
        return set_error(&server->base,
                         YUME_STATUS_INVALID_ARGUMENT,
                         "invalid service name");
    }
    try {
        std::string error;
        if (!server->runtime.register_service(service_name, &error)) {
            return set_error(&server->base, status_from_error(error), error);
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
    const std::string service_name(service);
    if (!valid_service_name(service_name)) {
        return set_error(&server->base,
                         YUME_STATUS_INVALID_ARGUMENT,
                         "invalid service name");
    }
    try {
        std::string error;
        auto stream = server->runtime.accept_service_stream(service_name, timeout_ms, &error);
        if (!stream) {
            return set_error(&server->base, status_from_error(error), error);
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
        switch (result) {
        case yume::runtime::ServiceStream::ReadResult::Data:
            return clear_error(&stream->base);
        case yume::runtime::ServiceStream::ReadResult::Eof:
        case yume::runtime::ServiceStream::ReadResult::Closed:
            return clear_error(&stream->base);
        case yume::runtime::ServiceStream::ReadResult::Timeout:
            return set_error(&stream->base,
                             YUME_STATUS_TIMEOUT,
                             "stream read timed out");
        }
        return set_error(&stream->base, YUME_STATUS_INTERNAL_ERROR, "unknown read result");
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
    (void)timeout_ms;
    if (!stream || (size > 0 && !data)) {
        return YUME_STATUS_INVALID_ARGUMENT;
    }
    if (bytes_written) {
        *bytes_written = 0;
    }
    try {
        std::string error;
        if (!stream->stream->write(data, size, &error)) {
            return set_error(&stream->base, status_from_error(error), error);
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
            return set_error(&stream->base, status_from_error(error), error);
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
