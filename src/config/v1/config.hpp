/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json_fwd.hpp>

namespace yume::config::v1 {

inline constexpr std::uint32_t kSchema = 1;
inline constexpr std::size_t kMaxDocumentBytes = 1024U * 1024U;
inline constexpr std::size_t kMaxNestingDepth = 16;
inline constexpr std::size_t kMaxFileReferenceBytes = 4096;
inline constexpr std::size_t kMaxServices = 64;
inline constexpr std::size_t kMaxAdapters = 16;
inline constexpr std::size_t kMaxListenAddresses = 16;

inline constexpr std::string_view kSuiteId = "ytp1-tls13-h2";
inline constexpr std::string_view kSecureChannelProvider = "tls13-native";
inline constexpr std::string_view kFrontDoorProvider = "h2-web";
inline constexpr std::string_view kCarrierProvider = "h2-duplex";
inline constexpr std::string_view kSessionComponent = "ytp1-hybrid";

enum class Role {
    Client,
    Server,
};

enum class ServiceKind {
    Stream,
    Packet,
};

enum class AdapterKind {
    Socks5,
    Packet,
    DirectTcp,
    DirectUdp,
};

class ValidationError final : public std::runtime_error {
public:
    ValidationError(std::string json_pointer, std::string detail);

    const std::string& json_pointer() const noexcept { return json_pointer_; }
    const std::string& detail() const noexcept { return detail_; }

private:
    std::string json_pointer_;
    std::string detail_;
};

class FileReference final {
public:
    explicit FileReference(std::string path) : path_(std::move(path)) {}

    const std::string& path() const noexcept { return path_; }

private:
    std::string path_;
};

class ClientEndpoint final {
public:
    ClientEndpoint(std::string host, std::uint16_t port)
        : host_(std::move(host)), port_(port) {}

    const std::string& host() const noexcept { return host_; }
    std::uint16_t port() const noexcept { return port_; }

private:
    std::string host_;
    std::uint16_t port_;
};

class ServerEndpoint final {
public:
    ServerEndpoint(std::vector<std::string> listen_addresses,
                   std::uint16_t port)
        : listen_addresses_(std::move(listen_addresses)), port_(port) {}

    const std::vector<std::string>& listen_addresses() const noexcept {
        return listen_addresses_;
    }
    std::uint16_t port() const noexcept { return port_; }

private:
    std::vector<std::string> listen_addresses_;
    std::uint16_t port_;
};

using Endpoint = std::variant<ClientEndpoint, ServerEndpoint>;

class Suite final {
public:
    Suite(std::string id,
          std::string secure_channel,
          std::string front_door,
          std::string carrier,
          std::string session)
        : id_(std::move(id)),
          secure_channel_(std::move(secure_channel)),
          front_door_(std::move(front_door)),
          carrier_(std::move(carrier)),
          session_(std::move(session)) {}

    const std::string& id() const noexcept { return id_; }
    const std::string& secure_channel() const noexcept {
        return secure_channel_;
    }
    const std::string& front_door() const noexcept { return front_door_; }
    const std::string& carrier() const noexcept { return carrier_; }
    const std::string& session() const noexcept { return session_; }

private:
    std::string id_;
    std::string secure_channel_;
    std::string front_door_;
    std::string carrier_;
    std::string session_;
};

class ClientCredentials final {
public:
    ClientCredentials(FileReference composite_key,
                      FileReference access_psk,
                      FileReference admission_key,
                      FileReference server_trust,
                      FileReference server_identity,
                      FileReference server_mlkem)
        : composite_key_(std::move(composite_key)),
          access_psk_(std::move(access_psk)),
          admission_key_(std::move(admission_key)),
          server_trust_(std::move(server_trust)),
          server_identity_(std::move(server_identity)),
          server_mlkem_(std::move(server_mlkem)) {}

    const FileReference& composite_key() const noexcept {
        return composite_key_;
    }
    const FileReference& access_psk() const noexcept {
        return access_psk_;
    }
    const FileReference& admission_key() const noexcept {
        return admission_key_;
    }
    const FileReference& server_trust() const noexcept {
        return server_trust_;
    }
    const FileReference& server_identity() const noexcept {
        return server_identity_;
    }
    const FileReference& server_mlkem() const noexcept {
        return server_mlkem_;
    }

private:
    FileReference composite_key_;
    FileReference access_psk_;
    FileReference admission_key_;
    FileReference server_trust_;
    FileReference server_identity_;
    FileReference server_mlkem_;
};

class ServerCredentials final {
public:
    ServerCredentials(FileReference composite_key,
                      FileReference authorized_keys,
                      FileReference admin_keys,
                      FileReference tls_certificate,
                      FileReference tls_key,
                      FileReference admission_key,
                      FileReference mlkem_key)
        : composite_key_(std::move(composite_key)),
          authorized_keys_(std::move(authorized_keys)),
          admin_keys_(std::move(admin_keys)),
          tls_certificate_(std::move(tls_certificate)),
          tls_key_(std::move(tls_key)),
          admission_key_(std::move(admission_key)),
          mlkem_key_(std::move(mlkem_key)) {}

    const FileReference& composite_key() const noexcept {
        return composite_key_;
    }
    // Ordinary traffic identities.
    const FileReference& authorized_keys() const noexcept {
        return authorized_keys_;
    }
    // Distinct second-factor identities, carrying no policy metadata. Keeping
    // this a separate mandatory store is what stops administrative capability
    // from ever becoming a field an operator can flip inside authorized_keys.
    const FileReference& admin_keys() const noexcept { return admin_keys_; }
    const FileReference& tls_certificate() const noexcept {
        return tls_certificate_;
    }
    const FileReference& tls_key() const noexcept { return tls_key_; }
    const FileReference& admission_key() const noexcept {
        return admission_key_;
    }
    const FileReference& mlkem_key() const noexcept { return mlkem_key_; }

private:
    FileReference composite_key_;
    FileReference authorized_keys_;
    FileReference admin_keys_;
    FileReference tls_certificate_;
    FileReference tls_key_;
    FileReference admission_key_;
    FileReference mlkem_key_;
};

using Credentials = std::variant<ClientCredentials, ServerCredentials>;

class ClientCover final {
public:
    explicit ClientCover(std::string profile)
        : profile_(std::move(profile)) {}

    const std::string& profile() const noexcept { return profile_; }

private:
    std::string profile_;
};

class StaticCover final {
public:
    StaticCover(std::string profile, FileReference root)
        : profile_(std::move(profile)), root_(std::move(root)) {}

    const std::string& profile() const noexcept { return profile_; }
    const FileReference& root() const noexcept { return root_; }

private:
    std::string profile_;
    FileReference root_;
};

class ReverseProxyCover final {
public:
    ReverseProxyCover(std::string profile, std::string url)
        : profile_(std::move(profile)), url_(std::move(url)) {}

    const std::string& profile() const noexcept { return profile_; }
    const std::string& url() const noexcept { return url_; }

private:
    std::string profile_;
    std::string url_;
};

using Cover = std::variant<ClientCover, StaticCover, ReverseProxyCover>;

class Service final {
public:
    Service(std::string name,
            ServiceKind kind,
            std::uint32_t max_concurrent_streams)
        : name_(std::move(name)),
          kind_(kind),
          max_concurrent_streams_(max_concurrent_streams) {}

    const std::string& name() const noexcept { return name_; }
    ServiceKind kind() const noexcept { return kind_; }
    std::uint32_t max_concurrent_streams() const noexcept {
        return max_concurrent_streams_;
    }

private:
    std::string name_;
    ServiceKind kind_;
    std::uint32_t max_concurrent_streams_;
};

class Socks5Adapter final {
public:
    Socks5Adapter(std::string service,
                  std::string listen_address,
                  std::uint16_t listen_port)
        : service_(std::move(service)),
          listen_address_(std::move(listen_address)),
          listen_port_(listen_port) {}

    const std::string& service() const noexcept { return service_; }
    const std::string& listen_address() const noexcept {
        return listen_address_;
    }
    std::uint16_t listen_port() const noexcept { return listen_port_; }

private:
    std::string service_;
    std::string listen_address_;
    std::uint16_t listen_port_;
};

class PacketAdapter final {
public:
    PacketAdapter(std::string service,
                  std::string interface_name,
                  std::uint16_t mtu)
        : service_(std::move(service)),
          interface_name_(std::move(interface_name)),
          mtu_(mtu) {}

    const std::string& service() const noexcept { return service_; }
    const std::string& interface_name() const noexcept {
        return interface_name_;
    }
    std::uint16_t mtu() const noexcept { return mtu_; }

private:
    std::string service_;
    std::string interface_name_;
    std::uint16_t mtu_;
};

class DirectTcpAdapter final {
public:
    explicit DirectTcpAdapter(std::string service)
        : service_(std::move(service)) {}

    const std::string& service() const noexcept { return service_; }

private:
    std::string service_;
};

class DirectUdpAdapter final {
public:
    explicit DirectUdpAdapter(std::string service)
        : service_(std::move(service)) {}

    const std::string& service() const noexcept { return service_; }

private:
    std::string service_;
};

using Adapter = std::variant<Socks5Adapter,
                             PacketAdapter,
                             DirectTcpAdapter,
                             DirectUdpAdapter>;

class ResourceLimits final {
public:
    ResourceLimits(std::uint32_t max_frame_bytes,
                   std::uint32_t max_streams,
                   std::uint32_t max_queued_bytes,
                   std::uint32_t max_pending_opens,
                   std::uint32_t max_rekey_jobs,
                   std::uint32_t max_control_messages,
                   std::uint32_t max_packet_bytes,
                   std::uint32_t max_packet_batch)
        : max_frame_bytes_(max_frame_bytes),
          max_streams_(max_streams),
          max_queued_bytes_(max_queued_bytes),
          max_pending_opens_(max_pending_opens),
          max_rekey_jobs_(max_rekey_jobs),
          max_control_messages_(max_control_messages),
          max_packet_bytes_(max_packet_bytes),
          max_packet_batch_(max_packet_batch) {}

    std::uint32_t max_frame_bytes() const noexcept {
        return max_frame_bytes_;
    }
    std::uint32_t max_streams() const noexcept { return max_streams_; }
    std::uint32_t max_queued_bytes() const noexcept {
        return max_queued_bytes_;
    }
    std::uint32_t max_pending_opens() const noexcept {
        return max_pending_opens_;
    }
    std::uint32_t max_rekey_jobs() const noexcept {
        return max_rekey_jobs_;
    }
    std::uint32_t max_control_messages() const noexcept {
        return max_control_messages_;
    }
    std::uint32_t max_packet_bytes() const noexcept {
        return max_packet_bytes_;
    }
    std::uint32_t max_packet_batch() const noexcept {
        return max_packet_batch_;
    }

private:
    std::uint32_t max_frame_bytes_;
    std::uint32_t max_streams_;
    std::uint32_t max_queued_bytes_;
    std::uint32_t max_pending_opens_;
    std::uint32_t max_rekey_jobs_;
    std::uint32_t max_control_messages_;
    std::uint32_t max_packet_bytes_;
    std::uint32_t max_packet_batch_;
};

class Config final {
public:
    Config(const Config&) = default;
    Config(Config&&) = default;
    Config& operator=(const Config&) = delete;
    Config& operator=(Config&&) = delete;

    std::uint32_t schema() const noexcept { return kSchema; }
    Role role() const noexcept { return role_; }
    const Endpoint& endpoint() const noexcept { return endpoint_; }
    const Suite& suite() const noexcept { return suite_; }
    const Credentials& credentials() const noexcept { return credentials_; }
    const Cover& cover() const noexcept { return cover_; }
    const std::vector<Service>& services() const noexcept { return services_; }
    const std::vector<Adapter>& adapters() const noexcept { return adapters_; }
    const ResourceLimits& limits() const noexcept { return limits_; }

private:
    Config(Role role,
           Endpoint endpoint,
           Suite suite,
           Credentials credentials,
           Cover cover,
           std::vector<Service> services,
           std::vector<Adapter> adapters,
           ResourceLimits limits)
        : role_(role),
          endpoint_(std::move(endpoint)),
          suite_(std::move(suite)),
          credentials_(std::move(credentials)),
          cover_(std::move(cover)),
          services_(std::move(services)),
          adapters_(std::move(adapters)),
          limits_(std::move(limits)) {}

    Role role_;
    Endpoint endpoint_;
    Suite suite_;
    Credentials credentials_;
    Cover cover_;
    std::vector<Service> services_;
    std::vector<Adapter> adapters_;
    ResourceLimits limits_;

    friend Config Parse(const nlohmann::json& document);
};

// Parses an already materialized JSON value. The returned object owns only
// validated typed values; it retains no JSON representation.
Config Parse(const nlohmann::json& document);

// Bounds input and nesting before delegating to Parse. No path is opened and
// no credential material is read by either entry point.
Config ParseJson(std::string_view text);

}  // namespace yume::config::v1
