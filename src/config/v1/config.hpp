/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include <nlohmann/json_fwd.hpp>

#include "common/ip_network.hpp"

namespace yume::config::v1 {

inline constexpr std::uint32_t kSchema = 1;
inline constexpr std::size_t kMaxDocumentBytes = 1024U * 1024U;
inline constexpr std::size_t kMaxNestingDepth = 16;
inline constexpr std::size_t kMaxFileReferenceBytes = 4096;
inline constexpr std::size_t kMaxServices = 64;
inline constexpr std::size_t kMaxAdapters = 16;
inline constexpr std::size_t kMaxListenAddresses = 16;
inline constexpr std::size_t kMaxDestinationNetworks = 64;
inline constexpr std::size_t kMaxDestinationLists = 16;
// A UNIX socket path must fit sockaddr_un with its terminator.
inline constexpr std::size_t kMaxUnixSocketPathBytes = 107;
inline constexpr std::size_t kMaxModuleArguments = 32;
inline constexpr std::size_t kMaxModuleArgumentBytes = 1024;

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
    Forward,
    Module,
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

// A SOCKS5 proxy that the client reaches its server through. The proxy
// resolves host, or connects to connect_address when that is set. TLS and
// admission still authenticate host.
class Socks5Proxy final {
public:
    Socks5Proxy(std::string address,
                std::uint16_t port,
                std::optional<FileReference> credentials)
        : address_(std::move(address)),
          port_(port),
          credentials_(std::move(credentials)) {}

    // An IP literal. The client never resolves the proxy's own name.
    const std::string& address() const noexcept { return address_; }
    std::uint16_t port() const noexcept { return port_; }
    // A protected file: the username on the first line and the password on
    // the second. Without it the client offers no authentication.
    const std::optional<FileReference>& credentials() const noexcept {
        return credentials_;
    }

private:
    std::string address_;
    std::uint16_t port_;
    std::optional<FileReference> credentials_;
};

class ClientEndpoint final {
public:
    ClientEndpoint(std::string host,
                   std::uint16_t port,
                   std::optional<std::string> connect_address,
                   std::optional<Socks5Proxy> socks5_proxy = std::nullopt)
        : host_(std::move(host)),
          port_(port),
          connect_address_(std::move(connect_address)),
          socks5_proxy_(std::move(socks5_proxy)) {}

    const std::string& host() const noexcept { return host_; }
    std::uint16_t port() const noexcept { return port_; }
    // A numeric address dialled instead of resolving host. TLS and admission
    // still authenticate host.
    const std::optional<std::string>& connect_address() const noexcept {
        return connect_address_;
    }
    const std::optional<Socks5Proxy>& socks5_proxy() const noexcept {
        return socks5_proxy_;
    }
    // Where the client's own TCP connection goes: the proxy when one is set,
    // else connect_address, else host. A managed TUN keeps it out of the
    // tunnel.
    const std::string& first_hop() const noexcept {
        if (socks5_proxy_) return socks5_proxy_->address();
        return connect_address_ ? *connect_address_ : host_;
    }

private:
    std::string host_;
    std::uint16_t port_;
    std::optional<std::string> connect_address_;
    std::optional<Socks5Proxy> socks5_proxy_;
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
                  std::uint16_t listen_port,
                  std::optional<std::string> udp_service = std::nullopt)
        : service_(std::move(service)),
          listen_address_(std::move(listen_address)),
          listen_port_(listen_port),
          udp_service_(std::move(udp_service)) {}

    const std::string& service() const noexcept { return service_; }
    const std::string& listen_address() const noexcept {
        return listen_address_;
    }
    std::uint16_t listen_port() const noexcept { return listen_port_; }
    // The packet service UDP ASSOCIATE opens. Without one, the adapter
    // refuses UDP ASSOCIATE.
    const std::optional<std::string>& udp_service() const noexcept {
        return udp_service_;
    }

private:
    std::string service_;
    std::string listen_address_;
    std::uint16_t listen_port_;
    std::optional<std::string> udp_service_;
};

struct TunNetwork final {
    std::vector<common::IpInterfaceAddress> addresses;
    std::vector<common::IpNetwork> routes;
    // Packet source and destination authorization, reversed on receive.
    std::vector<common::IpNetwork> local_networks;
    std::vector<common::IpNetwork> peer_networks;
    std::vector<common::IpInterfaceAddress> dns_servers;
    // Routing domains only. "." routes all DNS queries through this link.
    std::vector<std::string> dns_domains;
};

class PacketAdapter final {
public:
    PacketAdapter(std::string service,
                  std::string interface_name,
                  std::uint16_t mtu,
                  TunNetwork network)
        : service_(std::move(service)),
          interface_name_(std::move(interface_name)),
          mtu_(mtu), network_(std::move(network)) {}

    const std::string& service() const noexcept { return service_; }
    const std::string& interface_name() const noexcept {
        return interface_name_;
    }
    std::uint16_t mtu() const noexcept { return mtu_; }
    const TunNetwork& network() const noexcept { return network_; }

private:
    std::string service_;
    std::string interface_name_;
    std::uint16_t mtu_;
    TunNetwork network_;
};

enum class DestinationListAction : std::uint8_t {
    Allow,
    Deny,
};

enum class DestinationListFormat : std::uint8_t {
    // {"ips": [...], "countries": [...]}
    Json,
    // The binary VPN provider database, format 1.
    Vpdb,
};

// An egress list file. The runtime reads it when the policy is built.
class DestinationList final {
public:
    DestinationList(DestinationListAction action,
                    DestinationListFormat format,
                    FileReference file)
        : action_(action), format_(format), file_(std::move(file)) {}

    DestinationListAction action() const noexcept { return action_; }
    DestinationListFormat format() const noexcept { return format_; }
    const FileReference& file() const noexcept { return file_; }

private:
    DestinationListAction action_;
    DestinationListFormat format_;
    FileReference file_;
};

// Destinations a direct adapter may reach. Public addresses are globally
// reachable unicast addresses. Each network also permits its explicit prefix,
// including private or loopback space. Unspecified, multicast and reserved
// addresses are never reachable. A policy permits at least one destination.
// Egress lists only narrow that: a destination their most specific entry
// denies is refused. Countries in lists need a MaxMind country database.
class DestinationPolicy final {
public:
    DestinationPolicy(bool public_addresses,
                      std::vector<common::IpNetwork> networks,
                      std::vector<DestinationList> lists = {},
                      std::optional<FileReference> country_database = std::nullopt)
        : public_addresses_(public_addresses),
          networks_(std::move(networks)),
          lists_(std::move(lists)),
          country_database_(std::move(country_database)) {}

    bool public_addresses() const noexcept { return public_addresses_; }
    const std::vector<common::IpNetwork>& networks() const noexcept {
        return networks_;
    }
    const std::vector<DestinationList>& lists() const noexcept { return lists_; }
    const std::optional<FileReference>& country_database() const noexcept {
        return country_database_;
    }

private:
    bool public_addresses_;
    std::vector<common::IpNetwork> networks_;
    std::vector<DestinationList> lists_;
    std::optional<FileReference> country_database_;
};

class DirectTcpAdapter final {
public:
    DirectTcpAdapter(std::string service, DestinationPolicy destinations)
        : service_(std::move(service)), destinations_(std::move(destinations)) {}

    const std::string& service() const noexcept { return service_; }
    const DestinationPolicy& destinations() const noexcept {
        return destinations_;
    }

private:
    std::string service_;
    DestinationPolicy destinations_;
};

class DirectUdpAdapter final {
public:
    DirectUdpAdapter(std::string service, DestinationPolicy destinations)
        : service_(std::move(service)), destinations_(std::move(destinations)) {}

    const std::string& service() const noexcept { return service_; }
    const DestinationPolicy& destinations() const noexcept {
        return destinations_;
    }

private:
    std::string service_;
    DestinationPolicy destinations_;
};

// Where a client forward listens: a loopback TCP address and port, or an
// absolute UNIX socket path.
struct LoopbackListener final {
    std::string address;
    std::uint16_t port;
};

struct UnixListener final {
    std::string path;
};

using ForwardListener = std::variant<LoopbackListener, UnixListener>;

// The TCP destination each of a forward's streams names. The server's
// direct_tcp destinations decide whether it is reachable.
struct ForwardDestination final {
    std::string host;
    std::uint16_t port;
};

// Every local connection becomes one byte-stream OPEN on the service. With a
// destination the OPEN carries it. Without one, the server's handler for the
// service decides where the stream goes.
class ForwardAdapter final {
public:
    ForwardAdapter(std::string service,
                   ForwardListener listener,
                   std::optional<ForwardDestination> destination)
        : service_(std::move(service)),
          listener_(std::move(listener)),
          destination_(std::move(destination)) {}

    const std::string& service() const noexcept { return service_; }
    const ForwardListener& listener() const noexcept { return listener_; }
    const std::optional<ForwardDestination>& destination() const noexcept {
        return destination_;
    }

private:
    std::string service_;
    ForwardListener listener_;
    std::optional<ForwardDestination> destination_;
};

// A server module: a program that serves one stream service. The daemon
// starts it, restarts it after it exits and hands it each authorized stream
// of the service as a connection on a private UNIX socket.
class ModuleAdapter final {
public:
    ModuleAdapter(std::string service,
                  std::string program,
                  std::vector<std::string> arguments)
        : service_(std::move(service)),
          program_(std::move(program)),
          arguments_(std::move(arguments)) {}

    const std::string& service() const noexcept { return service_; }
    // An absolute path. The daemon runs it with arguments after its own name.
    const std::string& program() const noexcept { return program_; }
    const std::vector<std::string>& arguments() const noexcept {
        return arguments_;
    }

private:
    std::string service_;
    std::string program_;
    std::vector<std::string> arguments_;
};

using Adapter = std::variant<Socks5Adapter,
                             PacketAdapter,
                             DirectTcpAdapter,
                             DirectUdpAdapter,
                             ForwardAdapter,
                             ModuleAdapter>;

class ResourceLimits final {
public:
    ResourceLimits(std::uint32_t max_frame_bytes,
                   std::uint32_t max_streams,
                   std::uint32_t max_queued_bytes,
                   std::uint32_t max_pending_opens,
                   std::uint32_t max_rekey_jobs,
                   std::uint32_t max_control_messages,
                   std::uint32_t max_packet_bytes,
                   std::uint32_t max_packet_batch,
                   std::optional<std::uint32_t> max_egress_mbps = std::nullopt)
        : max_frame_bytes_(max_frame_bytes),
          max_streams_(max_streams),
          max_queued_bytes_(max_queued_bytes),
          max_pending_opens_(max_pending_opens),
          max_rekey_jobs_(max_rekey_jobs),
          max_control_messages_(max_control_messages),
          max_packet_bytes_(max_packet_bytes),
          max_packet_batch_(max_packet_batch),
          max_egress_mbps_(max_egress_mbps) {}

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
    // Server only: the rate, in megabits per second, that stream payload
    // shares across authenticated identities by weight. Absent means
    // unlimited.
    const std::optional<std::uint32_t>& max_egress_mbps() const noexcept {
        return max_egress_mbps_;
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
    std::optional<std::uint32_t> max_egress_mbps_;
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
