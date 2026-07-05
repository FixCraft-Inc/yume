/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/runtime/manager.hpp"

#include <algorithm>
#include "server/federation/manager.hpp"
#include "server/auth/auth.hpp"
#include "server/filter/ip_filter.hpp"
#include "server/host/socket_util.hpp"
#include "server/packet/tun_egress.hpp"
#include "server/session/session.hpp"
#include "util.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <random>
#include <sstream>
#include <string_view>
#include <stdexcept>
#include <vector>

namespace yume::server {

class Manager::WeightedEgressLimiter {
public:
    explicit WeightedEgressLimiter(std::uint32_t cap_mbps)
        : bytes_per_second_(std::max<double>(1.0, static_cast<double>(cap_mbps) * 1'000'000.0 / 8.0)) {}

    std::chrono::milliseconds reserve(const std::string& key, std::uint32_t priority, std::size_t bytes) {
        if (key.empty() || bytes == 0 || bytes_per_second_ <= 0.0) {
            return std::chrono::milliseconds(0);
        }

        const std::uint32_t weight = std::clamp<std::uint32_t>(priority == 0 ? 50 : priority, 1, 100);
        const auto now = std::chrono::steady_clock::now();
        std::lock_guard<std::mutex> lock(mutex_);
        prune_inactive_locked(now);

        auto& current = clients_[key];
        current.weight = weight;

        std::uint64_t active_weight = 0;
        bool current_counted = false;
        for (const auto& [client_key, state] : clients_) {
            if (state.next_available > now) {
                active_weight += state.weight;
                if (client_key == key) {
                    current_counted = true;
                }
            }
        }
        if (!current_counted) {
            active_weight += weight;
        }
        if (active_weight == 0) {
            active_weight = weight;
        }

        const double share = static_cast<double>(weight) / static_cast<double>(active_weight);
        const double fair_rate = std::max(1.0, bytes_per_second_ * share);
        const auto start = current.next_available > now ? current.next_available : now;
        const std::chrono::duration<double> service_seconds(static_cast<double>(bytes) / fair_rate);
        auto service_duration = std::chrono::duration_cast<std::chrono::steady_clock::duration>(service_seconds);
        if (service_duration.count() <= 0) {
            service_duration = std::chrono::milliseconds(1);
        }
        current.next_available = start + service_duration;

        if (start <= now) {
            return std::chrono::milliseconds(0);
        }
        return std::chrono::duration_cast<std::chrono::milliseconds>(start - now);
    }

private:
    struct ClientState {
        std::uint32_t weight{50};
        std::chrono::steady_clock::time_point next_available{};
    };

    void prune_inactive_locked(std::chrono::steady_clock::time_point now) {
        if (clients_.size() <= 4096) {
            return;
        }
        const auto cutoff = now - std::chrono::minutes(5);
        for (auto it = clients_.begin(); it != clients_.end();) {
            if (it->second.next_available < cutoff) {
                it = clients_.erase(it);
            } else {
                ++it;
            }
        }
    }

    double bytes_per_second_{0.0};
    std::mutex mutex_;
    std::unordered_map<std::string, ClientState> clients_;
};

namespace {

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

bool server_context_allows_h2(const ServerConfig& cfg) {
    if (cfg.host_mode == host::HostMode::Private && !cfg.accept_yume_clients) {
        return false;
    }
    return cfg.obfuscation || !cfg.real_http;
}

}  // namespace

Manager::Manager(boost::asio::io_context& io, const ServerConfig& cfg)
    : io_(io)
    , cfg_(cfg)
    , acceptor_(io)
    , ssl_ctx_(obfs::create_server_context(cfg.tls_cert, cfg.tls_key, server_context_allows_h2(cfg)))
    , authorized_keys_(std::make_shared<const std::vector<crypto::Bytes>>())
    , server_id_(cfg.server_id.empty() ? yume::identity::generate_endpoint_id() : cfg.server_id)
    , server_name_(cfg.server_name.empty() ? std::string("yumed") : cfg.server_name) {
    cfg_.server_id = server_id_;
    cfg_.server_name = server_name_;
    if (cfg_.egress_mbps > 0) {
        egress_limiter_ = std::make_unique<WeightedEgressLimiter>(cfg_.egress_mbps);
    }
    if (!cfg_.filter_lists.empty() ||
        !cfg_.filter_geolite.empty() ||
        cfg_.client_filter_mode != "blacklist" ||
        cfg_.egress_filter_mode != "blacklist") {
        auto client_mode = IpFilter::parse_mode(cfg_.client_filter_mode);
        auto egress_mode = IpFilter::parse_mode(cfg_.egress_filter_mode);
        if (!client_mode.has_value()) {
            throw std::runtime_error("invalid client filter mode: " + cfg_.client_filter_mode);
        }
        if (!egress_mode.has_value()) {
            throw std::runtime_error("invalid egress filter mode: " + cfg_.egress_filter_mode);
        }
        std::vector<FilterListSpec> specs;
        specs.reserve(cfg_.filter_lists.size());
        for (const auto& raw : cfg_.filter_lists) {
            std::string parse_error;
            auto spec = IpFilter::parse_list_spec(raw, &parse_error);
            if (!spec.has_value()) {
                throw std::runtime_error("--filter-list " + raw + ": " + parse_error);
            }
            specs.push_back(std::move(*spec));
        }
        ip_filter_ = std::make_unique<IpFilter>();
        ip_filter_->configure(*client_mode, *egress_mode);
        std::string load_error;
        if (!ip_filter_->load(specs, cfg_.filter_geolite, cfg_.filter_memory_mib, &load_error)) {
            throw std::runtime_error("filter load failed: " + load_error);
        }
    }
    if (cfg_.host_mode != host::HostMode::Off) {
        host_routes_.set_routes(cfg_.host_routes);
    }
    if (!cfg_.packet_egress.empty() && cfg_.packet_egress != "off" && cfg_.packet_egress != "none") {
        packet_egress_ = std::make_unique<PacketTunEgress>(io_, cfg_);
    }
}

Manager::~Manager() = default;

void Manager::start() {
    if (cfg_.auth_keys.empty()) {
        throw std::runtime_error("auth_keys must be set");
    }

    std::shared_ptr<const std::vector<crypto::Bytes>> loaded_keys;
    try {
        loaded_keys = std::make_shared<const std::vector<crypto::Bytes>>(
            load_authorized_keys(cfg_.auth_keys));
    } catch (const std::exception& ex) {
        throw std::runtime_error(std::string("authorized_keys load failed: ") + ex.what());
    }
    {
        std::lock_guard<std::mutex> lock(auth_keys_mutex_);
        authorized_keys_ = loaded_keys;
    }

    if (loaded_keys->empty()) {
        util::log_warn("authorized_keys is empty");
    } else {
        util::log_info("loaded " + std::to_string(loaded_keys->size()) +
                       " authorized key(s) from " + cfg_.auth_keys);
    }
    if (cfg_.federation_enable) {
        if (cfg_.federation_auth_key.empty() || cfg_.federation_anonym_ca.empty() || cfg_.federation_peers.empty()) {
            util::log_warn("federation disabled: federation_auth_key, federation_anonym_ca, and peers are required");
            cfg_.federation_enable = false;
        } else {
            federation_ = std::make_unique<FederationManager>(io_, cfg_, this);
        }
    }

    // Pick the bind endpoint. Empty listen_address means legacy:
    // bind any (0.0.0.0). A non-empty listen_address parses as an
    // IPv4 or IPv6 literal; cfg validation (in main_server.cpp's
    // --public-node block) rejected private ranges already.
    boost::asio::ip::tcp::endpoint ep;
    if (cfg_.listen_address.empty()) {
        ep = boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), cfg_.listen_port);
    } else {
        boost::system::error_code addr_ec;
        auto addr = boost::asio::ip::make_address(cfg_.listen_address, addr_ec);
        if (addr_ec) {
            throw std::runtime_error("invalid listen address '" + cfg_.listen_address +
                                     "': " + addr_ec.message());
        }
        ep = boost::asio::ip::tcp::endpoint(addr,
                                            static_cast<unsigned short>(cfg_.listen_port));
    }
    acceptor_.open(ep.protocol());
    acceptor_.set_option(boost::asio::ip::tcp::acceptor::reuse_address(true));
    acceptor_.bind(ep);
    acceptor_.listen();

    const std::string bind_desc = cfg_.listen_address.empty()
        ? std::string("port ") + std::to_string(cfg_.listen_port)
        : cfg_.listen_address + ":" + std::to_string(cfg_.listen_port);
    if (util::is_logging_enabled()) {
        util::log_info("yumed listening on " + bind_desc);
    } else {
        std::cerr << "\033[1;33myumed listening on " << bind_desc << "\033[0m\n";
    }
    if (!cfg_.upstream_response_dir.empty()) {
        const std::size_t loaded = reload_upstream_responses();
        util::log_info("--upstream-response-dir " + cfg_.upstream_response_dir +
                       ": loaded " + std::to_string(loaded) +
                       " capture(s) for per-probe rotation");
        if (cfg_.upstream_response_ttl_s > 0) {
            upstream_reload_timer_ = std::make_unique<boost::asio::steady_timer>(io_);
            schedule_upstream_reload();
            util::log_info("--upstream-response-ttl " + std::to_string(cfg_.upstream_response_ttl_s) +
                           "s: directory will reload on every tick (drop new captures in without restarting)");
        }
    }
    if (egress_limiter_) {
        util::log_info("weighted egress fairness enabled: cap=" +
                       std::to_string(cfg_.egress_mbps) +
                       " Mbps, grouped by auth key, priority weight range=1..100 (default 50)");
    }
    if (ip_filter_ && ip_filter_->active()) {
        util::log_info("IP filtering active: " + ip_filter_->summary());
    }
    if (cfg_.host_mode != host::HostMode::Off) {
        util::log_info(std::string("host controller mode=") + host::to_string(cfg_.host_mode) +
                       " accept_yume_clients=" + (cfg_.accept_yume_clients ? "true" : "false") +
                       " client_deny_action=" + host::to_string(cfg_.client_deny_action) +
                       " routes=" + std::to_string(cfg_.host_routes.size()));
    }
    if (!cfg_.exposure_check_hostname.empty()) {
        exposure_result_ = host::probe_exposure(cfg_.exposure_check_hostname, cfg_.listen_port);
        util::log_info("exposure check for " + cfg_.exposure_check_hostname + ": " +
                       std::string(host::to_string(exposure_result_.kind)) + " (" +
                       exposure_result_.detail + ")");
        if (exposure_result_.kind == host::ExposureKind::CfHttpProxy) {
            util::log_warn("cloudflare HTTP proxy detected: YUME TLS carrier requires TCP passthrough (e.g. Spectrum)");
        }
    }
    if (cfg_.host_mode != host::HostMode::Off && !cfg_.extra_listeners.empty()) {
        extra_listeners_ = std::make_unique<ExtraListeners>(io_, ssl_ctx_, cfg_, this);
        extra_listeners_->start();
    }
    if (packet_egress_) {
        packet_egress_->start();
    }

    do_accept();
    if (federation_) {
        federation_->start();
    }
}

void Manager::stop() {
    if (extra_listeners_) {
        extra_listeners_->stop();
        extra_listeners_.reset();
    }
    if (federation_) {
        federation_->stop();
    }
    if (packet_egress_) {
        packet_egress_->stop();
    }
    if (upstream_reload_timer_) {
        // No-arg cancel(): the error_code overload of basic_waitable_timer::cancel
        // was removed in Boost.Asio 1.87 (the vcpkg arm64-osx build pulls it).
        // The no-arg form is valid on every Boost version and does not throw for
        // an ordinary timer cancellation.
        upstream_reload_timer_->cancel();
        upstream_reload_stopped_ = true;
    }
    boost::system::error_code ec;
    acceptor_.close(ec);

    std::vector<std::shared_ptr<runtime::ServiceStream>> pending_services;
    {
        std::lock_guard<std::mutex> lock(service_mutex_);
        services_stopping_ = true;
        registered_services_.clear();
        for (auto& [_, queue] : pending_service_streams_) {
            while (!queue.empty()) {
                pending_services.push_back(std::move(queue.front()));
                queue.pop_front();
            }
        }
        pending_service_streams_.clear();
    }
    service_cv_.notify_all();
    for (const auto& stream : pending_services) {
        if (stream) {
            stream->receive_close("server stopping");
        }
    }

    std::vector<std::shared_ptr<Session>> sessions;
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (auto it = live_sessions_.begin(); it != live_sessions_.end();) {
            auto session = it->second.lock();
            if (!session) {
                it = live_sessions_.erase(it);
                continue;
            }
            sessions.push_back(std::move(session));
            ++it;
        }
    }
    for (const auto& session : sessions) {
        session->notify_server_shutdown("server closed");
    }
}

std::size_t Manager::reload_upstream_responses() {
    if (cfg_.upstream_response_dir.empty()) {
        return 0;
    }
    namespace fs = std::filesystem;
    std::vector<std::string> loaded;
    std::error_code ec;
    if (!fs::is_directory(cfg_.upstream_response_dir, ec)) {
        util::log_warn("--upstream-response-dir: " + cfg_.upstream_response_dir +
                       " is not a directory");
        return 0;
    }
    // Stable order across reloads so deterministic captures (e.g.
    // numbered files) don't get reshuffled into a different mix that
    // confuses operators reading logs side-by-side with the dir
    // contents.
    std::vector<fs::path> files;
    for (const auto& entry : fs::directory_iterator(cfg_.upstream_response_dir, ec)) {
        if (!entry.is_regular_file()) continue;
        const auto ext = entry.path().extension().string();
        if (ext == ".http" || ext == ".response") {
            files.push_back(entry.path());
        }
    }
    std::sort(files.begin(), files.end());
    for (const auto& path : files) {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            util::log_warn("--upstream-response-dir: cannot open " + path.string());
            continue;
        }
        std::stringstream ss; ss << in.rdbuf();
        std::string raw = ss.str();
        std::string normalized;
        normalized.reserve(raw.size() + raw.size() / 16);
        for (std::size_t i = 0; i < raw.size(); ++i) {
            char c = raw[i];
            if (c == '\n' && (i == 0 || raw[i - 1] != '\r')) {
                normalized += '\r';
            }
            normalized += c;
        }
        if (normalized.rfind("HTTP/1.", 0) != 0) {
            util::log_warn("--upstream-response-dir: " + path.string() +
                           " does not start with 'HTTP/1.' (skipped)");
            continue;
        }
        loaded.push_back(std::move(normalized));
    }
    const std::size_t count = loaded.size();
    auto snapshot = std::make_shared<const std::vector<std::string>>(std::move(loaded));
    {
        std::lock_guard<std::mutex> lock(upstream_cache_mu_);
        upstream_cache_ = std::move(snapshot);
    }
    return count;
}

namespace {
std::size_t pick_index(std::size_t bound) {
    if (bound <= 1) return 0;
    thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<std::size_t> dist(0, bound - 1);
    return dist(rng);
}
}  // namespace

std::string Manager::upstream_response_pick() const {
    std::shared_ptr<const std::vector<std::string>> snap;
    {
        std::lock_guard<std::mutex> lock(upstream_cache_mu_);
        snap = upstream_cache_;
    }
    if (!snap || snap->empty()) {
        return {};
    }
    return (*snap)[pick_index(snap->size())];
}

bool Manager::egress_fairness_enabled() const {
    return static_cast<bool>(egress_limiter_);
}

std::chrono::milliseconds Manager::reserve_egress_write(const std::string& client_key,
                                                        std::uint32_t priority,
                                                        std::size_t bytes) {
    if (!egress_limiter_) {
        return std::chrono::milliseconds(0);
    }
    return egress_limiter_->reserve(client_key, priority, bytes);
}

bool Manager::packet_egress_active() const {
    return packet_egress_ && packet_egress_->active();
}

std::optional<PacketTunAssignment> Manager::register_packet_client(
    Session* session,
    std::function<void(crypto::Bytes)> handler) {
    if (!packet_egress_) {
        return std::nullopt;
    }
    return packet_egress_->register_client(session, std::move(handler));
}

void Manager::unregister_packet_client(Session* session, std::uint32_t ipv4_be) {
    if (packet_egress_) {
        packet_egress_->unregister_client(session, ipv4_be);
    }
}

void Manager::write_packet_to_egress(std::uint32_t client_ipv4_be, crypto::Bytes packet) {
    if (packet_egress_) {
        packet_egress_->write_packet(client_ipv4_be, std::move(packet));
    }
}

bool Manager::egress_allowed(const boost::asio::ip::address& address, std::string* reason) const {
    if (!ip_filter_) {
        return true;
    }
    const auto decision = ip_filter_->check_egress(address);
    if (!decision.allowed && reason) {
        *reason = decision.source.empty() ? "egress filter" : decision.source;
    }
    return decision.allowed;
}

void Manager::schedule_upstream_reload() {
    if (!upstream_reload_timer_ || upstream_reload_stopped_) {
        return;
    }
    upstream_reload_timer_->expires_after(std::chrono::seconds(cfg_.upstream_response_ttl_s));
    upstream_reload_timer_->async_wait([this](const boost::system::error_code& ec) {
        if (ec || upstream_reload_stopped_) return;
        const std::size_t n = reload_upstream_responses();
        util::log_info("--upstream-response-dir: reloaded " + std::to_string(n) +
                       " capture(s) from " + cfg_.upstream_response_dir);
        schedule_upstream_reload();
    });
}

void Manager::register_session(const std::shared_ptr<Session>& session) {
    if (!session) {
        return;
    }
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    live_sessions_[session.get()] = session;
}

void Manager::unregister_session(Session* session) {
    if (!session) {
        return;
    }
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    live_sessions_.erase(session);
}

void Manager::update_anonym_proof(const std::string& hash,
                                  const std::string& sig,
                                  const std::string& ts,
                                  const std::string& nonce,
                                  const std::string& certfp,
                                  const std::string& proof_policy,
                                  const std::vector<std::string>& proof_sources,
                                  const std::string& ca_sig,
                                  const std::string& ca_alg,
                                  const std::string& sub_sig,
                                  const std::string& sub_alg,
                                  const std::string& sub_cert_b64,
                                  const std::string& pq_pub_b64,
                                  const std::string& pq_sig,
                                  const std::string& pq_alg) {
    std::lock_guard<std::mutex> lock(cfg_mutex_);
    cfg_.anonym_hash = hash;
    cfg_.anonym_sig = sig;
    cfg_.anonym_ts = ts;
    cfg_.anonym_nonce = nonce;
    cfg_.anonym_certfp = certfp;
    cfg_.anonym_proof_mode = proof_policy;
    cfg_.anonym_proof_sources = proof_sources;
    cfg_.anonym_ca_sig = ca_sig;
    cfg_.anonym_ca_alg = ca_alg;
    cfg_.anonym_sub_sig = sub_sig;
    cfg_.anonym_sub_alg = sub_alg;
    cfg_.anonym_sub_cert_b64 = sub_cert_b64;
    cfg_.pq_pub_b64 = pq_pub_b64;
    cfg_.pq_sig = pq_sig;
    cfg_.pq_alg = pq_alg;
}

void Manager::register_reverse_listener(int port, const std::shared_ptr<Session>& session) {
    std::lock_guard<std::mutex> lock(reverse_mutex_);
    reverse_port_sessions_[port] = session;
}

void Manager::unregister_reverse_listener(int port, Session* session) {
    std::lock_guard<std::mutex> lock(reverse_mutex_);
    auto it = reverse_port_sessions_.find(port);
    if (it == reverse_port_sessions_.end()) {
        return;
    }
    auto current = it->second.lock();
    if (!current || current.get() == session) {
        reverse_port_sessions_.erase(it);
    }
}

bool Manager::reclaim_reverse_listener(int port, const Session* requester) {
    std::shared_ptr<Session> session;
    {
        std::lock_guard<std::mutex> lock(reverse_mutex_);
        auto it = reverse_port_sessions_.find(port);
        if (it == reverse_port_sessions_.end()) {
            return false;
        }
        session = it->second.lock();
        if (!session) {
            reverse_port_sessions_.erase(it);
            return true;
        }
    }

    const bool same_endpoint =
        requester != nullptr &&
        session.get() != requester &&
        !requester->endpoint_id().empty() &&
        requester->endpoint_id() == session->endpoint_id();
    if (!session->is_stale() && !same_endpoint) {
        return false;
    }
    if (same_endpoint) {
        util::log_warn("reclaiming reverse listener " + std::to_string(port) +
                       " for reconnecting endpoint " + requester->endpoint_id());
    }

    session->force_close_reverse_port(port);
    {
        std::lock_guard<std::mutex> lock(reverse_mutex_);
        auto it = reverse_port_sessions_.find(port);
        if (it != reverse_port_sessions_.end()) {
            auto current = it->second.lock();
            if (!current || current.get() == session.get()) {
                reverse_port_sessions_.erase(it);
            }
        }
    }
    return true;
}

void Manager::register_controlled_client(const std::shared_ptr<Session>& session, const ControlledClientInfo& info) {
    if (!session || info.id.empty()) {
        return;
    }
    ControlledClientEntry entry;
    entry.info = info;
    entry.session = session;
    std::lock_guard<std::mutex> lock(control_mutex_);
    controlled_clients_[info.id] = std::move(entry);
}

void Manager::unregister_controlled_client(Session* session) {
    if (!session) {
        return;
    }
    std::lock_guard<std::mutex> lock(control_mutex_);
    for (auto it = controlled_clients_.begin(); it != controlled_clients_.end();) {
        auto current = it->second.session.lock();
        if (!current || current.get() == session) {
            it = controlled_clients_.erase(it);
        } else {
            ++it;
        }
    }
}

std::vector<ControlledClientInfo> Manager::list_controlled_clients(bool anonym_only) {
    std::vector<ControlledClientInfo> out;
    std::lock_guard<std::mutex> lock(control_mutex_);
    for (auto it = controlled_clients_.begin(); it != controlled_clients_.end();) {
        auto current = it->second.session.lock();
        if (!current) {
            it = controlled_clients_.erase(it);
            continue;
        }
        if (anonym_only && !(it->second.info.allow_exec || it->second.info.server_in_charge)) {
            ++it;
            continue;
        }
        out.push_back(it->second.info);
        ++it;
    }
    return out;
}

std::shared_ptr<Session> Manager::find_controlled_session(const std::string& id, ControlledClientInfo* info) {
    if (id.empty()) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(control_mutex_);
    auto it = controlled_clients_.find(id);
    if (it == controlled_clients_.end()) {
        return nullptr;
    }
    auto session = it->second.session.lock();
    if (!session) {
        controlled_clients_.erase(it);
        return nullptr;
    }
    if (info) {
        *info = it->second.info;
    }
    return session;
}

const ServerConfig& Manager::config_snapshot() const {
    return cfg_;
}

void Manager::append_lifecycle_event_locked(const control::ClientLifecycleEvent& event) {
    lifecycle_events_.push_back(event);
    while (lifecycle_events_.size() > kMaxLifecycleEvents) {
        lifecycle_events_.pop_front();
    }
}

bool Manager::admit_accept() {
    // Hard session cap first — cheap to check, and it's the absolute
    // ceiling regardless of any rate concerns.
    if (cfg_.max_sessions > 0) {
        std::size_t live = 0;
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            live = live_sessions_.size();
        }
        if (live >= cfg_.max_sessions) {
            ++accept_refused_cap_;
            // Throttle the warn line to once per 64 refusals so a
            // sustained DoS doesn't fill the log faster than it
            // exhausts memory.
            if ((accept_refused_cap_ & 0x3F) == 1) {
                util::log_warn("accept refused: max_sessions cap " +
                              std::to_string(cfg_.max_sessions) +
                              " reached (live=" + std::to_string(live) +
                              ", refused-total=" + std::to_string(accept_refused_cap_) + ")");
            }
            return false;
        }
    }

    // Token bucket over a 1 s rolling window.
    if (cfg_.accept_rate_limit > 0) {
        const auto now = std::chrono::steady_clock::now();
        if (accept_window_start_.time_since_epoch().count() == 0 ||
            now - accept_window_start_ >= std::chrono::seconds(1)) {
            // Window expired — open a fresh one. Snap to now instead
            // of rolling forward by 1 s steps to keep the math simple;
            // worst-case effect of snapping is one extra refused
            // connection per window vs strict sliding semantics.
            accept_window_start_ = now;
            accept_window_count_ = 0;
        }
        if (accept_window_count_ >= cfg_.accept_rate_limit) {
            ++accept_refused_rate_;
            if ((accept_refused_rate_ & 0x3F) == 1) {
                util::log_warn("accept refused: rate-limit " +
                              std::to_string(cfg_.accept_rate_limit) +
                              "/s exceeded (refused-total=" +
                              std::to_string(accept_refused_rate_) + ")");
            }
            return false;
        }
        ++accept_window_count_;
    }
    return true;
}

bool Manager::register_service(const std::string& service, std::string* error) {
    if (!valid_service_name(service)) {
        if (error) *error = "invalid service name";
        return false;
    }
    {
        std::lock_guard<std::mutex> cfg_lock(cfg_mutex_);
        if (std::find(cfg_.allowed_services.begin(), cfg_.allowed_services.end(), service) ==
            cfg_.allowed_services.end()) {
            if (error) *error = "service is not enabled in server config";
            return false;
        }
    }
    std::lock_guard<std::mutex> lock(service_mutex_);
    if (services_stopping_) {
        if (error) *error = "server is stopping";
        return false;
    }
    registered_services_.insert(service);
    return true;
}

bool Manager::enqueue_service_stream(const std::string& service,
                                     std::shared_ptr<runtime::ServiceStream> stream,
                                     std::string* error) {
    if (!valid_service_name(service) || !stream) {
        if (error) *error = "invalid service stream";
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(service_mutex_);
        if (services_stopping_) {
            if (error) *error = "server is stopping";
            return false;
        }
        if (registered_services_.find(service) == registered_services_.end()) {
            if (error) *error = "service is not registered";
            return false;
        }
        pending_service_streams_[service].push_back(std::move(stream));
    }
    service_cv_.notify_all();
    return true;
}

std::shared_ptr<runtime::ServiceStream> Manager::accept_service_stream(
    const std::string& service,
    std::uint32_t timeout_ms,
    std::string* error) {
    if (!valid_service_name(service)) {
        if (error) *error = "invalid service name";
        return {};
    }
    std::unique_lock<std::mutex> lock(service_mutex_);
    if (registered_services_.find(service) == registered_services_.end()) {
        if (error) *error = "service is not registered";
        return {};
    }
    auto has_pending = [&]() {
        auto it = pending_service_streams_.find(service);
        return services_stopping_ || (it != pending_service_streams_.end() && !it->second.empty());
    };
    if (!has_pending()) {
        if (timeout_ms == 0) {
            if (error) *error = "no service stream is pending";
            return {};
        }
        if (!service_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), has_pending)) {
            if (error) *error = "timed out waiting for service stream";
            return {};
        }
    }
    if (services_stopping_) {
        if (error) *error = "server is stopping";
        return {};
    }
    auto& queue = pending_service_streams_[service];
    auto stream = std::move(queue.front());
    queue.pop_front();
    return stream;
}

std::shared_ptr<const std::vector<crypto::Bytes>>
Manager::authorized_keys_snapshot() const {
    std::lock_guard<std::mutex> lock(auth_keys_mutex_);
    return authorized_keys_;
}

void Manager::do_accept() {
    if (!acceptor_.is_open()) {
        return;
    }
    acceptor_.async_accept([this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
        if (!ec) {
            if (ip_filter_) {
                boost::system::error_code ep_ec;
                auto remote = socket.remote_endpoint(ep_ec);
                if (!ep_ec) {
                    const auto decision = ip_filter_->check_client(remote.address());
                    if (!decision.allowed) {
                        ++accept_refused_filter_;
                        if ((accept_refused_filter_ & 0x3F) == 1) {
                            util::log_info("accept refused by client IP filter (refused-total=" +
                                           std::to_string(accept_refused_filter_) + ")");
                        }
                        refuse_client_socket(socket);
                        if (acceptor_.is_open()) {
                            do_accept();
                        }
                        return;
                    }
                }
            }
            if (!admit_accept()) {
                refuse_client_socket(socket);
            } else {
                uint64_t session_id = next_session_id_.fetch_add(1);
                ServerConfig cfg_copy;
                {
                    std::lock_guard<std::mutex> lock(cfg_mutex_);
                    cfg_copy = cfg_;
                }
                auto session = std::make_shared<Session>(std::move(socket), ssl_ctx_,
                                                         cfg_copy,
                                                         authorized_keys_snapshot(),
                                                         session_id, this);
                register_session(session);
                session->start();
            }
        } else if (ec != boost::asio::error::operation_aborted && acceptor_.is_open()) {
            util::log_warn(std::string("accept failed: ") + ec.message());
        }
        if (acceptor_.is_open()) {
            do_accept();
        }
    });
}

void Manager::refuse_client_socket(boost::asio::ip::tcp::socket& socket) {
    host::close_socket(cfg_.client_deny_action, socket);
}

bool Manager::admit_plain_client(boost::asio::ip::tcp::socket& socket) {
    if (ip_filter_) {
        boost::system::error_code ep_ec;
        auto remote = socket.remote_endpoint(ep_ec);
        if (!ep_ec) {
            const auto decision = ip_filter_->check_client(remote.address());
            if (!decision.allowed) {
                ++accept_refused_filter_;
                refuse_client_socket(socket);
                return false;
            }
        }
    }
    if (!admit_accept()) {
        refuse_client_socket(socket);
        return false;
    }
    return true;
}

bool Manager::reload_auth(std::string* error) {
    std::string auth_keys_path;
    {
        std::lock_guard<std::mutex> lock(cfg_mutex_);
        auth_keys_path = cfg_.auth_keys;
    }
    if (auth_keys_path.empty()) {
        if (error) *error = "auth_keys must be set";
        return false;
    }

    std::shared_ptr<const std::vector<crypto::Bytes>> loaded_keys;
    try {
        loaded_keys = std::make_shared<const std::vector<crypto::Bytes>>(
            load_authorized_keys(auth_keys_path));
    } catch (const std::exception& ex) {
        if (error) {
            *error = std::string("authorized_keys reload failed: ") + ex.what();
        }
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(auth_keys_mutex_);
        authorized_keys_ = loaded_keys;
    }

    util::log_info("reloaded " + std::to_string(loaded_keys->size()) +
                   " authorized key(s) from " + auth_keys_path);
    if (error) error->clear();
    return true;
}

bool Manager::reload_client_filter(std::string* error) {
    if (!ip_filter_) {
        if (error) {
            *error = "client filter not configured";
        }
        return false;
    }
    auto client_mode = IpFilter::parse_mode(cfg_.client_filter_mode);
    auto egress_mode = IpFilter::parse_mode(cfg_.egress_filter_mode);
    if (!client_mode.has_value() || !egress_mode.has_value()) {
        if (error) {
            *error = "invalid filter mode";
        }
        return false;
    }
    std::vector<FilterListSpec> specs;
    specs.reserve(cfg_.filter_lists.size());
    for (const auto& raw : cfg_.filter_lists) {
        std::string parse_error;
        auto spec = IpFilter::parse_list_spec(raw, &parse_error);
        if (!spec.has_value()) {
            if (error) {
                *error = parse_error;
            }
            return false;
        }
        specs.push_back(std::move(*spec));
    }
    ip_filter_->configure(*client_mode, *egress_mode);
    std::string load_error;
    if (!ip_filter_->load(specs, cfg_.filter_geolite, cfg_.filter_memory_mib, &load_error)) {
        if (error) {
            *error = load_error;
        }
        return false;
    }
    return true;
}

bool Manager::kill_sessions(const std::string& query, std::string* error) {
    if (query.empty()) {
        if (error) {
            *error = "query required (session id, endpoint id, or client ip)";
        }
        return false;
    }
    std::vector<std::shared_ptr<Session>> targets;
    {
        std::lock_guard<std::mutex> lock(sessions_mutex_);
        for (auto& [ptr, weak] : live_sessions_) {
            auto session = weak.lock();
            if (!session) {
                continue;
            }
            if (std::to_string(session->session_id()) == query ||
                session->endpoint_id() == query ||
                session->client_wan_ip() == query) {
                targets.push_back(session);
            }
        }
    }
    if (targets.empty()) {
        if (error) {
            *error = "no matching session";
        }
        return false;
    }
    for (auto& session : targets) {
        session->stop();
    }
    return true;
}

nlohmann::json Manager::host_runtime_info() const {
    nlohmann::json routes = nlohmann::json::array();
    for (const auto& route : host_routes_.routes()) {
        routes.push_back({
            {"sni", route.sni},
            {"host", route.host},
            {"path_prefix", route.path_prefix},
            {"backend", route.backend},
        });
    }
    nlohmann::json listeners = nlohmann::json::array();
    for (const auto& listener : cfg_.extra_listeners) {
        listeners.push_back({
            {"bind_address", listener.bind_address},
            {"bind_port", listener.bind_port},
            {"mode", host::to_string(listener.mode)},
            {"backend", listener.backend},
        });
    }
    return {
        {"host_mode", host::to_string(cfg_.host_mode)},
        {"accept_yume_clients", cfg_.accept_yume_clients},
        {"client_deny_action", host::to_string(cfg_.client_deny_action)},
        {"accept_refused_filter", accept_refused_filter_},
        {"routes", routes},
        {"extra_listeners", listeners},
        {"exposure", {
             {"hostname", exposure_result_.hostname},
             {"kind", host::to_string(exposure_result_.kind)},
             {"detail", exposure_result_.detail},
         }},
    };
}

}  // namespace yume::server
