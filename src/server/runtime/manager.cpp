/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/runtime/manager.hpp"

#include <future>

#include <boost/asio/bind_executor.hpp>
#include <boost/asio/strand.hpp>
#include "server/runtime/service_queue_policy.hpp"
#include "server/runtime/weighted_egress_limiter.hpp"

#include "core/protocol/directory_policy.hpp"
#include "core/runtime/file_transaction_lock.hpp"

#include <algorithm>
#include "server/federation/manager.hpp"
#include "server/auth/auth.hpp"
#include "server/filter/ip_filter.hpp"
#include "server/host/socket_util.hpp"
#include "server/packet/tun_egress.hpp"
#include "server/runtime/cover_response.hpp"
#include "server/session/session.hpp"
#include "util.hpp"

#include <filesystem>
#include <iostream>
#include <random>
#include <string_view>
#include <stdexcept>
#include <vector>
#include <boost/asio/error.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>

namespace yume::server {

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

bool key_sets_overlap(const std::vector<crypto::Bytes>& regular,
                      const std::vector<crypto::Bytes>& operators) {
    for (const auto& regular_key : regular) {
        if (std::find(operators.begin(), operators.end(), regular_key) !=
            operators.end()) {
            return true;
        }
    }
    return false;
}

void validate_auth_policy_store(const AuthKeyPolicyMap& policies,
                                bool operator_store) {
    for (const auto& [fingerprint, policy] : policies) {
        if (operator_store && policy.key_type == AuthKeyType::Bulk) {
            throw std::runtime_error(
                "operator key " + fingerprint + " cannot use key_type 'bulk'");
        }
        if (!operator_store && policy.allow_outbound_admin.value_or(false)) {
            throw std::runtime_error(
                "regular key " + fingerprint +
                " cannot grant allow_outbound_admin; move the key to operator_keys");
        }
    }
}

}  // namespace

Manager::Manager(boost::asio::io_context& io, const ServerConfig& cfg)
    : io_(io)
    , cfg_(cfg)
    , accept_strand_(boost::asio::make_strand(io))
    , acceptor_(accept_strand_)
    , ssl_ctx_(obfs::create_server_context(cfg.tls_cert, cfg.tls_key, server_context_allows_h2(cfg)))
    , authorized_keys_(std::make_shared<const std::vector<crypto::Bytes>>())
    , auth_policies_(std::make_shared<const AuthKeyPolicyMap>())
    , operator_keys_(std::make_shared<const std::vector<crypto::Bytes>>())
    , operator_policies_(std::make_shared<const AuthKeyPolicyMap>())
    , admission_replay_cache_(std::make_shared<obfs::AdmissionReplayCache>())
    , server_id_(cfg.server_id.empty() ? yume::identity::generate_endpoint_id() : cfg.server_id)
    , server_name_(cfg.server_name.empty() ? std::string("yumed") : cfg.server_name) {
    cfg_.server_id = server_id_;
    cfg_.server_name = server_name_;
    if (!control::is_valid_directory_server_identity(
            server_id_, server_name_, cfg_.federation_enable)) {
        throw std::runtime_error(
            cfg_.federation_enable
                ? "invalid server identity: federation server_id must be 1-64 "
                  "ASCII letters, digits, '.', '_' or '-', and server_name "
                  "must be safe text within the directory limit"
                : "invalid server identity: server_id/server_name must be "
                  "nonempty safe text within the directory limits");
    }
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
    std::shared_ptr<const AuthKeyPolicyMap> loaded_policies;
    std::shared_ptr<const std::vector<crypto::Bytes>> loaded_operator_keys;
    std::shared_ptr<const AuthKeyPolicyMap> loaded_operator_policies;
    std::shared_ptr<const std::vector<crypto::Bytes>> loaded_admin_keys;
    runtime::FileTransactionLock snapshot_lock;
    std::string lock_error;
    if (!snapshot_lock.Acquire(
            {cfg_.auth_keys, cfg_.auth_keys_meta, cfg_.operator_keys,
             cfg_.operator_keys_meta, cfg_.admin_keys},
            &lock_error)) {
        throw std::runtime_error(
            "authorization snapshot lock failed: " + lock_error);
    }
    try {
        loaded_keys = std::make_shared<const std::vector<crypto::Bytes>>(
            load_authorized_keys(cfg_.auth_keys));
    } catch (const std::exception& ex) {
        throw std::runtime_error(std::string("authorized_keys load failed: ") +
                                 ex.what());
    }
    try {
        loaded_policies = std::make_shared<const AuthKeyPolicyMap>(
            load_auth_policies(cfg_.auth_keys_meta));
        validate_auth_policy_store(*loaded_policies, false);
    } catch (const std::exception& ex) {
        throw std::runtime_error(std::string("auth_keys_meta load failed: ") +
                                 ex.what());
    }
    try {
        loaded_operator_keys = std::make_shared<const std::vector<crypto::Bytes>>(
            cfg_.operator_keys.empty()
                ? std::vector<crypto::Bytes>{}
                : load_authorized_keys(cfg_.operator_keys));
        loaded_operator_policies = std::make_shared<const AuthKeyPolicyMap>(
            load_auth_policies(cfg_.operator_keys_meta));
        validate_auth_policy_store(*loaded_operator_policies, true);
    } catch (const std::exception& ex) {
        throw std::runtime_error(std::string("operator key store load failed: ") +
                                 ex.what());
    }
    if (key_sets_overlap(*loaded_keys, *loaded_operator_keys)) {
        throw std::runtime_error(
            "the same public key is present in auth_keys and operator_keys");
    }
    validate_unique_federation_peer_ids(
        *loaded_policies, *loaded_operator_policies);
    try {
        loaded_admin_keys = std::make_shared<const std::vector<crypto::Bytes>>(
            cfg_.admin_keys.empty()
                ? std::vector<crypto::Bytes>{}
                : load_admin_keys(cfg_.admin_keys));
    } catch (const std::exception& ex) {
        throw std::runtime_error(std::string("admin_keys load failed: ") +
                                 ex.what());
    }
    // An identity in both stores would satisfy "two distinct keys" using two
    // credentials the same person already holds for ordinary access, which is
    // not the separation the requirement asks for. Refuse at startup rather
    // than discovering it per-session.
    if (key_sets_overlap(*loaded_keys, *loaded_admin_keys) ||
        key_sets_overlap(*loaded_operator_keys, *loaded_admin_keys)) {
        throw std::runtime_error(
            "the same public key is present in a visitor store and admin_keys; "
            "the admin list must be disjoint from auth_keys and operator_keys");
    }
    {
        std::lock_guard<std::mutex> lock(auth_keys_mutex_);
        authorized_keys_ = loaded_keys;
        admin_keys_ = loaded_admin_keys;
        auth_policies_ = loaded_policies;
        operator_keys_ = loaded_operator_keys;
        operator_policies_ = loaded_operator_policies;
    }
    snapshot_lock.Unlock();

    if (loaded_keys->empty()) {
        util::log_warn("authorized_keys is empty");
    } else {
        util::log_info("loaded " + std::to_string(loaded_keys->size()) +
                       " authorized key(s) from " + cfg_.auth_keys);
    }
    if (!loaded_operator_keys->empty()) {
        util::log_info("loaded " + std::to_string(loaded_operator_keys->size()) +
                       " operator key(s) from " + cfg_.operator_keys);
    }
    if (cfg_.federation_enable) {
        if (cfg_.federation_identity.empty() ||
            cfg_.federation_operator_ca.empty() ||
            (cfg_.federation_peers.empty() && !cfg_.cluster_bootstrap)) {
            util::log_warn(
                "federation disabled: federation_identity, "
                "federation_operator_ca, and peers (or cluster_bootstrap) "
                "are required");
            cfg_.federation_enable = false;
        } else {
            federation_ = std::make_unique<FederationManager>(io_, cfg_, this);
        }
    }

    // An empty address binds 0.0.0.0. Explicit addresses must be IP literals.
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
                       " Mbps, grouped by authenticated identity, weight range=0.1..100 (default 1.0)");
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
    {
        std::lock_guard<std::mutex> lock(endpoint_mutex_);
        invite_expiry_stopped_ = true;
        if (invite_expiry_timer_) {
            invite_expiry_timer_->cancel();
        }
        invites_.clear();
    }
    // basic_socket_acceptor is not thread-safe, and the accept completion
    // handler reads is_open() on the io_context thread. Closing from the
    // caller's thread races that read on the acceptor's internal state.
    // ThreadSanitizer catches it whenever a server is started and stopped
    // in-process, which the C ABI does and yumed never did.
    //
    // RuntimeController::stop() runs this before io->stop(). During startup
    // rollback there may not be a worker yet, so this thread polls the context
    // until it executes the strand-confined close. Never fall back to touching
    // the acceptor off-strand: a delayed strand handler is evidence of
    // contention, not evidence that concurrent access became safe.
    if (accept_strand_.running_in_this_thread()) {
        boost::system::error_code ec;
        acceptor_.close(ec);
    } else {
        auto closed = std::make_shared<std::promise<void>>();
        std::future<void> closed_future = closed->get_future();
        boost::asio::post(accept_strand_, [this, closed]() {
            boost::system::error_code ec;
            acceptor_.close(ec);
            closed->set_value();
        });
        while (closed_future.wait_for(std::chrono::milliseconds::zero()) !=
               std::future_status::ready) {
            if (io_.poll_one() == 0U) {
                (void)closed_future.wait_for(std::chrono::milliseconds(1));
            }
        }
    }

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
        pending_service_stream_count_ = 0;
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
    std::size_t directory_entries = 0;
    fs::directory_iterator iterator(cfg_.upstream_response_dir, ec);
    const fs::directory_iterator end;
    for (; !ec && iterator != end; iterator.increment(ec)) {
        const auto& entry = *iterator;
        if (++directory_entries > cover_response::kMaxDirectoryEntries) {
            util::log_warn(
                "--upstream-response-dir: directory entry limit exceeded; "
                "keeping the previous capture set");
            return 0;
        }
        std::error_code entry_ec;
        if (!entry.is_regular_file(entry_ec) || entry_ec) continue;
        const auto ext = entry.path().extension().string();
        if (ext == ".http" || ext == ".response") {
            files.push_back(entry.path());
            if (files.size() > cover_response::kMaxResponseFiles) {
                util::log_warn(
                    "--upstream-response-dir: capture count limit exceeded; "
                    "keeping the previous capture set");
                return 0;
            }
        }
    }
    if (ec) {
        util::log_warn("--upstream-response-dir: cannot enumerate " +
                       cfg_.upstream_response_dir + ": " + ec.message());
        return 0;
    }
    std::sort(files.begin(), files.end());
    std::size_t loaded_bytes = 0;
    for (const auto& path : files) {
        std::string normalized;
        std::string error;
        if (!cover_response::load_file(path, &normalized, &error)) {
            util::log_warn("--upstream-response-dir: " + error +
                           " (skipped)");
            continue;
        }
        if (normalized.size() >
            cover_response::kMaxCacheBytes - loaded_bytes) {
            util::log_warn(
                "--upstream-response-dir: aggregate capture size limit "
                "reached; remaining captures skipped");
            break;
        }
        loaded_bytes += normalized.size();
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
                                                        double weight,
                                                        std::size_t bytes) {
    if (!egress_limiter_) {
        return std::chrono::milliseconds(0);
    }
    return egress_limiter_->reserve(client_key, weight, bytes);
}

bool Manager::admit_authenticated_identity(std::uint64_t session_id,
                                           const std::string& fingerprint,
                                           std::uint32_t max_sessions,
                                           std::string* error) {
    return identity_admission_.admit(
        session_id, fingerprint, max_sessions, error);
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

bool Manager::write_packets_to_egress(std::uint32_t client_ipv4_be,
                                      std::vector<crypto::Bytes> packets) {
    if (packet_egress_) {
        return packet_egress_->write_packets(
            client_ipv4_be, std::move(packets));
    }
    return false;
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

void Manager::register_inbound_federation_session(
        Session* session, const std::string& peer_id) {
    if (session == nullptr || !cfg_.federation_enable ||
        !is_valid_federation_peer_id(peer_id)) {
        return;
    }
    const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    inbound_federation_sessions_[session] =
        InboundFederationSession{peer_id, now};
}

void Manager::unregister_session(Session* session) {
    if (!session) {
        return;
    }
    identity_admission_.release(session->session_id());
    std::lock_guard<std::mutex> lock(sessions_mutex_);
    inbound_federation_sessions_.erase(session);
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
    std::lock_guard<std::mutex> admission_lock(accept_admission_mutex_);

    // Hard session cap first — cheap to check, and it's the absolute
    // ceiling regardless of any rate concerns.
    if (cfg_.max_sessions > 0) {
        std::size_t live = 0;
        {
            std::lock_guard<std::mutex> lock(sessions_mutex_);
            live = live_sessions_.size();
        }
        if (live >= cfg_.max_sessions) {
            const auto refused_total =
                accept_refused_cap_.fetch_add(1, std::memory_order_relaxed) + 1;
            // Throttle the warn line to once per 64 refusals so a
            // sustained DoS doesn't fill the log faster than it
            // exhausts memory.
            if ((refused_total & 0x3F) == 1) {
                util::log_warn("accept refused: max_sessions cap " +
                              std::to_string(cfg_.max_sessions) +
                              " reached (live=" + std::to_string(live) +
                              ", refused-total=" + std::to_string(refused_total) + ")");
            }
            return false;
        }
    }

    // Fixed one-second accounting window shared by all listeners.
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
            const auto refused_total =
                accept_refused_rate_.fetch_add(1, std::memory_order_relaxed) + 1;
            if ((refused_total & 0x3F) == 1) {
                util::log_warn("accept refused: rate-limit " +
                              std::to_string(cfg_.accept_rate_limit) +
                              "/s exceeded (refused-total=" +
                              std::to_string(refused_total) + ")");
            }
            return false;
        }
        ++accept_window_count_;
    }
    return true;
}

bool Manager::register_service(
    const std::string& service,
    std::string* error,
    runtime::OperationStatus* operation_status) {
    if (error) error->clear();
    runtime::SetOperationStatus(
        operation_status, runtime::OperationStatus::InternalError);
    if (!valid_service_name(service)) {
        if (error) *error = "invalid service name";
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::InvalidArgument);
        return false;
    }
    {
        std::lock_guard<std::mutex> cfg_lock(cfg_mutex_);
        if (std::find(cfg_.allowed_services.begin(), cfg_.allowed_services.end(), service) ==
            cfg_.allowed_services.end()) {
            if (error) *error = "service is not enabled in server config";
            runtime::SetOperationStatus(
                operation_status, runtime::OperationStatus::PermissionDenied);
            return false;
        }
    }
    std::lock_guard<std::mutex> lock(service_mutex_);
    if (services_stopping_) {
        if (error) *error = "server is stopping";
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::NotRunning);
        return false;
    }
    registered_services_.insert(service);
    runtime::SetOperationStatus(
        operation_status, runtime::OperationStatus::Success);
    return true;
}

bool Manager::enqueue_service_stream(const std::string& service,
                                     std::shared_ptr<runtime::ServiceStream> stream,
                                     std::string* error,
                                     runtime::OperationStatus* operation_status) {
    if (error) error->clear();
    runtime::SetOperationStatus(
        operation_status, runtime::OperationStatus::InternalError);
    if (!valid_service_name(service) || !stream) {
        if (error) *error = "invalid service stream";
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::InvalidArgument);
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(service_mutex_);
        if (services_stopping_) {
            if (error) *error = "server is stopping";
            runtime::SetOperationStatus(
                operation_status, runtime::OperationStatus::NotRunning);
            return false;
        }
        if (registered_services_.find(service) == registered_services_.end()) {
            if (error) *error = "service is not registered";
            runtime::SetOperationStatus(
                operation_status, runtime::OperationStatus::NotFound);
            return false;
        }
        auto& queue = pending_service_streams_[service];
        if (!service_queue_policy::admission_allowed(
                pending_service_stream_count_, queue.size())) {
            if (error) *error = "pending service stream limit reached";
            runtime::SetOperationStatus(
                operation_status, runtime::OperationStatus::ResourceExhausted);
            return false;
        }
        queue.push_back(std::move(stream));
        ++pending_service_stream_count_;
    }
    service_cv_.notify_all();
    runtime::SetOperationStatus(
        operation_status, runtime::OperationStatus::Success);
    return true;
}

std::shared_ptr<runtime::ServiceStream> Manager::accept_service_stream(
    const std::string& service,
    std::uint32_t timeout_ms,
    std::string* error,
    runtime::OperationStatus* operation_status) {
    if (error) error->clear();
    runtime::SetOperationStatus(
        operation_status, runtime::OperationStatus::InternalError);
    if (!valid_service_name(service)) {
        if (error) *error = "invalid service name";
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::InvalidArgument);
        return {};
    }
    std::unique_lock<std::mutex> lock(service_mutex_);
    if (registered_services_.find(service) == registered_services_.end()) {
        if (error) *error = "service is not registered";
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::NotFound);
        return {};
    }
    auto has_pending = [&]() {
        auto it = pending_service_streams_.find(service);
        return services_stopping_ || (it != pending_service_streams_.end() && !it->second.empty());
    };
    if (!has_pending()) {
        if (timeout_ms == 0) {
            if (error) *error = "no service stream is pending";
            runtime::SetOperationStatus(
                operation_status, runtime::OperationStatus::WouldBlock);
            return {};
        }
        if (!service_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), has_pending)) {
            if (error) *error = "timed out waiting for service stream";
            runtime::SetOperationStatus(
                operation_status, runtime::OperationStatus::Timeout);
            return {};
        }
    }
    if (services_stopping_) {
        if (error) *error = "server is stopping";
        runtime::SetOperationStatus(
            operation_status, runtime::OperationStatus::NotRunning);
        return {};
    }
    auto& queue = pending_service_streams_[service];
    auto stream = std::move(queue.front());
    queue.pop_front();
    if (pending_service_stream_count_ > 0) {
        --pending_service_stream_count_;
    }
    if (queue.empty()) {
        pending_service_streams_.erase(service);
    }
    runtime::SetOperationStatus(
        operation_status, runtime::OperationStatus::Success);
    return stream;
}

Manager::AuthStateSnapshot Manager::auth_state_snapshot() const {
    std::lock_guard<std::mutex> lock(auth_keys_mutex_);
    return {authorized_keys_, auth_policies_, operator_keys_, operator_policies_,
            admin_keys_};
}

void Manager::do_accept() {
    if (!acceptor_.is_open()) {
        return;
    }
    acceptor_.async_accept(boost::asio::bind_executor(
        accept_strand_,
        [this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
        if (!ec) {
            if (ip_filter_) {
                boost::system::error_code ep_ec;
                auto remote = socket.remote_endpoint(ep_ec);
                if (!ep_ec) {
                    const auto decision = ip_filter_->check_client(remote.address());
                    if (!decision.allowed) {
                        const auto refused_total =
                            accept_refused_filter_.fetch_add(
                                1, std::memory_order_relaxed) + 1;
                        if ((refused_total & 0x3F) == 1) {
                            util::log_info("accept refused by client IP filter (refused-total=" +
                                           std::to_string(refused_total) + ")");
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
                const auto auth_state = auth_state_snapshot();
                auto session = std::make_shared<Session>(std::move(socket), ssl_ctx_,
                                                         cfg_copy,
                                                         auth_state.keys,
                                                         auth_state.policies,
                                                         auth_state.operator_keys,
                                                         auth_state.operator_policies,
                                                         auth_state.admin_keys,
                                                         admission_replay_cache_,
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
        }));
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
                accept_refused_filter_.fetch_add(1, std::memory_order_relaxed);
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
    std::string auth_keys_meta_path;
    std::string operator_keys_path;
    std::string operator_keys_meta_path;
    std::string admin_keys_path;
    {
        std::lock_guard<std::mutex> lock(cfg_mutex_);
        auth_keys_path = cfg_.auth_keys;
        auth_keys_meta_path = cfg_.auth_keys_meta;
        operator_keys_path = cfg_.operator_keys;
        operator_keys_meta_path = cfg_.operator_keys_meta;
        admin_keys_path = cfg_.admin_keys;
    }
    if (auth_keys_path.empty()) {
        if (error) *error = "auth_keys must be set";
        return false;
    }

    std::shared_ptr<const std::vector<crypto::Bytes>> loaded_keys;
    std::shared_ptr<const AuthKeyPolicyMap> loaded_policies;
    std::shared_ptr<const std::vector<crypto::Bytes>> loaded_operator_keys;
    std::shared_ptr<const AuthKeyPolicyMap> loaded_operator_policies;
    std::shared_ptr<const std::vector<crypto::Bytes>> loaded_admin_keys;
    runtime::FileTransactionLock snapshot_lock;
    std::string lock_error;
    if (!snapshot_lock.Acquire(
            {auth_keys_path, auth_keys_meta_path, operator_keys_path,
             operator_keys_meta_path, admin_keys_path},
            &lock_error)) {
        if (error) {
            *error = "authorization snapshot lock failed: " + lock_error;
        }
        return false;
    }
    try {
        loaded_keys = std::make_shared<const std::vector<crypto::Bytes>>(
            load_authorized_keys(auth_keys_path));
    } catch (const std::exception& ex) {
        if (error) {
            *error = std::string("authorized_keys reload failed: ") + ex.what();
        }
        return false;
    }
    try {
        loaded_policies = std::make_shared<const AuthKeyPolicyMap>(
            load_auth_policies(auth_keys_meta_path));
        validate_auth_policy_store(*loaded_policies, false);
    } catch (const std::exception& ex) {
        if (error) {
            *error = std::string("auth_keys_meta reload failed: ") + ex.what();
        }
        return false;
    }
    try {
        loaded_operator_keys = std::make_shared<const std::vector<crypto::Bytes>>(
            operator_keys_path.empty()
                ? std::vector<crypto::Bytes>{}
                : load_authorized_keys(operator_keys_path));
        loaded_operator_policies = std::make_shared<const AuthKeyPolicyMap>(
            load_auth_policies(operator_keys_meta_path));
        validate_auth_policy_store(*loaded_operator_policies, true);
    } catch (const std::exception& ex) {
        if (error) {
            *error = std::string("operator key store reload failed: ") + ex.what();
        }
        return false;
    }
    if (key_sets_overlap(*loaded_keys, *loaded_operator_keys)) {
        if (error) {
            *error = "the same public key is present in auth_keys and operator_keys";
        }
        return false;
    }
    try {
        validate_unique_federation_peer_ids(
            *loaded_policies, *loaded_operator_policies);
    } catch (const std::exception& ex) {
        if (error) {
            *error = ex.what();
        }
        return false;
    }
    try {
        loaded_admin_keys = std::make_shared<const std::vector<crypto::Bytes>>(
            admin_keys_path.empty()
                ? std::vector<crypto::Bytes>{}
                : load_admin_keys(admin_keys_path));
    } catch (const std::exception& ex) {
        if (error) {
            *error = std::string("admin_keys reload failed: ") + ex.what();
        }
        return false;
    }
    if (key_sets_overlap(*loaded_keys, *loaded_admin_keys) ||
        key_sets_overlap(*loaded_operator_keys, *loaded_admin_keys)) {
        if (error) {
            *error =
                "the same public key is present in a visitor store and "
                "admin_keys; the admin list must be disjoint from auth_keys "
                "and operator_keys";
        }
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(auth_keys_mutex_);
        authorized_keys_ = loaded_keys;
        auth_policies_ = loaded_policies;
        operator_keys_ = loaded_operator_keys;
        operator_policies_ = loaded_operator_policies;
        admin_keys_ = loaded_admin_keys;
    }
    snapshot_lock.Unlock();

    util::log_info("reloaded " + std::to_string(loaded_keys->size()) +
                   " authorized key(s) and " +
                   std::to_string(loaded_policies->size()) +
                   " regular policy entries and " +
                   std::to_string(loaded_operator_keys->size()) +
                   " operator key(s) and " +
                   std::to_string(loaded_admin_keys->size()) +
                   " admin key(s)");
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

bool Manager::kill_sessions(RuntimeSessionSelector selector,
                            const std::string& value,
                            std::string* error) {
    if (value.empty()) {
        if (error) {
            *error = "session selector value is required";
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
            if (runtime_session_selector_matches(
                    selector, value, session->session_id(),
                    session->endpoint_id(), session->client_wan_ip())) {
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
        {"accept_refused_filter",
         accept_refused_filter_.load(std::memory_order_relaxed)},
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
