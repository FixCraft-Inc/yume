/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2020-2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/relay/runtime.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>
#include <span>
#include <stdexcept>
#include <utility>

#include <boost/asio/post.hpp>
#include "core/protocol/directory_policy.hpp"
#include "core/protocol/relay_policy.hpp"
#include "core/security/secure_erase.hpp"
#include "util.hpp"

namespace yume::client {

namespace {

inline constexpr std::size_t kMaxPendingApplicationRecords = 8;
inline constexpr std::size_t kMaxPendingApplicationBytes = 256U * 1024U;
inline constexpr std::uint16_t kRelayRekeyWindow =
    ratchet::kDefaultRekeyWindow;

std::string bytes_to_b64(const crypto::Bytes& bytes) {
    return yume::util::base64_encode(std::string(bytes.begin(), bytes.end()));
}

crypto::Bytes b64_to_bytes(const std::string& value) {
    std::string raw = yume::util::base64_decode(value);
    struct RawWiper {
        std::string* value;
        ~RawWiper() { if (value) wipe_relay_secret(*value); }
    } raw_wiper{&raw};
    return crypto::Bytes(raw.begin(), raw.end());
}

}  // namespace

struct RelayRuntime::OutboundTransfer {
    uint8_t stream_id{0};
    control::ChannelKind kind{control::ChannelKind::file};
    std::shared_ptr<RelayOutboundSource> source;
    std::string name;
    std::uint64_t expected_size{0};
    std::uint64_t sent_size{0};
    enum class Phase { metadata, chunks, done } phase{Phase::metadata};
};

RelayRuntime::PendingOutgoingInvite::~PendingOutgoingInvite() {
    expected_peer_identity.clear();
    expires_at = {};
}

RelayRuntime::PendingIncomingInvite::~PendingIncomingInvite() {
    ratchet.reset();
    expires_at = {};
}

RelayRuntime::PendingApplication::PendingApplication(
        relay_v2::Bytes value, ChannelWriteCompletion callback)
    : plaintext(std::move(value)), completion(std::move(callback)) {}

RelayRuntime::PendingApplication::PendingApplication(
        PendingApplication&& other) noexcept
    : plaintext(std::move(other.plaintext)),
      completion(std::move(other.completion)) {}

RelayRuntime::PendingApplication&
RelayRuntime::PendingApplication::operator=(PendingApplication&& other) noexcept {
    if (this != &other) {
        security::secure_erase(plaintext);
        plaintext = std::move(other.plaintext);
        completion = std::move(other.completion);
    }
    return *this;
}

RelayRuntime::PendingApplication::~PendingApplication() {
    security::secure_erase(plaintext);
}

RelayRuntime::ChannelState::~ChannelState() {
    if (receive_timer) {
        boost::system::error_code ignored;
        receive_timer->cancel(ignored);
    }
    if (rekey_timer) {
        boost::system::error_code ignored;
        rekey_timer->cancel(ignored);
    }
    receiver.Abort();
    pending_applications.clear();
    pending_application_bytes = 0;
    ratchet.reset();
}

RelayRuntime::RelayRuntime(std::shared_ptr<Tunnel> tunnel, ClientConfig cfg, Options options)
    : tunnel_(std::move(tunnel))
    , cfg_(std::move(cfg))
    , options_(std::move(options))
    , history_(options_.history_enabled ? options_.history_dir : std::filesystem::path(),
               options_.instance_name.empty() ? "default" : options_.instance_name) {
#if !defined(_WIN32)
    peer_trust_ = std::make_unique<relay_v2::PeerTrustStore>(
        options_.peer_trust);
#endif
    if (options_.receive_dir.empty() && !options_.history_dir.empty()) {
        options_.receive_dir = options_.history_dir.parent_path() / "received";
    }
#if defined(_WIN32)
    // Windows does not yet have descriptor-relative/reparse-safe receive-file
    // creation. Keep the rest of relay usable but never advertise receipt.
    options_.allow_file = false;
    options_.allow_bytes = false;
#endif
    self_.endpoint_kind = control::EndpointKind::client;
    self_.hostname = options_.hostname;
    self_.client_platform = options_.client_platform;
    self_.client_variant = options_.client_variant;
    self_.client_version = options_.client_version;
    self_.relay_mode = options_.relay_mode;
    self_.allow_inbound_admin = options_.allow_inbound_admin;
    self_.allow_outbound_admin = options_.allow_outbound_admin;
    self_.allow_chat = options_.allow_chat;
    self_.allow_file = options_.allow_file;
    self_.allow_bytes = options_.allow_bytes;
    self_.display_name = options_.preferred_name;
    self_.endpoint_id = options_.preferred_id;
    auto keys = load_identity_keypair();
    self_.auth_pubkey_b64 = bytes_to_b64(
        relay_v2::EncodeIdentity(keys));
}

RelayRuntime::~RelayRuntime() {
    std::lock_guard<std::mutex> lock(mutex_);
    ++pending_invite_timer_generation_;
    if (pending_invite_timer_) {
        boost::system::error_code ignored;
        pending_invite_timer_->cancel(ignored);
        pending_invite_timer_.reset();
    }
    outgoing_invites_.clear();
    incoming_invites_.clear();
    channels_.clear();
    active_chat_stream_.reset();
    active_admin_stream_.reset();
}

bool RelayRuntime::announce_presence(std::string* error) {
    if ((options_.allow_file || options_.allow_bytes) &&
        !PrepareRelayReceiveDirectory(options_.receive_dir, error)) {
        return false;
    }
    nlohmann::json req;
    req["cmd"] = "presence.announce";
    req["endpoint_kind"] = "client";
    req["preferred_id"] = options_.preferred_id;
    req["preferred_name"] = options_.preferred_name;
    req["hostname"] = options_.hostname;
    req["client_platform"] = options_.client_platform;
    req["client_variant"] = options_.client_variant;
    req["client_version"] = options_.client_version;
    req["relay_mode"] = control::to_string(options_.relay_mode);
    req["allow_chat"] = options_.allow_chat;
    req["allow_file"] = options_.allow_file;
    req["allow_bytes"] = options_.allow_bytes;
    req["allow_inbound_admin"] = options_.allow_inbound_admin;
    req["allow_outbound_admin"] = options_.allow_outbound_admin;
    auto resp = send_control_request(std::move(req), error);
    if (!resp.value("ok", false)) {
        if (error) {
            *error = resp.value("error", "presence announce failed");
        }
        return false;
    }
    std::string name;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        self_ = control::endpoint_from_json(resp.value("endpoint", nlohmann::json::object()));
        server_id_ = resp.value("server_id", "");
        server_name_ = resp.value("server_name", "");
        name = self_.display_name.empty() ? self_.endpoint_id : self_.display_name;
    }
    std::string ignored_error;
    notify_lifecycle("connecting",
                     "connecting now, im " + name,
                     "client registered with relay directory",
                     "",
                     false,
                     "",
                     "",
                     &ignored_error,
                     1500,
                     true);
    return true;
}

std::vector<control::EndpointInfo> RelayRuntime::request_directory(std::string* error) {
    auto resp = send_control_request({{"cmd", "directory.list"}}, error);
    auto clear_directory = [this]() {
        std::lock_guard<std::mutex> lock(mutex_);
        server_id_.clear();
        server_name_.clear();
        update_directory_locked({});
    };
    if (resp.is_object() && resp.contains("ok") &&
        resp["ok"].is_boolean() && !resp["ok"].get<bool>()) {
        clear_directory();
        if (error) {
            *error = resp.contains("error") && resp["error"].is_string()
                ? resp["error"].get<std::string>()
                : "directory request failed";
        }
        return {};
    }

    std::string parse_error;
    auto parsed = control::try_directory_response_from_json(
        resp, control::DirectoryNamespace::ClientVisible, &parse_error);
    if (!parsed) {
        clear_directory();
        if (error) {
            *error = parse_error.empty()
                ? "directory response is invalid" : parse_error;
        }
        return {};
    }

    auto out = std::move(parsed->endpoints);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        server_id_ = std::move(parsed->server_id);
        server_name_ = std::move(parsed->server_name);
        update_directory_locked(out);
    }
    return out;
}

control::EndpointInfo RelayRuntime::self_info() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return self_;
}

std::vector<control::PendingInvite> RelayRuntime::pending_invites() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<control::PendingInvite> out;
    out.reserve(incoming_invites_.size());
    for (const auto& entry : incoming_invites_) {
        out.push_back(entry.second.invite);
    }
    return out;
}

bool RelayRuntime::open_chat(const std::string& peer, const std::string& relay_secret_b64, std::string* error) {
    if (relay_secret_b64.empty()) {
        if (error) {
            *error = "relay password is required";
        }
        return false;
    }
    if (!validate_relay_secret_b64(relay_secret_b64, error)) {
        return false;
    }
    auto peer_list = request_directory(error);
    (void)peer_list;
    std::lock_guard<std::mutex> lock(mutex_);
    auto peer_info = resolve_peer_locked(peer);
    if (!peer_info.has_value()) {
        if (error) {
            *error = "peer not found";
        }
        return false;
    }
    if (!peer_info->allow_chat) {
        if (error) {
            *error = "peer disabled chat";
        }
        return false;
    }
    control::PendingInvite invite;
    invite.invite_id = next_invite_id();
    invite.from_endpoint_id = self_.endpoint_id;
    invite.to_endpoint_id = peer_info->endpoint_id;
    invite.channel_kind = control::ChannelKind::chat;
    invite.requires_password = true;
    invite.from_display_name = self_.display_name;
    return begin_outgoing_invite_locked(
        std::move(invite), *peer_info, relay_secret_b64, {}, {}, error);
}

bool RelayRuntime::send_chat(const std::string& text, std::string* error) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!active_chat_stream_.has_value()) {
        if (error) {
            *error = "no active chat channel";
        }
        return false;
    }
    auto it = channels_.find(*active_chat_stream_);
    if (it == channels_.end() ||
        it->second.channel_kind != control::ChannelKind::chat) {
        if (error) {
            *error = "chat channel unavailable";
        }
        return false;
    }
    nlohmann::json message{{"type", "chat"}, {"text", text}, {"ts_ms", yume::util::now_ms()}};
    std::string send_error;
    if (!send_channel_payload_locked(
            it->second, message.dump(), {}, &send_error)) {
        const uint8_t stream_id = it->second.stream_id;
        close_channel_locked(
            stream_id,
            send_error.empty() ? "chat write failed" : send_error);
        if (error) {
            *error = send_error.empty() ? "chat write failed" : send_error;
        }
        return false;
    }
    append_history(it->second.peer_id, it->second.peer_name, "out", text);
    return true;
}

bool RelayRuntime::send_file(const std::string& peer, const std::filesystem::path& path, const std::string& relay_secret_b64, std::string* error) {
    const std::string transfer_name = path.filename().string();
    if (!RelayFileReceiver::IsSafeBasename(transfer_name)) {
        if (error) *error = "file name is not a safe portable relay basename";
        return false;
    }
    if (relay_secret_b64.empty()) {
        if (error) {
            *error = "relay password is required";
        }
        return false;
    }
    if (!validate_relay_secret_b64(relay_secret_b64, error)) {
        return false;
    }
    std::shared_ptr<RelayOutboundSource> source;
    std::string transfer_sha256;
    try {
        source = RelayOutboundSource::Open(
            path, options_.receive_limits.max_transfer_bytes, error);
        if (source) transfer_sha256 = source->Sha256Hex(error);
    } catch (const std::exception& ex) {
        if (error) {
            *error = std::string("failed to prepare relay transfer source: ") +
                     ex.what();
        }
        return false;
    }
    if (!source) {
        return false;
    }
    const auto transfer_size = source->size();
    if (!RelayFileReceiver::IsCanonicalSha256Digest(transfer_sha256)) {
        if (error && error->empty()) {
            *error = "failed to hash relay transfer source";
        }
        return false;
    }
    auto peer_list = request_directory(error);
    (void)peer_list;
    std::lock_guard<std::mutex> lock(mutex_);
    auto peer_info = resolve_peer_locked(peer);
    if (!peer_info.has_value()) {
        if (error) {
            *error = "peer not found";
        }
        return false;
    }
    if (!peer_info->allow_file) {
        if (error) *error = "peer disabled file relay";
        return false;
    }
    control::PendingInvite invite;
    invite.invite_id = next_invite_id();
    invite.from_endpoint_id = self_.endpoint_id;
    invite.to_endpoint_id = peer_info->endpoint_id;
    invite.channel_kind = control::ChannelKind::file;
    invite.requires_password = true;
    invite.from_display_name = self_.display_name;
    nlohmann::json meta{
        {"name", transfer_name},
        {"size", static_cast<std::uint64_t>(transfer_size)},
        {"sha256", transfer_sha256},
    };
    invite.metadata_json = meta.dump();
    return begin_outgoing_invite_locked(
        std::move(invite), *peer_info, relay_secret_b64,
        std::move(source), {}, error);
}

bool RelayRuntime::send_bytes_path(const std::string& peer, const std::filesystem::path& path, const std::string& relay_secret_b64, std::string* error) {
    const std::string transfer_name = path.filename().string();
    if (!RelayFileReceiver::IsSafeBasename(transfer_name)) {
        if (error) *error = "byte source name is not a safe portable relay basename";
        return false;
    }
    if (relay_secret_b64.empty()) {
        if (error) {
            *error = "relay password is required";
        }
        return false;
    }
    if (!validate_relay_secret_b64(relay_secret_b64, error)) {
        return false;
    }
    std::shared_ptr<RelayOutboundSource> source;
    std::string transfer_sha256;
    try {
        source = RelayOutboundSource::Open(
            path, options_.receive_limits.max_transfer_bytes, error);
        if (source) transfer_sha256 = source->Sha256Hex(error);
    } catch (const std::exception& ex) {
        if (error) {
            *error = std::string("failed to prepare relay byte source: ") +
                     ex.what();
        }
        return false;
    }
    if (!source) {
        return false;
    }
    const auto transfer_size = source->size();
    if (!RelayFileReceiver::IsCanonicalSha256Digest(transfer_sha256)) {
        if (error && error->empty()) {
            *error = "failed to hash relay byte source";
        }
        return false;
    }
    auto peer_list = request_directory(error);
    (void)peer_list;
    std::lock_guard<std::mutex> lock(mutex_);
    auto peer_info = resolve_peer_locked(peer);
    if (!peer_info.has_value()) {
        if (error) {
            *error = "peer not found";
        }
        return false;
    }
    if (!peer_info->allow_bytes) {
        if (error) *error = "peer disabled byte relay";
        return false;
    }
    control::PendingInvite invite;
    invite.invite_id = next_invite_id();
    invite.from_endpoint_id = self_.endpoint_id;
    invite.to_endpoint_id = peer_info->endpoint_id;
    invite.channel_kind = control::ChannelKind::bytes;
    invite.requires_password = true;
    invite.from_display_name = self_.display_name;
    invite.metadata_json = nlohmann::json{
        {"name", transfer_name},
        {"size", static_cast<std::uint64_t>(transfer_size)},
        {"sha256", transfer_sha256},
    }.dump();
    return begin_outgoing_invite_locked(
        std::move(invite), *peer_info, relay_secret_b64,
        std::move(source),
        transfer_name, error);
}

bool RelayRuntime::accept_invite(const std::string& invite_id, const std::string& relay_secret_b64, std::string* error) {
    std::lock_guard<std::mutex> lock(mutex_);
    expire_pending_invites_locked(std::chrono::steady_clock::now());
    schedule_pending_invite_expiry_locked();
    bool ambiguous = false;
    auto find_invite = [&](const std::string& selector) {
        auto direct = incoming_invites_.find(selector);
        if (direct != incoming_invites_.end()) {
            return direct;
        }
        auto match = incoming_invites_.end();
        for (auto it = incoming_invites_.begin(); it != incoming_invites_.end(); ++it) {
            const auto& invite = it->second.invite;
            if (invite.from_endpoint_id != selector && invite.from_display_name != selector) {
                continue;
            }
            if (match != incoming_invites_.end()) {
                ambiguous = true;
                return incoming_invites_.end();
            }
            match = it;
        }
        return match;
    };
    auto it = find_invite(invite_id);
    if (it == incoming_invites_.end()) {
        if (error) {
            *error = ambiguous ? "invite selector is ambiguous" : "invite not found";
        }
        return false;
    }
    auto& pending = it->second;
    if (pending.invite.accepted || pending.ratchet) {
        if (error) *error = "invite has already been accepted";
        return false;
    }
    if (!control::relay_v2_password_policy_valid(
            pending.invite.channel_kind,
            pending.invite.requires_password) ||
        !control::relay_target_allows(self_, pending.invite.channel_kind)) {
        if (error) *error = "invite no longer satisfies local relay policy";
        return false;
    }
    if (pending.invite.requires_password && relay_secret_b64.empty()) {
        if (error) {
            *error = "invite password is required";
        }
        return false;
    }
    if (pending.invite.requires_password && !validate_relay_secret_b64(relay_secret_b64, error)) {
        return false;
    }
    if (!pending.invite.requires_password && !relay_secret_b64.empty()) {
        if (error) *error = "admin invites must not use a relay password";
        return false;
    }
    try {
        const relay_v2::Bytes initiator_identity =
            decode_relay_identity(
                pending.invite.from_auth_pubkey_b64);
        (void)peer_trust_store().precheck(
            pending.source_trust_id, initiator_identity,
            trust_requirement(pending.invite.channel_kind));

        const auto request = b64_to_bytes(
            pending.invite.handshake_request_b64);
        const auto inspected =
            relay_v2::InspectInitiatorRequest(request);
        const auto expected_context = make_handshake_context(
            pending.invite, inspected.nonce);
        if (inspected != expected_context) {
            throw std::runtime_error(
                "relay-v2 request context does not match the invite");
        }

        auto identity = load_identity_keypair();
        const relay_v2::Bytes own_identity =
            relay_v2::EncodeIdentity(identity);
        const std::string own_identity_b64 = bytes_to_b64(own_identity);
        if (self_.auth_pubkey_b64.empty() ||
            own_identity_b64 != self_.auth_pubkey_b64) {
            throw std::runtime_error(
                "relay identity does not match the authenticated session");
        }

        auto relay_psk = decode_relay_psk(relay_secret_b64);
        struct PskWiper {
            relay_v2::Bytes& value;
            ~PskWiper() { security::secure_erase(value); }
        } psk_wiper{relay_psk};
        auto response = relay_v2::Respond(
            request, expected_context, initiator_identity,
            identity, std::move(relay_psk));
        (void)peer_trust_store().commit_verified(
            pending.source_trust_id, initiator_identity,
            trust_requirement(pending.invite.channel_kind));

        pending.ratchet = relay_v2::MakeSessionRatchet(
            std::move(response.secrets),
            ratchet::EndpointRole::Server,
            kRelayRekeyWindow, kRelayRekeyWindow,
            ratchet::kExtremePolicy, ratchet::kExtremePolicy);
        pending.invite.response_present = true;
        pending.invite.accepted = true;
        pending.invite.response_reason.clear();
        pending.invite.handshake_response_b64 =
            bytes_to_b64(response.encoded);
        pending.invite.responder_auth_pubkey_b64 = own_identity_b64;
        pending.expires_at = std::chrono::steady_clock::now() +
            control::kPendingRelayInviteLifetime;
        schedule_pending_invite_expiry_locked();
    } catch (const std::exception& ex) {
        incoming_invites_.erase(it);
        schedule_pending_invite_expiry_locked();
        if (error) *error = std::string("failed to accept relay invite: ") + ex.what();
        return false;
    }
    nlohmann::json req = control::invite_to_json(pending.invite, true);
    req["cmd"] = "invite.reply";
    try {
        tunnel_->send_control_json(req);
    } catch (const std::exception& ex) {
        incoming_invites_.erase(it);
        schedule_pending_invite_expiry_locked();
        if (error) {
            *error = std::string("failed to send relay invite reply: ") +
                ex.what();
        }
        return false;
    }
    return true;
}

bool RelayRuntime::reject_invite(const std::string& invite_id, const std::string& reason, std::string* error) {
    std::lock_guard<std::mutex> lock(mutex_);
    expire_pending_invites_locked(std::chrono::steady_clock::now());
    schedule_pending_invite_expiry_locked();
    bool ambiguous = false;
    auto find_invite = [&](const std::string& selector) {
        auto direct = incoming_invites_.find(selector);
        if (direct != incoming_invites_.end()) {
            return direct;
        }
        auto match = incoming_invites_.end();
        for (auto it = incoming_invites_.begin(); it != incoming_invites_.end(); ++it) {
            const auto& invite = it->second.invite;
            if (invite.from_endpoint_id != selector && invite.from_display_name != selector) {
                continue;
            }
            if (match != incoming_invites_.end()) {
                ambiguous = true;
                return incoming_invites_.end();
            }
            match = it;
        }
        return match;
    };
    auto it = find_invite(invite_id);
    if (it == incoming_invites_.end()) {
        if (error) {
            *error = ambiguous ? "invite selector is ambiguous" : "invite not found";
        }
        return false;
    }
    it->second.invite.accepted = false;
    it->second.invite.response_present = true;
    it->second.invite.response_reason = reason.empty() ? "rejected" : reason;
    nlohmann::json req = control::invite_to_json(it->second.invite, true);
    req["cmd"] = "invite.reply";
    incoming_invites_.erase(it);
    schedule_pending_invite_expiry_locked();
    try {
        tunnel_->send_control_json(req);
    } catch (const std::exception& ex) {
        if (error) {
            *error = std::string("failed to send relay invite rejection: ") +
                ex.what();
        }
        return false;
    }
    return true;
}

bool RelayRuntime::admin_attach(const std::string& peer, std::string* error) {
    auto peer_list = request_directory(error);
    (void)peer_list;
    std::lock_guard<std::mutex> lock(mutex_);
    auto peer_info = resolve_peer_locked(peer);
    if (!peer_info.has_value()) {
        if (error) {
            *error = "peer not found";
        }
        return false;
    }
    if (options_.relay_mode != control::RelayMode::trusted) {
        if (error) {
            *error = "admin attach requires trusted relay mode";
        }
        return false;
    }
    if (!options_.allow_outbound_admin || !peer_info->allow_inbound_admin) {
        if (error) {
            *error = "admin attach requires local outbound-admin and peer inbound-admin permission";
        }
        return false;
    }
    control::PendingInvite invite;
    invite.invite_id = next_invite_id();
    invite.from_endpoint_id = self_.endpoint_id;
    invite.to_endpoint_id = peer_info->endpoint_id;
    invite.channel_kind = control::ChannelKind::admin;
    invite.requires_password = false;
    invite.from_display_name = self_.display_name;
    return begin_outgoing_invite_locked(
        std::move(invite), *peer_info, {}, {}, {}, error);
}

std::optional<control::EndpointInfo> RelayRuntime::resolve_peer_locked(const std::string& peer) const {
    auto it = directory_by_id_.find(peer);
    if (it != directory_by_id_.end()) {
        return it->second;
    }
    auto it_name = directory_name_to_id_.find(peer);
    if (it_name != directory_name_to_id_.end()) {
        auto it_id = directory_by_id_.find(it_name->second);
        if (it_id != directory_by_id_.end()) {
            return it_id->second;
        }
    }
    return std::nullopt;
}

void RelayRuntime::update_directory_locked(const std::vector<control::EndpointInfo>& endpoints) {
    directory_by_id_.clear();
    directory_name_to_id_.clear();
    for (const auto& endpoint : endpoints) {
        directory_by_id_.emplace(endpoint.endpoint_id, endpoint);
        const auto [name_it, inserted] = directory_name_to_id_.emplace(
            endpoint.display_name, endpoint.endpoint_id);
        if (!inserted) {
            // Empty is an impossible endpoint id and marks this display name
            // as ambiguous. Further duplicates keep it unresolvable.
            name_it->second.clear();
        }
    }
}

bool RelayRuntime::admit_outgoing_invite_locked(
        PendingOutgoingInvite pending,
        std::string* error) {
    const auto now = std::chrono::steady_clock::now();
    expire_pending_invites_locked(now);
    if (outgoing_invites_.size() >=
        control::kMaxPendingRelayInvitesPerEndpoint) {
        if (error) {
            *error = "too many pending outgoing relay invites; wait for one to expire";
        }
        return false;
    }
    if (pending.invite.invite_id.empty()) {
        if (error) *error = "relay invite id is empty";
        return false;
    }
    pending.expires_at = now + control::kPendingRelayInviteLifetime;
    const std::string invite_id = pending.invite.invite_id;
    const auto [stored, inserted] = outgoing_invites_.emplace(
        invite_id, std::move(pending));
    (void)stored;
    if (!inserted) {
        if (error) *error = "duplicate relay invite id";
        return false;
    }
    schedule_pending_invite_expiry_locked();
    return true;
}

bool RelayRuntime::send_outgoing_invite_locked(
        const control::PendingInvite& invite,
        std::string* error) {
    nlohmann::json request = control::invite_to_json(invite, false);
    request["cmd"] = "invite.request";
    try {
        tunnel_->send_control_json(request);
        return true;
    } catch (const std::exception& ex) {
        outgoing_invites_.erase(invite.invite_id);
        schedule_pending_invite_expiry_locked();
        if (error) {
            *error = std::string("failed to send relay invite: ") + ex.what();
        }
        return false;
    }
}

bool RelayRuntime::begin_outgoing_invite_locked(
        control::PendingInvite invite,
        const control::EndpointInfo& peer,
        const std::string& relay_secret_b64,
        std::shared_ptr<RelayOutboundSource> payload_source,
        std::string bytes_label,
        std::string* error) {
    try {
        invite.relay_protocol_version = control::kRelayProtocolVersion;
        invite.created_ms = yume::util::now_ms();
        invite.response_present = false;
        invite.accepted = false;
        invite.response_reason.clear();
        invite.handshake_response_b64.clear();
        invite.responder_auth_pubkey_b64.clear();

        const relay_v2::Bytes peer_identity =
            decode_relay_identity(peer.auth_pubkey_b64);
        (void)peer_trust_store().precheck(
            peer.endpoint_id, peer_identity,
            trust_requirement(invite.channel_kind));

        auto identity = load_identity_keypair();
        const relay_v2::Bytes own_identity =
            relay_v2::EncodeIdentity(identity);
        const std::string own_identity_b64 = bytes_to_b64(own_identity);
        if (self_.auth_pubkey_b64.empty() ||
            own_identity_b64 != self_.auth_pubkey_b64) {
            throw std::runtime_error(
                "relay identity does not match the authenticated session");
        }

        relay_v2::Digest32 nonce{};
        const auto random_nonce = crypto::random_bytes(nonce.size());
        std::copy(random_nonce.begin(), random_nonce.end(), nonce.begin());
        const auto context = make_handshake_context(invite, nonce);
        auto relay_psk = decode_relay_psk(relay_secret_b64);
        struct PskWiper {
            relay_v2::Bytes& value;
            ~PskWiper() { security::secure_erase(value); }
        } psk_wiper{relay_psk};
        auto request = relay_v2::BeginInitiator(
            context, identity, peer_identity, std::move(relay_psk));

        invite.handshake_request_b64 = bytes_to_b64(request.encoded);
        invite.from_auth_pubkey_b64 = own_identity_b64;
        if (!control::relay_v2_invite_request_valid(invite)) {
            throw std::runtime_error(
                "constructed relay-v2 invite failed local validation");
        }

        PendingOutgoingInvite outgoing;
        outgoing.invite = invite;
        outgoing.handshake_state = std::move(request.state);
        outgoing.expected_peer_identity = peer_identity;
        outgoing.peer = peer;
        outgoing.payload_source = std::move(payload_source);
        outgoing.channel_kind = invite.channel_kind;
        outgoing.bytes_label = std::move(bytes_label);
        if (!admit_outgoing_invite_locked(std::move(outgoing), error)) {
            return false;
        }
        return send_outgoing_invite_locked(invite, error);
    } catch (const std::exception& ex) {
        if (error) {
            *error = std::string("failed to create relay-v2 invite: ") +
                ex.what();
        }
        return false;
    }
}

bool RelayRuntime::admit_incoming_invite_locked(
        PendingIncomingInvite pending) {
    const auto now = std::chrono::steady_clock::now();
    expire_pending_invites_locked(now);
    if (pending.invite.invite_id.empty() ||
        incoming_invites_.find(pending.invite.invite_id) !=
            incoming_invites_.end() ||
        incoming_invites_.size() >=
            control::kMaxPendingRelayInvitesPerEndpoint) {
        return false;
    }
    pending.expires_at = now + control::kPendingRelayInviteLifetime;
    const std::string invite_id = pending.invite.invite_id;
    const auto [stored, inserted] = incoming_invites_.emplace(
        invite_id, std::move(pending));
    (void)stored;
    if (inserted) schedule_pending_invite_expiry_locked();
    return inserted;
}

void RelayRuntime::expire_pending_invites_locked(
        std::chrono::steady_clock::time_point now) {
    for (auto it = outgoing_invites_.begin();
         it != outgoing_invites_.end();) {
        if (it->second.expires_at <= now) {
            it = outgoing_invites_.erase(it);
        } else {
            ++it;
        }
    }
    for (auto it = incoming_invites_.begin();
         it != incoming_invites_.end();) {
        if (it->second.expires_at <= now) {
            it = incoming_invites_.erase(it);
        } else {
            ++it;
        }
    }
}

void RelayRuntime::schedule_pending_invite_expiry_locked() {
    std::optional<std::chrono::steady_clock::time_point> earliest;
    auto observe = [&earliest](const auto& entries) {
        for (const auto& [id, pending] : entries) {
            (void)id;
            if (!earliest || pending.expires_at < *earliest) {
                earliest = pending.expires_at;
            }
        }
    };
    observe(outgoing_invites_);
    observe(incoming_invites_);

    const std::uint64_t generation = ++pending_invite_timer_generation_;
    if (!earliest) {
        if (pending_invite_timer_) {
            boost::system::error_code ignored;
            pending_invite_timer_->cancel(ignored);
            pending_invite_timer_.reset();
        }
        return;
    }

    if (!pending_invite_timer_) {
        pending_invite_timer_ = std::make_shared<boost::asio::steady_timer>(
            tunnel_->get_executor());
    }
    auto timer = pending_invite_timer_;
    timer->expires_at(*earliest);
    timer->async_wait(
        [weak = weak_from_this(), timer, generation](
                const boost::system::error_code& timer_error) {
            if (timer_error) return;
            auto self = weak.lock();
            if (!self) return;
            std::lock_guard<std::mutex> lock(self->mutex_);
            if (generation != self->pending_invite_timer_generation_ ||
                timer != self->pending_invite_timer_) {
                return;
            }
            self->expire_pending_invites_locked(
                std::chrono::steady_clock::now());
            self->schedule_pending_invite_expiry_locked();
        });
}

crypto::CompositeKeyPair RelayRuntime::load_identity_keypair() const {
    return crypto::load_composite_keypair(options_.identity_path);
}

relay_v2::Bytes RelayRuntime::decode_relay_identity(
        const std::string& encoded) {
    if (encoded.empty()) {
        throw std::runtime_error("relay peer identity is missing");
    }
    const relay_v2::Bytes decoded = b64_to_bytes(encoded);
    const relay_v2::Bytes canonical =
        relay_v2::CanonicalizeIdentity(decoded);
    if (decoded != canonical) {
        throw std::runtime_error(
            "relay peer identity is not canonically encoded");
    }
    return canonical;
}

relay_v2::Bytes RelayRuntime::decode_relay_psk(
        const std::string& encoded) {
    if (encoded.empty()) {
        return {};
    }
    relay_v2::Bytes decoded = b64_to_bytes(encoded);
    if (decoded.size() != relay_v2::kRelayPskBytes) {
        security::secure_erase(decoded);
        throw std::runtime_error(
            "relay password must derive exactly 32 bytes");
    }
    return decoded;
}

relay_v2::HandshakeContext RelayRuntime::make_handshake_context(
        const control::PendingInvite& invite,
        relay_v2::Digest32 nonce) {
    relay_v2::HandshakeContext context;
    context.channel_kind = invite.channel_kind;
    context.initiator_endpoint_id = invite.from_endpoint_id;
    context.responder_endpoint_id = invite.to_endpoint_id;
    context.nonce = nonce;
    context.password_policy = invite.requires_password
        ? relay_v2::PasswordPolicy::Required
        : relay_v2::PasswordPolicy::NotRequired;
    const auto digest = crypto::sha256(invite.metadata_json);
    if (digest.size() != context.metadata_digest.size()) {
        throw std::runtime_error("SHA-256 returned an invalid digest size");
    }
    std::copy(digest.begin(), digest.end(),
              context.metadata_digest.begin());
    return context;
}

relay_v2::PeerTrustRequirement RelayRuntime::trust_requirement(
        control::ChannelKind kind) noexcept {
    return kind == control::ChannelKind::admin
        ? relay_v2::PeerTrustRequirement::Admin
        : relay_v2::PeerTrustRequirement::Ordinary;
}

relay_v2::PeerTrustStore& RelayRuntime::peer_trust_store() {
    if (!peer_trust_) {
        throw relay_v2::PeerTrustError(
            "secure relay peer trust storage is unavailable on this platform");
    }
    return *peer_trust_;
}

bool RelayRuntime::open_channel_from_reply(
        PendingOutgoingInvite outgoing,
        const control::PendingInvite& reply,
        std::string* error) {
    if (!reply.accepted || !reply.response_present ||
        !control::relay_v2_invite_response_valid(reply) ||
        !control::relay_v2_request_fields_match(outgoing.invite, reply)) {
        if (error) *error = "invite reply does not match the outgoing request";
        return false;
    }
    std::string transfer_name;
    std::uint64_t transfer_size = 0;
    if (outgoing.channel_kind == control::ChannelKind::file ||
        outgoing.channel_kind == control::ChannelKind::bytes) {
        try {
            const auto metadata = nlohmann::json::parse(
                outgoing.invite.metadata_json);
            if (!metadata.is_object() || !metadata.contains("name") ||
                !metadata["name"].is_string() ||
                !metadata.contains("size") ||
                !metadata["size"].is_number_unsigned()) {
                throw std::runtime_error("invalid transfer metadata");
            }
            transfer_name = metadata["name"].get<std::string>();
            transfer_size = metadata["size"].get<std::uint64_t>();
            if (!RelayFileReceiver::IsSafeBasename(transfer_name) ||
                transfer_size > options_.receive_limits.max_transfer_bytes ||
                !outgoing.payload_source ||
                outgoing.payload_source->size() != transfer_size) {
                throw std::runtime_error("unsafe transfer metadata");
            }
        } catch (const std::exception&) {
            if (error) *error = "outgoing transfer metadata is invalid";
            return false;
        }
    }
    std::unique_ptr<ratchet::SessionRatchet> channel_ratchet;
    try {
        const relay_v2::Bytes responder_identity =
            decode_relay_identity(reply.responder_auth_pubkey_b64);
        if (responder_identity != outgoing.expected_peer_identity) {
            throw std::runtime_error(
                "reply identity differs from the requested peer identity");
        }
        const auto response = b64_to_bytes(reply.handshake_response_b64);
        auto secrets = relay_v2::CompleteInitiator(
            std::move(outgoing.handshake_state), response);
        (void)peer_trust_store().commit_verified(
            outgoing.peer.endpoint_id, responder_identity,
            trust_requirement(outgoing.channel_kind));
        channel_ratchet = relay_v2::MakeSessionRatchet(
            std::move(secrets), ratchet::EndpointRole::Client,
            kRelayRekeyWindow, kRelayRekeyWindow,
            ratchet::kExtremePolicy, ratchet::kExtremePolicy);
    } catch (const std::exception& ex) {
        if (error) {
            *error = std::string("relay-v2 handshake failed: ") + ex.what();
        }
        return false;
    }
    uint8_t stream_id = tunnel_->reserve_stream_id();
    if (stream_id == 0) {
        if (error) {
            *error = "no stream ids available";
        }
        return false;
    }
    ChannelState channel;
    channel.channel_id = outgoing.invite.invite_id;
    channel.channel_kind = outgoing.channel_kind;
    channel.role = control::RelayChannelRole::initiator;
    channel.peer_id = outgoing.peer.endpoint_id;
    channel.peer_name = outgoing.peer.display_name;
    channel.stream_id = stream_id;
    channel.ratchet = std::move(channel_ratchet);
    auto payload = nlohmann::json{
        {"relay_protocol_version", control::kRelayProtocolVersion},
        {"channel_id", outgoing.invite.invite_id},
        {"channel_kind", control::to_string(outgoing.channel_kind)},
        {"from_id", self_.endpoint_id},
        {"to_id", outgoing.peer.endpoint_id},
        {"target_id", outgoing.peer.endpoint_id},
        {"e2ee_required", true},
    };
    auto payload_source = std::move(outgoing.payload_source);
    auto channel_kind = outgoing.channel_kind;
    auto pending_channel = std::make_shared<ChannelState>(std::move(channel));
    try {
        tunnel_->open_relay_stream(
            stream_id,
            payload,
            [weak = weak_from_this(), stream_id, pending_channel,
             payload_source,
             channel_kind, transfer_size,
             transfer_name = std::move(transfer_name)](
                bool ok, const std::string& reason) mutable {
            auto self = weak.lock();
            if (!self) return;
            if (!ok) {
                util::log_warn("relay open failed: " + reason);
                return;
            }
            {
                std::lock_guard<std::mutex> lock(self->mutex_);
                if (!self->register_channel(stream_id,
                                            std::move(*pending_channel))) {
                    return;
                }
                if (channel_kind == control::ChannelKind::chat) {
                    self->active_chat_stream_ = stream_id;
                } else if (channel_kind == control::ChannelKind::admin) {
                    self->active_admin_stream_ = stream_id;
                }
            }
            if (channel_kind == control::ChannelKind::file ||
                channel_kind == control::ChannelKind::bytes) {
                self->start_outbound_transfer(stream_id,
                                              payload_source,
                                              channel_kind,
                                              transfer_size,
                                              std::move(transfer_name));
            }
        });
    } catch (const std::exception& ex) {
        tunnel_->release_reserved_stream(stream_id);
        if (error) {
            *error = std::string("failed to open relay stream: ") + ex.what();
        }
        return false;
    }
    return true;
}

void RelayRuntime::start_outbound_transfer(
    uint8_t stream_id,
    std::shared_ptr<RelayOutboundSource> source,
    control::ChannelKind kind,
    std::uint64_t expected_size,
    std::string expected_name) {
    auto transfer = std::make_shared<OutboundTransfer>();
    transfer->stream_id = stream_id;
    transfer->kind = kind;
    transfer->source = std::move(source);
    transfer->name = std::move(expected_name);
    transfer->expected_size = expected_size;
    std::string source_error;
    if (!transfer->source ||
        transfer->source->size() != transfer->expected_size ||
        !transfer->source->ValidateSize(&source_error)) {
        fail_outbound_transfer(stream_id,
            source_error.empty() ? "relay transfer source is unavailable"
                                 : source_error);
        return;
    }
    pump_outbound_transfer(transfer);
}

void RelayRuntime::pump_outbound_transfer(
    const std::shared_ptr<OutboundTransfer>& transfer) {
    if (!transfer) return;
    nlohmann::json message;
    bool final_record = false;
    if (transfer->phase == OutboundTransfer::Phase::metadata) {
        message = {
            {"type", transfer->kind == control::ChannelKind::file
                         ? "file_meta" : "bytes_meta"},
            {"name", transfer->name},
            {"size", transfer->expected_size},
        };
        transfer->phase = OutboundTransfer::Phase::chunks;
    } else if (transfer->phase == OutboundTransfer::Phase::chunks &&
               transfer->sent_size < transfer->expected_size) {
        const std::uint64_t remaining =
            transfer->expected_size - transfer->sent_size;
        const std::size_t wanted = static_cast<std::size_t>(
            std::min<std::uint64_t>(remaining, kRelayTransferChunkBytes));
        std::array<std::uint8_t, kRelayTransferChunkBytes> buffer{};
        std::string source_error;
        if (!transfer->source->ReadExact(
                std::span<std::uint8_t>(buffer.data(), wanted),
                &source_error)) {
            fail_outbound_transfer(
                transfer->stream_id,
                source_error.empty()
                    ? "relay transfer source changed or ended early"
                    : source_error);
            return;
        }
        transfer->sent_size += static_cast<std::uint64_t>(wanted);
        message = {
            {"type", transfer->kind == control::ChannelKind::file
                         ? "file_chunk" : "bytes_chunk"},
            {"data_b64", util::base64_encode(std::string(
                 reinterpret_cast<const char*>(buffer.data()), wanted))},
        };
    } else {
        std::string source_error;
        if (!transfer->source->ValidateSize(&source_error)) {
            fail_outbound_transfer(transfer->stream_id,
                source_error.empty() ? "relay transfer source changed size"
                                     : source_error);
            return;
        }
        message = {{"type", transfer->kind == control::ChannelKind::file
                                 ? "file_done" : "bytes_done"}};
        transfer->phase = OutboundTransfer::Phase::done;
        final_record = true;
    }

    const auto weak = weak_from_this();
    const ChannelWriteCompletion completion =
        [weak, transfer, final_record](bool ok, const std::string& reason) {
            auto self = weak.lock();
            if (!self) return;
            if (!ok) {
                self->fail_outbound_transfer(
                    transfer->stream_id,
                    reason.empty() ? "relay transfer write failed" : reason);
                return;
            }
            if (!final_record) {
                self->pump_outbound_transfer(transfer);
                return;
            }
            self->tunnel_->send_close(transfer->stream_id,
                                      "transfer complete");
            self->tunnel_->unregister_stream(transfer->stream_id);
            std::lock_guard<std::mutex> lock(self->mutex_);
            self->handle_channel_close(transfer->stream_id, {});
        };
    std::string send_error;
    bool accepted = false;
    try {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = channels_.find(transfer->stream_id);
        if (it == channels_.end() ||
            it->second.role != control::RelayChannelRole::initiator ||
            it->second.channel_kind != transfer->kind) {
            return;
        }
        accepted = send_channel_payload_locked(
            it->second, message.dump(), completion, &send_error);
    } catch (const std::exception& ex) {
        fail_outbound_transfer(transfer->stream_id, ex.what());
        return;
    }
    if (!accepted) {
        fail_outbound_transfer(
            transfer->stream_id,
            send_error.empty() ? "relay transfer write failed" : send_error);
    }
}

void RelayRuntime::fail_outbound_transfer(uint8_t stream_id,
                                          const std::string& reason) {
    tunnel_->send_close(stream_id, reason);
    tunnel_->unregister_stream(stream_id);
    std::lock_guard<std::mutex> lock(mutex_);
    handle_channel_close(stream_id, reason);
}

bool RelayRuntime::register_channel(uint8_t stream_id, ChannelState channel) {
    const auto [it, inserted] = channels_.emplace(stream_id, std::move(channel));
    (void)it;
    if (!inserted) {
        close_channel_locked(stream_id, "duplicate relay stream id");
        return false;
    }
    const auto weak = weak_from_this();
    if (!tunnel_->register_stream(
        stream_id,
        [weak, stream_id](const Tunnel::Bytes& payload,
                          Tunnel::InboundCredit) {
            auto self = weak.lock();
            if (!self) return;
            std::lock_guard<std::mutex> lock(self->mutex_);
            auto it = self->channels_.find(stream_id);
            if (it != self->channels_.end()) {
                self->handle_channel_data(&it->second, payload);
            }
        },
        [weak, stream_id](const std::string& reason) {
            auto self = weak.lock();
            if (!self) return;
            std::lock_guard<std::mutex> lock(self->mutex_);
            self->handle_channel_close(stream_id, reason);
        })) {
        channels_.erase(stream_id);
        return false;
    }
    return true;
}

void RelayRuntime::handle_channel_data(ChannelState* channel, const Tunnel::Bytes& payload) {
    if (!channel) {
        return;
    }
    const uint8_t stream_id = channel->stream_id;
    try {
        if (!channel->ratchet) {
            throw std::runtime_error("relay-v2 channel ratchet is missing");
        }
        const auto now = std::chrono::steady_clock::now();
        auto opened = relay_v2::record::OpenRecord(
            *channel->ratchet, payload, now);
        if (opened.control_response) {
            auto ack = relay_v2::record::SealControlResponse(
                *channel->ratchet,
                std::move(*opened.control_response), now);
            std::string ack_error;
            if (!send_sealed_record_locked(
                    *channel, std::move(ack), {}, &ack_error)) {
                throw std::runtime_error(
                    ack_error.empty() ?
                        "relay-v2 rekey ACK write failed" : ack_error);
            }
        }
        if (opened.outbound_rekey_completed) {
            schedule_rekey_deadline_locked(*channel);
            flush_pending_applications_locked(*channel);
        }
        if (!opened.application_frame) {
            return;
        }
        auto plaintext_bytes =
            std::move(opened.application_frame->payload);
        struct PlaintextBytesWiper {
            relay_v2::Bytes& value;
            ~PlaintextBytesWiper() { security::secure_erase(value); }
        } bytes_wiper{plaintext_bytes};
        std::string plain(plaintext_bytes.begin(), plaintext_bytes.end());
        struct PlaintextStringWiper {
            std::string& value;
            ~PlaintextStringWiper() { wipe_relay_secret(value); }
        } plain_wiper{plain};
        auto json = nlohmann::json::parse(plain);
        if (!json.is_object() || !json.contains("type") ||
            !json["type"].is_string()) {
            throw std::runtime_error("relay message has no valid type");
        }
        const auto message_type = control::try_relay_message_type(
            json["type"].get_ref<const std::string&>());
        if (!message_type) {
            throw std::runtime_error("unknown relay message type");
        }

        bool response_outstanding = false;
        std::string admin_request_id;
        if (*message_type == control::RelayMessageType::admin_response) {
            if (!json.contains("request_id") ||
                !json["request_id"].is_string()) {
                throw std::runtime_error("admin response has no request id");
            }
            admin_request_id = json["request_id"].get<std::string>();
            auto pending = admin_responses_.find(admin_request_id);
            response_outstanding = pending != admin_responses_.end() &&
                pending->second.stream_id == stream_id &&
                !pending->second.ready;
        }
        const auto decision = control::evaluate_relay_message_policy({
            channel->channel_kind,
            channel->role,
            channel->transfer_phase,
            *message_type,
            options_.relay_mode == control::RelayMode::trusted &&
                options_.allow_inbound_admin,
            response_outstanding,
        });
        if (!decision.allowed) {
            throw std::runtime_error(std::string(decision.reason));
        }

        if (*message_type == control::RelayMessageType::chat) {
            if (!json.contains("text") || !json["text"].is_string()) {
                throw std::runtime_error("chat message text is invalid");
            }
            const std::string text = json["text"].get<std::string>();
            util::log_info("[" + channel->peer_name + "] " + text);
            append_history(channel->peer_id, channel->peer_name, "in", text);
            return;
        }
        if (*message_type == control::RelayMessageType::file_meta ||
            *message_type == control::RelayMessageType::bytes_meta) {
            if (!json.contains("name") || !json["name"].is_string() ||
                !json.contains("size") ||
                !json["size"].is_number_unsigned()) {
                throw std::runtime_error("relay transfer metadata is invalid");
            }
            const std::string name = json["name"].get<std::string>();
            const auto size = json["size"].get<std::uint64_t>();
            if (!channel->expected_receive_size ||
                name != channel->expected_receive_name ||
                size != *channel->expected_receive_size) {
                throw std::runtime_error(
                    "relay transfer metadata differs from the accepted invite");
            }
            std::string receive_error;
            if (!channel->receiver.Begin(options_.receive_dir,
                                         name,
                                         size,
                                         channel->expected_receive_sha256,
                                         options_.receive_limits,
                                         &receive_error)) {
                throw std::runtime_error(receive_error);
            }
            channel->bytes_label = name;
            channel->transfer_phase = decision.next_transfer_phase;
            start_receive_deadline_locked(*channel);
            util::log_info("receiving " + name + " from " + channel->peer_name);
            return;
        }
        if (*message_type == control::RelayMessageType::file_chunk ||
            *message_type == control::RelayMessageType::bytes_chunk) {
            if (!json.contains("data_b64") ||
                !json["data_b64"].is_string()) {
                throw std::runtime_error("relay transfer chunk is invalid");
            }
            std::vector<std::uint8_t> decoded;
            std::string receive_error;
            if (!DecodeRelayChunkBase64(
                    json["data_b64"].get_ref<const std::string&>(),
                    options_.receive_limits.max_chunk_bytes,
                    &decoded,
                    &receive_error)) {
                throw std::runtime_error(receive_error);
            }
            const bool appended = channel->receiver.Append(decoded,
                                                           &receive_error);
            security::secure_erase(decoded);
            if (!appended) throw std::runtime_error(receive_error);
            channel->transfer_phase = decision.next_transfer_phase;
            return;
        }
        if (*message_type == control::RelayMessageType::file_done ||
            *message_type == control::RelayMessageType::bytes_done) {
            std::string receive_error;
            if (!channel->receiver.Finish(&receive_error)) {
                throw std::runtime_error(receive_error);
            }
            if (channel->receive_timer) {
                boost::system::error_code ignored;
                channel->receive_timer->cancel(ignored);
                channel->receive_timer.reset();
            }
            channel->transfer_phase = decision.next_transfer_phase;
            util::log_info("saved " + channel->receiver.path().string());
            return;
        }
        if (*message_type == control::RelayMessageType::admin_request) {
            if (!json.contains("request_id") ||
                !json["request_id"].is_string() ||
                json["request_id"].get_ref<const std::string&>().empty() ||
                !json.contains("op") || !json["op"].is_string()) {
                throw std::runtime_error("admin request is invalid");
            }
            bool stop_after_response = false;
            auto response = handle_admin_request(
                json, &stop_after_response);
            send_admin_response(
                *channel, response, stop_after_response);
            return;
        }
        if (*message_type == control::RelayMessageType::admin_response) {
            auto it = admin_responses_.find(admin_request_id);
            if (it == admin_responses_.end() ||
                it->second.stream_id != stream_id || it->second.ready) {
                throw std::runtime_error("unsolicited admin response");
            }
            it->second.ready = true;
            it->second.value = json.value("payload", nlohmann::json::object());
            admin_cv_.notify_all();
            return;
        }
    } catch (const std::exception& ex) {
        const std::string detail = ex.what();
        const std::string reason =
            detail.find("authentication check failed") != std::string::npos
                ? "relay password mismatch or channel authentication failed"
                : "relay protocol violation: " + detail;
        close_channel_locked(stream_id, reason);
    }
}

void RelayRuntime::start_receive_deadline_locked(ChannelState& channel) {
    auto timer = std::make_shared<boost::asio::steady_timer>(
        tunnel_->get_executor());
    timer->expires_after(options_.receive_limits.max_duration);
    channel.receive_timer = timer;
    const uint8_t stream_id = channel.stream_id;
    timer->async_wait(
        [weak = weak_from_this(), stream_id, timer](
            const boost::system::error_code& error) {
            if (error) return;
            auto self = weak.lock();
            if (!self) return;
            std::lock_guard<std::mutex> lock(self->mutex_);
            auto it = self->channels_.find(stream_id);
            if (it == self->channels_.end() ||
                it->second.receive_timer != timer ||
                !it->second.receiver.active()) {
                return;
            }
            self->close_channel_locked(
                stream_id, "relay transfer receive deadline exceeded");
        });
}

void RelayRuntime::close_channel_locked(uint8_t stream_id,
                                        const std::string& reason) {
    if (channels_.find(stream_id) == channels_.end()) return;
    tunnel_->send_close(stream_id, reason);
    tunnel_->unregister_stream(stream_id);
    handle_channel_close(stream_id, reason);
}

void RelayRuntime::handle_channel_close(uint8_t stream_id, const std::string& reason) {
    auto it = channels_.find(stream_id);
    if (it == channels_.end()) {
        return;
    }
    const std::string peer_label = it->second.peer_name.empty() ? it->second.peer_id : it->second.peer_name;
    if (active_chat_stream_ == stream_id) {
        active_chat_stream_.reset();
    }
    if (active_admin_stream_ == stream_id) {
        active_admin_stream_.reset();
    }
    for (auto& [request_id, response] : admin_responses_) {
        (void)request_id;
        if (response.stream_id == stream_id && !response.ready) {
            response.ready = true;
            response.failed = true;
            response.error = reason.empty()
                ? "admin channel closed" : reason;
        }
    }
    admin_cv_.notify_all();
    if (!reason.empty()) {
        util::log_warn("channel with " + peer_label + " closed: " + reason);
    }
    channels_.erase(it);
}

bool RelayRuntime::send_sealed_record_locked(
        ChannelState& channel,
        relay_v2::record::Bytes encoded,
        ChannelWriteCompletion completion,
        std::string* error) {
    const std::uint8_t stream_id = channel.stream_id;
    const auto weak = weak_from_this();
    const auto executor = tunnel_->get_executor();
    const auto admission = tunnel_->wait_send_data(
        stream_id, std::move(encoded),
        std::chrono::milliseconds::zero(),
        [weak, executor, stream_id,
         completion = std::move(completion)](
                bool ok, std::size_t, const std::string& reason) mutable {
            // TransportCore may settle an admitted write inline when frame
            // encoding or the writer throws. RelayRuntime callers hold
            // mutex_ during admission, so always defer both completion and
            // channel teardown to prevent same-stack lock re-entry.
            boost::asio::post(
                executor,
                [weak, stream_id, ok, reason,
                 completion = std::move(completion)]() mutable {
                    if (completion) {
                        try {
                            completion(ok, reason);
                            return;
                        } catch (const std::exception& ex) {
                            util::log_warn(
                                std::string("relay-v2 write completion failed: ") +
                                ex.what());
                        } catch (...) {
                            util::log_warn(
                                "relay-v2 write completion failed");
                        }
                    }
                    if (!ok || completion) {
                        if (auto self = weak.lock()) {
                            std::lock_guard<std::mutex> lock(self->mutex_);
                            self->close_channel_locked(
                                stream_id,
                                reason.empty() ?
                                    "relay-v2 record write failed" : reason);
                        }
                    }
                }
            );
        });
    if (admission == TransportCore::DataWriteAdmission::accepted) {
        return true;
    }
    if (error) {
        switch (admission) {
            case TransportCore::DataWriteAdmission::would_block:
                *error = "relay-v2 transport write queue is full";
                break;
            case TransportCore::DataWriteAdmission::timeout:
                *error = "relay-v2 transport write admission timed out";
                break;
            case TransportCore::DataWriteAdmission::stopped:
                *error = "relay-v2 transport is stopped";
                break;
            case TransportCore::DataWriteAdmission::invalid:
                *error = "relay-v2 transport rejected an invalid record";
                break;
            case TransportCore::DataWriteAdmission::accepted:
                break;
        }
    }
    return false;
}

bool RelayRuntime::send_channel_payload_locked(
        ChannelState& channel,
        std::string plaintext,
        ChannelWriteCompletion completion,
        std::string* error) {
    RelaySecretWiper plaintext_wiper(plaintext);
    if (!channel.ratchet) {
        if (error) *error = "relay-v2 channel ratchet is missing";
        return false;
    }
    if (plaintext.size() >
        relay_v2::record::kMaxPlaintextPayloadBytes) {
        if (error) *error = "relay-v2 application payload exceeds 64 KiB";
        return false;
    }

    relay_v2::Bytes bytes(plaintext.begin(), plaintext.end());
    struct BytesWiper {
        relay_v2::Bytes& value;
        ~BytesWiper() { security::secure_erase(value); }
    } bytes_wiper{bytes};
    protocol::Frame probe{
        {static_cast<std::uint32_t>(bytes.size()), protocol::DATA, 0, 0},
        std::move(bytes)};
    struct ProbeWiper {
        protocol::Frame& value;
        ~ProbeWiper() { security::secure_erase(value.payload); }
    } probe_wiper{probe};

    try {
        const auto now = std::chrono::steady_clock::now();
        if (channel.ratchet->rekey_timed_out(now)) {
            if (error) *error = "relay-v2 rekey acknowledgement timed out";
            return false;
        }
        if (channel.ratchet->ShouldStartRekey(probe, now)) {
            auto init = channel.ratchet->BeginOutboundRekey(now);
            auto encoded_init =
                relay_v2::record::EncodeSealedFrame(init);
            std::string init_error;
            if (!send_sealed_record_locked(
                    channel, std::move(encoded_init), {}, &init_error)) {
                if (error) {
                    *error = init_error.empty() ?
                        "relay-v2 rekey offer write failed" : init_error;
                }
                return false;
            }
            schedule_rekey_deadline_locked(channel);
        }
        if (channel.ratchet->ApplicationWriteBlocked(probe, now)) {
            if (channel.pending_applications.size() >=
                    kMaxPendingApplicationRecords ||
                probe.payload.size() >
                    kMaxPendingApplicationBytes -
                        std::min(channel.pending_application_bytes,
                                 kMaxPendingApplicationBytes)) {
                if (error) {
                    *error = "relay-v2 pending application queue is full";
                }
                return false;
            }
            channel.pending_application_bytes += probe.payload.size();
            channel.pending_applications.emplace_back(
                std::move(probe.payload), std::move(completion));
            schedule_rekey_deadline_locked(channel);
            return true;
        }

        auto encoded = relay_v2::record::SealApplication(
            *channel.ratchet, std::move(probe.payload), now);
        return send_sealed_record_locked(
            channel, std::move(encoded), std::move(completion), error);
    } catch (const std::exception& ex) {
        if (error) *error = ex.what();
        return false;
    }
}

void RelayRuntime::flush_pending_applications_locked(
        ChannelState& channel) {
    if (!channel.ratchet) {
        throw std::runtime_error("relay-v2 channel ratchet is missing");
    }
    while (!channel.pending_applications.empty()) {
        const auto now = std::chrono::steady_clock::now();
        const auto pending_size =
            channel.pending_applications.front().plaintext.size();
        protocol::Frame probe{
            {static_cast<std::uint32_t>(pending_size),
             protocol::DATA, 0, 0},
            relay_v2::Bytes(pending_size)};
        if (channel.ratchet->ShouldStartRekey(probe, now)) {
            auto init = channel.ratchet->BeginOutboundRekey(now);
            std::string init_error;
            if (!send_sealed_record_locked(
                    channel,
                    relay_v2::record::EncodeSealedFrame(init), {},
                    &init_error)) {
                throw std::runtime_error(
                    init_error.empty() ?
                        "relay-v2 rekey offer write failed" : init_error);
            }
            schedule_rekey_deadline_locked(channel);
        }
        if (channel.ratchet->ApplicationWriteBlocked(probe, now)) {
            return;
        }

        PendingApplication pending =
            std::move(channel.pending_applications.front());
        channel.pending_applications.pop_front();
        channel.pending_application_bytes -= pending.plaintext.size();
        auto encoded = relay_v2::record::SealApplication(
            *channel.ratchet, std::move(pending.plaintext), now);
        std::string send_error;
        auto completion = std::move(pending.completion);
        if (!send_sealed_record_locked(
                channel, std::move(encoded), completion, &send_error)) {
            if (completion) {
                boost::asio::post(
                    tunnel_->get_executor(),
                    [completion = std::move(completion),
                     send_error]() mutable {
                        try {
                            completion(false, send_error);
                        } catch (const std::exception& ex) {
                            util::log_warn(
                                std::string(
                                    "relay-v2 rejected write completion failed: ") +
                                ex.what());
                        } catch (...) {
                            util::log_warn(
                                "relay-v2 rejected write completion failed");
                        }
                    });
            }
            throw std::runtime_error(
                send_error.empty() ?
                    "relay-v2 record write failed" : send_error);
        }
    }
}

void RelayRuntime::schedule_rekey_deadline_locked(ChannelState& channel) {
    if (!channel.ratchet) return;
    const auto deadline = channel.ratchet->rekey_deadline();
    if (!deadline) {
        if (channel.rekey_timer) {
            boost::system::error_code ignored;
            channel.rekey_timer->cancel(ignored);
            channel.rekey_timer.reset();
        }
        return;
    }
    if (!channel.rekey_timer) {
        channel.rekey_timer =
            std::make_shared<boost::asio::steady_timer>(
                tunnel_->get_executor());
    }
    auto timer = channel.rekey_timer;
    const auto stream_id = channel.stream_id;
    timer->expires_at(*deadline);
    timer->async_wait(
        [weak = weak_from_this(), timer, stream_id, expected = *deadline](
                const boost::system::error_code& timer_error) {
            if (timer_error) return;
            auto self = weak.lock();
            if (!self) return;
            std::lock_guard<std::mutex> lock(self->mutex_);
            auto it = self->channels_.find(stream_id);
            if (it == self->channels_.end() ||
                it->second.rekey_timer != timer ||
                !it->second.ratchet) {
                return;
            }
            const auto current = it->second.ratchet->rekey_deadline();
            if (!current) {
                self->schedule_rekey_deadline_locked(it->second);
                return;
            }
            if (*current != expected) {
                self->schedule_rekey_deadline_locked(it->second);
                return;
            }
            if (it->second.ratchet->rekey_timed_out(
                    std::chrono::steady_clock::now())) {
                self->close_channel_locked(
                    stream_id,
                    "relay-v2 rekey acknowledgement timed out");
                return;
            }
            self->schedule_rekey_deadline_locked(it->second);
        });
}

void RelayRuntime::append_history(const std::string& peer_id, const std::string& peer_name, const std::string& direction, const std::string& text) {
    if (!options_.history_enabled) {
        return;
    }
    history_.append_chat(ChatHistoryEntry{yume::util::now_ms(), peer_id, peer_name, direction, text});
}

nlohmann::json RelayRuntime::handle_admin_request(
        const nlohmann::json& json,
        bool* stop_after_response) {
    if (stop_after_response) {
        *stop_after_response = false;
    }
    const std::string op = json.value("op", "");
    const std::string request_id = json.value("request_id", "");
    if (op == "runtime.status") {
        nlohmann::json payload;
        payload["self"] = control::endpoint_to_json(self_, true);
        payload["server_id"] = server_id_;
        payload["server_name"] = server_name_;
        payload["directory_size"] = directory_by_id_.size();
        payload["pending_invites"] = incoming_invites_.size();
        payload["active_channels"] = channels_.size();
        return {{"type", "admin_resp"}, {"request_id", request_id}, {"payload", payload}};
    }
    if (op == "runtime.sessions") {
        nlohmann::json payload;
        payload["channels"] = nlohmann::json::array();
        for (const auto& entry : channels_) {
            payload["channels"].push_back({
                {"stream_id", entry.first},
                {"channel_id", entry.second.channel_id},
                {"channel_kind", control::to_string(entry.second.channel_kind)},
                {"peer_id", entry.second.peer_id},
                {"peer_name", entry.second.peer_name},
            });
        }
        payload["pending_invites"] = nlohmann::json::array();
        for (const auto& entry : incoming_invites_) {
            payload["pending_invites"].push_back(control::invite_to_json(entry.second.invite, true));
        }
        return {{"type", "admin_resp"}, {"request_id", request_id}, {"payload", payload}};
    }
    if (op == "runtime.stop") {
        if (stop_after_response) {
            *stop_after_response = true;
        }
        return {{"type", "admin_resp"}, {"request_id", request_id}, {"payload", {{"stopping", true}}}};
    }
    return {{"type", "admin_resp"}, {"request_id", request_id}, {"payload", {{"error", "unsupported op"}}}};
}

void RelayRuntime::send_admin_response(
        ChannelState& channel,
        const nlohmann::json& response,
        bool stop_after_response) {
    ChannelWriteCompletion completion;
    if (stop_after_response) {
        const auto weak = weak_from_this();
        const auto stream_id = channel.stream_id;
        completion = [weak, stream_id](
                         bool ok, const std::string& reason) {
            auto self = weak.lock();
            if (!self) return;
            if (!ok) {
                std::lock_guard<std::mutex> lock(self->mutex_);
                self->close_channel_locked(
                    stream_id,
                    reason.empty() ?
                        "admin response write failed" : reason);
                return;
            }
            self->invoke_stop_callback();
        };
    }
    std::string send_error;
    if (!send_channel_payload_locked(
            channel, response.dump(), std::move(completion), &send_error)) {
        close_channel_locked(channel.stream_id,
            send_error.empty() ?
                "admin response write failed" : send_error);
    }
}

void RelayRuntime::invoke_stop_callback() {
    std::function<void()> callback;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        callback = stop_callback_;
    }
    if (!callback) return;
    try {
        callback();
    } catch (const std::exception& ex) {
        util::log_warn(
            std::string("relay runtime stop callback failed: ") + ex.what());
    } catch (...) {
        util::log_warn("relay runtime stop callback failed");
    }
}

}  // namespace yume::client
