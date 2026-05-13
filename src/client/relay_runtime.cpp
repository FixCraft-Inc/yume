#include "client/relay_runtime.hpp"

#include <array>
#include <fstream>
#include <sstream>
#include <stdexcept>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include "core/identity.hpp"
#include "util.hpp"

namespace yume::client {

namespace {

std::string bytes_to_b64(const crypto::Bytes& bytes) {
    return yume::util::base64_encode(std::string(bytes.begin(), bytes.end()));
}

crypto::Bytes b64_to_bytes(const std::string& value) {
    const std::string raw = yume::util::base64_decode(value);
    return crypto::Bytes(raw.begin(), raw.end());
}

crypto::EVP_PKEY_ptr load_public_key_from_b64(const std::string& value) {
    const std::string pem = yume::util::base64_decode(value);
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) {
        throw std::runtime_error("failed to allocate public key BIO");
    }
    EVP_PKEY* pub = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!pub) {
        throw std::runtime_error("failed to parse public key");
    }
    return crypto::EVP_PKEY_ptr(pub, EVP_PKEY_free);
}

std::string public_key_to_b64(EVP_PKEY* key) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw std::runtime_error("failed to allocate public key BIO");
    }
    if (PEM_write_bio_PUBKEY(bio, key) != 1) {
        BIO_free(bio);
        throw std::runtime_error("failed to write public key");
    }
    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    std::string pem;
    if (len > 0 && data) {
        pem.assign(data, static_cast<std::size_t>(len));
    }
    BIO_free(bio);
    return yume::util::base64_encode(pem);
}

crypto::Bytes counter_nonce(const crypto::Bytes& prefix, std::uint64_t counter) {
    crypto::Bytes nonce(12, 0);
    for (std::size_t i = 0; i < std::min<std::size_t>(4, prefix.size()); ++i) {
        nonce[i] = prefix[i];
    }
    for (int i = 0; i < 8; ++i) {
        nonce[4 + i] = static_cast<std::uint8_t>((counter >> ((7 - i) * 8)) & 0xFF);
    }
    return nonce;
}

std::string now_request_id() {
    return yume::identity::derive_instance_key(std::to_string(yume::util::now_ms()) + ":" + yume::util::random_hex(8));
}

std::string sha256_file_hex(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return {};
    }
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("failed to allocate EVP_MD_CTX");
    }
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }
    std::array<char, 65536> buf{};
    while (in) {
        in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
        if (in.gcount() > 0) {
            if (EVP_DigestUpdate(ctx, buf.data(), static_cast<size_t>(in.gcount())) != 1) {
                EVP_MD_CTX_free(ctx);
                throw std::runtime_error("EVP_DigestUpdate failed");
            }
        }
    }
    unsigned char digest[EVP_MAX_MD_SIZE] = {0};
    unsigned int digest_len = 0;
    if (EVP_DigestFinal_ex(ctx, digest, &digest_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }
    EVP_MD_CTX_free(ctx);
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(digest_len * 2);
    for (unsigned int i = 0; i < digest_len; ++i) {
        const unsigned char byte = digest[i];
        out.push_back(kHex[(byte >> 4) & 0xF]);
        out.push_back(kHex[byte & 0xF]);
    }
    return out;
}

std::string relay_secret_from_args(const nlohmann::json& args) {
    std::string relay_secret_b64 = args.value("relay_secret", "");
    if (relay_secret_b64.empty()) {
        const std::string password = args.value("password", "");
        if (!password.empty()) {
            relay_secret_b64 = derive_relay_secret_b64(password);
        }
    }
    return relay_secret_b64;
}

}  // namespace

RelayRuntime::RelayRuntime(std::shared_ptr<Tunnel> tunnel, ClientConfig cfg, Options options)
    : tunnel_(std::move(tunnel))
    , cfg_(std::move(cfg))
    , options_(std::move(options))
    , history_(options_.history_enabled ? options_.history_dir : std::filesystem::path(),
               options_.instance_name.empty() ? "default" : options_.instance_name) {
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
    try {
        auto keys = load_identity_keypair();
        self_.auth_pubkey_b64 = public_key_to_b64(keys.public_key.get());
    } catch (...) {
    }
}

bool RelayRuntime::announce_presence(std::string* error) {
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
    std::vector<control::EndpointInfo> out;
    if (!resp.value("ok", false)) {
        if (error) {
            *error = resp.value("error", "directory request failed");
        }
        return out;
    }
    server_id_ = resp.value("server_id", server_id_);
    server_name_ = resp.value("server_name", server_name_);
    if (resp.contains("endpoints") && resp["endpoints"].is_array()) {
        for (const auto& item : resp["endpoints"]) {
            out.push_back(control::endpoint_from_json(item));
        }
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
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
    auto ephemeral = crypto::generate_x25519_key();
    control::PendingInvite invite;
    invite.invite_id = next_invite_id();
    invite.from_endpoint_id = self_.endpoint_id;
    invite.to_endpoint_id = peer_info->endpoint_id;
    invite.channel_kind = control::ChannelKind::chat;
    invite.requires_password = true;
    invite.nonce_b64 = bytes_to_b64(crypto::random_bytes(16));
    invite.from_display_name = self_.display_name;
    invite.ephemeral_pubkey_b64 = bytes_to_b64(crypto::export_raw_public_key(ephemeral.get()));
    invite.from_auth_pubkey_b64 = self_.auth_pubkey_b64;
    const std::string signed_payload = build_invite_signature_message(invite, false);
    auto identity = load_identity_keypair();
    invite.ephemeral_signature_b64 =
        bytes_to_b64(crypto::sign_message(identity.private_key.get(),
                                          crypto::Bytes(signed_payload.begin(), signed_payload.end())));
    PendingOutgoingInvite outgoing;
    outgoing.invite = invite;
    outgoing.relay_secret_b64 = relay_secret_b64;
    outgoing.ephemeral_key = std::move(ephemeral);
    outgoing.peer = *peer_info;
    outgoing.channel_kind = control::ChannelKind::chat;
    outgoing_invites_[invite.invite_id] = std::move(outgoing);
    nlohmann::json req = control::invite_to_json(invite, false);
    req["cmd"] = "invite.request";
    tunnel_->send_control_json(req);
    return true;
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
    if (it == channels_.end()) {
        if (error) {
            *error = "chat channel unavailable";
        }
        return false;
    }
    nlohmann::json message{{"type", "chat"}, {"text", text}, {"ts_ms", yume::util::now_ms()}};
    auto payload = encrypt_channel_payload(it->second, message.dump());
    tunnel_->send_data(it->second.stream_id, payload);
    append_history(it->second.peer_id, it->second.peer_name, "out", text);
    return true;
}

bool RelayRuntime::send_file(const std::string& peer, const std::filesystem::path& path, const std::string& relay_secret_b64, std::string* error) {
    if (!std::filesystem::exists(path)) {
        if (error) {
            *error = "file not found";
        }
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
    auto ephemeral = crypto::generate_x25519_key();
    control::PendingInvite invite;
    invite.invite_id = next_invite_id();
    invite.from_endpoint_id = self_.endpoint_id;
    invite.to_endpoint_id = peer_info->endpoint_id;
    invite.channel_kind = control::ChannelKind::file;
    invite.requires_password = true;
    invite.nonce_b64 = bytes_to_b64(crypto::random_bytes(16));
    invite.from_display_name = self_.display_name;
    nlohmann::json meta{
        {"name", path.filename().string()},
        {"size", static_cast<std::uint64_t>(std::filesystem::file_size(path))},
        {"sha256", sha256_file_hex(path)},
    };
    invite.metadata_json = meta.dump();
    invite.ephemeral_pubkey_b64 = bytes_to_b64(crypto::export_raw_public_key(ephemeral.get()));
    invite.from_auth_pubkey_b64 = self_.auth_pubkey_b64;
    const std::string signed_payload = build_invite_signature_message(invite, false);
    auto identity = load_identity_keypair();
    invite.ephemeral_signature_b64 =
        bytes_to_b64(crypto::sign_message(identity.private_key.get(),
                                          crypto::Bytes(signed_payload.begin(), signed_payload.end())));
    PendingOutgoingInvite outgoing;
    outgoing.invite = invite;
    outgoing.relay_secret_b64 = relay_secret_b64;
    outgoing.ephemeral_key = std::move(ephemeral);
    outgoing.peer = *peer_info;
    outgoing.payload_path = path;
    outgoing.channel_kind = control::ChannelKind::file;
    outgoing_invites_[invite.invite_id] = std::move(outgoing);
    nlohmann::json req = control::invite_to_json(invite, false);
    req["cmd"] = "invite.request";
    tunnel_->send_control_json(req);
    return true;
}

bool RelayRuntime::send_bytes_path(const std::string& peer, const std::filesystem::path& path, const std::string& relay_secret_b64, std::string* error) {
    if (!std::filesystem::exists(path)) {
        if (error) {
            *error = "path not found";
        }
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
    auto ephemeral = crypto::generate_x25519_key();
    control::PendingInvite invite;
    invite.invite_id = next_invite_id();
    invite.from_endpoint_id = self_.endpoint_id;
    invite.to_endpoint_id = peer_info->endpoint_id;
    invite.channel_kind = control::ChannelKind::bytes;
    invite.requires_password = true;
    invite.nonce_b64 = bytes_to_b64(crypto::random_bytes(16));
    invite.from_display_name = self_.display_name;
    invite.metadata_json = nlohmann::json{{"label", path.filename().string()}}.dump();
    invite.ephemeral_pubkey_b64 = bytes_to_b64(crypto::export_raw_public_key(ephemeral.get()));
    invite.from_auth_pubkey_b64 = self_.auth_pubkey_b64;
    const std::string signed_payload = build_invite_signature_message(invite, false);
    auto identity = load_identity_keypair();
    invite.ephemeral_signature_b64 =
        bytes_to_b64(crypto::sign_message(identity.private_key.get(),
                                          crypto::Bytes(signed_payload.begin(), signed_payload.end())));
    PendingOutgoingInvite outgoing;
    outgoing.invite = invite;
    outgoing.relay_secret_b64 = relay_secret_b64;
    outgoing.ephemeral_key = std::move(ephemeral);
    outgoing.peer = *peer_info;
    outgoing.payload_path = path;
    outgoing.channel_kind = control::ChannelKind::bytes;
    outgoing_invites_[invite.invite_id] = std::move(outgoing);
    nlohmann::json req = control::invite_to_json(invite, false);
    req["cmd"] = "invite.request";
    tunnel_->send_control_json(req);
    return true;
}

bool RelayRuntime::accept_invite(const std::string& invite_id, const std::string& relay_secret_b64, std::string* error) {
    std::lock_guard<std::mutex> lock(mutex_);
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
    if (pending.invite.requires_password && relay_secret_b64.empty()) {
        if (error) {
            *error = "invite password is required";
        }
        return false;
    }
    if (pending.invite.requires_password && !validate_relay_secret_b64(relay_secret_b64, error)) {
        return false;
    }
    pending.relay_secret_b64 = relay_secret_b64;
    pending.ephemeral_key = crypto::generate_x25519_key();
    pending.invite.accepted = true;
    pending.invite.response_reason.clear();
    pending.invite.response_ephemeral_pubkey_b64 = bytes_to_b64(crypto::export_raw_public_key(pending.ephemeral_key.get()));
    const std::string signed_payload = build_invite_signature_message(pending.invite, true);
    auto identity = load_identity_keypair();
    pending.invite.response_ephemeral_signature_b64 =
        bytes_to_b64(crypto::sign_message(identity.private_key.get(),
                                          crypto::Bytes(signed_payload.begin(), signed_payload.end())));
    nlohmann::json req = control::invite_to_json(pending.invite, true);
    req["cmd"] = "invite.reply";
    tunnel_->send_control_json(req);
    return true;
}

bool RelayRuntime::reject_invite(const std::string& invite_id, const std::string& reason, std::string* error) {
    std::lock_guard<std::mutex> lock(mutex_);
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
    it->second.invite.response_reason = reason.empty() ? "rejected" : reason;
    nlohmann::json req = control::invite_to_json(it->second.invite, true);
    req["cmd"] = "invite.reply";
    tunnel_->send_control_json(req);
    incoming_invites_.erase(it);
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
    auto ephemeral = crypto::generate_x25519_key();
    control::PendingInvite invite;
    invite.invite_id = next_invite_id();
    invite.from_endpoint_id = self_.endpoint_id;
    invite.to_endpoint_id = peer_info->endpoint_id;
    invite.channel_kind = control::ChannelKind::admin;
    invite.requires_password = false;
    invite.nonce_b64 = bytes_to_b64(crypto::random_bytes(16));
    invite.from_display_name = self_.display_name;
    invite.ephemeral_pubkey_b64 = bytes_to_b64(crypto::export_raw_public_key(ephemeral.get()));
    invite.from_auth_pubkey_b64 = self_.auth_pubkey_b64;
    const std::string signed_payload = build_invite_signature_message(invite, false);
    auto identity = load_identity_keypair();
    invite.ephemeral_signature_b64 =
        bytes_to_b64(crypto::sign_message(identity.private_key.get(),
                                          crypto::Bytes(signed_payload.begin(), signed_payload.end())));
    PendingOutgoingInvite outgoing;
    outgoing.invite = invite;
    outgoing.relay_secret_b64.clear();
    outgoing.ephemeral_key = std::move(ephemeral);
    outgoing.peer = *peer_info;
    outgoing.channel_kind = control::ChannelKind::admin;
    outgoing_invites_[invite.invite_id] = std::move(outgoing);
    nlohmann::json req = control::invite_to_json(invite, false);
    req["cmd"] = "invite.request";
    tunnel_->send_control_json(req);
    return true;
}

nlohmann::json RelayRuntime::status_json() const {
    std::lock_guard<std::mutex> lock(mutex_);
    nlohmann::json json;
    json["self"] = control::endpoint_to_json(self_, true);
    json["server_id"] = server_id_;
    json["server_name"] = server_name_;
    json["directory_size"] = directory_by_id_.size();
    json["pending_invites"] = incoming_invites_.size();
    json["active_channels"] = channels_.size();
    if (active_chat_stream_.has_value()) {
        json["active_chat_stream"] = *active_chat_stream_;
    }
    if (active_admin_stream_.has_value()) {
        json["active_admin_stream"] = *active_admin_stream_;
    }
    if (latest_lifecycle_.has_value()) {
        json["latest_lifecycle"] = control::lifecycle_event_to_json(*latest_lifecycle_);
    }
    if (tunnel_) {
        json["bytes_in"]  = tunnel_->bytes_received();
        json["bytes_out"] = tunnel_->bytes_sent();
    }
    return json;
}

nlohmann::json RelayRuntime::handle_local_request(const nlohmann::json& request) {
    const std::string op = request.value("op", "");
    const nlohmann::json args = request.value("args", nlohmann::json::object());
    if (op == "runtime.info" || op == "runtime.status") {
        return {{"ok", true}, {"result", status_json()}};
    }
    if (op == "directory.list") {
        std::vector<nlohmann::json> items;
        std::string error;
        for (const auto& endpoint : request_directory(&error)) {
            items.push_back(control::endpoint_to_json(endpoint, true));
        }
        if (!error.empty()) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", items}};
    }
    if (op == "history.list") {
        std::optional<std::string> peer_id;
        if (args.contains("peer_id")) {
            peer_id = args["peer_id"].get<std::string>();
        }
        nlohmann::json items = nlohmann::json::array();
        for (const auto& item : history_.list_chat(peer_id)) {
            items.push_back({{"ts_ms", item.ts_ms}, {"peer_id", item.peer_id}, {"peer_name", item.peer_name},
                             {"direction", item.direction}, {"text", item.text}});
        }
        return {{"ok", true}, {"result", items}};
    }
    if (op == "history.delete") {
        if (args.contains("peer_id")) {
            history_.delete_chat(args["peer_id"].get<std::string>());
        } else {
            history_.delete_chat();
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "invite.list") {
        nlohmann::json items = nlohmann::json::array();
        for (const auto& invite : pending_invites()) {
            items.push_back(control::invite_to_json(invite, true));
        }
        return {{"ok", true}, {"result", items}};
    }
    if (op == "invite.accept") {
        std::string error;
        if (!accept_invite(args.value("invite_id", ""), relay_secret_from_args(args), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "invite.reject") {
        std::string error;
        if (!reject_invite(args.value("invite_id", ""), args.value("reason", ""), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "chat.open") {
        std::string error;
        if (!open_chat(args.value("peer", ""), relay_secret_from_args(args), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "chat.send") {
        std::string error;
        if (!send_chat(args.value("text", ""), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "file.send") {
        std::string error;
        if (!send_file(args.value("peer", ""), args.value("path", ""), relay_secret_from_args(args), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "bytes.send") {
        std::string error;
        if (!send_bytes_path(args.value("peer", ""), args.value("path", ""), relay_secret_from_args(args), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "admin.attach") {
        std::string error;
        if (!admin_attach(args.value("peer", ""), &error)) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", true}};
    }
    if (op == "admin.status" || op == "admin.sessions" || op == "admin.stop") {
        std::string error;
        const std::string remote_op =
            (op == "admin.stop") ? "runtime.stop" :
            ((op == "admin.sessions") ? "runtime.sessions" : "runtime.status");
        auto response = send_admin_request(remote_op, args, &error);
        if (!error.empty()) {
            return {{"ok", false}, {"error", error}};
        }
        return {{"ok", true}, {"result", response}};
    }
    if (op == "runtime.stop") {
        if (stop_callback_) {
            stop_callback_();
        }
        return {{"ok", true}, {"result", true}};
    }
    return {{"ok", false}, {"error", "unsupported op"}};
}

void RelayRuntime::set_stop_callback(std::function<void()> callback) {
    stop_callback_ = std::move(callback);
}

bool RelayRuntime::notify_authenticated(const std::string& effective_protection, std::string* error) {
    return notify_lifecycle("authenticated",
                            "authenticated",
                            "authenticated control path is active",
                            effective_protection,
                            false,
                            "",
                            "",
                            error,
                            2000,
                            true);
}

bool RelayRuntime::notify_traffic_flow(const std::string& effective_protection, std::string* error) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (traffic_flow_announced_) {
            return true;
        }
    }
    const bool ok = notify_lifecycle("traffic_flowing",
                                     "success, traffic flowing",
                                     "first usable traffic observed",
                                     effective_protection,
                                     true,
                                     "",
                                     "",
                                     error,
                                     2000,
                                     true);
    if (ok) {
        std::lock_guard<std::mutex> lock(mutex_);
        traffic_flow_announced_ = true;
    }
    return ok;
}

bool RelayRuntime::notify_disconnecting(const std::string& message, std::string* error) {
    return notify_lifecycle("disconnecting",
                            message,
                            "client requested shutdown",
                            "",
                            false,
                            "",
                            "",
                            error,
                            1200,
                            true);
}

bool RelayRuntime::notify_error(const std::string& message, const std::string& error_code, std::string* error) {
    return notify_lifecycle("error",
                            "error, disconnect",
                            message,
                            "",
                            false,
                            "",
                            error_code,
                            error,
                            1200,
                            true);
}

void RelayRuntime::on_control_message(const nlohmann::json& json) {
    const std::string request_id = json.value("request_id", "");
    if (!request_id.empty()) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = control_responses_.find(request_id);
        if (it != control_responses_.end()) {
            it->second.ready = true;
            it->second.value = json;
            control_cv_.notify_all();
            return;
        }
    }
    const std::string cmd = json.value("cmd", "");
    if (cmd == "invite.request") {
        const std::string invite_id = json.value("invite_id", "");
        if (invite_id.empty()) {
            return;
        }
        control::PendingInvite invite = control::invite_from_json(json);
        if (!verify_invite_signature(invite, false)) {
            util::log_warn("relay invite signature verification failed for " + invite.invite_id);
            return;
        }
        std::lock_guard<std::mutex> lock(mutex_);
        PendingIncomingInvite pending;
        pending.invite = invite;
        incoming_invites_[invite.invite_id] = std::move(pending);
        util::log_info("invite " + invite.invite_id + " from " +
                       (invite.from_display_name.empty() ? invite.from_endpoint_id : invite.from_display_name) +
                       " [" + control::to_string(invite.channel_kind) + "]");
        return;
    }
    if (cmd == "invite.reply") {
        const std::string invite_id = json.value("invite_id", "");
        if (invite_id.empty()) {
            return;
        }
        control::PendingInvite invite = control::invite_from_json(json);
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = outgoing_invites_.find(invite.invite_id);
        if (it == outgoing_invites_.end()) {
            return;
        }
        if (!invite.accepted) {
            util::log_warn("invite rejected: " + invite.response_reason);
            outgoing_invites_.erase(it);
            return;
        }
        std::string error;
        if (!open_channel_from_reply(it->second, invite, &error)) {
            util::log_warn("relay open failed: " + error);
            outgoing_invites_.erase(it);
        } else {
            outgoing_invites_.erase(it);
        }
        return;
    }
}

bool RelayRuntime::notify_lifecycle(const std::string& state,
                                    const std::string& message,
                                    const std::string& detail,
                                    const std::string& effective_protection,
                                    bool traffic_verified,
                                    const std::string& exit_ip,
                                    const std::string& error_code,
                                    std::string* error,
                                    int timeout_ms,
                                    bool quiet_unsupported) {
    control::ClientLifecycleEvent accepted;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (self_.endpoint_id.empty()) {
            if (error) {
                *error = "presence announce required";
            }
            return false;
        }
        accepted.endpoint_id = self_.endpoint_id;
        accepted.display_name = self_.display_name;
        accepted.client_platform = self_.client_platform;
        accepted.client_variant = self_.client_variant;
        accepted.client_version = self_.client_version;
    }

    nlohmann::json req;
    req["cmd"] = "client.lifecycle";
    req["state"] = state;
    req["message"] = message;
    req["detail"] = detail;
    req["client_platform"] = accepted.client_platform;
    req["client_variant"] = accepted.client_variant;
    req["client_version"] = accepted.client_version;
    req["effective_protection"] = effective_protection;
    req["traffic_verified"] = traffic_verified;
    req["exit_ip"] = exit_ip;
    req["error_code"] = error_code;

    std::string request_error;
    auto resp = send_control_request(std::move(req), &request_error, timeout_ms);
    if (!request_error.empty()) {
        if (!quiet_unsupported) {
            log_lifecycle_unsupported_once(request_error);
        }
        if (error) {
            *error = request_error;
        }
        return false;
    }
    if (!resp.value("ok", false)) {
        const std::string server_error = resp.value("error", "lifecycle update failed");
        if (server_error == "unknown control command") {
            if (!quiet_unsupported) {
                log_lifecycle_unsupported_once(server_error);
            }
        } else if (error) {
            *error = server_error;
        }
        return false;
    }

    accepted.state = resp.value("accepted_state", state);
    accepted.message = message;
    accepted.detail = detail;
    accepted.effective_protection = effective_protection;
    accepted.traffic_verified = traffic_verified;
    accepted.exit_ip = exit_ip;
    accepted.error_code = error_code;
    accepted.server_time_ms = resp.value("server_time_ms", 0LL);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        latest_lifecycle_ = accepted;
    }
    return true;
}

void RelayRuntime::log_lifecycle_unsupported_once(const std::string& reason) {
    bool should_log = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!lifecycle_unsupported_logged_) {
            lifecycle_unsupported_logged_ = true;
            should_log = true;
        }
    }
    if (should_log) {
        util::log_warn("relay lifecycle notifications unavailable: " + reason);
    }
}

void RelayRuntime::on_inbound_open(uint8_t stream_id, const nlohmann::json& json) {
    const std::string channel_id = json.value("channel_id", "");
    const std::string from_id = json.value("from_id", "");
    const auto kind = control::channel_kind_from_string(json.value("channel_kind", "chat"));
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = incoming_invites_.find(channel_id);
    if (it == incoming_invites_.end() || !it->second.invite.accepted || !it->second.ephemeral_key) {
        tunnel_->send_open_ack(stream_id, false, "invite not accepted");
        return;
    }
    const auto peer_it = directory_by_id_.find(from_id);
    if (peer_it == directory_by_id_.end()) {
        tunnel_->send_open_ack(stream_id, false, "unknown peer");
        return;
    }
    ChannelState channel;
    channel.channel_id = channel_id;
    channel.channel_kind = kind;
    channel.peer_id = from_id;
    channel.peer_name = peer_it->second.display_name;
    channel.stream_id = stream_id;
    auto keys = derive_channel_keys(false,
                                    it->second.ephemeral_key.get(),
                                    it->second.invite.ephemeral_pubkey_b64,
                                    it->second.relay_secret_b64,
                                    it->second.invite.nonce_b64);
    channel.send_key = std::move(keys.send_key);
    channel.recv_key = std::move(keys.recv_key);
    channel.send_nonce_prefix = std::move(keys.send_nonce_prefix);
    channel.recv_nonce_prefix = std::move(keys.recv_nonce_prefix);
    register_channel(stream_id, std::move(channel));
    if (kind == control::ChannelKind::chat) {
        active_chat_stream_ = stream_id;
    } else if (kind == control::ChannelKind::admin) {
        active_admin_stream_ = stream_id;
    }
    incoming_invites_.erase(it);
    tunnel_->send_open_ack(stream_id, true, "");
}

std::string RelayRuntime::next_request_id() {
    return now_request_id();
}

std::string RelayRuntime::next_invite_id() {
    return yume::identity::generate_endpoint_id();
}

nlohmann::json RelayRuntime::send_control_request(nlohmann::json request, std::string* error, int timeout_ms) {
    const std::string request_id = next_request_id();
    request["request_id"] = request_id;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        control_responses_[request_id] = PendingControlResponse{};
    }
    tunnel_->send_control_json(request);
    std::unique_lock<std::mutex> lock(mutex_);
    auto ok = control_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&]() {
        auto it = control_responses_.find(request_id);
        return it != control_responses_.end() && it->second.ready;
    });
    if (!ok) {
        control_responses_.erase(request_id);
        if (error) {
            *error = "control request timed out";
        }
        return nlohmann::json::object();
    }
    auto value = control_responses_[request_id].value;
    control_responses_.erase(request_id);
    return value;
}

nlohmann::json RelayRuntime::send_admin_request(const std::string& op,
                                                const nlohmann::json& args,
                                                std::string* error,
                                                int timeout_ms) {
    const std::string request_id = next_request_id();
    uint8_t stream_id = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!active_admin_stream_.has_value()) {
            if (error) {
                *error = "no active admin channel";
            }
            return nlohmann::json::object();
        }
        stream_id = *active_admin_stream_;
        auto it = channels_.find(stream_id);
        if (it == channels_.end()) {
            if (error) {
                *error = "admin channel is unavailable";
            }
            return nlohmann::json::object();
        }
        admin_responses_[request_id] = PendingAdminResponse{};
        nlohmann::json request{
            {"type", "admin_req"},
            {"request_id", request_id},
            {"op", op},
            {"args", args},
        };
        auto blob = encrypt_channel_payload(it->second, request.dump());
        tunnel_->send_data(stream_id, blob);
    }

    std::unique_lock<std::mutex> lock(mutex_);
    const bool ok = admin_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&]() {
        auto it = admin_responses_.find(request_id);
        return it != admin_responses_.end() && it->second.ready;
    });
    if (!ok) {
        admin_responses_.erase(request_id);
        if (error) {
            *error = "admin request timed out";
        }
        return nlohmann::json::object();
    }
    auto response = admin_responses_[request_id].value;
    admin_responses_.erase(request_id);
    return response;
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
        directory_by_id_[endpoint.endpoint_id] = endpoint;
        directory_name_to_id_[endpoint.display_name] = endpoint.endpoint_id;
    }
}

std::string RelayRuntime::build_invite_signature_message(const control::PendingInvite& invite, bool response) {
    std::ostringstream oss;
    oss << invite.invite_id << '|'
        << control::to_string(invite.channel_kind) << '|'
        << invite.from_endpoint_id << '|'
        << invite.to_endpoint_id << '|'
        << invite.nonce_b64 << '|';
    if (response) {
        oss << invite.response_ephemeral_pubkey_b64;
    } else {
        oss << invite.ephemeral_pubkey_b64;
    }
    oss << '|' << (response ? "resp" : "req");
    return oss.str();
}

crypto::KeyPair RelayRuntime::load_identity_keypair() const {
    return crypto::load_keypair(options_.identity_path, "");
}

bool RelayRuntime::verify_invite_signature(const control::PendingInvite& invite, bool response) const {
    try {
        std::string auth_b64 = response ? self_.auth_pubkey_b64 : invite.from_auth_pubkey_b64;
        if (response) {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = directory_by_id_.find(invite.to_endpoint_id);
            if (it != directory_by_id_.end()) {
                auth_b64 = it->second.auth_pubkey_b64;
            }
        }
        if (auth_b64.empty()) {
            return false;
        }
        auto pub = load_public_key_from_b64(auth_b64);
        const std::string message = build_invite_signature_message(invite, response);
        auto sig = response ? b64_to_bytes(invite.response_ephemeral_signature_b64)
                            : b64_to_bytes(invite.ephemeral_signature_b64);
        return crypto::verify_key(pub.get(),
                                  crypto::Bytes(message.begin(), message.end()),
                                  sig);
    } catch (...) {
        return false;
    }
}

RelayRuntime::DerivedChannelKeys RelayRuntime::derive_channel_keys(bool initiator,
                                                                   EVP_PKEY* local_ephemeral,
                                                                   const std::string& peer_ephemeral_b64,
                                                                   const std::string& relay_secret_b64,
                                                                   const std::string& nonce_b64) const {
    auto peer = crypto::import_x25519_public_key(b64_to_bytes(peer_ephemeral_b64));
    auto shared = crypto::generate_session_key(local_ephemeral, peer.get(), 32);
    crypto::Bytes material = shared;
    auto relay_secret = b64_to_bytes(relay_secret_b64);
    material.insert(material.end(), relay_secret.begin(), relay_secret.end());
    auto nonce = b64_to_bytes(nonce_b64);
    material.insert(material.end(), nonce.begin(), nonce.end());
    auto master = crypto::hkdf_sha256(material, "yume-relay-master", 32);
    DerivedChannelKeys keys;
    if (initiator) {
        keys.send_key = crypto::hkdf_sha256(master, "yume-relay-initiator-send", 32);
        keys.recv_key = crypto::hkdf_sha256(master, "yume-relay-responder-send", 32);
        keys.send_nonce_prefix = crypto::hkdf_sha256(master, "yume-relay-initiator-nonce", 4);
        keys.recv_nonce_prefix = crypto::hkdf_sha256(master, "yume-relay-responder-nonce", 4);
    } else {
        keys.send_key = crypto::hkdf_sha256(master, "yume-relay-responder-send", 32);
        keys.recv_key = crypto::hkdf_sha256(master, "yume-relay-initiator-send", 32);
        keys.send_nonce_prefix = crypto::hkdf_sha256(master, "yume-relay-responder-nonce", 4);
        keys.recv_nonce_prefix = crypto::hkdf_sha256(master, "yume-relay-initiator-nonce", 4);
    }
    return keys;
}

bool RelayRuntime::open_channel_from_reply(const PendingOutgoingInvite& outgoing, const control::PendingInvite& reply, std::string* error) {
    if (!verify_invite_signature(reply, true)) {
        if (error) {
            *error = "reply signature verification failed";
        }
        return false;
    }
    const auto keys = derive_channel_keys(true,
                                          outgoing.ephemeral_key.get(),
                                          reply.response_ephemeral_pubkey_b64,
                                          outgoing.relay_secret_b64,
                                          reply.nonce_b64);
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
    channel.peer_id = outgoing.peer.endpoint_id;
    channel.peer_name = outgoing.peer.display_name;
    channel.stream_id = stream_id;
    channel.send_key = keys.send_key;
    channel.recv_key = keys.recv_key;
    channel.send_nonce_prefix = keys.send_nonce_prefix;
    channel.recv_nonce_prefix = keys.recv_nonce_prefix;
    auto payload = nlohmann::json{
        {"channel_id", outgoing.invite.invite_id},
        {"channel_kind", control::to_string(outgoing.channel_kind)},
        {"from_id", self_.endpoint_id},
        {"to_id", outgoing.peer.endpoint_id},
        {"target_id", outgoing.peer.endpoint_id},
        {"e2ee_required", true},
    };
    if (!outgoing.invite.metadata_json.empty()) {
        try {
            payload["meta"] = nlohmann::json::parse(outgoing.invite.metadata_json);
        } catch (...) {
            payload["meta_json"] = outgoing.invite.metadata_json;
        }
    }
    auto payload_path = outgoing.payload_path;
    auto channel_kind = outgoing.channel_kind;
    auto pending_channel = std::make_shared<ChannelState>(std::move(channel));
    tunnel_->open_relay_stream(
        stream_id,
        payload,
        [this, stream_id, pending_channel, payload_path, channel_kind](bool ok, const std::string& reason) mutable {
        if (!ok) {
            util::log_warn("relay open failed: " + reason);
            return;
        }
        {
            std::lock_guard<std::mutex> lock(mutex_);
            register_channel(stream_id, std::move(*pending_channel));
            if (channel_kind == control::ChannelKind::chat) {
                active_chat_stream_ = stream_id;
            } else if (channel_kind == control::ChannelKind::admin) {
                active_admin_stream_ = stream_id;
            }
        }
        if (channel_kind == control::ChannelKind::file || channel_kind == control::ChannelKind::bytes) {
            std::ifstream in(payload_path, std::ios::binary);
            if (!in) {
                return;
            }
            nlohmann::json meta{
                {"type", channel_kind == control::ChannelKind::file ? "file_meta" : "bytes_meta"},
                {"name", payload_path.filename().string()},
                {"size", static_cast<std::uint64_t>(std::filesystem::file_size(payload_path))},
            };
            {
                std::lock_guard<std::mutex> lock(mutex_);
                auto it = channels_.find(stream_id);
                if (it != channels_.end()) {
                    auto blob = encrypt_channel_payload(it->second, meta.dump());
                    tunnel_->send_data(stream_id, blob);
                }
            }
            std::array<char, 32768> buf{};
            while (in) {
                in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
                if (in.gcount() <= 0) {
                    break;
                }
                nlohmann::json chunk{{"type", channel_kind == control::ChannelKind::file ? "file_chunk" : "bytes_chunk"},
                                     {"data_b64", yume::util::base64_encode(std::string(buf.data(), static_cast<size_t>(in.gcount())))}};
                std::lock_guard<std::mutex> lock(mutex_);
                auto it = channels_.find(stream_id);
                if (it != channels_.end()) {
                    auto blob = encrypt_channel_payload(it->second, chunk.dump());
                    tunnel_->send_data(stream_id, blob);
                }
            }
            nlohmann::json done{{"type", channel_kind == control::ChannelKind::file ? "file_done" : "bytes_done"}};
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = channels_.find(stream_id);
            if (it != channels_.end()) {
                auto blob = encrypt_channel_payload(it->second, done.dump());
                tunnel_->send_data(stream_id, blob);
                tunnel_->send_close(stream_id, "transfer complete");
            }
        }
    });
    return true;
}

void RelayRuntime::register_channel(uint8_t stream_id, ChannelState channel) {
    channels_[stream_id] = std::move(channel);
    tunnel_->register_stream(
        stream_id,
        [this, stream_id](const Tunnel::Bytes& payload) {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = channels_.find(stream_id);
            if (it != channels_.end()) {
                handle_channel_data(&it->second, payload);
            }
        },
        [this, stream_id](const std::string& reason) {
            std::lock_guard<std::mutex> lock(mutex_);
            handle_channel_close(stream_id, reason);
        });
}

void RelayRuntime::handle_channel_data(ChannelState* channel, const Tunnel::Bytes& payload) {
    if (!channel) {
        return;
    }
    try {
        const std::string plain = decrypt_channel_payload(*channel, payload);
        auto json = nlohmann::json::parse(plain);
        const std::string type = json.value("type", "");
        if (type == "chat") {
            const std::string text = json.value("text", "");
            util::log_info("[" + channel->peer_name + "] " + text);
            append_history(channel->peer_id, channel->peer_name, "in", text);
            return;
        }
        if (type == "file_meta" || type == "bytes_meta") {
            std::string name = json.value("name", channel->channel_id + ".bin");
            auto out_path = std::filesystem::current_path() / name;
            if (std::filesystem::exists(out_path)) {
                out_path += ".recv";
            }
            channel->receive_path = out_path;
            channel->receive_stream.open(out_path, std::ios::binary | std::ios::trunc);
            channel->bytes_label = name;
            util::log_info("receiving " + name + " from " + channel->peer_name);
            return;
        }
        if (type == "file_chunk" || type == "bytes_chunk") {
            if (channel->receive_stream.is_open()) {
                std::string data = yume::util::base64_decode(json.value("data_b64", ""));
                channel->receive_stream.write(data.data(), static_cast<std::streamsize>(data.size()));
            }
            return;
        }
        if (type == "file_done" || type == "bytes_done") {
            if (channel->receive_stream.is_open()) {
                channel->receive_stream.close();
                util::log_info("saved " + channel->receive_path.string());
            }
            return;
        }
        if (type == "admin_req") {
            send_admin_response(*channel, handle_admin_request(json));
            return;
        }
        if (type == "admin_resp") {
            const std::string request_id = json.value("request_id", "");
            if (!request_id.empty()) {
                auto it = admin_responses_.find(request_id);
                if (it != admin_responses_.end()) {
                    it->second.ready = true;
                    it->second.value = json.value("payload", nlohmann::json::object());
                    admin_cv_.notify_all();
                    return;
                }
            }
            util::log_info("admin: " + json.value("payload", nlohmann::json::object()).dump());
        }
    } catch (const std::exception& ex) {
        const std::string detail = ex.what();
        if (detail.find("authentication check failed") != std::string::npos) {
            const std::string reason = "relay password mismatch or channel authentication failed";
            util::log_warn("communication with " +
                           (channel->peer_name.empty() ? channel->peer_id : channel->peer_name) +
                           " failed: " + reason);
            tunnel_->send_close(channel->stream_id, reason);
            tunnel_->unregister_stream(channel->stream_id);
            handle_channel_close(channel->stream_id, reason);
            return;
        }
        util::log_warn(std::string("channel decode failed: ") + detail);
    }
}

void RelayRuntime::handle_channel_close(uint8_t stream_id, const std::string& reason) {
    auto it = channels_.find(stream_id);
    if (it == channels_.end()) {
        return;
    }
    const std::string peer_label = it->second.peer_name.empty() ? it->second.peer_id : it->second.peer_name;
    if (it->second.receive_stream.is_open()) {
        it->second.receive_stream.close();
    }
    if (active_chat_stream_ == stream_id) {
        active_chat_stream_.reset();
    }
    if (active_admin_stream_ == stream_id) {
        active_admin_stream_.reset();
    }
    if (!reason.empty()) {
        util::log_warn("channel with " + peer_label + " closed: " + reason);
    }
    channels_.erase(it);
}

Tunnel::Bytes RelayRuntime::encrypt_channel_payload(ChannelState& channel, const std::string& plaintext) {
    auto nonce = counter_nonce(channel.send_nonce_prefix, channel.send_counter++);
    return crypto::encrypt_chacha20(crypto::Bytes(plaintext.begin(), plaintext.end()), channel.send_key, nonce);
}

std::string RelayRuntime::decrypt_channel_payload(ChannelState& channel, const Tunnel::Bytes& ciphertext) {
    auto nonce = counter_nonce(channel.recv_nonce_prefix, channel.recv_counter++);
    auto plain = crypto::decrypt_chacha20(ciphertext, channel.recv_key, nonce);
    return std::string(plain.begin(), plain.end());
}

void RelayRuntime::append_history(const std::string& peer_id, const std::string& peer_name, const std::string& direction, const std::string& text) {
    if (!options_.history_enabled) {
        return;
    }
    history_.append_chat(ChatHistoryEntry{yume::util::now_ms(), peer_id, peer_name, direction, text});
}

nlohmann::json RelayRuntime::handle_admin_request(const nlohmann::json& json) {
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
        if (stop_callback_) {
            stop_callback_();
        }
        return {{"type", "admin_resp"}, {"request_id", request_id}, {"payload", {{"stopping", true}}}};
    }
    return {{"type", "admin_resp"}, {"request_id", request_id}, {"payload", {{"error", "unsupported op"}}}};
}

void RelayRuntime::send_admin_response(ChannelState& channel, const nlohmann::json& response) {
    auto blob = encrypt_channel_payload(channel, response.dump());
    tunnel_->send_data(channel.stream_id, blob);
}

}  // namespace yume::client
