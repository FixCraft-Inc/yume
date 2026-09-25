/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_credentials.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <exception>
#include <initializer_list>
#include <limits>
#include <new>
#include <set>
#include <utility>

#include <nlohmann/json.hpp>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/x509.h>

#include "common/secure_erase.hpp"
#include "fs/secret_file.hpp"
#include "providers/openssl_security_provider.hpp"
#include "providers/tls13_secure_channel.hpp"
#include "runtime/egress_limiter.hpp"
#include "ytp/security.hpp"

namespace yume::runtime {
namespace {

using Json = nlohmann::json;
using engine::Result;
using engine::Status;
using engine::StatusCode;
constexpr std::size_t kMaxPemBytes = 256U * 1024U;
constexpr std::size_t kMaxStoreBytes = 1024U * 1024U;
constexpr std::size_t kMaxAdminIdentities = 4096U;
constexpr const char* kProperties = "provider=default";

class CredentialError final : public std::exception {
public:
    explicit CredentialError(
        const char* message,
        StatusCode code = StatusCode::InvalidArgument) noexcept
        : message_(message), code_(code) {}
    const char* what() const noexcept override { return message_; }
    StatusCode code() const noexcept { return code_; }

private:
    const char* message_;
    StatusCode code_;
};

void require(bool condition, const char* message,
             StatusCode code = StatusCode::InvalidArgument) {
    if (!condition) throw CredentialError(message, code);
}

class SecretBytes final {
public:
    explicit SecretBytes(std::vector<std::uint8_t>&& bytes) noexcept
        : bytes_(std::move(bytes)) {}
    explicit SecretBytes(std::size_t size) : bytes_(size) {}
    SecretBytes(const SecretBytes&) = delete;
    SecretBytes& operator=(const SecretBytes&) = delete;
    SecretBytes(SecretBytes&& other) noexcept
        : bytes_(std::move(other.bytes_)) {}
    SecretBytes& operator=(SecretBytes&& other) noexcept {
        if (this != &other) {
            security::secure_erase(bytes_);
            bytes_ = std::move(other.bytes_);
        }
        return *this;
    }
    ~SecretBytes() { security::secure_erase(bytes_); }
    std::span<const std::byte> bytes() const noexcept {
        return std::as_bytes(std::span(bytes_));
    }
    std::string_view text() const noexcept {
        return {reinterpret_cast<const char*>(bytes_.data()), bytes_.size()};
    }
    unsigned char* data() noexcept { return bytes_.data(); }
    std::size_t size() const noexcept { return bytes_.size(); }

private:
    std::vector<std::uint8_t> bytes_;
};

using LibCtxPtr = std::unique_ptr<OSSL_LIB_CTX, decltype(&OSSL_LIB_CTX_free)>;
using ProviderPtr =
    std::unique_ptr<OSSL_PROVIDER, decltype(&OSSL_PROVIDER_unload)>;
using MdPtr = std::unique_ptr<EVP_MD, decltype(&EVP_MD_free)>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
using PkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

struct Pkcs8Deleter final {
    void operator()(PKCS8_PRIV_KEY_INFO* value) const noexcept {
        if (!value) return;
        const unsigned char* bytes = nullptr;
        int size = 0;
        if (PKCS8_pkey_get0(nullptr, &bytes, &size, nullptr, value) == 1 &&
            size > 0) {
            OPENSSL_cleanse(const_cast<unsigned char*>(bytes),
                            static_cast<std::size_t>(size));
        }
        PKCS8_PRIV_KEY_INFO_free(value);
    }
};

// PEM decoding, canonicalization and fingerprints have their own private
// context. Only DER bytes cross into the independently owned session factory.
class CredentialCrypto final {
public:
    CredentialCrypto()
        : context_(OSSL_LIB_CTX_new(), OSSL_LIB_CTX_free),
          provider_(context_ ? OSSL_PROVIDER_load(context_.get(), "default")
                             : nullptr,
                    OSSL_PROVIDER_unload),
          sha256_(context_ ? EVP_MD_fetch(context_.get(), "SHA256", kProperties)
                           : nullptr,
                  EVP_MD_free) {
        require(context_ && provider_ && sha256_,
                "credential OpenSSL default provider is unavailable",
                StatusCode::ProviderMismatch);
    }
    OSSL_LIB_CTX* context() const noexcept { return context_.get(); }

    std::string fingerprint(std::span<const std::byte> classical,
                            std::span<const std::byte> post_quantum) const {
        MdCtxPtr digest(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        require(
            digest &&
                EVP_DigestInit_ex2(digest.get(), sha256_.get(), nullptr) == 1 &&
                EVP_DigestUpdate(digest.get(),
                                 ytp1::kCompositeIdentityDomain.data(),
                                 ytp1::kCompositeIdentityDomain.size()) == 1,
            "composite fingerprint initialization failed");
        for (const auto bytes : {classical, post_quantum}) {
            require(bytes.size() <= std::numeric_limits<std::uint32_t>::max(),
                    "composite identity exceeds its size bound");
            const auto size = static_cast<std::uint32_t>(bytes.size());
            const std::array<unsigned char, 4> length{
                static_cast<unsigned char>(size >> 24U),
                static_cast<unsigned char>(size >> 16U),
                static_cast<unsigned char>(size >> 8U),
                static_cast<unsigned char>(size)};
            require(EVP_DigestUpdate(digest.get(), length.data(),
                                     length.size()) == 1 &&
                        EVP_DigestUpdate(digest.get(), bytes.data(),
                                         bytes.size()) == 1,
                    "composite fingerprint update failed");
        }
        std::array<unsigned char, 32> hash{};
        unsigned int size = 0;
        require(EVP_DigestFinal_ex(digest.get(), hash.data(), &size) == 1 &&
                    size == hash.size(),
                "composite fingerprint failed");
        constexpr char kHex[] = "0123456789abcdef";
        std::string output(64, '0');
        for (std::size_t i = 0; i < hash.size(); ++i) {
            output[i * 2] = kHex[hash[i] >> 4U];
            output[i * 2 + 1] = kHex[hash[i] & 15U];
        }
        return output;
    }

private:
    LibCtxPtr context_;
    ProviderPtr provider_;
    MdPtr sha256_;
};

bool ascii_space(char value) noexcept {
    return value == ' ' || value == '\t' || value == '\r' || value == '\n';
}

std::filesystem::path resolve_reference(const std::filesystem::path& base,
                                        std::string_view text) {
    require(
        !text.empty() && text.size() <= config::v1::kMaxFileReferenceBytes &&
            !ascii_space(text.front()) && !ascii_space(text.back()) &&
            text.front() != '~' && text.find("://") == std::string_view::npos &&
            !text.starts_with("-----BEGIN") && text != ".",
        "credential file reference is invalid");
    require(std::all_of(text.begin(), text.end(),
                        [](unsigned char value) {
                            return value >= 0x20U && value != 0x7fU;
                        }),
            "credential file reference contains a control character");
    require(!(text.size() == 64 &&
              std::all_of(text.begin(), text.end(),
                          [](unsigned char value) {
                              return (value >= '0' && value <= '9') ||
                                     (value >= 'a' && value <= 'f') ||
                                     (value >= 'A' && value <= 'F');
                          })),
            "inline credential material is forbidden");
    std::size_t begin = 0;
    do {
        const auto end = text.find_first_of("/\\", begin);
        require(text.substr(
                    begin, end == std::string_view::npos ? end : end - begin) !=
                    "..",
                "credential file reference contains parent traversal");
        if (end == std::string_view::npos) break;
        begin = end + 1;
    } while (begin <= text.size());
    std::filesystem::path path(text);
    return path.is_absolute() ? path : base / path;
}

SecretBytes read_file(const std::filesystem::path& path, std::size_t maximum) {
    try {
        SecretBytes bytes(security::read_private_file_strict(
            path, maximum, "native credential"));
        require(bytes.size() != 0, "credential file must not be empty");
        return bytes;
    } catch (const std::bad_alloc&) {
        throw;
    } catch (...) {
        // The lower-level loader can mention a local path. Runtime diagnostics
        // identify the failed operation without publishing credential inputs.
        throw CredentialError("credential file failed protected read");
    }
}

SecretBytes read_file(const std::filesystem::path& base,
                      const config::v1::FileReference& reference,
                      std::size_t maximum = kMaxPemBytes) {
    return read_file(resolve_reference(base, reference.path()), maximum);
}

SecretBytes read_psk(const std::filesystem::path& path) {
    auto bytes = read_file(path, 32);
    require(bytes.size() == 32,
            "credential secret must contain exactly 32 raw bytes");
    require(std::any_of(bytes.bytes().begin(), bytes.bytes().end(),
                        [](std::byte value) { return value != std::byte{0}; }),
            "credential secret must not be all zero");
    return bytes;
}

// The username on the first line and the password on the second, each 1 to
// 255 bytes, with at most one final newline and no carriage return or NUL.
common::Socks5Credentials read_socks5_credentials(const std::filesystem::path& base,
                                                  const config::v1::FileReference& reference) {
    const auto bytes = read_file(base, reference, 2U * common::Socks5Credentials::kMaxFieldBytes + 2U);
    std::string_view text = bytes.text();
    require(text.find('\r') == std::string_view::npos &&
                text.find('\0') == std::string_view::npos,
            "SOCKS5 proxy credentials must not contain a carriage return or NUL");
    const auto line_end = text.find('\n');
    require(line_end != std::string_view::npos,
            "SOCKS5 proxy credentials need a username line and a password line");
    std::string_view password = text.substr(line_end + 1U);
    if (!password.empty() && password.back() == '\n') password.remove_suffix(1U);
    require(password.find('\n') == std::string_view::npos,
            "SOCKS5 proxy credentials hold only a username line and a password line");
    auto credentials = common::Socks5Credentials::create(std::string(text.substr(0U, line_end)),
                                                         std::string(password));
    require(credentials.has_value(),
            "SOCKS5 proxy username and password need 1 to 255 bytes each");
    return std::move(*credentials);
}

std::vector<std::string_view> pem_blocks(std::string_view text,
                                         bool private_key, std::size_t count) {
    const std::string_view begin = private_key ? "-----BEGIN PRIVATE KEY-----"
                                               : "-----BEGIN PUBLIC KEY-----";
    const std::string_view end =
        private_key ? "-----END PRIVATE KEY-----" : "-----END PUBLIC KEY-----";
    std::vector<std::string_view> output;
    output.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        while (!text.empty() && ascii_space(text.front()))
            text.remove_prefix(1);
        require(text.starts_with(begin),
                "credential PEM block type or order is invalid");
        const auto boundary = text.find(end, begin.size());
        require(boundary != std::string_view::npos,
                "credential PEM block is unterminated");
        const auto body = text.substr(begin.size(), boundary - begin.size());
        require(std::all_of(body.begin(), body.end(), [](unsigned char value) {
                    return ascii_space(static_cast<char>(value)) ||
                           (value >= 'a' && value <= 'z') ||
                           (value >= 'A' && value <= 'Z') ||
                           (value >= '0' && value <= '9') || value == '+' ||
                           value == '/' || value == '=';
                }),
                "credential PEM contains headers or invalid encoding");
        const auto size = boundary + end.size();
        output.push_back(text.substr(0, size));
        text.remove_prefix(size);
    }
    require(std::all_of(text.begin(), text.end(), ascii_space),
            "credential PEM contains trailing data or extra keys");
    return output;
}

int refuse_password(char*, int, int, void*) noexcept {
    return 0;
}

PkeyPtr parse_key(const CredentialCrypto& crypto, std::string_view pem,
                  bool private_key, const char* algorithm) {
    require(
        pem.size() <= static_cast<std::size_t>(std::numeric_limits<int>::max()),
        "credential PEM exceeds parser bounds");
    BioPtr input(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())),
                 BIO_free);
    require(static_cast<bool>(input),
            "credential PEM reader allocation failed");
    PkeyPtr key(
        private_key
            ? PEM_read_bio_PrivateKey_ex(input.get(), nullptr, refuse_password,
                                         nullptr, crypto.context(), kProperties)
            : PEM_read_bio_PUBKEY_ex(input.get(), nullptr, refuse_password,
                                     nullptr, crypto.context(), kProperties),
        EVP_PKEY_free);
    require(key && EVP_PKEY_is_a(key.get(), algorithm) == 1,
            "credential key does not match the required algorithm");
    const auto* provider = EVP_PKEY_get0_provider(key.get());
    require(provider && std::string_view(OSSL_PROVIDER_get0_name(provider)) ==
                            "default",
            "credential key uses an unexpected provider");
    return key;
}

SecretBytes private_der(EVP_PKEY* key) {
    std::unique_ptr<PKCS8_PRIV_KEY_INFO, Pkcs8Deleter> encoded(
        EVP_PKEY2PKCS8(key));
    const int size =
        encoded ? i2d_PKCS8_PRIV_KEY_INFO(encoded.get(), nullptr) : -1;
    require(size > 0 && static_cast<std::size_t>(size) <=
                            security::kMaxPrivateKeyFileBytes,
            "credential private DER encoding size is invalid");
    SecretBytes result(static_cast<std::size_t>(size));
    unsigned char* cursor = result.data();
    require(i2d_PKCS8_PRIV_KEY_INFO(encoded.get(), &cursor) == size &&
                cursor == result.data() + result.size(),
            "credential private DER encoding failed");
    return result;
}

std::vector<std::byte> public_der(EVP_PKEY* key) {
    const int size = i2d_PUBKEY(key, nullptr);
    require(size > 0 && static_cast<std::size_t>(size) <=
                            security::kMaxPrivateKeyFileBytes,
            "credential public DER encoding size is invalid");
    std::vector<std::byte> result(static_cast<std::size_t>(size));
    auto* cursor = reinterpret_cast<unsigned char*>(result.data());
    require(i2d_PUBKEY(key, &cursor) == size &&
                cursor == reinterpret_cast<unsigned char*>(result.data()) +
                              result.size(),
            "credential public DER encoding failed");
    return result;
}

struct CompositePublic final {
    std::vector<std::byte> classical;
    std::vector<std::byte> post_quantum;
    std::string fingerprint;
    providers::CompositePublicIdentityView view() const noexcept {
        return {classical, post_quantum};
    }
};

CompositePublic read_public_identity(const CredentialCrypto& crypto,
                                     const std::filesystem::path& path) {
    auto pem = read_file(path, kMaxPemBytes);
    auto blocks = pem_blocks(pem.text(), false, 2);
    auto classical = parse_key(crypto, blocks[0], false, "ED25519");
    auto pq = parse_key(crypto, blocks[1], false, "ML-DSA-87");
    CompositePublic identity{
        public_der(classical.get()), public_der(pq.get()), {}};
    identity.fingerprint =
        crypto.fingerprint(identity.classical, identity.post_quantum);
    return identity;
}

struct CompositePrivate final {
    SecretBytes classical;
    SecretBytes post_quantum;
    providers::CompositePrivateIdentityView view() const noexcept {
        return {classical.bytes(), post_quantum.bytes()};
    }
};

CompositePrivate read_private_identity(const CredentialCrypto& crypto,
                                       const std::filesystem::path& path) {
    auto pem = read_file(path, kMaxPemBytes);
    auto blocks = pem_blocks(pem.text(), true, 2);
    auto classical = parse_key(crypto, blocks[0], true, "ED25519");
    auto pq = parse_key(crypto, blocks[1], true, "ML-DSA-87");
    return {private_der(classical.get()), private_der(pq.get())};
}

const Json& closed_object(const Json& value,
                          std::initializer_list<std::string_view> fields) {
    require(value.is_object() && value.size() == fields.size(),
            "credential store object has missing or unknown fields");
    for (auto field : fields) {
        require(value.contains(field),
                "credential store object is missing a field");
    }
    return value;
}

// Like closed_object, with fields that may be absent.
const Json& closed_object(const Json& value,
                          std::initializer_list<std::string_view> fields,
                          std::initializer_list<std::string_view> optional) {
    require(value.is_object(), "credential store object has missing or unknown fields");
    std::size_t present = 0U;
    for (auto field : fields) {
        require(value.contains(field), "credential store object is missing a field");
        ++present;
    }
    for (auto field : optional) {
        if (value.contains(field)) ++present;
    }
    require(value.size() == present,
            "credential store object has missing or unknown fields");
    return value;
}

const std::string& string_field(const Json& value, std::size_t maximum) {
    require(value.is_string(), "credential store field must be a string");
    const auto& text = value.get_ref<const std::string&>();
    require(!text.empty() && text.size() <= maximum,
            "credential store string size is invalid");
    return text;
}

Json read_store(const std::filesystem::path& path, std::size_t maximum,
                bool empty_allowed) {
    auto bytes = read_file(path, kMaxStoreBytes);
    std::vector<std::set<std::string>> object_keys;
    auto callback = [&object_keys](int depth, Json::parse_event_t event,
                                   Json& value) {
        require(depth >= 0 && depth <= 16,
                "credential store nesting is too deep");
        if (event == Json::parse_event_t::object_start)
            object_keys.emplace_back();
        if (event == Json::parse_event_t::key) {
            require(
                !object_keys.empty() &&
                    object_keys.back().insert(value.get<std::string>()).second,
                "credential store contains a duplicate object key");
        }
        if (event == Json::parse_event_t::object_end) object_keys.pop_back();
        return true;
    };
    Json document;
    try {
        document = Json::parse(bytes.text(), callback);
    } catch (const Json::exception&) {
        throw CredentialError("credential store JSON is invalid");
    }
    closed_object(document, {"schema", "keys"});
    const auto& schema = document.at("schema");
    require(schema.is_number_integer() && schema == 1,
            "credential store schema must be integer 1");
    const auto& keys = document.at("keys");
    require(keys.is_array() && keys.size() <= maximum &&
                (empty_allowed || !keys.empty()),
            "credential store key count is invalid");
    return document;
}

void validate_label(const std::string& label) {
    const auto alnum = [](unsigned char byte) {
        return (byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
               (byte >= '0' && byte <= '9');
    };
    require(alnum(label.front()) && alnum(label.back()) &&
                std::all_of(label.begin(), label.end(),
                            [alnum](unsigned char byte) {
                                return alnum(byte) || byte == '.' ||
                                       byte == '_' || byte == '-';
                            }),
            "credential store identity name is invalid");
}

CompositePublic store_identity(const CredentialCrypto& crypto,
                               const Json& value,
                               const std::filesystem::path& directory) {
    closed_object(value, {"file", "sha256"});
    const auto& expected = string_field(value.at("sha256"), 64);
    require(expected.size() == 64 &&
                std::all_of(expected.begin(), expected.end(),
                            [](unsigned char byte) {
                                return (byte >= '0' && byte <= '9') ||
                                       (byte >= 'a' && byte <= 'f');
                            }),
            "credential identity fingerprint must be lowercase SHA-256");
    auto identity = read_public_identity(
        crypto,
        resolve_reference(directory,
                          string_field(value.at("file"),
                                       config::v1::kMaxFileReferenceBytes)));
    require(
        CRYPTO_memcmp(expected.data(), identity.fingerprint.data(), 64) == 0,
        "credential identity fingerprint does not match its keys");
    return identity;
}

engine::ServiceKind service_kind(config::v1::ServiceKind kind) noexcept {
    return kind == config::v1::ServiceKind::Stream
               ? engine::ServiceKind::ByteStream
               : engine::ServiceKind::PacketChannel;
}

std::vector<NativeAuthorizationPolicy::Grant> read_capabilities(
    const config::v1::Config& config, const Json& value,
    const std::string& fingerprint) {
    require(value.is_array() && !value.empty() &&
                value.size() <= config::v1::kMaxServices,
            "credential capability count is invalid");
    std::vector<NativeAuthorizationPolicy::Grant> grants;
    for (const auto& capability : value) {
        closed_object(capability, {"service", "kind"});
        const auto& name = string_field(capability.at("service"), 128);
        const auto& kind = string_field(capability.at("kind"), 16);
        require(kind == "stream" || kind == "packet",
                "credential capability kind is invalid");
        const auto expected_kind = kind == "stream"
                                       ? config::v1::ServiceKind::Stream
                                       : config::v1::ServiceKind::Packet;
        require(std::any_of(config.services().begin(), config.services().end(),
                            [&](const auto& service) {
                                return service.name() == name &&
                                       service.kind() == expected_kind;
                            }),
                "credential capability is not a configured service");
        const auto native_kind = service_kind(expected_kind);
        require(std::none_of(grants.begin(), grants.end(),
                             [&](const auto& grant) {
                                 return grant.service_name == name &&
                                        grant.service_kind == native_kind;
                             }),
                "credential store contains a duplicate capability");
        grants.push_back({fingerprint, name, native_kind});
    }
    return grants;
}

struct AuthorizedIdentity final {
    CompositePublic identity;
    SecretBytes access_psk;
};

LoadedNativeCredentials load_server(const config::v1::Config& config,
                                    const std::filesystem::path& base,
                                    const CredentialCrypto& crypto) {
    const auto& refs =
        std::get<config::v1::ServerCredentials>(config.credentials());
    auto admission =
        read_psk(resolve_reference(base, refs.admission_key().path()));
    auto local = read_private_identity(
        crypto, resolve_reference(base, refs.composite_key().path()));
    auto kem_pem = read_file(base, refs.mlkem_key());
    auto kem_blocks = pem_blocks(kem_pem.text(), true, 1);
    auto kem_key = parse_key(crypto, kem_blocks[0], true, "ML-KEM-1024");
    auto kem = private_der(kem_key.get());

    const auto store_path =
        resolve_reference(base, refs.authorized_keys().path());
    auto store =
        read_store(store_path, providers::kMaxAuthorizedIdentities, false);
    std::set<std::string> labels;
    std::set<std::string> identities;
    std::vector<AuthorizedIdentity> authorized;
    authorized.reserve(store.at("keys").size());
    std::vector<NativeAuthorizationPolicy::Grant> grants;
    std::vector<NativeAuthorizationPolicy::SessionLimit> session_limits;
    std::vector<NativeAuthorizationPolicy::EgressWeight> egress_weights;
    for (const auto& entry : store.at("keys")) {
        closed_object(entry, {"name", "identity", "access_psk", "capabilities"},
                      {"max_sessions", "weight"});
        const auto& label = string_field(entry.at("name"), 63);
        validate_label(label);
        require(labels.insert(label).second,
                "credential store contains a duplicate identity name");
        auto identity = store_identity(crypto, entry.at("identity"),
                                       store_path.parent_path());
        require(identities.insert(identity.fingerprint).second,
                "credential store contains a duplicate identity");
        const auto& psk_ref = closed_object(entry.at("access_psk"), {"file"});
        auto psk = read_psk(resolve_reference(
            store_path.parent_path(),
            string_field(psk_ref.at("file"),
                         config::v1::kMaxFileReferenceBytes)));
        require(CRYPTO_memcmp(psk.data(), admission.data(), 32) != 0,
                "access PSK must differ from admission key");
        require(std::none_of(authorized.begin(), authorized.end(),
                             [&](const auto& other) {
                                 return CRYPTO_memcmp(
                                            other.access_psk.bytes().data(),
                                            psk.data(), 32) == 0;
                             }),
                "access PSK must not be reused across identities");
        auto allowed = read_capabilities(config, entry.at("capabilities"),
                                         identity.fingerprint);
        grants.insert(grants.end(), std::make_move_iterator(allowed.begin()),
                      std::make_move_iterator(allowed.end()));
        if (const auto limit = entry.find("max_sessions"); limit != entry.end()) {
            require(limit->is_number_unsigned() &&
                        limit->get<std::uint64_t>() >= 1U &&
                        limit->get<std::uint64_t>() <= kMaxSessionsPerIdentity,
                    "credential max_sessions must be an integer from 1 to 1024");
            session_limits.push_back(
                {identity.fingerprint,
                 static_cast<std::size_t>(limit->get<std::uint64_t>())});
        }
        if (const auto weight = entry.find("weight"); weight != entry.end()) {
            require(weight->is_number() && std::isfinite(weight->get<double>()) &&
                        weight->get<double>() >= EgressLimiter::kMinWeight &&
                        weight->get<double>() <= EgressLimiter::kMaxWeight,
                    "credential weight must be a number from 0.1 to 100");
            egress_weights.push_back({identity.fingerprint, weight->get<double>()});
        }
        authorized.push_back({std::move(identity), std::move(psk)});
    }

    const auto admin_path = resolve_reference(base, refs.admin_keys().path());
    auto admins = read_store(admin_path, kMaxAdminIdentities, true);
    labels.clear();
    std::set<std::string> admin_identities;
    for (const auto& entry : admins.at("keys")) {
        closed_object(entry, {"name", "identity"});
        const auto& label = string_field(entry.at("name"), 63);
        validate_label(label);
        require(labels.insert(label).second,
                "admin store contains a duplicate identity name");
        auto identity = store_identity(crypto, entry.at("identity"),
                                       admin_path.parent_path());
        require(!identities.contains(identity.fingerprint),
                "admin identity must not also authorize ordinary traffic");
        require(admin_identities.insert(identity.fingerprint).second,
                "admin store contains a duplicate identity");
    }

    std::vector<providers::AuthorizedIdentityView> views;
    views.reserve(authorized.size());
    for (const auto& identity : authorized) {
        views.push_back({identity.identity.view(), identity.access_psk.bytes(),
                         identity.identity.fingerprint});
    }
    auto factory = providers::OpenSslSecurityProviderFactory::create_server(
        {local.view(), kem.bytes(), views});
    require(factory.ok(),
            "native session security credential validation failed",
            factory.status().code());
    auto certificate = read_file(base, refs.tls_certificate());
    auto tls_key = read_file(base, refs.tls_key());
    // Prevent a password callback from reaching a terminal inside the TLS
    // provider. Setup kits use one unencrypted PKCS#8 key.
    (void)pem_blocks(tls_key.text(), true, 1);
    auto tls = providers::Tls13SecureChannelProvider::create_server(
        {certificate.bytes(), tls_key.bytes(), {}, {}});
    require(tls.ok(), "native TLS credential validation failed",
            tls.status().code());
    return {std::move(factory).take_value(), std::move(tls).take_value(),
            std::make_shared<const NativeAuthorizationPolicy>(
                engine::EndpointRole::Client, std::move(grants),
                std::move(session_limits), std::move(egress_weights)),
            NativeAdmissionKey(
                std::span<const std::byte, 32>(admission.bytes().data(), 32)),
            std::nullopt};
}

LoadedNativeCredentials load_client(const config::v1::Config& config,
                                    const std::filesystem::path& base,
                                    std::string_view tls_server_name,
                                    const CredentialCrypto& crypto) {
    require(!tls_server_name.empty(), "client TLS server name is required");
    const auto& refs =
        std::get<config::v1::ClientCredentials>(config.credentials());
    auto admission =
        read_psk(resolve_reference(base, refs.admission_key().path()));
    auto psk = read_psk(resolve_reference(base, refs.access_psk().path()));
    require(CRYPTO_memcmp(psk.data(), admission.data(), 32) != 0,
            "access PSK must differ from admission key");
    auto local = read_private_identity(
        crypto, resolve_reference(base, refs.composite_key().path()));
    auto remote = read_public_identity(
        crypto, resolve_reference(base, refs.server_identity().path()));
    auto kem_pem = read_file(base, refs.server_mlkem());
    auto kem_blocks = pem_blocks(kem_pem.text(), false, 1);
    auto kem_key = parse_key(crypto, kem_blocks[0], false, "ML-KEM-1024");
    auto kem = public_der(kem_key.get());
    auto factory = providers::OpenSslSecurityProviderFactory::create_client(
        {local.view(), remote.view(), kem, psk.bytes(), remote.fingerprint});
    require(factory.ok(),
            "native session security credential validation failed",
            factory.status().code());
    auto trust = read_file(base, refs.server_trust());
    auto tls = providers::Tls13SecureChannelProvider::create_client(
        {tls_server_name, trust.bytes(), {}, {}, {}});
    require(tls.ok(), "native TLS credential validation failed",
            tls.status().code());
    std::vector<NativeAuthorizationPolicy::Grant> grants;
    grants.reserve(config.services().size());
    for (const auto& service : config.services()) {
        grants.push_back(
            {remote.fingerprint, service.name(), service_kind(service.kind())});
    }
    std::optional<common::Socks5Credentials> socks5;
    const auto& proxy =
        std::get<config::v1::ClientEndpoint>(config.endpoint()).socks5_proxy();
    if (proxy && proxy->credentials()) {
        socks5.emplace(read_socks5_credentials(base, *proxy->credentials()));
    }
    return {std::move(factory).take_value(), std::move(tls).take_value(),
            std::make_shared<const NativeAuthorizationPolicy>(
                engine::EndpointRole::Server, std::move(grants)),
            NativeAdmissionKey(
                std::span<const std::byte, 32>(admission.bytes().data(), 32)),
            std::move(socks5)};
}

}  // namespace

NativeAdmissionKey::NativeAdmissionKey(
    std::span<const std::byte, 32> bytes) noexcept {
    std::copy(bytes.begin(), bytes.end(), bytes_.begin());
}

NativeAdmissionKey::NativeAdmissionKey(NativeAdmissionKey&& other) noexcept
    : bytes_(other.bytes_) {
    OPENSSL_cleanse(other.bytes_.data(), other.bytes_.size());
}

NativeAdmissionKey& NativeAdmissionKey::operator=(
    NativeAdmissionKey&& other) noexcept {
    if (this != &other) {
        OPENSSL_cleanse(bytes_.data(), bytes_.size());
        bytes_ = other.bytes_;
        OPENSSL_cleanse(other.bytes_.data(), other.bytes_.size());
    }
    return *this;
}

NativeAdmissionKey::~NativeAdmissionKey() {
    OPENSSL_cleanse(bytes_.data(), bytes_.size());
}

NativeAuthorizationPolicy::NativeAuthorizationPolicy(
    engine::EndpointRole peer_role, std::vector<Grant> grants,
    std::vector<SessionLimit> session_limits,
    std::vector<EgressWeight> egress_weights) noexcept
    : peer_role_(peer_role),
      grants_(std::move(grants)),
      session_limits_(std::move(session_limits)),
      egress_weights_(std::move(egress_weights)) {}

bool NativeAuthorizationPolicy::recognizes(
    std::string_view peer_identity) const noexcept {
    return std::any_of(grants_.begin(), grants_.end(), [&](const auto& grant) {
        return grant.peer_identity == peer_identity;
    });
}

std::size_t NativeAuthorizationPolicy::max_sessions(
    std::string_view peer_identity) const noexcept {
    for (const auto& limit : session_limits_) {
        if (limit.peer_identity == peer_identity) return limit.max_sessions;
    }
    return 0U;
}

double NativeAuthorizationPolicy::egress_weight(
    std::string_view peer_identity) const noexcept {
    for (const auto& weight : egress_weights_) {
        if (weight.peer_identity == peer_identity) return weight.weight;
    }
    return EgressLimiter::kDefaultWeight;
}

Status NativeAuthorizationPolicy::authorize(
    const engine::StreamOpenContext& context) const noexcept {
    if (context.peer_evidence().peer_role() == peer_role_ &&
        std::any_of(grants_.begin(), grants_.end(), [&](const auto& grant) {
            return grant.peer_identity == context.peer_evidence().identity() &&
                   grant.service_name == context.service_name() &&
                   grant.service_kind == context.service_kind();
        })) {
        return Status::success();
    }
    return Status(StatusCode::FailedPrecondition);
}

Result<LoadedNativeCredentials> load_native_credentials(
    const config::v1::Config& config,
    const std::filesystem::path& config_base_directory,
    std::string_view tls_server_name) noexcept {
    try {
        CredentialCrypto crypto;
        return Result<LoadedNativeCredentials>(
            config.role() == config::v1::Role::Server
                ? load_server(config, config_base_directory, crypto)
                : load_client(config, config_base_directory, tls_server_name,
                              crypto));
    } catch (const std::bad_alloc&) {
        return Result<LoadedNativeCredentials>(
            Status(StatusCode::ResourceExhausted));
    } catch (const CredentialError& error) {
        try {
            return Result<LoadedNativeCredentials>(
                Status(error.code(), error.what()));
        } catch (...) {
            return Result<LoadedNativeCredentials>(
                Status(StatusCode::ResourceExhausted));
        }
    } catch (...) {
        return Result<LoadedNativeCredentials>(Status(StatusCode::Internal));
    }
}

}  // namespace yume::runtime
