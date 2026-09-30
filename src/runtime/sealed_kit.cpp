/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/sealed_kit.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <memory>
#include <new>
#include <set>
#include <stdexcept>
#include <system_error>
#include <utility>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#include "common/secure_erase.hpp"
#include "fs/bounded_file.hpp"

namespace yume::runtime::kit {
namespace {
using engine::Result;
using engine::Status;
using engine::StatusCode;

constexpr std::string_view kCodeAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
constexpr char kPropertyQuery[] = "provider=default";

// A normalized code, checked without copying it.
bool is_code(std::string_view code) noexcept {
    return code.size() == kCodeCharacters &&
           std::all_of(code.begin(), code.end(), [](char ch) {
               return kCodeAlphabet.find(ch) != std::string_view::npos;
           });
}

Status invalid(std::string_view message) {
    return Status::diagnostic(StatusCode::InvalidArgument, message);
}

struct LibCtxDeleter final {
    void operator()(OSSL_LIB_CTX* value) const noexcept {
        OSSL_LIB_CTX_free(value);
    }
};
struct ProviderDeleter final {
    void operator()(OSSL_PROVIDER* value) const noexcept {
        OSSL_PROVIDER_unload(value);
    }
};
struct KdfDeleter final {
    void operator()(EVP_KDF* value) const noexcept { EVP_KDF_free(value); }
};
struct KdfCtxDeleter final {
    void operator()(EVP_KDF_CTX* value) const noexcept {
        EVP_KDF_CTX_free(value);
    }
};
struct CipherDeleter final {
    void operator()(EVP_CIPHER* value) const noexcept {
        EVP_CIPHER_free(value);
    }
};
struct CipherCtxDeleter final {
    void operator()(EVP_CIPHER_CTX* value) const noexcept {
        EVP_CIPHER_CTX_free(value);
    }
};

// A private library context with the default provider, and the two
// algorithms the format uses, fetched from it. A missing algorithm fails.
class Crypto final {
public:
    Crypto()
        : context_(OSSL_LIB_CTX_new()),
          provider_(context_ ? OSSL_PROVIDER_load(context_.get(), "default")
                             : nullptr),
          argon2id_(context_ ? EVP_KDF_fetch(context_.get(), "ARGON2ID",
                                             kPropertyQuery)
                             : nullptr),
          aes_(context_ ? EVP_CIPHER_fetch(context_.get(), "AES-256-GCM",
                                           kPropertyQuery)
                        : nullptr) {
        if (!context_ || !provider_ || !argon2id_ || !aes_) {
            throw std::runtime_error(
                "OpenSSL 3.5 Argon2id or AES-256-GCM is unavailable");
        }
    }

    OSSL_LIB_CTX* context() const noexcept { return context_.get(); }
    EVP_KDF* argon2id() const noexcept { return argon2id_.get(); }
    const EVP_CIPHER* aes() const noexcept { return aes_.get(); }

private:
    std::unique_ptr<OSSL_LIB_CTX, LibCtxDeleter> context_;
    std::unique_ptr<OSSL_PROVIDER, ProviderDeleter> provider_;
    std::unique_ptr<EVP_KDF, KdfDeleter> argon2id_;
    std::unique_ptr<EVP_CIPHER, CipherDeleter> aes_;
};

// The derived key, wiped when it leaves scope.
struct Key final {
    std::array<std::uint8_t, kKeyBytes> bytes{};
    Key() = default;
    Key(const Key&) = delete;
    Key& operator=(const Key&) = delete;
    ~Key() noexcept { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};

bool derive_key(const Crypto& crypto, std::string_view code,
                std::span<const std::uint8_t> salt, Key& key) {
    std::unique_ptr<EVP_KDF_CTX, KdfCtxDeleter> context(
        EVP_KDF_CTX_new(crypto.argon2id()));
    if (!context) return false;
    std::uint32_t passes = kArgonPasses;
    std::uint32_t memory = kArgonMemoryKiB;
    std::uint32_t lanes = kArgonLanes;
    std::uint32_t threads = 1U;
    std::uint32_t version = 0x13U;
    const OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
                                          const_cast<char*>(code.data()),
                                          code.size()),
        OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, const_cast<std::uint8_t*>(salt.data()),
            salt.size()),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &passes),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memory),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads),
        OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_VERSION, &version),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_ARGON2_AD,
                                          const_cast<char*>(kDomain.data()),
                                          kDomain.size()),
        OSSL_PARAM_construct_end(),
    };
    return EVP_KDF_derive(context.get(), key.bytes.data(), key.bytes.size(),
                          parameters) == 1;
}

void put_u32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

std::uint32_t get_u32(std::span<const std::uint8_t> bytes) noexcept {
    return static_cast<std::uint32_t>(bytes[0]) << 24U |
           static_cast<std::uint32_t>(bytes[1]) << 16U |
           static_cast<std::uint32_t>(bytes[2]) << 8U | bytes[3];
}

bool valid_component(std::string_view part) noexcept {
    if (part.empty() || part == "." || part == "..") return false;
    return std::all_of(part.begin(), part.end(), [](char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
               (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-';
    });
}

bool valid_path(std::string_view path) noexcept {
    if (path.empty() || path.size() > kMaxPathBytes) return false;
    const auto slash = path.find('/');
    if (slash == std::string_view::npos) return valid_component(path);
    return valid_component(path.substr(0U, slash)) &&
           valid_component(path.substr(slash + 1U));
}

// Parses the decrypted content. Every byte must belong to a field.
Result<Kit> parse_content(std::span<const std::uint8_t> content) {
    const auto malformed = [] {
        return Result<Kit>(Status::diagnostic(StatusCode::InvalidArgument,
                                              "the sealed kit is malformed"));
    };
    std::size_t offset = 0U;
    const auto remaining = [&] { return content.size() - offset; };
    if (remaining() < 2U || content[0] != kContentVersion) return malformed();
    const std::size_t count = content[1];
    offset = 2U;
    Kit kit;
    kit.files.reserve(count);
    for (std::size_t index = 0; index < count; ++index) {
        if (remaining() < 1U) return malformed();
        const std::size_t path_bytes = content[offset++];
        if (remaining() < path_bytes + 5U) return malformed();
        KitFile file;
        file.path.assign(reinterpret_cast<const char*>(content.data() + offset),
                         path_bytes);
        offset += path_bytes;
        const std::uint8_t executable = content[offset++];
        if (executable > 1U) return malformed();
        file.executable = executable == 1U;
        const std::size_t size = get_u32(content.subspan(offset, 4U));
        offset += 4U;
        if (size > kMaxFileBytes || remaining() < size) return malformed();
        file.bytes.assign(
            content.begin() + static_cast<std::ptrdiff_t>(offset),
            content.begin() + static_cast<std::ptrdiff_t>(offset + size));
        offset += size;
        kit.files.push_back(std::move(file));
    }
    if (offset != content.size()) return malformed();
    const auto checked = check_kit(kit);
    if (!checked.ok()) return malformed();
    return Result<Kit>(std::move(kit));
}

// Writes all of bytes to a new file relative to a directory descriptor.
bool write_new_file(int directory, const std::string& name,
                    std::span<const std::uint8_t> bytes, mode_t mode) noexcept {
    const int fd =
        ::openat(directory, name.c_str(),
                 O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode);
    if (fd < 0) return false;
    bool ok = ::fchmod(fd, mode) == 0;
    std::size_t written = 0U;
    while (ok && written < bytes.size()) {
        const auto count =
            ::write(fd, bytes.data() + written, bytes.size() - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) {
            ok = false;
            break;
        }
        written += static_cast<std::size_t>(count);
    }
    ok = ok && ::fsync(fd) == 0;
    return ::close(fd) == 0 && ok;
}

class Descriptor final {
public:
    explicit Descriptor(int fd) noexcept : fd_(fd) {}
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    ~Descriptor() noexcept {
        if (fd_ >= 0) ::close(fd_);
    }
    int get() const noexcept { return fd_; }

private:
    int fd_;
};

std::string random_suffix(const Crypto& crypto) {
    std::array<std::uint8_t, 8> random{};
    if (RAND_bytes_ex(crypto.context(), random.data(), random.size(), 0) != 1) {
        throw std::runtime_error("random bytes are unavailable");
    }
    std::string text;
    for (const std::uint8_t byte : random) {
        char pair[3];
        static_cast<void>(std::snprintf(pair, sizeof(pair), "%02x", byte));
        text += pair;
    }
    return text;
}

}  // namespace

Kit::~Kit() noexcept {
    for (auto& file : files) security::secure_erase(file.bytes);
}

Result<std::string> generate_code() {
    try {
        const Crypto crypto;
        std::array<std::uint8_t, 16> random{};
        if (RAND_bytes_ex(crypto.context(), random.data(), random.size(), 0) !=
            1) {
            return Result<std::string>(Status::diagnostic(
                StatusCode::Internal, "random bytes are unavailable"));
        }
        std::string code;
        code.reserve(kCodeCharacters);
        // 125 of the 128 bits, five at a time.
        for (std::size_t index = 0; index < kCodeCharacters; ++index) {
            const std::size_t bit = index * 5U;
            const unsigned pair =
                static_cast<unsigned>(random[bit / 8U]) << 8U |
                (bit / 8U + 1U < random.size() ? random[bit / 8U + 1U] : 0U);
            code.push_back(kCodeAlphabet[(pair >> (11U - bit % 8U)) & 0x1fU]);
        }
        OPENSSL_cleanse(random.data(), random.size());
        return Result<std::string>(std::move(code));
    } catch (const std::bad_alloc&) {
        return Result<std::string>(Status(StatusCode::ResourceExhausted));
    } catch (const std::exception& error) {
        return Result<std::string>(
            Status::diagnostic(StatusCode::Internal, error.what()));
    }
}

std::string display_code(std::string_view code) {
    std::string text;
    for (std::size_t index = 0; index < code.size(); ++index) {
        if (index != 0U && index % 5U == 0U) text.push_back('-');
        text.push_back(code[index]);
    }
    return text;
}

std::optional<std::string> normalize_code(std::string_view typed) {
    std::string code;
    code.reserve(kCodeCharacters + 1U);
    for (char ch : typed) {
        if (ch == '-' || ch == ' ' || ch == '\t') continue;
        if (ch >= 'a' && ch <= 'z') ch = static_cast<char>(ch - 'a' + 'A');
        if (ch == 'O') ch = '0';
        if (ch == 'I' || ch == 'L') ch = '1';
        if (kCodeAlphabet.find(ch) == std::string_view::npos ||
            code.size() > kCodeCharacters) {
            security::secure_erase(code);
            return std::nullopt;
        }
        code.push_back(ch);
    }
    if (code.size() != kCodeCharacters) {
        security::secure_erase(code);
        return std::nullopt;
    }
    return code;
}

Status check_kit(const Kit& kit) {
    if (kit.files.empty() || kit.files.size() > kMaxFiles) {
        return invalid("a kit holds 1 to 32 files");
    }
    std::size_t content = 2U;
    bool config = false;
    std::set<std::string> directories;
    std::set<std::string> leaves;
    for (std::size_t index = 0; index < kit.files.size(); ++index) {
        const auto& file = kit.files[index];
        if (!valid_path(file.path))
            return invalid("a kit path is not a plain file name");
        if (index != 0U && !(kit.files[index - 1U].path < file.path)) {
            return invalid("kit paths are not sorted and unique");
        }
        if (file.bytes.size() > kMaxFileBytes)
            return invalid("a kit file exceeds 256 KiB");
        content += 6U + file.path.size() + file.bytes.size();
        if (content > kMaxContentBytes) return invalid("a kit exceeds 1 MiB");
        const auto slash = file.path.find('/');
        if (slash == std::string::npos) {
            leaves.insert(file.path);
        } else {
            directories.insert(file.path.substr(0U, slash));
        }
        config = config || file.path == "yume.json";
    }
    for (const auto& directory : directories) {
        if (leaves.count(directory))
            return invalid("a kit name is both a file and a directory");
    }
    if (!config) return invalid("a kit holds yume.json");
    return Status::success();
}

Result<std::vector<std::uint8_t>> seal(const Kit& kit, std::string_view code) {
    using Sealed = Result<std::vector<std::uint8_t>>;
    if (!is_code(code)) {
        return Sealed(invalid("the kit code is not 25 code characters"));
    }
    if (const auto checked = check_kit(kit); !checked.ok())
        return Sealed(checked);
    std::vector<std::uint8_t> plaintext;
    const security::ScopedErase plaintext_guard(plaintext);
    try {
        const Crypto crypto;
        plaintext.reserve(kMaxSealedBytes);
        put_u32(plaintext, 0U);
        plaintext.push_back(kContentVersion);
        plaintext.push_back(static_cast<std::uint8_t>(kit.files.size()));
        for (const auto& file : kit.files) {
            plaintext.push_back(static_cast<std::uint8_t>(file.path.size()));
            plaintext.insert(plaintext.end(), file.path.begin(),
                             file.path.end());
            plaintext.push_back(file.executable ? 1U : 0U);
            put_u32(plaintext, static_cast<std::uint32_t>(file.bytes.size()));
            plaintext.insert(plaintext.end(), file.bytes.begin(),
                             file.bytes.end());
        }
        const std::uint32_t content =
            static_cast<std::uint32_t>(plaintext.size() - 4U);
        for (int index = 0; index < 4; ++index) {
            plaintext[static_cast<std::size_t>(index)] =
                static_cast<std::uint8_t>(content >> (24 - 8 * index));
        }
        plaintext.resize((plaintext.size() + kPaddingBlock - 1U) /
                             kPaddingBlock * kPaddingBlock,
                         0U);

        std::vector<std::uint8_t> sealed(kSaltBytes + kNonceBytes +
                                         plaintext.size() + kTagBytes);
        if (RAND_bytes_ex(crypto.context(), sealed.data(),
                          kSaltBytes + kNonceBytes, 0) != 1) {
            return Sealed(Status::diagnostic(StatusCode::Internal,
                                             "random bytes are unavailable"));
        }
        const std::span<const std::uint8_t> salt(sealed.data(), kSaltBytes);
        const std::span<const std::uint8_t> nonce(sealed.data() + kSaltBytes,
                                                  kNonceBytes);
        Key key;
        if (!derive_key(crypto, code, salt, key)) {
            return Sealed(
                Status::diagnostic(StatusCode::Internal, "Argon2id failed"));
        }
        std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter> cipher(
            EVP_CIPHER_CTX_new());
        int length = 0;
        std::uint8_t* const output = sealed.data() + kSaltBytes + kNonceBytes;
        if (!cipher ||
            EVP_EncryptInit_ex2(cipher.get(), crypto.aes(), key.bytes.data(),
                                nonce.data(), nullptr) != 1 ||
            EVP_EncryptUpdate(
                cipher.get(), nullptr, &length,
                reinterpret_cast<const unsigned char*>(kDomain.data()),
                static_cast<int>(kDomain.size())) != 1 ||
            EVP_EncryptUpdate(cipher.get(), output, &length, plaintext.data(),
                              static_cast<int>(plaintext.size())) != 1 ||
            static_cast<std::size_t>(length) != plaintext.size() ||
            EVP_EncryptFinal_ex(cipher.get(), output + length, &length) != 1 ||
            length != 0 ||
            EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_AEAD_GET_TAG,
                                static_cast<int>(kTagBytes),
                                output + plaintext.size()) != 1) {
            return Sealed(
                Status::diagnostic(StatusCode::Internal, "AES-256-GCM failed"));
        }
        return Sealed(std::move(sealed));
    } catch (const std::bad_alloc&) {
        return Sealed(Status(StatusCode::ResourceExhausted));
    } catch (const std::exception& error) {
        return Sealed(
            Status::diagnostic(StatusCode::FailedPrecondition, error.what()));
    }
}

Result<Kit> open(std::span<const std::uint8_t> sealed, std::string_view code) {
    const std::size_t overhead = kSaltBytes + kNonceBytes + kTagBytes;
    if (!is_code(code)) {
        return Result<Kit>(invalid("the kit code is not 25 code characters"));
    }
    // The size is checked before the KDF runs, so an arbitrary file costs
    // nothing but its length check.
    if (sealed.size() < overhead + kPaddingBlock ||
        sealed.size() > kMaxSealedBytes ||
        (sealed.size() - overhead) % kPaddingBlock != 0U) {
        return Result<Kit>(Status::diagnostic(StatusCode::InvalidArgument,
                                              "the file is not a sealed kit"));
    }
    std::vector<std::uint8_t> plaintext;
    const security::ScopedErase plaintext_guard(plaintext);
    try {
        const Crypto crypto;
        const auto salt = sealed.first(kSaltBytes);
        const auto nonce = sealed.subspan(kSaltBytes, kNonceBytes);
        const auto body =
            sealed.subspan(kSaltBytes + kNonceBytes, sealed.size() - overhead);
        const auto tag = sealed.last(kTagBytes);
        Key key;
        if (!derive_key(crypto, code, salt, key)) {
            return Result<Kit>(
                Status::diagnostic(StatusCode::Internal, "Argon2id failed"));
        }
        plaintext.resize(body.size());
        std::unique_ptr<EVP_CIPHER_CTX, CipherCtxDeleter> cipher(
            EVP_CIPHER_CTX_new());
        int length = 0;
        if (!cipher ||
            EVP_DecryptInit_ex2(cipher.get(), crypto.aes(), key.bytes.data(),
                                nonce.data(), nullptr) != 1 ||
            EVP_DecryptUpdate(
                cipher.get(), nullptr, &length,
                reinterpret_cast<const unsigned char*>(kDomain.data()),
                static_cast<int>(kDomain.size())) != 1 ||
            EVP_DecryptUpdate(cipher.get(), plaintext.data(), &length,
                              body.data(),
                              static_cast<int>(body.size())) != 1 ||
            static_cast<std::size_t>(length) != body.size() ||
            EVP_CIPHER_CTX_ctrl(cipher.get(), EVP_CTRL_AEAD_SET_TAG,
                                static_cast<int>(kTagBytes),
                                const_cast<std::uint8_t*>(tag.data())) != 1) {
            return Result<Kit>(
                Status::diagnostic(StatusCode::Internal, "AES-256-GCM failed"));
        }
        if (EVP_DecryptFinal_ex(cipher.get(), plaintext.data() + length,
                                &length) != 1) {
            return Result<Kit>(Status::diagnostic(
                StatusCode::PermissionDenied,
                "the code is wrong or the file is not a sealed kit"));
        }
        const std::size_t content = get_u32(plaintext);
        const auto padding_start = 4U + static_cast<std::size_t>(content);
        if (content > kMaxContentBytes || padding_start > plaintext.size() ||
            plaintext.size() - padding_start >= kPaddingBlock ||
            !std::all_of(
                plaintext.begin() + static_cast<std::ptrdiff_t>(padding_start),
                plaintext.end(),
                [](std::uint8_t byte) { return byte == 0U; })) {
            return Result<Kit>(Status::diagnostic(
                StatusCode::InvalidArgument, "the sealed kit is malformed"));
        }
        return parse_content(
            std::span<const std::uint8_t>(plaintext).subspan(4U, content));
    } catch (const std::bad_alloc&) {
        return Result<Kit>(Status(StatusCode::ResourceExhausted));
    } catch (const std::exception& error) {
        return Result<Kit>(
            Status::diagnostic(StatusCode::FailedPrecondition, error.what()));
    }
}

Result<Kit> read_directory(const std::filesystem::path& directory) {
    namespace fs = std::filesystem;
    try {
        std::error_code error;
        if (!fs::is_directory(fs::symlink_status(directory, error))) {
            return Result<Kit>(invalid("the kit is not a directory"));
        }
        Kit kit;
        std::vector<std::pair<fs::path, std::string>> found;
        for (const auto& entry : fs::directory_iterator(directory)) {
            const auto name = entry.path().filename().string();
            const auto status = entry.symlink_status();
            if (fs::is_directory(status)) {
                for (const auto& child : fs::directory_iterator(entry.path())) {
                    if (!fs::is_regular_file(child.symlink_status())) {
                        return Result<Kit>(
                            invalid("the kit holds a link, special file or "
                                    "nested directory"));
                    }
                    found.emplace_back(
                        child.path(),
                        name + "/" + child.path().filename().string());
                }
            } else if (fs::is_regular_file(status)) {
                found.emplace_back(entry.path(), name);
            } else {
                return Result<Kit>(
                    invalid("the kit holds a link or special file"));
            }
            if (found.size() > kMaxFiles)
                return Result<Kit>(invalid("a kit holds 1 to 32 files"));
        }
        std::sort(found.begin(), found.end(),
                  [](const auto& left, const auto& right) {
                      return left.second < right.second;
                  });
        for (const auto& [path, name] : found) {
            KitFile file;
            file.path = name;
            if (!valid_path(name))
                return Result<Kit>(
                    invalid("a kit path is not a plain file name"));
            std::string read_error;
            if (!read_file_bounded(path, kMaxFileBytes, &file.bytes,
                                   &read_error)) {
                return Result<Kit>(invalid("cannot read the kit file " + name +
                                           ": " + read_error));
            }
            struct stat info{};
            file.executable = ::stat(path.c_str(), &info) == 0 &&
                              (info.st_mode & S_IXUSR) != 0;
            kit.files.push_back(std::move(file));
        }
        if (const auto checked = check_kit(kit); !checked.ok())
            return Result<Kit>(checked);
        return Result<Kit>(std::move(kit));
    } catch (const std::bad_alloc&) {
        return Result<Kit>(Status(StatusCode::ResourceExhausted));
    } catch (const std::exception&) {
        return Result<Kit>(invalid("cannot read the kit directory"));
    }
}

Status write_directory(const Kit& kit, const std::filesystem::path& directory) {
    namespace fs = std::filesystem;
    if (const auto checked = check_kit(kit); !checked.ok()) return checked;
    fs::path staging;
    try {
        const fs::path target = fs::absolute(directory).lexically_normal();
        if (target.filename().empty())
            return invalid("the kit directory has no name");
        std::error_code error;
        if (fs::exists(fs::symlink_status(target, error))) {
            return Status::diagnostic(StatusCode::AlreadyExists,
                                      "the kit directory exists");
        }
        const Crypto crypto;
        staging = target.parent_path() / ("." + target.filename().string() +
                                          ".partial-" + random_suffix(crypto));
        if (::mkdir(staging.c_str(), 0700) != 0) {
            staging.clear();
            return Status::diagnostic(StatusCode::PermissionDenied,
                                      "cannot create the kit directory");
        }
        bool ok = true;
        {
            const Descriptor root(
                ::open(staging.c_str(),
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
            ok = root.get() >= 0;
            std::set<std::string> made;
            for (const auto& file : kit.files) {
                if (!ok) break;
                const auto slash = file.path.find('/');
                const mode_t mode = file.executable ? 0700 : 0600;
                if (slash == std::string::npos) {
                    ok =
                        write_new_file(root.get(), file.path, file.bytes, mode);
                    continue;
                }
                const std::string parent = file.path.substr(0U, slash);
                if (made.insert(parent).second) {
                    ok = ::mkdirat(root.get(), parent.c_str(), 0700) == 0;
                    if (!ok) break;
                }
                const Descriptor child(
                    ::openat(root.get(), parent.c_str(),
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
                ok = child.get() >= 0 &&
                     write_new_file(child.get(), file.path.substr(slash + 1U),
                                    file.bytes, mode) &&
                     ::fsync(child.get()) == 0;
            }
            ok = ok && ::fsync(root.get()) == 0;
        }
        if (ok && ::renameat2(AT_FDCWD, staging.c_str(), AT_FDCWD,
                              target.c_str(), RENAME_NOREPLACE) == 0) {
            const Descriptor parent(::open(target.parent_path().c_str(),
                                           O_RDONLY | O_DIRECTORY | O_CLOEXEC));
            if (parent.get() >= 0) static_cast<void>(::fsync(parent.get()));
            return Status::success();
        }
        const bool exists = ok && errno == EEXIST;
        fs::remove_all(staging, error);
        return exists ? Status::diagnostic(StatusCode::AlreadyExists,
                                           "the kit directory exists")
                      : Status::diagnostic(StatusCode::PermissionDenied,
                                           "cannot write the kit directory");
    } catch (const std::bad_alloc&) {
        std::error_code error;
        if (!staging.empty()) fs::remove_all(staging, error);
        return Status(StatusCode::ResourceExhausted);
    } catch (const std::exception&) {
        std::error_code error;
        if (!staging.empty()) fs::remove_all(staging, error);
        return Status::diagnostic(StatusCode::Internal,
                                  "cannot write the kit directory");
    }
}

}  // namespace yume::runtime::kit
