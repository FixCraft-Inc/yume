/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/sealed_kit.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

namespace {
namespace kit = yume::runtime::kit;
using yume::engine::StatusCode;
using Bytes = std::vector<std::uint8_t>;

void check(bool condition, const char* description) {
    if (!condition) throw std::runtime_error(description);
}

template <typename T>
T require(yume::engine::Result<T> result) {
    if (!result.ok()) {
        throw std::runtime_error("unexpected failure: " +
                                 std::string(result.status().message()));
    }
    return std::move(result).take_value();
}

Bytes bytes_of(std::string_view text) {
    return Bytes(text.begin(), text.end());
}

kit::Kit sample() {
    kit::Kit value;
    value.files.push_back(
        {"adapters/socks5.json", false, bytes_of("{\"schema\":1}\n")});
    Bytes key(4000U);
    for (std::size_t index = 0; index < key.size(); ++index) {
        key[index] = static_cast<std::uint8_t>(index * 7U + 3U);
    }
    value.files.push_back({"credentials/client-composite.pem", false, key});
    value.files.push_back(
        {"start-client", true, bytes_of("#!/bin/sh\nexec yume\n")});
    value.files.push_back(
        {"yume.json", false, bytes_of("{\"role\":\"client\"}\n")});
    return value;
}

bool same(const kit::Kit& left, const kit::Kit& right) {
    if (left.files.size() != right.files.size()) return false;
    for (std::size_t index = 0; index < left.files.size(); ++index) {
        const auto& a = left.files[index];
        const auto& b = right.files[index];
        if (a.path != b.path || a.executable != b.executable ||
            a.bytes != b.bytes)
            return false;
    }
    return true;
}

// The format again, written from the header comment with direct OpenSSL
// calls, to check the implementation against its description.
Bytes argon2id(std::string_view code, std::span<const std::uint8_t> salt) {
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
    EVP_KDF_CTX* context = kdf ? EVP_KDF_CTX_new(kdf) : nullptr;
    check(context != nullptr, "Argon2id is unavailable to the test");
    std::uint32_t passes = 3U, memory = 65536U, lanes = 4U;
    const std::string ad = "yume-kit/1";
    const OSSL_PARAM parameters[] = {
        OSSL_PARAM_construct_octet_string(
            "pass", const_cast<char*>(code.data()), code.size()),
        OSSL_PARAM_construct_octet_string(
            "salt", const_cast<std::uint8_t*>(salt.data()), salt.size()),
        OSSL_PARAM_construct_uint32("iter", &passes),
        OSSL_PARAM_construct_uint32("memcost", &memory),
        OSSL_PARAM_construct_uint32("lanes", &lanes),
        OSSL_PARAM_construct_octet_string("ad", const_cast<char*>(ad.data()),
                                          ad.size()),
        OSSL_PARAM_construct_end(),
    };
    Bytes key(32U);
    check(EVP_KDF_derive(context, key.data(), key.size(), parameters) == 1,
          "Argon2id failed");
    EVP_KDF_CTX_free(context);
    EVP_KDF_free(kdf);
    return key;
}

// Encrypts or decrypts body under the file's salt and nonce. Decryption
// returns nothing on a tag failure.
std::optional<Bytes> gcm(bool encrypt, std::string_view code,
                         std::span<const std::uint8_t> salt,
                         std::span<const std::uint8_t> nonce,
                         std::span<const std::uint8_t> body,
                         std::span<std::uint8_t> tag) {
    const Bytes key = argon2id(code, salt);
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    const std::string aad = "yume-kit/1";
    Bytes output(body.size());
    int length = 0;
    check(
        context &&
            EVP_CipherInit_ex2(context, EVP_aes_256_gcm(), key.data(),
                               nonce.data(), encrypt ? 1 : 0, nullptr) == 1 &&
            EVP_CipherUpdate(context, nullptr, &length,
                             reinterpret_cast<const unsigned char*>(aad.data()),
                             static_cast<int>(aad.size())) == 1 &&
            EVP_CipherUpdate(context, output.data(), &length, body.data(),
                             static_cast<int>(body.size())) == 1,
        "AES-256-GCM failed in the test");
    if (!encrypt) {
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_SET_TAG, 16, tag.data());
    }
    const bool finished =
        EVP_CipherFinal_ex(context, output.data() + length, &length) == 1;
    if (encrypt)
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_AEAD_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(context);
    if (!finished) return std::nullopt;
    return output;
}

// A sealed file around any plaintext, with fixed salt and nonce.
Bytes seal_plaintext(std::string_view code, const Bytes& plaintext) {
    Bytes file(16U + 12U, 0x5aU);
    std::array<std::uint8_t, 16> tag{};
    const auto body = *gcm(true, code, std::span(file).first(16U),
                           std::span(file).subspan(16U), plaintext, tag);
    file.insert(file.end(), body.begin(), body.end());
    file.insert(file.end(), tag.begin(), tag.end());
    return file;
}

void put_u32(Bytes& output, std::uint32_t value) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>(value >> shift));
    }
}

Bytes content_of(const kit::Kit& value, std::uint8_t version = 1U) {
    Bytes content{version, static_cast<std::uint8_t>(value.files.size())};
    for (const auto& file : value.files) {
        content.push_back(static_cast<std::uint8_t>(file.path.size()));
        content.insert(content.end(), file.path.begin(), file.path.end());
        content.push_back(file.executable ? 1U : 0U);
        put_u32(content, static_cast<std::uint32_t>(file.bytes.size()));
        content.insert(content.end(), file.bytes.begin(), file.bytes.end());
    }
    return content;
}

Bytes plaintext_of(const Bytes& content, std::size_t padding_to = 1024U) {
    Bytes plaintext;
    put_u32(plaintext, static_cast<std::uint32_t>(content.size()));
    plaintext.insert(plaintext.end(), content.begin(), content.end());
    plaintext.resize(
        (plaintext.size() + padding_to - 1U) / padding_to * padding_to, 0U);
    return plaintext;
}

void test_codes() {
    const auto code = require(kit::generate_code());
    check(code.size() == 25U && kit::normalize_code(code) == code,
          "a generated code is invalid");
    check(require(kit::generate_code()) != code,
          "two generated codes were equal");
    check(kit::display_code("ABCDEFGHJKMNPQRSTVWXYZ012") ==
              "ABCDE-FGHJK-MNPQR-STVWX-YZ012",
          "the display grouping is wrong");
    check(kit::normalize_code("abcde-fghjk mnpqr-stvwx-yzO1l") ==
              "ABCDEFGHJKMNPQRSTVWXYZ011",
          "typed input was not normalized");
    for (const char* typed :
         {"", "ABCDE", "ABCDEFGHJKMNPQRSTVWXYZ0123",
          "ABCDEFGHJKMNPQRSTVWXYZ01U", "ABCDEFGHJKMNPQRSTVWXYZ01!"}) {
        check(!kit::normalize_code(typed), "a malformed code was accepted");
    }
}

// The implementation writes exactly the documented layout, and the test's
// own AES-GCM and Argon2id open it.
void test_layout_and_round_trip() {
    const std::string code = "ABCDEFGHJKMNPQRSTVWXYZ012";
    const kit::Kit original = sample();
    const auto sealed = require(kit::seal(original, code));
    check((sealed.size() - 44U) % 1024U == 0U,
          "the ciphertext is not padded to 1024 bytes");
    std::array<std::uint8_t, 16> tag{};
    std::copy(sealed.end() - 16, sealed.end(), tag.begin());
    const auto plaintext =
        gcm(false, code, std::span(sealed).first(16U),
            std::span(sealed).subspan(16U, 12U),
            std::span(sealed).subspan(28U, sealed.size() - 44U), tag);
    check(plaintext.has_value(), "an independent decryption failed");
    check(*plaintext == plaintext_of(content_of(original)),
          "the plaintext differs from the documented layout");
    const auto opened = require(kit::open(sealed, code));
    check(same(opened, original), "the opened kit differs");
    const auto again = require(kit::seal(original, code));
    check(std::memcmp(again.data(), sealed.data(), 28U) != 0,
          "two seals shared a salt and nonce");
}

void test_wrong_code_and_tampering() {
    const std::string code = "ABCDEFGHJKMNPQRSTVWXYZ012";
    const auto sealed = require(kit::seal(sample(), code));
    const auto wrong = kit::open(sealed, "ABCDEFGHJKMNPQRSTVWXYZ013");
    check(!wrong.ok() && wrong.status().code() == StatusCode::PermissionDenied,
          "a wrong code opened the kit");
    for (const std::size_t position : {std::size_t{0}, std::size_t{20},
                                       std::size_t{100}, sealed.size() - 1U}) {
        Bytes changed = sealed;
        changed[position] ^= 0x01U;
        const auto opened = kit::open(changed, code);
        check(!opened.ok() &&
                  opened.status().code() == StatusCode::PermissionDenied,
              "a changed byte was accepted");
    }
    // Sizes that no sealed kit has are refused before the KDF.
    for (const std::size_t size :
         {std::size_t{0}, std::size_t{44}, sealed.size() - 1U,
          kit::kMaxSealedBytes + 1024U}) {
        Bytes resized = sealed;
        resized.resize(size);
        const auto opened = kit::open(resized, code);
        check(!opened.ok() &&
                  opened.status().code() == StatusCode::InvalidArgument,
              "a file of the wrong size was not refused as not a kit");
    }
    check(kit::open(sealed, "abcde").status().code() ==
              StatusCode::InvalidArgument,
          "an unnormalized code was used");
}

// Contents that pass the tag but break the layout are refused.
void test_malformed_contents() {
    const std::string code = "ABCDEFGHJKMNPQRSTVWXYZ012";
    const Bytes content = content_of(sample());
    Bytes trailing = content;
    trailing.push_back(0U);
    Bytes nonzero_padding = plaintext_of(content);
    nonzero_padding.back() = 1U;
    kit::Kit unsorted = sample();
    std::swap(unsorted.files[0], unsorted.files[3]);
    kit::Kit escaping = sample();
    escaping.files[0].path = "../yume.json";
    const Bytes cases[] = {
        plaintext_of(content_of(sample(), 2U)),
        plaintext_of(trailing),
        nonzero_padding,
        plaintext_of(content, 2048U),
        plaintext_of(content_of(unsorted)),
        plaintext_of(content_of(escaping)),
        plaintext_of(Bytes{1U, 0U}),
    };
    for (const auto& plaintext : cases) {
        const auto opened = kit::open(seal_plaintext(code, plaintext), code);
        check(!opened.ok() &&
                  opened.status().code() == StatusCode::InvalidArgument,
              "malformed contents were accepted");
    }
    check(kit::open(seal_plaintext(code, plaintext_of(content)), code).ok(),
          "the test's own well-formed kit was refused");
}

void test_kit_checks() {
    const auto refused = [](kit::Kit value) {
        return !kit::check_kit(value).ok();
    };
    kit::Kit value = sample();
    value.files.pop_back();
    check(refused(std::move(value)), "a kit without yume.json was accepted");
    for (const char* path :
         {"", ".", "..", "a/..", "../x", "a/b/c", "a b", "a/", "/a", "a\\b"}) {
        kit::Kit named = sample();
        named.files[0].path = path;
        check(refused(std::move(named)), "a bad path was accepted");
    }
    kit::Kit duplicate = sample();
    duplicate.files[1].path = duplicate.files[0].path;
    check(refused(std::move(duplicate)), "a duplicate path was accepted");
    kit::Kit large = sample();
    large.files[1].bytes.resize(kit::kMaxFileBytes + 1U);
    check(refused(std::move(large)), "a file over 256 KiB was accepted");
    kit::Kit many;
    for (int index = 0; index < 33; ++index) {
        many.files.push_back({"f" + std::to_string(100 + index), false, {}});
    }
    many.files.push_back({"yume.json", false, {}});
    check(refused(std::move(many)), "33 files were accepted");
    kit::Kit clash = sample();
    clash.files.insert(clash.files.begin() + 1,
                       kit::KitFile{"credentials", false, {}});
    check(refused(std::move(clash)),
          "a name used as file and directory was accepted");
}

class Directory final {
public:
    Directory() {
        std::string pattern = "/tmp/yume-kit-XXXXXX";
        check(::mkdtemp(pattern.data()) != nullptr, "mkdtemp failed");
        path = pattern;
    }
    ~Directory() {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
    std::filesystem::path path;
};

mode_t mode_of(const std::filesystem::path& path) {
    struct stat info{};
    check(::lstat(path.c_str(), &info) == 0, "stat failed");
    return info.st_mode & 07777;
}

void test_directories() {
    Directory directory;
    const auto target = directory.path / "client";
    check(kit::write_directory(sample(), target).ok(),
          "the kit directory was not written");
    check(mode_of(target) == 0700 && mode_of(target / "credentials") == 0700 &&
              mode_of(target / "yume.json") == 0600 &&
              mode_of(target / "start-client") == 0700 &&
              mode_of(target / "credentials/client-composite.pem") == 0600,
          "the kit directory has the wrong modes");
    check(same(require(kit::read_directory(target)), sample()),
          "the written directory reads back differently");
    const auto again = kit::write_directory(sample(), target);
    check(!again.ok() && again.code() == StatusCode::AlreadyExists,
          "an existing directory was replaced");
    std::size_t entries = 0U;
    for ([[maybe_unused]] const auto& entry :
         std::filesystem::directory_iterator(directory.path)) {
        ++entries;
    }
    check(entries == 1U, "a partial kit directory was left behind");

    std::filesystem::create_symlink(target / "yume.json",
                                    target / "adapters/link.json");
    check(!kit::read_directory(target).ok(),
          "a kit with a symbolic link was read");
    std::filesystem::remove(target / "adapters/link.json");
    std::filesystem::create_directory(target / "adapters/nested");
    check(!kit::read_directory(target).ok(),
          "a kit with a nested directory was read");
    std::filesystem::remove(target / "adapters/nested");
    check(::mkfifo((target / "pipe").c_str(), 0600) == 0, "mkfifo failed");
    check(!kit::read_directory(target).ok(), "a kit with a FIFO was read");
}

}  // namespace

int main() {
    try {
        test_codes();
        test_kit_checks();
        test_layout_and_round_trip();
        test_wrong_code_and_tampering();
        test_malformed_contents();
        test_directories();
    } catch (const std::exception& error) {
        std::cerr << "sealed kit test failure: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
    std::cout << "sealed kit tests passed\n";
    return EXIT_SUCCESS;
}
