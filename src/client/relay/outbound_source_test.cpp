/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/relay/outbound_source.hpp"

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <cassert>
#include <filesystem>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#include "core/security/crypto.hpp"
#include "util.hpp"

#if !defined(_WIN32)
#include <cerrno>
#include <unistd.h>
#endif

namespace {

class TempDirectory {
public:
    TempDirectory() {
#if defined(_WIN32)
        path_ = std::filesystem::temp_directory_path() /
                ("yume-relay-source-" + yume::util::random_hex(12));
        if (!std::filesystem::create_directory(path_)) {
            throw std::runtime_error("create relay source test directory");
        }
#else
        std::string pattern =
            (std::filesystem::temp_directory_path() /
             "yume-relay-source-XXXXXX").string();
        if (!::mkdtemp(pattern.data())) {
            throw std::system_error(errno, std::generic_category(),
                                    "create relay source test directory");
        }
        path_ = pattern;
#endif
    }

    ~TempDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

void Write(const std::filesystem::path& path, const std::string& contents) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    if (!output) throw std::runtime_error("write relay source fixture");
}

std::string ReadAll(const std::shared_ptr<yume::client::RelayOutboundSource>& source) {
    std::vector<std::uint8_t> bytes(static_cast<std::size_t>(source->size()));
    std::string error;
    assert(source->ReadExact(bytes, &error));
    assert(error.empty());
    return {bytes.begin(), bytes.end()};
}

}  // namespace

int main() {
    TempDirectory temp;
    const auto offered_path = temp.path() / "offered.bin";
    const auto retained_path = temp.path() / "retained.bin";
    const auto replacement_path = temp.path() / "replacement.bin";
    const std::string offered = "original-public-payload";
    const std::string replacement(offered.size(), 'S');
    Write(offered_path, offered);
    Write(replacement_path, replacement);

    std::string error;
    auto source = yume::client::RelayOutboundSource::Open(
        offered_path, offered.size(), &error);
    assert(source);
    assert(error.empty());
    assert(source->size() == offered.size());
    assert(source->Sha256Hex(&error) ==
           yume::crypto::sha256_hex(std::span<const std::uint8_t>(
               reinterpret_cast<const std::uint8_t*>(offered.data()),
               offered.size())));
    assert(error.empty());

#if !defined(_WIN32)
    // Replace the validated pathname after hashing with a same-size symlink.
    // Reads must continue to come from the retained descriptor, never from the
    // replacement path.
    std::filesystem::rename(offered_path, retained_path);
    assert(::symlink(replacement_path.c_str(), offered_path.c_str()) == 0);
    assert(ReadAll(source) == offered);
    assert(source->ValidateSize(&error));
    assert(error.empty());

    auto linked = yume::client::RelayOutboundSource::Open(
        offered_path, offered.size(), &error);
    assert(!linked);
    assert(!error.empty());
#else
    assert(ReadAll(source) == offered);
#endif

    auto oversized = yume::client::RelayOutboundSource::Open(
        replacement_path, replacement.size() - 1U, &error);
    assert(!oversized);
    assert(error.find("size limit") != std::string::npos);
    return 0;
}
