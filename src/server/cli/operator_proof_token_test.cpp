/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/operator_proof_token.hpp"

#include <cassert>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

#include <sys/stat.h>
#include <unistd.h>

namespace {

namespace fs = std::filesystem;

class TemporaryDirectory final {
public:
    TemporaryDirectory() {
        std::string pattern =
            (fs::temp_directory_path() /
             "yume-operator-proof-token-test-XXXXXX").string();
        const char* created = ::mkdtemp(pattern.data());
        if (!created) throw std::runtime_error("mkdtemp failed");
        path_ = created;
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        fs::remove_all(path_, ignored);
    }

    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;

    const fs::path& path() const noexcept { return path_; }

private:
    fs::path path_;
};

void write_private(const fs::path& path,
                   const std::string& contents,
                   mode_t mode = 0600) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    assert(output);
    output.close();
    assert(::chmod(path.c_str(), mode) == 0);
}

template <typename Function>
bool throws(Function&& function) {
    try {
        function();
    } catch (const std::exception&) {
        return true;
    }
    return false;
}

}  // namespace

int main() {
    TemporaryDirectory temporary;
    const auto token_path = temporary.path() / "proof.token";

    write_private(token_path, "token-sentinel-with-spaces");
    assert(yume::server::cli::load_operator_proof_token_file(
               token_path.string()) == "token-sentinel-with-spaces");

    write_private(token_path, "");
    assert(throws([&] {
        (void)yume::server::cli::load_operator_proof_token_file(
            token_path.string());
    }));

    write_private(token_path, "token\n");
    assert(throws([&] {
        (void)yume::server::cli::load_operator_proof_token_file(
            token_path.string());
    }));

    write_private(
        token_path,
        std::string(yume::server::cli::kMaxOperatorProofTokenBytes + 1U, 'x'));
    assert(throws([&] {
        (void)yume::server::cli::load_operator_proof_token_file(
            token_path.string());
    }));

    write_private(token_path, "private-token", 0640);
    assert(throws([&] {
        (void)yume::server::cli::load_operator_proof_token_file(
            token_path.string());
    }));

    assert(::chmod(token_path.c_str(), 0600) == 0);
    const auto link_path = temporary.path() / "proof-link.token";
    assert(::symlink(token_path.c_str(), link_path.c_str()) == 0);
    assert(throws([&] {
        (void)yume::server::cli::load_operator_proof_token_file(
            link_path.string());
    }));

    return 0;
}
