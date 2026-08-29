/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/security/secure_materials.hpp"

#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <algorithm>
#include <cassert>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace {

namespace fs = std::filesystem;
namespace sm = yume::facade::secure_materials;
using nlohmann::json;

fs::path metadata_path() {
    return sm::store_dir() / "materials.json";
}

void write_text(const fs::path& path, const std::string& value) {
    fs::create_directories(path.parent_path());
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    output.write(value.data(), static_cast<std::streamsize>(value.size()));
    output.close();
    assert(output);
}

std::string read_text(const fs::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input),
            std::istreambuf_iterator<char>()};
}

std::string private_key_pem() {
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> key(
        EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"), EVP_PKEY_free);
    assert(key);
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()),
                                                  BIO_free);
    assert(bio);
    assert(PEM_write_bio_PrivateKey(
               bio.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1);
    char* data = nullptr;
    const long length = BIO_get_mem_data(bio.get(), &data);
    assert(length > 0 && data != nullptr);
    return std::string(data, static_cast<std::size_t>(length));
}

json record(std::string id, std::string path = {}) {
    json value = {
        {"id", std::move(id)},
        {"display_name", "Legacy key"},
        {"type", "auth_key"},
        {"source_label", "Legacy"},
        {"fingerprint", "0123456789ab"},
        {"imported_encrypted", false},
        {"created_at_epoch_ms", 1},
    };
    if (!path.empty()) value["path"] = std::move(path);
    return value;
}

json metadata(json materials) {
    return {
        {"embedded_anonym_ca_enabled", false},
        {"materials", std::move(materials)},
    };
}

void reset_store() {
    std::error_code error;
    fs::remove_all(sm::store_dir(), error);
    assert(!error);
}

#ifndef _WIN32
void assert_private(const fs::path& path, mode_t expected) {
    struct stat status {};
    assert(::lstat(path.c_str(), &status) == 0);
    assert((status.st_mode & 07777) == expected);
    assert(status.st_uid == ::geteuid());
}
#endif

void test_default_ca() {
    std::string error;
    const auto materials = sm::list(sm::MaterialType::AnonymCa, &error);
    assert(error.empty());
    const auto found = std::find_if(materials.begin(), materials.end(),
                                    [](const auto& material) {
        return material.id == sm::kDefaultAnonymCaId;
    });
    assert(found != materials.end());
#ifndef _WIN32
    assert_private(sm::store_dir(), 0700);
    assert_private(found->path, 0600);
#endif
    assert(sm::remove(sm::kDefaultAnonymCaId, &error));
    assert(error.empty());
    assert(!sm::material_path(sm::kDefaultAnonymCaId, &error));
}

void test_default_ca_remove_race() {
    for (unsigned iteration = 0; iteration < 32U; ++iteration) {
        reset_store();
        std::string error;
        assert(!sm::list(sm::MaterialType::AnonymCa, &error).empty());
        assert(error.empty());

        bool removed = false;
        std::string remove_error;
        std::string list_error;
        std::thread list_thread([&] {
            (void)sm::list(sm::MaterialType::AnonymCa, &list_error);
        });
        std::thread remove_thread([&] {
            removed = sm::remove(sm::kDefaultAnonymCaId, &remove_error);
        });
        list_thread.join();
        remove_thread.join();

        assert(removed);
        assert(remove_error.empty());
        assert(list_error.empty());
        const auto after = sm::list(sm::MaterialType::AnonymCa, &error);
        assert(error.empty());
        assert(std::none_of(after.begin(), after.end(), [](const auto& item) {
            return item.id == sm::kDefaultAnonymCaId;
        }));
        assert(!fs::exists(sm::store_dir() / "default_anonym_ca.pem"));
    }
}

void test_malformed_metadata() {
    std::string error;
    auto expect_rejected = [&](const std::string& text) {
        reset_store();
        write_text(metadata_path(), text);
        (void)sm::list(sm::MaterialType::AuthKey, &error);
        assert(!error.empty());
    };

    expect_rejected("[]");
    expect_rejected(R"({"materials":"wrong"})");
    expect_rejected(R"({"schema":18446744073709551615,"materials":[]})");
    expect_rejected(R"({"materials":[{"id":7}]})");
    expect_rejected(metadata(json::array({record("../escape")})).dump());
    auto wrong_type = record("1-0123456789abcdef");
    wrong_type["type"] = "future_key";
    expect_rejected(metadata(json::array({wrong_type})).dump());
    auto wrong_fingerprint = record("1-0123456789abcdef");
    wrong_fingerprint["fingerprint"] = "ABC";
    expect_rejected(metadata(json::array({wrong_fingerprint})).dump());
    auto negative_created_at = record("1-0123456789abcdef");
    negative_created_at["created_at_epoch_ms"] = -1;
    expect_rejected(metadata(json::array({negative_created_at})).dump());

    reset_store();
    write_text(metadata_path(),
               std::string(sm::kMaximumMetadataBytes + 1U, ' '));
    (void)sm::list(sm::MaterialType::AuthKey, &error);
    assert(error.find("size limit") != std::string::npos);

    json records = json::array();
    for (std::size_t index = 0; index < sm::kMaximumMaterialRecords + 1U;
         ++index) {
        char suffix[17]{};
        std::snprintf(suffix, sizeof(suffix), "%016zx", index);
        records.push_back(record(std::string("1-") + suffix));
    }
    reset_store();
    write_text(metadata_path(), metadata(std::move(records)).dump());
    (void)sm::list(sm::MaterialType::AuthKey, &error);
    assert(error.find("record limit") != std::string::npos);
}

void test_legacy_migration_and_confinement(const std::string& pem) {
    reset_store();
    const std::string legacy_id = "1-0123456789abcdef";
    const fs::path derived = sm::store_dir() / (legacy_id + ".key.pem");
    write_text(derived, pem);
    write_text(metadata_path(),
               metadata(json::array({record(legacy_id, "/tmp/escape.pem")}))
                   .dump(2));

    std::string error;
    const auto materials = sm::list(sm::MaterialType::AuthKey, &error);
    assert(error.empty());
    assert(materials.size() == 1U);
    assert(materials.front().path == derived);

    sm::MaterialSummary imported;
    assert(sm::import_text(sm::MaterialType::AuthKey, "New key", pem,
                           &imported, &error));
    assert(error.empty());
    assert(imported.id.size() == 32U);
    assert(std::all_of(imported.id.begin(), imported.id.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    }));
#ifndef _WIN32
    assert_private(imported.path, 0600);
    assert_private(metadata_path(), 0600);
#endif

    const json canonical = json::parse(read_text(metadata_path()));
    assert(canonical.at("schema") == 1);
    assert(canonical.at("materials").size() == 2U);
    for (const auto& item : canonical.at("materials")) {
        assert(!item.contains("path"));
    }

    fs::remove(derived);
    const fs::path victim = sm::store_dir() / "victim.pem";
    write_text(victim, "unchanged");
    fs::create_symlink(victim, derived);
    assert(sm::list(sm::MaterialType::AuthKey, &error).empty());
    assert(!error.empty());
    assert(!sm::material_path(legacy_id, &error));
    assert(!error.empty());
    assert(read_text(victim) == "unchanged");

    fs::remove(derived);
    fs::create_directory(derived);
    assert(sm::list(sm::MaterialType::AuthKey, &error).empty());
    assert(!error.empty());
    fs::remove(derived);
}

void test_import_limits_and_concurrency(const std::string& pem) {
    reset_store();
    std::string error;
    assert(!sm::import_text(sm::MaterialType::AuthKey,
                            std::string(sm::kMaximumMaterialLabelBytes + 1U, 'x'),
                            pem, nullptr, &error));
    assert(!sm::import_text(sm::MaterialType::AuthKey, "oversized",
                            std::string(sm::kMaximumPemBytes + 1U, 'x'),
                            nullptr, &error));

    constexpr std::size_t kThreads = 8U;
    std::vector<int> results(kThreads, 0);
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (std::size_t index = 0; index < kThreads; ++index) {
        workers.emplace_back([&, index] {
            std::string thread_error;
            results[index] = sm::import_text(
                sm::MaterialType::AuthKey,
                "Concurrent " + std::to_string(index), pem, nullptr,
                &thread_error) ? 1 : 0;
        });
    }
    for (auto& worker : workers) worker.join();
    assert(std::all_of(results.begin(), results.end(), [](int value) {
        return value == 1;
    }));
    const auto materials = sm::list(sm::MaterialType::AuthKey, &error);
    assert(error.empty());
    assert(materials.size() == kThreads);
}

void test_metadata_symlink_rejected() {
    reset_store();
    fs::create_directories(sm::store_dir());
    const fs::path victim = sm::store_dir().parent_path() / "metadata-victim";
    const std::string victim_contents = metadata(json::array()).dump();
    write_text(victim, victim_contents);
    fs::create_symlink(victim, metadata_path());
    std::string error;
    (void)sm::list(sm::MaterialType::AuthKey, &error);
    assert(!error.empty());
    assert(read_text(victim) == victim_contents);
}

void test_metadata_publish_rollback(const std::string& pem) {
    reset_store();
    const pid_t child = ::fork();
    assert(child >= 0);
    if (child == 0) {
        (void)std::signal(SIGXFSZ, SIG_IGN);
        const rlim_t maximum_file_bytes = static_cast<rlim_t>(
            std::max<std::size_t>(128U, pem.size() + 16U));
        const rlimit limit{maximum_file_bytes, maximum_file_bytes};
        if (::setrlimit(RLIMIT_FSIZE, &limit) != 0) ::_exit(2);

        std::string error;
        const bool imported = sm::import_text(
            sm::MaterialType::AuthKey, "Rollback", pem, nullptr, &error);
        bool material_remained = false;
        std::error_code iterator_error;
        for (fs::directory_iterator iterator(sm::store_dir(), iterator_error),
             end;
             !iterator_error && iterator != end;
             iterator.increment(iterator_error)) {
            if (iterator->path().filename().string().ends_with(".key.pem")) {
                material_remained = true;
            }
        }
        ::_exit(!imported && !error.empty() && !iterator_error &&
                       !material_remained
                   ? 0
                   : 3);
    }

    int status = 0;
    assert(::waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    for (const auto& entry : fs::directory_iterator(sm::store_dir())) {
        assert(!entry.path().filename().string().ends_with(".key.pem"));
    }
}

void test_remove_metadata_publish_rollback(const std::string& pem) {
    reset_store();
    std::string error;
    sm::MaterialSummary imported;
    assert(sm::import_text(sm::MaterialType::AuthKey, "Keep on failure", pem,
                           &imported, &error));

    const pid_t child = ::fork();
    assert(child >= 0);
    if (child == 0) {
        (void)std::signal(SIGXFSZ, SIG_IGN);
        const rlimit limit{64, 64};
        if (::setrlimit(RLIMIT_FSIZE, &limit) != 0) ::_exit(2);

        std::string child_error;
        const bool removed = sm::remove(imported.id, &child_error);
        const bool file_remained = fs::is_regular_file(imported.path);
        const auto material = sm::material_path(imported.id, &child_error);
        ::_exit(!removed && file_remained && material.has_value() ? 0 : 3);
    }

    int status = 0;
    assert(::waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    assert(sm::material_path(imported.id, &error).has_value());
}

}  // namespace

int main() {
#ifdef _WIN32
    return 0;
#else
    char temporary_home[] = "/tmp/yume-secure-materials-XXXXXX";
    assert(::mkdtemp(temporary_home) != nullptr);
    const char* previous_home_value = std::getenv("HOME");
    const std::string previous_home =
        previous_home_value ? previous_home_value : "";
    assert(::setenv("HOME", temporary_home, 1) == 0);

    const std::string pem = private_key_pem();
    test_default_ca();
    test_default_ca_remove_race();
    test_malformed_metadata();
    test_legacy_migration_and_confinement(pem);
    test_metadata_publish_rollback(pem);
    test_remove_metadata_publish_rollback(pem);
    test_import_limits_and_concurrency(pem);
    test_metadata_symlink_rejected();

    if (previous_home_value) {
        assert(::setenv("HOME", previous_home.c_str(), 1) == 0);
    } else {
        assert(::unsetenv("HOME") == 0);
    }
    std::error_code cleanup_error;
    fs::remove_all(temporary_home, cleanup_error);
    assert(!cleanup_error);
    return 0;
#endif
}
