/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/runtime/bounded_file.hpp"

#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#include <utime.h>
#endif

namespace {

namespace fs = std::filesystem;

fs::path make_temp_dir() {
#if defined(_WIN32)
    for (unsigned int attempt = 0; attempt < 32; ++attempt) {
        const auto path = fs::temp_directory_path() /
            ("yume-bounded-file-test-" + std::to_string(
                 std::chrono::steady_clock::now().time_since_epoch().count()) +
             "-" + std::to_string(attempt));
        std::error_code error;
        if (fs::create_directory(path, error)) return path;
    }
    assert(false && "could not create temporary test directory");
    return {};
#else
    std::string pattern =
        (fs::temp_directory_path() / "yume-bounded-file-test-XXXXXX").string();
    const char* created = ::mkdtemp(pattern.data());
    assert(created != nullptr);
    return fs::canonical(created);
#endif
}

class TempDir final {
public:
    TempDir() : path_(make_temp_dir()) {}
    ~TempDir() {
        std::error_code error;
        fs::remove_all(path_, error);
    }

    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    const fs::path& path() const noexcept { return path_; }

private:
    fs::path path_;
};

void write_text(const fs::path& path, const std::string& contents) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    assert(output);
    output.write(contents.data(), static_cast<std::streamsize>(contents.size()));
    assert(output);
}

void test_optional_absence_is_explicit() {
    TempDir directory;
    const auto missing = directory.path() / "missing";
    std::string contents = "stale";
    std::string error = "stale";
    bool existed = true;

    assert(yume::runtime::read_optional_text_file_bounded(
        missing, 16, true, &contents, &existed, &error));
    assert(contents.empty());
    assert(!existed);
    assert(error.empty());

    contents = "stale";
    existed = true;
    assert(!yume::runtime::read_optional_text_file_bounded(
        missing, 16, false, &contents, &existed, &error));
    assert(contents.empty());
    assert(!existed);
    assert(error.find("does not exist") != std::string::npos);
}

void test_regular_file_and_bound() {
    TempDir directory;
    const auto path = directory.path() / "store";
    write_text(path, "identity");

    std::string contents;
    std::string error;
    bool existed = false;
    assert(yume::runtime::read_optional_text_file_bounded(
        path, 8, true, &contents, &existed, &error));
    assert(contents == "identity");
    assert(existed);
    assert(error.empty());

    assert(!yume::runtime::read_optional_text_file_bounded(
        path, 7, true, &contents, &existed, &error));
    assert(contents.empty());
    assert(!existed);
    assert(error.find("size limit") != std::string::npos);
}

void test_special_paths_are_not_missing() {
    TempDir directory;
    const auto child = directory.path() / "child";
    assert(fs::create_directory(child));

    std::string contents;
    std::string error;
    bool existed = true;
    assert(!yume::runtime::read_optional_text_file_bounded(
        child, 64, true, &contents, &existed, &error));
    assert(contents.empty());
    assert(!existed);
    assert(!error.empty());

#if !defined(_WIN32)
    const auto target = directory.path() / "target";
    const auto link = directory.path() / "link";
    write_text(target, "must not be followed");
    assert(::symlink(target.c_str(), link.c_str()) == 0);
    error.clear();
    existed = true;
    assert(!yume::runtime::read_optional_text_file_bounded(
        link, 64, true, &contents, &existed, &error));
    assert(contents.empty());
    assert(!existed);
    assert(!error.empty());
    const auto fifo = directory.path() / "fifo";
    assert(::mkfifo(fifo.c_str(), 0600) == 0);
    ::alarm(3);  // A regression must fail the test, not hang the test worker.
    assert(!yume::runtime::read_text_file_bounded(fifo, 64, &contents, &error));
    ::alarm(0);
#endif
}

#if !defined(_WIN32)
void test_confined_root_is_pinned_across_rename() {
    TempDir directory;
    const fs::path root = directory.path() / "root";
    const fs::path replacement = directory.path() / "replacement";
    const fs::path moved = directory.path() / "moved";
    assert(fs::create_directory(root));
    assert(fs::create_directory(replacement));
    write_text(root / "marker.txt", "original");
    write_text(replacement / "marker.txt", "outside");
    const struct utimbuf timestamp {1700000000, 1700000000};
    assert(::utime((root / "marker.txt").c_str(), &timestamp) == 0);

    std::string error;
    auto pinned = yume::runtime::FileRoot::open(root, &error);
    assert(pinned.has_value());
    std::error_code rename_error;
    fs::rename(root, moved, rename_error);
    assert(!rename_error);
    assert(::symlink(replacement.c_str(), root.c_str()) == 0);

    std::string contents;
    std::time_t modification_time{};
    assert(pinned->read_text("marker.txt", 64, &contents, &error, &modification_time));
    assert(contents == "original");
    assert(modification_time == timestamp.modtime);
    assert(::symlink(replacement.c_str(), (moved / "link").c_str()) == 0);
    assert(!pinned->read_text("link/marker.txt", 64, &contents, &error));
    assert(!yume::runtime::FileRoot::open(root, &error));
    assert(::mkfifo((moved / "fifo").c_str(), 0600) == 0);
    ::alarm(3);
    assert(!pinned->read_text("fifo", 64, &contents, &error));
    ::alarm(0);
    assert(!pinned->read_text("../marker.txt", 64, &contents, &error));
    assert(!pinned->read_text("missing.txt", 64, &contents, &error));
    assert(fs::remove(root));
    fs::remove_all(moved);
    fs::remove_all(replacement);
}
#endif

}  // namespace

int main() {
    test_optional_absence_is_explicit();
    test_regular_file_and_bound();
    test_special_paths_are_not_missing();
#if !defined(_WIN32)
    test_confined_root_is_pinned_across_rename();
#endif
    return 0;
}
