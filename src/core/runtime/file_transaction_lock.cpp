/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/runtime/file_transaction_lock.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <exception>
#include <map>
#include <mutex>
#include <system_error>

#if defined(_WIN32)
#define NOMINMAX
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace yume::runtime {
namespace {

struct SidecarPathLess {
    bool operator()(const std::filesystem::path& lhs,
                    const std::filesystem::path& rhs) const noexcept {
#if defined(_WIN32)
        // Windows paths are normally case-insensitive. CompareStringOrdinal is
        // locale-independent, so callers using different path casing still
        // share one in-process lock domain.
        const int comparison = CompareStringOrdinal(
            lhs.c_str(), -1, rhs.c_str(), -1, TRUE);
        if (comparison == CSTR_LESS_THAN) return true;
        if (comparison == CSTR_GREATER_THAN || comparison == CSTR_EQUAL) {
            return false;
        }
#endif
        return lhs.native() < rhs.native();
    }
};

bool same_sidecar_path(const std::filesystem::path& lhs,
                       const std::filesystem::path& rhs) noexcept {
    const SidecarPathLess less;
    return !less(lhs, rhs) && !less(rhs, lhs);
}

struct LocalLockRegistry {
    std::mutex mutex;
    std::map<std::filesystem::path,
             std::weak_ptr<std::mutex>,
             SidecarPathLess>
        locks;
};

LocalLockRegistry& local_lock_registry() {
    // A process-global registry supplements advisory OS locks whose
    // same-process semantics differ across flock/LockFileEx implementations.
    // It intentionally outlives static FileTransactionLock instances.
    static auto* registry = new LocalLockRegistry();
    return *registry;
}

std::vector<std::shared_ptr<std::mutex>> local_locks_for(
    const std::vector<std::filesystem::path>& sidecars) {
    auto& registry = local_lock_registry();
    std::lock_guard<std::mutex> guard(registry.mutex);
    for (auto it = registry.locks.begin(); it != registry.locks.end();) {
        if (it->second.expired()) {
            it = registry.locks.erase(it);
        } else {
            ++it;
        }
    }
    std::vector<std::shared_ptr<std::mutex>> result;
    result.reserve(sidecars.size());
    for (const auto& sidecar : sidecars) {
        auto& weak = registry.locks[sidecar];
        auto lock = weak.lock();
        if (!lock) {
            lock = std::make_shared<std::mutex>();
            weak = lock;
        }
        result.push_back(std::move(lock));
    }
    return result;
}

void set_error(std::string* error,
               const std::filesystem::path& path,
               const std::string& operation,
               const std::string& detail) {
    if (error) {
        *error = operation + " '" + path.string() + "': " + detail;
    }
}

#if defined(_WIN32)
std::string windows_error(DWORD code) {
    char* message = nullptr;
    const DWORD length = FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, code, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<char*>(&message), 0, nullptr);
    std::string result = length && message
                             ? std::string(message, message + length)
                             : "Windows error " + std::to_string(code);
    if (message) LocalFree(message);
    while (!result.empty() &&
           (result.back() == '\r' || result.back() == '\n')) {
        result.pop_back();
    }
    return result;
}
#endif

bool sidecar_path_for(const std::filesystem::path& resource,
                      std::filesystem::path* sidecar,
                      std::string* error) {
    if (!sidecar || resource.empty() || resource.filename().empty()) {
        set_error(error, resource, "cannot lock transaction",
                  "invalid resource path");
        return false;
    }
    std::error_code path_error;
    auto absolute = std::filesystem::absolute(resource, path_error);
    if (path_error) {
        set_error(error, resource, "cannot resolve transaction resource",
                  path_error.message());
        return false;
    }
    absolute = absolute.lexically_normal();
    auto parent = absolute.parent_path();
    std::filesystem::create_directories(parent, path_error);
    if (path_error) {
        set_error(error, parent, "cannot create lock directory",
                  path_error.message());
        return false;
    }
    const auto canonical_parent =
        std::filesystem::weakly_canonical(parent, path_error);
    if (path_error) {
        set_error(error, parent, "cannot canonicalize lock directory",
                  path_error.message());
        return false;
    }
    auto sidecar_filename = absolute.filename();
    sidecar_filename += ".yume.lock";
    *sidecar = canonical_parent / sidecar_filename;
    return true;
}

}  // namespace

struct FileTransactionLock::Impl {
    std::vector<std::shared_ptr<std::mutex>> local_mutexes;
    std::vector<std::unique_lock<std::mutex>> local_locks;
#if defined(_WIN32)
    std::vector<HANDLE> handles;
#else
    std::vector<int> descriptors;
#endif
    bool acquired{false};

    void release() noexcept {
#if defined(_WIN32)
        for (auto it = handles.rbegin(); it != handles.rend(); ++it) {
            OVERLAPPED overlapped{};
            (void)UnlockFileEx(*it, 0, MAXDWORD, MAXDWORD, &overlapped);
            (void)CloseHandle(*it);
        }
#else
        for (auto it = descriptors.rbegin(); it != descriptors.rend(); ++it) {
            (void)::flock(*it, LOCK_UN);
            (void)::close(*it);
        }
#endif
        acquired = false;
#if defined(_WIN32)
        handles.clear();
#else
        descriptors.clear();
#endif
        local_locks.clear();
        local_mutexes.clear();
    }

    ~Impl() { release(); }
};

FileTransactionLock::FileTransactionLock() : impl_(std::make_unique<Impl>()) {}
FileTransactionLock::~FileTransactionLock() = default;

bool FileTransactionLock::Acquire(
    const std::vector<std::filesystem::path>& resources,
    std::string* error) {
    if (error) error->clear();
    if (impl_->acquired) {
        if (error) *error = "transaction lock was already acquired";
        return false;
    }

    std::vector<std::filesystem::path> sidecars;
    sidecars.reserve(resources.size());
    for (const auto& resource : resources) {
        if (resource.empty()) continue;
        std::filesystem::path sidecar;
        if (!sidecar_path_for(resource, &sidecar, error)) return false;
        sidecars.push_back(std::move(sidecar));
    }
    std::sort(sidecars.begin(), sidecars.end(), SidecarPathLess{});
    sidecars.erase(std::unique(sidecars.begin(), sidecars.end(),
                               same_sidecar_path),
                   sidecars.end());
    if (sidecars.empty()) {
        if (error) *error = "transaction lock has no valid resources";
        return false;
    }

    try {
        impl_->local_mutexes = local_locks_for(sidecars);
        impl_->local_locks.reserve(impl_->local_mutexes.size());
        for (const auto& local_mutex : impl_->local_mutexes) {
            impl_->local_locks.emplace_back(*local_mutex);
        }
    } catch (const std::exception& ex) {
        impl_->release();
        if (error) {
            *error = std::string("cannot acquire in-process transaction lock: ") +
                     ex.what();
        }
        return false;
    }

    for (const auto& sidecar : sidecars) {
#if defined(_WIN32)
        HANDLE handle = CreateFileW(
            sidecar.c_str(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS,
            FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
            nullptr);
        if (handle == INVALID_HANDLE_VALUE) {
            set_error(error, sidecar, "cannot open transaction lock",
                      windows_error(GetLastError()));
            impl_->release();
            return false;
        }
        OVERLAPPED overlapped{};
        if (!LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD,
                        MAXDWORD, &overlapped)) {
            const DWORD lock_error = GetLastError();
            (void)CloseHandle(handle);
            set_error(error, sidecar, "cannot acquire transaction lock",
                      windows_error(lock_error));
            impl_->release();
            return false;
        }
        impl_->handles.push_back(handle);
#else
        int flags = O_RDWR | O_CREAT | O_CLOEXEC;
#ifdef O_NOFOLLOW
        flags |= O_NOFOLLOW;
#endif
        const int descriptor = ::open(sidecar.c_str(), flags,
                                      S_IRUSR | S_IWUSR);
        if (descriptor < 0) {
            set_error(error, sidecar, "cannot open transaction lock",
                      std::strerror(errno));
            impl_->release();
            return false;
        }
        struct stat status {};
        if (::fstat(descriptor, &status) != 0) {
            const int status_error = errno;
            (void)::close(descriptor);
            set_error(error, sidecar, "invalid transaction lock file",
                      std::strerror(status_error));
            impl_->release();
            return false;
        }
        if (!S_ISREG(status.st_mode)) {
            (void)::close(descriptor);
            set_error(error, sidecar, "invalid transaction lock file",
                      std::strerror(EINVAL));
            impl_->release();
            return false;
        }
        if (::fchmod(descriptor, S_IRUSR | S_IWUSR) != 0) {
            const int mode_error = errno;
            (void)::close(descriptor);
            set_error(error, sidecar, "cannot secure transaction lock",
                      std::strerror(mode_error));
            impl_->release();
            return false;
        }
        while (::flock(descriptor, LOCK_EX) != 0) {
            if (errno == EINTR) continue;
            const int lock_error = errno;
            (void)::close(descriptor);
            set_error(error, sidecar, "cannot acquire transaction lock",
                      std::strerror(lock_error));
            impl_->release();
            return false;
        }
        impl_->descriptors.push_back(descriptor);
#endif
    }
    impl_->acquired = true;
    return true;
}

void FileTransactionLock::Unlock() noexcept {
    impl_->release();
}

bool FileTransactionLock::owns_lock() const noexcept {
    return impl_->acquired;
}

}  // namespace yume::runtime
