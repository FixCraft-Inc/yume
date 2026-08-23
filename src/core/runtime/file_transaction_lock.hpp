/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace yume::runtime {

// Exclusive advisory lock for a transaction spanning one or more replaceable
// files. Each resource maps to a persistent same-directory `.yume.lock`
// sidecar because locking the resource itself would be invalidated by rename.
// All sidecars are acquired in canonical sorted order to avoid deadlock.
class FileTransactionLock {
public:
    FileTransactionLock();
    ~FileTransactionLock();

    FileTransactionLock(const FileTransactionLock&) = delete;
    FileTransactionLock& operator=(const FileTransactionLock&) = delete;
    FileTransactionLock(FileTransactionLock&&) = delete;
    FileTransactionLock& operator=(FileTransactionLock&&) = delete;

    bool Acquire(const std::vector<std::filesystem::path>& resources,
                 std::string* error = nullptr);
    void Unlock() noexcept;
    bool owns_lock() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace yume::runtime
