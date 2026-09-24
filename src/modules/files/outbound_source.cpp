/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "modules/files/outbound_source.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <exception>
#include <limits>
#include <mutex>
#include <utility>

#include "modules/relay/identity.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace yume::files {
namespace {

void set_error(std::string* error, const std::string& message) {
    if (error) *error = message;
}


}  // namespace

struct RelayOutboundSource::Impl {
    int descriptor{-1};
    std::uint64_t opened_size{0};
    std::uint64_t read_offset{0};
    mutable std::mutex mutex;

    ~Impl() {
        if (descriptor >= 0) {
            (void)::close(descriptor);
        }
    }

    bool current_size_locked(std::uint64_t* value,
                             std::string* error) const {
        if (!value) {
            set_error(error, "invalid relay transfer size destination");
            return false;
        }
        struct stat info {};
        if (descriptor < 0 || ::fstat(descriptor, &info) != 0) {
            set_error(error,
                      "failed to inspect pinned relay transfer source: " +
                          std::string(std::strerror(errno)));
            return false;
        }
        if (!S_ISREG(info.st_mode) || info.st_size < 0) {
            set_error(error,
                      "relay transfer source is not a regular file");
            return false;
        }
        *value = static_cast<std::uint64_t>(info.st_size);
        return true;
    }

    bool read_at_locked(std::uint64_t offset,
                        std::span<std::uint8_t> output,
                        std::string* error) const {
        std::size_t completed = 0;
        while (completed < output.size()) {
            if (offset > static_cast<std::uint64_t>(
                             std::numeric_limits<off_t>::max()) -
                             completed) {
                set_error(error, "relay transfer source offset overflow");
                return false;
            }
            const ssize_t received = ::pread(
                descriptor, output.data() + completed,
                output.size() - completed,
                static_cast<off_t>(offset + completed));
            if (received < 0) {
                if (errno == EINTR) continue;
                set_error(error,
                          "failed to read pinned relay transfer source: " +
                              std::string(std::strerror(errno)));
                return false;
            }
            if (received == 0) {
                set_error(error,
                          "pinned relay transfer source ended early");
                return false;
            }
            completed += static_cast<std::size_t>(received);
        }
        return true;
    }
};

RelayOutboundSource::RelayOutboundSource(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

RelayOutboundSource::~RelayOutboundSource() = default;

std::shared_ptr<RelayOutboundSource> RelayOutboundSource::Open(
    const std::filesystem::path& path,
    std::uint64_t max_bytes,
    std::string* error) {
    if (error) error->clear();
    if (path.empty() || path.filename().empty()) {
        set_error(error, "relay transfer source path is invalid");
        return {};
    }

    auto impl = std::make_unique<Impl>();
#if !defined(O_NOFOLLOW) || !defined(O_CLOEXEC) || !defined(O_NONBLOCK)
    set_error(error,
              "secure relay transfer sources require O_NOFOLLOW, O_CLOEXEC, "
              "and O_NONBLOCK on this platform");
    return {};
#else
    impl->descriptor = ::open(
        path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (impl->descriptor < 0) {
        set_error(error, "failed to open relay transfer source: " +
                             std::string(std::strerror(errno)));
        return {};
    }
#endif

    std::uint64_t source_size = 0;
    if (!impl->current_size_locked(&source_size, error)) return {};
    if (source_size > max_bytes) {
        set_error(error, "relay transfer source exceeds the size limit");
        return {};
    }
    impl->opened_size = source_size;
    return std::shared_ptr<RelayOutboundSource>(
        new RelayOutboundSource(std::move(impl)));
}

std::uint64_t RelayOutboundSource::size() const noexcept {
    return impl_ ? impl_->opened_size : 0;
}

std::string RelayOutboundSource::Sha256Hex(std::string* error) const {
    if (error) error->clear();
    if (!impl_) {
        set_error(error, "relay transfer source is unavailable");
        return {};
    }
    std::lock_guard<std::mutex> lock(impl_->mutex);
    std::uint64_t current_size = 0;
    if (!impl_->current_size_locked(&current_size, error) ||
        current_size != impl_->opened_size) {
        if (error && error->empty()) {
            *error = "relay transfer source changed size while hashing";
        }
        return {};
    }

    try {
        relay::identity::Sha256Stream digest;
        std::array<std::uint8_t, 65536> buffer{};
        std::uint64_t offset = 0;
        while (offset < impl_->opened_size) {
            const std::size_t wanted = static_cast<std::size_t>(
                std::min<std::uint64_t>(buffer.size(),
                                        impl_->opened_size - offset));
            if (!impl_->read_at_locked(
                    offset, std::span<std::uint8_t>(buffer.data(), wanted),
                    error)) {
                return {};
            }
            digest.Update(
                std::span<const std::uint8_t>(buffer.data(), wanted));
            offset += wanted;
        }
        if (!impl_->current_size_locked(&current_size, error) ||
            current_size != impl_->opened_size) {
            if (error && error->empty()) {
                *error = "relay transfer source changed size while hashing";
            }
            return {};
        }
        return digest.FinishHex();
    } catch (const std::exception& ex) {
        set_error(error, std::string("failed to hash relay transfer source: ") +
                             ex.what());
        return {};
    }
}

bool RelayOutboundSource::ReadExact(std::span<std::uint8_t> output,
                                    std::string* error) {
    if (error) error->clear();
    if (!impl_) {
        set_error(error, "relay transfer source is unavailable");
        return false;
    }
    std::lock_guard<std::mutex> lock(impl_->mutex);
    if (impl_->read_offset > impl_->opened_size ||
        output.size() > impl_->opened_size - impl_->read_offset) {
        set_error(error, "relay transfer read exceeds the pinned source size");
        return false;
    }
    if (!impl_->read_at_locked(impl_->read_offset, output, error)) {
        return false;
    }
    impl_->read_offset += output.size();
    return true;
}

bool RelayOutboundSource::ValidateSize(std::string* error) const {
    if (error) error->clear();
    if (!impl_) {
        set_error(error, "relay transfer source is unavailable");
        return false;
    }
    std::lock_guard<std::mutex> lock(impl_->mutex);
    std::uint64_t current_size = 0;
    if (!impl_->current_size_locked(&current_size, error)) return false;
    if (current_size != impl_->opened_size) {
        set_error(error, "pinned relay transfer source changed size");
        return false;
    }
    return true;
}

}  // namespace yume::files
