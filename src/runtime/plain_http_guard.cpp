/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/plain_http_guard.hpp"

#include <algorithm>
#include <new>
#include <string_view>
#include <utility>
#include <vector>

namespace yume::runtime {
namespace {

using engine::Buffer;
using engine::CancellationToken;
using engine::Result;
using engine::Status;
using engine::StatusCode;
using engine::StreamResponder;

constexpr std::string_view kPreface = "PRI * HTTP/2.0\r\n";
constexpr std::string_view kVersion = "HTTP/1.";
constexpr std::size_t kMaxMethodBytes = 20U;

bool method_byte(char ch) noexcept {
    return (ch >= 'A' && ch <= 'Z') || ch == '-' || ch == '_';
}

bool target_byte(char ch) noexcept {
    const auto byte = static_cast<unsigned char>(ch);
    return byte > 0x20U && byte != 0x7fU;
}

class Guard final : public StreamResponder,
                    public std::enable_shared_from_this<Guard> {
public:
    explicit Guard(std::shared_ptr<StreamResponder> inner) noexcept
        : inner_(std::move(inner)) {}

    engine::ExecutorAffinity executor_affinity() const noexcept override {
        return inner_->executor_affinity();
    }
    engine::ServiceKind service_kind() const noexcept override {
        return inner_->service_kind();
    }
    std::size_t max_write_size() const noexcept override {
        return inner_->max_write_size();
    }
    bool terminated() const noexcept override {
        return decided_ == Cleartext::Http || inner_->terminated();
    }
    void async_read(CancellationToken cancellation,
                    ReadCompletion completion) override {
        inner_->async_read(std::move(cancellation), std::move(completion));
    }

    void async_write(Buffer payload, CancellationToken cancellation,
                     WriteCompletion completion) override {
        const std::size_t size = payload.size();
        if (decided_ == Cleartext::Other) {
            inner_->async_write(std::move(payload), std::move(cancellation),
                                std::move(completion));
            return;
        }
        if (decided_ == Cleartext::Http) {
            completion(Status(StatusCode::PermissionDenied), 0U);
            return;
        }
        try {
            const auto bytes = payload.bytes();
            held_.insert(held_.end(), bytes.begin(), bytes.end());
        } catch (const std::bad_alloc&) {
            completion(Status(StatusCode::ResourceExhausted), 0U);
            return;
        }
        decided_ = classify_cleartext(held_);
        if (decided_ == Cleartext::Undecided) {
            completion(Status::success(), size);
            return;
        }
        if (decided_ == Cleartext::Http) {
            held_.clear();
            inner_->close(Status(StatusCode::PermissionDenied));
            completion(Status(StatusCode::PermissionDenied), 0U);
            return;
        }
        flush(std::move(cancellation), [completion = std::move(completion),
                                        size](Status status, std::size_t) {
            completion(std::move(status), status.ok() ? size : 0U);
        });
    }

    Status shutdown_write() noexcept override {
        if (decided_ == Cleartext::Undecided) {
            // An unfinished line is not a request.
            decided_ = Cleartext::Other;
            try {
                flush({}, [](Status, std::size_t) {});
            } catch (...) {
                inner_->close(Status(StatusCode::ResourceExhausted));
                return Status(StatusCode::ResourceExhausted);
            }
        }
        if (decided_ == Cleartext::Http)
            return Status(StatusCode::PermissionDenied);
        return inner_->shutdown_write();
    }

    void close(Status reason) noexcept override {
        inner_->close(std::move(reason));
    }

private:
    // Sends what was held in pieces the stream accepts, the last one
    // completing through done.
    void flush(CancellationToken cancellation, WriteCompletion done) {
        auto held = std::move(held_);
        held_.clear();
        if (held.empty()) {
            done(Status::success(), 0U);
            return;
        }
        const std::size_t piece =
            std::max<std::size_t>(1U, inner_->max_write_size());
        for (std::size_t offset = 0U; offset < held.size(); offset += piece) {
            const std::size_t size = std::min(piece, held.size() - offset);
            auto buffer =
                Buffer::copy_from(std::span(held).subspan(offset, size), size);
            if (!buffer.ok()) {
                inner_->close(Status(buffer.status().code()));
                done(Status(buffer.status().code()), 0U);
                return;
            }
            const bool last = offset + size == held.size();
            inner_->async_write(
                std::move(buffer).take_value(), cancellation,
                last ? std::move(done)
                     : WriteCompletion([](Status, std::size_t) {}));
        }
    }

    std::shared_ptr<StreamResponder> inner_;
    Cleartext decided_{Cleartext::Undecided};
    std::vector<std::byte> held_;
};

}  // namespace

Cleartext classify_cleartext(std::span<const std::byte> start) noexcept {
    const std::string_view text(reinterpret_cast<const char*>(start.data()),
                                start.size());
    if (text.empty()) return Cleartext::Undecided;
    // The HTTP/2 cleartext preface.
    const auto shared = std::min(text.size(), kPreface.size());
    if (text.substr(0U, shared) == kPreface.substr(0U, shared)) {
        return text.size() >= kPreface.size() ? Cleartext::Http
                                              : Cleartext::Undecided;
    }
    // method SP target SP HTTP/1.d (CR) LF
    std::size_t at = 0U;
    while (at < text.size() && method_byte(text[at])) {
        if (++at > kMaxMethodBytes) return Cleartext::Other;
    }
    const auto undecided = [&] {
        return text.size() >= kCleartextHoldBytes ? Cleartext::Http
                                                  : Cleartext::Undecided;
    };
    if (at == text.size()) return undecided();
    if (at == 0U || text[at] != ' ') return Cleartext::Other;
    ++at;
    const std::size_t target = at;
    while (at < text.size() && target_byte(text[at])) ++at;
    if (at == text.size()) return undecided();
    if (at == target || text[at] != ' ') return Cleartext::Other;
    ++at;
    for (const char expected : kVersion) {
        if (at == text.size()) return undecided();
        if (text[at++] != expected) return Cleartext::Other;
    }
    if (at == text.size()) return undecided();
    if (text[at] < '0' || text[at] > '9') return Cleartext::Other;
    ++at;
    if (at == text.size()) return undecided();
    if (text[at] == '\n') return Cleartext::Http;
    if (text[at] != '\r') return Cleartext::Other;
    ++at;
    if (at == text.size()) return undecided();
    return text[at] == '\n' ? Cleartext::Http : Cleartext::Other;
}

std::shared_ptr<StreamResponder> guard_plain_http(
    std::shared_ptr<StreamResponder> stream) {
    return std::make_shared<Guard>(std::move(stream));
}

}  // namespace yume::runtime
