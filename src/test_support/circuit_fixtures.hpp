/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

// Fixtures for circuit tests that run nodes and clients over in-memory
// streams on one execution thread: the thread, a packet stream pair, an
// echoing destination, node identities and open contexts.

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <future>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <utility>

#include <boost/asio/post.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include "engine/stream_handler.hpp"
#include "providers/asio_execution_context.hpp"
#include "providers/circuit_crypto.hpp"
#include "providers/composite_keys.hpp"
#include "ytp/protocol.hpp"

namespace yume::test {

using namespace std::chrono_literals;
using engine::Buffer;
using engine::CancellationToken;
using engine::ReceivedRecord;
using engine::Result;
using engine::Status;
using engine::StatusCode;
using engine::StreamResponder;
namespace keys = providers::keys;

template <typename T>
T take(Result<T> result) {
    if (!result.ok()) throw std::runtime_error(result.status().message());
    return std::move(result).take_value();
}

class IoRuntime final {
public:
    IoRuntime()
        : context_(take(providers::AsioExecutionContext::create(
              engine::ExecutorAffinity(207U)))),
          worker_([this] {
              for (;;) {
                  try {
                      context_->run();
                      return;
                  } catch (...) {
                  }
              }
          }) {}
    ~IoRuntime() {
        context_->finish();
        if (worker_.joinable()) worker_.join();
    }
    const std::shared_ptr<providers::AsioExecutionContext>& context() const {
        return context_;
    }
    template <typename Function>
    auto sync(Function&& function) -> std::invoke_result_t<Function> {
        using Value = std::invoke_result_t<Function>;
        auto task = std::make_shared<std::packaged_task<Value()>>(
            std::forward<Function>(function));
        auto future = task->get_future();
        boost::asio::post(context_->executor(), [task] { (*task)(); });
        if (future.wait_for(20s) != std::future_status::ready)
            throw std::runtime_error("sync timed out");
        return future.get();
    }

private:
    std::shared_ptr<providers::AsioExecutionContext> context_;
    std::thread worker_;
};

// One end of an in-memory packet stream. What one end writes, the other
// reads, and every completion comes from the executor.
class PipeEnd final : public StreamResponder,
                      public std::enable_shared_from_this<PipeEnd> {
public:
    explicit PipeEnd(std::shared_ptr<providers::AsioExecutionContext> context)
        : context_(std::move(context)) {}

    static std::pair<std::shared_ptr<PipeEnd>, std::shared_ptr<PipeEnd>> pair(
        const std::shared_ptr<providers::AsioExecutionContext>& context) {
        auto left = std::make_shared<PipeEnd>(context);
        auto right = std::make_shared<PipeEnd>(context);
        left->peer_ = right;
        right->peer_ = left;
        return {left, right};
    }

    engine::ExecutorAffinity executor_affinity() const noexcept override {
        return context_->affinity();
    }
    engine::ServiceKind service_kind() const noexcept override {
        return engine::ServiceKind::PacketChannel;
    }
    std::size_t max_write_size() const noexcept override { return 65536U; }
    bool terminated() const noexcept override { return closed_; }

    void async_read(CancellationToken, ReadCompletion completion) override {
        pending_ = std::move(completion);
        deliver();
    }
    void async_write(Buffer payload, CancellationToken,
                     WriteCompletion completion) override {
        const auto size = payload.size();
        const auto peer = peer_.lock();
        const bool ok = !closed_ && peer && !peer->closed_;
        if (ok) {
            ++writes;
            peer->inbox_.push_back(std::move(payload));
            peer->deliver();
        }
        boost::asio::post(
            context_->executor(),
            [completion = std::move(completion), ok, size] {
                completion(ok ? Status::success() : Status(StatusCode::Closed),
                           ok ? size : 0U);
            });
    }
    // The peer reads what is queued, then EndOfStream.
    Status shutdown_write() noexcept override {
        if (const auto peer = peer_.lock()) {
            peer->peer_shut_ = true;
            peer->deliver();
        }
        return Status::success();
    }
    void close(Status) noexcept override {
        if (closed_) return;
        closed_ = true;
        deliver();
        if (const auto peer = peer_.lock()) {
            peer->peer_closed_ = true;
            peer->deliver();
        }
    }

    std::size_t writes{0U};

private:
    void deliver() {
        if (!pending_) return;
        auto completion = std::move(pending_);
        pending_ = nullptr;
        if (!inbox_.empty() && !closed_) {
            auto buffer = std::move(inbox_.front());
            inbox_.pop_front();
            auto shared = std::make_shared<Buffer>(std::move(buffer));
            boost::asio::post(context_->executor(),
                              [completion = std::move(completion), shared] {
                                  completion(Result<ReceivedRecord>(
                                      ReceivedRecord(std::move(*shared), {})));
                              });
            return;
        }
        if (closed_ || peer_closed_ || peer_shut_) {
            const auto code = closed_ || peer_closed_ ? StatusCode::Closed
                                                      : StatusCode::EndOfStream;
            boost::asio::post(
                context_->executor(),
                [completion = std::move(completion), code] {
                    completion(Result<ReceivedRecord>(Status(code)));
                });
            return;
        }
        pending_ = std::move(completion);
    }

    std::shared_ptr<providers::AsioExecutionContext> context_;
    std::weak_ptr<PipeEnd> peer_;
    std::deque<Buffer> inbox_;
    ReadCompletion pending_;
    bool closed_{false};
    bool peer_closed_{false};
    bool peer_shut_{false};
};

// A destination that sends back what it receives, and ends after the
// circuit's stream shut down its side.
class EchoChannel final : public engine::ByteChannel {
public:
    explicit EchoChannel(
        std::shared_ptr<providers::AsioExecutionContext> context)
        : context_(std::move(context)) {}
    engine::ExecutorAffinity executor_affinity() const noexcept override {
        return context_->affinity();
    }
    std::size_t max_read_size() const noexcept override { return 65536U; }
    std::size_t max_write_size() const noexcept override { return 65536U; }
    void async_read(std::size_t max_bytes, CancellationToken,
                    ReadCompletion completion) override {
        pending_ = std::move(completion);
        pending_max_ = max_bytes;
        deliver();
    }
    void async_write(Buffer buffer, CancellationToken,
                     WriteCompletion completion) override {
        const auto size = buffer.size();
        for (const auto byte : buffer.bytes()) echo_.push_back(byte);
        deliver();
        boost::asio::post(context_->executor(),
                          [completion = std::move(completion), size] {
                              completion(Status::success(), size);
                          });
    }
    Status shutdown_write() noexcept override {
        shut_ = true;
        deliver();
        return Status::success();
    }
    void cancel() noexcept override {}
    void close() noexcept override {
        closed_ = true;
        deliver();
    }

private:
    void deliver() {
        if (!pending_) return;
        auto completion = std::move(pending_);
        pending_ = nullptr;
        if (!echo_.empty()) {
            const auto size = std::min(pending_max_, echo_.size());
            auto buffer = take(Buffer::allocate(size, 65536U));
            std::copy(echo_.begin(),
                      echo_.begin() + static_cast<std::ptrdiff_t>(size),
                      buffer.mutable_bytes().begin());
            echo_.erase(echo_.begin(),
                        echo_.begin() + static_cast<std::ptrdiff_t>(size));
            auto shared = std::make_shared<Buffer>(std::move(buffer));
            boost::asio::post(
                context_->executor(),
                [completion = std::move(completion), shared] {
                    completion(Result<Buffer>(std::move(*shared)));
                });
            return;
        }
        if (shut_ || closed_) {
            boost::asio::post(
                context_->executor(), [completion = std::move(completion)] {
                    // A TCP channel reports the peer's end as Closed.
                    completion(Result<Buffer>(Status(StatusCode::Closed)));
                });
            return;
        }
        pending_ = std::move(completion);
    }

    std::shared_ptr<providers::AsioExecutionContext> context_;
    std::deque<std::byte> echo_;
    ReadCompletion pending_;
    std::size_t pending_max_{0U};
    bool shut_{false};
    bool closed_{false};
};

inline std::string pem_of(EVP_PKEY* key) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new(BIO_s_mem()),
                                                  BIO_free);
    if (!bio || PEM_write_bio_PrivateKey(bio.get(), key, nullptr, nullptr, 0,
                                         nullptr, nullptr) != 1)
        throw std::runtime_error("PEM export failed");
    char* data = nullptr;
    const long size = BIO_get_mem_data(bio.get(), &data);
    return std::string(data, static_cast<std::size_t>(size));
}

inline std::shared_ptr<const keys::CompositePrivate> make_identity(
    const providers::circuit::CircuitCrypto& crypto) {
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> classical(
        EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"), EVP_PKEY_free);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> post_quantum(
        EVP_PKEY_Q_keygen(nullptr, nullptr, "ML-DSA-87"), EVP_PKEY_free);
    if (!classical || !post_quantum)
        throw std::runtime_error("key generation failed");
    return std::make_shared<const keys::CompositePrivate>(
        keys::composite_private_from_pem(
            crypto.key_context(),
            pem_of(classical.get()) + pem_of(post_quantum.get())));
}

inline engine::StreamOpenContext open_context(const std::string& identity) {
    return take(engine::StreamOpenContext::create(
        take(engine::StreamId::wire_application(1U)), "yume.circuit",
        engine::ServiceKind::PacketChannel,
        take(engine::PeerEvidence::create(engine::EndpointRole::Client,
                                          identity, "test", {std::byte{1}})),
        std::nullopt));
}

inline ytp1::Destination destination(std::uint16_t port) {
    ytp1::Destination result;
    result.transport = ytp1::TransportProtocol::Tcp;
    result.address_kind = ytp1::AddressKind::Ipv4;
    result.address = {192, 0, 2, 9};
    result.address_length = 4;
    result.port = port;
    return result;
}

}  // namespace yume::test
