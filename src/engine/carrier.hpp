/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <utility>

#include "engine/secure_channel.hpp"

namespace yume::engine {

// Single ownership of outer carrier receive credit. Destruction and explicit
// release are idempotent and callback exceptions are contained.
class CarrierCredit final {
public:
    using ReleaseHandler = std::function<void(std::size_t)>;

    CarrierCredit() = default;
    CarrierCredit(std::size_t bytes, ReleaseHandler release) noexcept;
    CarrierCredit(const CarrierCredit&) = delete;
    CarrierCredit& operator=(const CarrierCredit&) = delete;
    CarrierCredit(CarrierCredit&& other) noexcept;
    CarrierCredit& operator=(CarrierCredit&& other) noexcept;
    ~CarrierCredit() noexcept;

    void release_now() noexcept;
    std::size_t size() const noexcept { return bytes_; }
    explicit operator bool() const noexcept { return bytes_ != 0U; }

private:
    std::size_t bytes_{0U};
    ReleaseHandler release_;
};

class ReceivedRecord final {
public:
    ReceivedRecord(Buffer payload, CarrierCredit credit) noexcept
        : payload_(std::move(payload)), credit_(std::move(credit)) {}

    ReceivedRecord(const ReceivedRecord&) = delete;
    ReceivedRecord& operator=(const ReceivedRecord&) = delete;
    ReceivedRecord(ReceivedRecord&&) noexcept = default;
    ReceivedRecord& operator=(ReceivedRecord&&) noexcept = default;

    Buffer& payload() noexcept { return payload_; }
    const Buffer& payload() const noexcept { return payload_; }
    CarrierCredit take_credit() noexcept { return std::move(credit_); }

private:
    Buffer payload_;
    CarrierCredit credit_;
};

class Carrier {
public:
    using ReceiveCompletion = std::function<void(Result<ReceivedRecord>)>;
    using SendCompletion = std::function<void(Status, std::size_t)>;

    virtual ~Carrier() = default;
    // Immutable provenance of the concrete instance. A carrier handed to the
    // session directly must still match the exact frozen provider graph.
    virtual const ProviderDescriptor& descriptor() const noexcept = 0;
    virtual ExecutorAffinity executor_affinity() const noexcept = 0;
    virtual std::size_t max_record_size() const noexcept = 0;
    virtual SecureChannel& secure_channel() noexcept = 0;
    virtual const SecureChannel& secure_channel() const noexcept = 0;

    virtual void async_receive(CancellationToken cancellation,
                               ReceiveCompletion completion) = 0;
    virtual void async_send(Buffer record,
                            CancellationToken cancellation,
                            SendCompletion completion) = 0;
    virtual void cancel() noexcept = 0;
    virtual void close() noexcept = 0;
};

class CarrierProvider {
public:
    using Completion = std::function<void(Result<std::unique_ptr<Carrier>>)>;

    virtual ~CarrierProvider() = default;
    virtual const ProviderDescriptor& descriptor() const noexcept = 0;
    virtual void async_create(std::unique_ptr<SecureChannel> channel,
                              EndpointRole local_role,
                              CancellationToken cancellation,
                              Completion completion) = 0;
};

}  // namespace yume::engine
