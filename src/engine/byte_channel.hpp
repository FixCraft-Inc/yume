/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <functional>
#include <memory>

#include "engine/buffer.hpp"
#include "engine/cancellation.hpp"
#include "engine/transport_suite.hpp"
#include "engine/types.hpp"

namespace yume::engine {

class ByteChannel {
public:
    using ReadCompletion = std::function<void(Result<Buffer>)>;
    using WriteCompletion = std::function<void(Status, std::size_t)>;

    virtual ~ByteChannel() = default;

    virtual ExecutorAffinity executor_affinity() const noexcept = 0;
    virtual std::size_t max_read_size() const noexcept = 0;
    virtual std::size_t max_write_size() const noexcept = 0;

    // Implementations complete each accepted operation exactly once on the
    // declared executor affinity. Reads and writes preserve issue order.
    // Unknown callbacks are invoked without internal locks and exceptions are
    // contained at the channel boundary.
    virtual void async_read(std::size_t max_bytes,
                            CancellationToken cancellation,
                            ReadCompletion completion) = 0;
    virtual void async_write(Buffer buffer,
                             CancellationToken cancellation,
                             WriteCompletion completion) = 0;

    // Stops only the local write direction, ordered after every write already
    // accepted by the channel. Repeated calls are successful, and reads stay
    // valid until the peer independently closes its write direction or the
    // whole channel is closed. Providers that cannot preserve these semantics
    // must return a failure instead of approximating them with close().
    virtual Status shutdown_write() noexcept = 0;

    // cancel() settles pending operations as Cancelled without necessarily
    // closing the channel. close() is terminal and settles them as Closed.
    virtual void cancel() noexcept = 0;
    virtual void close() noexcept = 0;
};

class ByteChannelProvider {
public:
    using Completion =
        std::function<void(Result<std::unique_ptr<ByteChannel>>)>;

    virtual ~ByteChannelProvider() = default;
    virtual const ProviderDescriptor& descriptor() const noexcept = 0;
    virtual void async_create(EndpointRole role,
                              CancellationToken cancellation,
                              Completion completion) = 0;
};

}  // namespace yume::engine
