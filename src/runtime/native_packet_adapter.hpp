/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <functional>
#include <memory>

#include "config/v1/config.hpp"
#include "engine/stream_handler.hpp"
#include "providers/asio_execution_context.hpp"

namespace yume::runtime {

// One named IP service over one device. A session receives an exclusive lease;
// closing it cancels packet I/O without closing the device. A replacement lease
// is refused until those I/O callbacks drain. Address policy applies in both
// directions before packets cross the device/transport boundary.
//
// All calls, including close/destruction, run on the supplied context. start's
// shared channel retains its device owner. close first drains the lease, then
// invokes on_closed while the device still exists, so that callback may remove
// managed addresses/routes/DNS. It finally closes the channel. Keep the context
// running through this drain.
class NativePacketAdapter final : public engine::StreamHandler {
public:
    using Closed = std::function<void()>;
    using Ended = std::function<void()>;

    static engine::Result<std::shared_ptr<NativePacketAdapter>> create(
        std::shared_ptr<providers::AsioExecutionContext> context,
        const config::v1::PacketAdapter& adapter);

    NativePacketAdapter(const NativePacketAdapter&) = delete;
    NativePacketAdapter& operator=(const NativePacketAdapter&) = delete;
    ~NativePacketAdapter() noexcept override;

    engine::Status start(std::shared_ptr<engine::PacketChannel> channel, Closed on_closed);
    engine::Status attach(std::shared_ptr<engine::StreamResponder> stream, Ended on_ended = {});
    void close() noexcept;

    const engine::ProviderDescriptor& descriptor() const noexcept override;
    engine::ServiceKind service_kind() const noexcept override;
    engine::Status authorize(const engine::StreamOpenContext& context) override;
    void async_open(engine::StreamOpenContext context,
                    std::shared_ptr<engine::StreamResponder> stream,
                    AcceptanceCompletion completion) override;
    void on_open(engine::StreamOpenContext context,
                 std::shared_ptr<engine::StreamResponder> stream) override;

private:
    struct State;
    explicit NativePacketAdapter(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::runtime
