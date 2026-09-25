/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string_view>
#include <vector>

#include <boost/asio/ip/address.hpp>

#include "engine/status.hpp"
#include "providers/asio_execution_context.hpp"

namespace yume::providers {

struct SystemResolverOptions final {
    // Executable that serves the helper protocol when started with argv[0]
    // resolver_protocol::kHelperArgv0: the standalone yume-resolver or a YUME
    // program that dispatches to it. It must be absolute. A program named
    // /proc/self/exe re-executes the current image. Any other path must be
    // a regular file owned by root or the effective user and not writable by
    // group or others. Empty leaves hostname lookup unavailable, so requests
    // fail closed while numeric callers never need the helper.
    std::filesystem::path program;
    // Outstanding lookups, including cancelled ones the helper has not yet
    // answered. At most resolver_protocol::kMaxOutstanding.
    std::size_t max_outstanding{64U};
};

// System name resolution in a separate, killable process. getaddrinfo and its
// NSS modules cannot be interrupted, so an in-process lookup can hold final
// shutdown indefinitely. Here, cancellation settles at once and close() kills
// and reaps the helper. The helper uses the unchanged system resolver
// configuration and runs each lookup on its own thread, so one slow name
// does not delay the others. A cancelled lookup keeps its helper slot until
// answered. When every slot is taken and some are cancelled, the helper is
// replaced and the live lookups fail. It starts on the first lookup and again
// after it exits.
//
// resolve() and cancel() require the context. close() and destruction may
// cross threads, and close is delivered through reserved control dispatch.
// Close resolvers before the final drain of their context.
class SystemResolver final {
public:
    // Addresses in system preference order, or a failure status: NotFound for
    // a name without addresses, Closed after close(), FailedPrecondition when
    // the helper is not configured or not usable, ResourceExhausted under
    // saturation or allocation failure. Invoked once on the context unless
    // cancelled first. Exceptions from it are contained.
    using Completion =
        std::function<void(engine::Result<std::vector<boost::asio::ip::address>>)>;

    static engine::Result<std::shared_ptr<SystemResolver>> create(
        std::shared_ptr<AsioExecutionContext> context, SystemResolverOptions options);

    SystemResolver(const SystemResolver&) = delete;
    SystemResolver& operator=(const SystemResolver&) = delete;
    // Closes the resolver.
    ~SystemResolver() noexcept;

    // Starts one lookup of at most max_addresses results and returns its
    // nonzero identifier. A refusal is returned synchronously without
    // invoking completion.
    engine::Result<std::uint64_t> resolve(std::string_view host,
                                          std::size_t max_addresses,
                                          Completion completion);
    // Drops a lookup. Its completion is released without being invoked. Keep
    // the object the completion owns alive until this returns.
    void cancel(std::uint64_t lookup) noexcept;
    // Refuses later lookups, fails outstanding ones with Closed and ends the
    // helper process. Idempotent.
    void close() noexcept;

    engine::ExecutorAffinity executor_affinity() const noexcept;

private:
    struct State;
    explicit SystemResolver(std::shared_ptr<State> state) noexcept;
    std::shared_ptr<State> state_;
};

}  // namespace yume::providers
