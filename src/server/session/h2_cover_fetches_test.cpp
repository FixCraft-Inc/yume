#include "server/session/h2_cover_fetches.hpp"

#include <cassert>
#include <cstdint>
#include <memory>
#include <vector>

namespace {

using yume::server::detail::H2CoverFetches;

void PerConnectionSaturationAndRecovery() {
    H2CoverFetches fetches;
    for (std::int32_t id = 1;
         id <= static_cast<std::int32_t>(H2CoverFetches::kPerConnectionLimit);
         ++id) {
        assert(fetches.admit(id));
    }
    assert(fetches.size() == H2CoverFetches::kPerConnectionLimit);
    assert(!fetches.admit(101));

    int cancellations = 0;
    assert(fetches.attach_cancel(1, [&]() { ++cancellations; }));
    assert(fetches.close_stream(1));
    assert(cancellations == 1);
    assert(!fetches.close_stream(1));
    assert(fetches.admit(101));
}

void CompletedFetchRetainsAdmissionUntilStreamClose() {
    H2CoverFetches fetches;
    for (std::int32_t id = 1;
         id <= static_cast<std::int32_t>(H2CoverFetches::kPerConnectionLimit);
         ++id) {
        assert(fetches.admit(id));
        assert(fetches.attach_cancel(id, []() {}));
        assert(fetches.complete_fetch(id));
    }
    assert(!fetches.admit(100));
    assert(fetches.close_stream(2));
    assert(fetches.admit(100));
}

void ConnectionCleanupIsIdempotentAndReentrantSafe() {
    H2CoverFetches fetches;
    int cancellations = 0;
    for (std::int32_t id = 1; id <= 3; ++id) {
        assert(fetches.admit(id));
        assert(fetches.attach_cancel(id, [&, id]() {
            ++cancellations;
            assert(!fetches.complete_fetch(id));
            assert(!fetches.close_stream(id));
        }));
    }
    fetches.cancel_all();
    assert(cancellations == 3);
    assert(fetches.size() == 0);
    fetches.cancel_all();
    assert(cancellations == 3);
    assert(fetches.admit(9));
}

void ProcessSaturationAndRecovery() {
    std::vector<std::unique_ptr<H2CoverFetches>> connections;
    connections.reserve(H2CoverFetches::kProcessLimit /
                        H2CoverFetches::kPerConnectionLimit);
    std::int32_t stream_id = 1;
    for (std::size_t admitted = 0;
         admitted < H2CoverFetches::kProcessLimit;) {
        auto connection = std::make_unique<H2CoverFetches>();
        for (std::size_t local = 0;
             local < H2CoverFetches::kPerConnectionLimit; ++local) {
            assert(connection->admit(stream_id++));
            ++admitted;
        }
        connections.push_back(std::move(connection));
    }

    H2CoverFetches saturated;
    assert(!saturated.admit(10001));
    connections.front()->cancel_all();
    assert(saturated.admit(10001));
}

void OutputByteSaturationAndRecovery() {
    H2CoverFetches fetches;
    constexpr std::size_t half =
        H2CoverFetches::kPerConnectionOutputLimit / 2U;
    assert(fetches.reserve_output_bytes(half));
    assert(fetches.reserve_output_bytes(half));
    assert(fetches.output_bytes() ==
           H2CoverFetches::kPerConnectionOutputLimit);
    assert(!fetches.reserve_output_bytes(1));
    assert(!fetches.release_output_bytes(
        H2CoverFetches::kPerConnectionOutputLimit + 1U));
    assert(fetches.output_bytes() ==
           H2CoverFetches::kPerConnectionOutputLimit);
    assert(fetches.release_output_bytes(half));
    assert(fetches.reserve_output_bytes(1));
    assert(fetches.release_output_bytes(half + 1U));
    assert(fetches.output_bytes() == 0U);
}

void ProcessOutputByteSaturationAndRecovery() {
    std::vector<std::unique_ptr<H2CoverFetches>> connections;
    const std::size_t connection_count =
        H2CoverFetches::kProcessOutputLimit /
        H2CoverFetches::kPerConnectionOutputLimit;
    connections.reserve(connection_count);
    for (std::size_t index = 0; index < connection_count; ++index) {
        auto connection = std::make_unique<H2CoverFetches>();
        assert(connection->reserve_output_bytes(
            H2CoverFetches::kPerConnectionOutputLimit));
        connections.push_back(std::move(connection));
    }

    H2CoverFetches saturated;
    assert(!saturated.reserve_output_bytes(1));
    assert(connections.front()->release_output_bytes(1));
    assert(saturated.reserve_output_bytes(1));
    assert(saturated.release_output_bytes(1));
    for (auto& connection : connections) {
        const auto retained = connection->output_bytes();
        assert(connection->release_output_bytes(retained));
    }
}

}  // namespace

int main() {
    // Repeat within one process so a leaked static/global permit cannot be
    // hidden by test-process teardown.
    for (int cycle = 0; cycle < 100; ++cycle) {
        PerConnectionSaturationAndRecovery();
        CompletedFetchRetainsAdmissionUntilStreamClose();
        ConnectionCleanupIsIdempotentAndReentrantSafe();
        ProcessSaturationAndRecovery();
        OutputByteSaturationAndRecovery();
        ProcessOutputByteSaturationAndRecovery();
    }
    return 0;
}
