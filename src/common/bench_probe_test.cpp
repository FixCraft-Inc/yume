/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "common/bench_probe.hpp"

#include <cassert>
#include <type_traits>

#if YUME_ENABLE_DEV_DIAGNOSTICS
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>
#include <unistd.h>
#endif

// The test must see the build's diagnostics option, or its checks of the
// compiled-out shape would pass in a build that compiled the probes in.
static_assert(yume::bench_probe::kEnabled ==
              static_cast<bool>(YUME_TEST_EXPECT_DEV_DIAGNOSTICS));

int main() {
    namespace probe = yume::bench_probe;
#if YUME_ENABLE_DEV_DIAGNOSTICS
    static_assert(probe::kEnabled);
    const char* prefix = std::getenv("YUME_BENCH_PROBE_FILE");
    probe::count(probe::Count::RotationBytes);
    probe::count(probe::Count::DeferredBytes, 4096);
    probe::amount(probe::Amount::EpochBytesAtStart, 524288);
    {
        [[maybe_unused]] const probe::ScopedDuration scope(
            probe::Duration::ProviderBeginRekey);
    }
    probe::Stamp stamp;
    stamp.finish(probe::Duration::DeferredStall);
    stamp.set();
    stamp.finish(probe::Duration::RotationRoundTrip);
    if (prefix != nullptr) {
        // The writer appends a snapshot each second.
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        const std::string path =
            std::string(prefix) + "." + std::to_string(::getpid());
        std::ifstream in(path);
        const std::string text((std::istreambuf_iterator<char>(in)),
                               std::istreambuf_iterator<char>());
        assert(text.find("\"rotation_bytes\":1") != std::string::npos);
        assert(text.find("\"deferred_bytes\":4096") != std::string::npos);
        assert(text.find("\"provider_begin_rekey\":{\"count\":1") !=
               std::string::npos);
        assert(text.find("\"rotation_round_trip\":{\"count\":1") !=
               std::string::npos);
        assert(text.find("\"deferred_stall\":{\"count\":0") !=
               std::string::npos);
        assert(
            text.find("\"epoch_bytes_at_start\":{\"count\":1,\"sum\":524288") !=
            std::string::npos);
        std::remove(path.c_str());
    }
#else
    // Without the switch every probe is an empty type and an empty call.
    static_assert(!probe::kEnabled);
    static_assert(std::is_empty_v<probe::Stamp>);
    static_assert(std::is_empty_v<probe::ScopedDuration>);
    probe::count(probe::Count::RotationBytes);
    probe::duration(probe::Duration::RotationRoundTrip, 1);
    probe::amount(probe::Amount::EpochBytesAtStart, 1);
#endif
    return 0;
}
