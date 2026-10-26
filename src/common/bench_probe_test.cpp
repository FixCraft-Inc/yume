/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "common/bench_probe.hpp"

#include <cassert>
#include <type_traits>

#if YUME_ENABLE_DEV_DIAGNOSTICS
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <sys/resource.h>
#include <unistd.h>
#endif

// The test must see the build's diagnostics option, or its checks of the
// compiled-out shape would pass in a build that compiled the probes in.
static_assert(yume::bench_probe::kEnabled ==
              static_cast<bool>(YUME_TEST_EXPECT_DEV_DIAGNOSTICS));

#if YUME_ENABLE_DEV_DIAGNOSTICS
// Runs this program again under a process limit below this user's thread
// count, so the recorder's writer thread is refused before main.
int run_with_threads_refused(char* program) {
    rlimit limit{};
    if (::getrlimit(RLIMIT_NPROC, &limit) != 0) return 1;
    std::string original_limit = std::to_string(limit.rlim_cur);
    limit.rlim_cur = 1;
    if (::setrlimit(RLIMIT_NPROC, &limit) != 0) return 1;
    char child_flag[] = "--writer-refused-child";
    char* child[] = {program, child_flag, original_limit.data(), nullptr};
    ::execv("/proc/self/exe", child);
    std::perror("execv");
    return 1;
}

// The process must still reach main, with the probes off.
int writer_refused(std::string_view original_limit) {
    namespace probe = yume::bench_probe;
    bool refused = false;
    try {
        std::thread([] {}).join();
    } catch (const std::system_error&) {
        refused = true;
    }
    // Thread refusal is established. LeakSanitizer needs its own inspection
    // process at exit, so restore the inherited limit before that phase.
    rlimit limit{};
    if (::getrlimit(RLIMIT_NPROC, &limit) != 0) return 1;
    const auto parsed = std::from_chars(
        original_limit.data(), original_limit.data() + original_limit.size(),
        limit.rlim_cur);
    if (parsed.ec != std::errc{} ||
        parsed.ptr != original_limit.data() + original_limit.size() ||
        ::setrlimit(RLIMIT_NPROC, &limit) != 0) {
        return 1;
    }
    if (!refused) {
        std::puts("skipped: the process limit does not refuse threads");
        return 77;
    }
    assert(!probe::detail::recorder().active());
    probe::count(probe::Count::RotationBytes);
    probe::duration(probe::Duration::RotationRoundTrip, 1);
    probe::amount(probe::Amount::EpochBytesAtStart, 1);
    // The recorder opened its file before the writer failed.
    if (const char* prefix = std::getenv("YUME_BENCH_PROBE_FILE")) {
        std::remove(
            (std::string(prefix) + "." + std::to_string(::getpid())).c_str());
    }
    return 0;
}
#endif

int main([[maybe_unused]] int argc, [[maybe_unused]] char** argv) {
    namespace probe = yume::bench_probe;
#if YUME_ENABLE_DEV_DIAGNOSTICS
    if (argc == 2 && std::string_view(argv[1]) == "--writer-refused") {
        return run_with_threads_refused(argv[0]);
    }
    if (argc == 3 && std::string_view(argv[1]) == "--writer-refused-child") {
        return writer_refused(argv[2]);
    }
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
