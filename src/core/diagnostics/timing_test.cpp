/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/diagnostics/timing.hpp"

#include <cassert>
#include <chrono>

int main() {
    using namespace std::chrono_literals;
    using yume::diagnostics::IntervalTimer;
    using yume::diagnostics::SampleAccumulator;
    using yume::diagnostics::Stopwatch;

#if YUME_ENABLE_DEV_DIAGNOSTICS
    static_assert(yume::diagnostics::kTimingCompiledIn);
    yume::diagnostics::set_timing_enabled(false);
    assert(!yume::diagnostics::timing_enabled());
    yume::diagnostics::set_timing_enabled(true);
    assert(yume::diagnostics::timing_enabled());

    SampleAccumulator samples(true);
    Stopwatch stopwatch(true);
    samples.record(stopwatch);
    assert(!samples.take_if(2).has_value());
    const auto sample = samples.take_if(1);
    assert(sample.has_value());
    assert(sample->count == 1);

    IntervalTimer interval;
    const auto start = IntervalTimer::Clock::time_point{} + 1s;
    interval.start_if(true, start);
    const auto elapsed = interval.finish_us(start + 125us);
    assert(elapsed.has_value());
    assert(*elapsed == 125);
    assert(!interval.finish_us(start + 250us).has_value());
#else
    static_assert(!yume::diagnostics::kTimingCompiledIn);
    yume::diagnostics::set_timing_enabled(true);
    assert(!yume::diagnostics::timing_enabled());
    SampleAccumulator samples(true);
    Stopwatch stopwatch(true);
    samples.record(stopwatch);
    assert(!samples.take_if(1, true).has_value());
    IntervalTimer interval;
    interval.start_if(true, IntervalTimer::Clock::time_point{});
    assert(!interval.finish_us(IntervalTimer::Clock::time_point{} + 1s)
                .has_value());
#endif
    return 0;
}
