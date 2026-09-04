/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * libFuzzer entry for the client configuration loader shared by the GUI and
 * the C ABI. The key set is closed, so the contract is that any input either
 * yields a config or reports a typed failure -- never an escaping exception,
 * and never a crash.
 */

#include "facade/config/config_io.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <string>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    std::string err;
    std::string pointer;
    try {
        const auto parsed = yume::facade::config_io::parse_client_json(
            text, std::filesystem::path("/nonexistent-fuzz-base"), &err,
            &pointer);
        if (parsed.has_value()) {
            (void)yume::facade::config_io::validate(*parsed);
        }
    } catch (const std::exception&) {
        __builtin_trap();  // must report, never throw
    }
    return 0;
}
