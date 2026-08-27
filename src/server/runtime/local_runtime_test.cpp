/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/runtime/local_runtime.hpp"

#ifdef NDEBUG
#undef NDEBUG
#endif

#include <cassert>
#include <stdexcept>
#include <string>

#include <nlohmann/json.hpp>

int main() {
    using yume::server::LocalRuntime;

    LocalRuntime unavailable("", nullptr, {});
    const auto empty_operation = unavailable.handle_request({{"op", ""}});
    assert(!empty_operation.value("ok", true));
    assert(empty_operation.value("error", "").find("non-empty") !=
           std::string::npos);
    const auto unavailable_response = unavailable.handle_request(
        {{"op", "runtime.stop"}, {"args", nlohmann::json::object()}});
    assert(!unavailable_response.value("ok", true));
    assert(unavailable_response.value("error", "").find("unavailable") !=
           std::string::npos);

    LocalRuntime throwing("", nullptr, []() {
        throw std::runtime_error("intentional server stop failure");
    });
    const auto throwing_response = throwing.handle_request(
        {{"op", "runtime.stop"}, {"args", nlohmann::json::object()}});
    assert(!throwing_response.value("ok", true));
    assert(throwing_response.value("error", "").find(
               "intentional server stop failure") != std::string::npos);

    int callback_count = 0;
    LocalRuntime successful("", nullptr, [&callback_count]() {
        ++callback_count;
    });
    const auto rejected_arguments = successful.handle_request(
        {{"op", "runtime.stop"}, {"args", {{"force", true}}}});
    assert(!rejected_arguments.value("ok", true));
    assert(callback_count == 0);

    const auto successful_response = successful.handle_request(
        {{"op", "runtime.stop"}, {"args", nlohmann::json::object()}});
    assert(successful_response.value("ok", false));
    assert(callback_count == 1);
    return 0;
}
