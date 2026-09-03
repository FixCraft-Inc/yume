/*
 * Clean-prefix C++ consumer for the YUME C ABI v1 scaffold.
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <yume/yume.h>

#include <cstring>
#include <iostream>
#include <memory>
#include <string_view>

namespace {

constexpr std::string_view kConfigJson = R"json({
  "schema": 1,
  "role": "client",
  "endpoint": {"host": "origin.example.com", "port": 443},
  "suite": {
    "id": "ytp1-tls13-h2",
    "secure_channel": "tls13-native",
    "front_door": "h2-web",
    "carrier": "h2-duplex",
    "session": "ytp1-hybrid"
  },
  "credentials": {
    "composite_key": {"file": "credentials/client-composite.pem"},
    "access_psk": {"file": "credentials/client-access.psk"},
    "admission_key": {"file": "credentials/admission.key"},
    "server_trust": {"file": "credentials/server-trust.pem"},
    "server_identity": {"file": "credentials/server-composite.pub.pem"},
    "server_mlkem": {"file": "credentials/server-mlkem.pub"}
  },
  "cover": {"profile": "chrome151-node24-v1"},
  "services": [{
    "name": "echo",
    "kind": "stream",
    "max_concurrent_streams": 8
  }],
  "adapters": [],
  "limits": {
    "max_frame_bytes": 262144,
    "max_streams": 256,
    "max_queued_bytes": 4194304,
    "max_pending_opens": 64,
    "max_rekey_jobs": 4,
    "max_control_messages": 128,
    "max_packet_bytes": 65535,
    "max_packet_batch": 64
  }
})json";

bool check(bool condition, const char* message) {
    if (!condition) {
        std::cerr << "C++ installed-ABI consumer: " << message << '\n';
    }
    return condition;
}

using Runtime = std::unique_ptr<yume_runtime, decltype(&yume_runtime_destroy)>;
using Config = std::unique_ptr<yume_config, decltype(&yume_config_destroy)>;
using Endpoint = std::unique_ptr<yume_endpoint, decltype(&yume_endpoint_destroy)>;

}  // namespace

int main() {
    yume_build_info build{};
    build.struct_size = sizeof(build);
    build.abi_version = YUME_ABI_VERSION;
    if (!check(yume_get_build_info(&build, sizeof(build)) == YUME_STATUS_OK,
               "build metadata query failed") ||
        !check(yume_abi_version() == YUME_ABI_VERSION &&
                   build.abi_version == YUME_ABI_VERSION &&
                   build.struct_size == sizeof(build) &&
                   std::strcmp(build.crypto_backend, "unwired") == 0,
               "build metadata does not describe the unwired ABI v1 scaffold")) {
        return 2;
    }

    yume_compatibility compatibility{};
    compatibility.struct_size = sizeof(compatibility);
    compatibility.abi_version = YUME_ABI_VERSION;
    if (!check(yume_get_compatibility(&compatibility,
                                      sizeof(compatibility)) == YUME_STATUS_OK,
               "compatibility metadata query failed") ||
        !check(compatibility.abi_version == YUME_ABI_VERSION &&
                   compatibility.ytp_version == 1U &&
                   compatibility.config_schema == 1U &&
                   std::strcmp(compatibility.product_version,
                               build.product_version) == 0 &&
                   std::strcmp(compatibility.ytp_name, "YTP/1") == 0 &&
                   std::strcmp(compatibility.suite, "ytp1-tls13-h2") == 0 &&
                   std::strcmp(compatibility.crypto_backend,
                               build.crypto_backend) == 0 &&
                   compatibility.secure_channel_provider[0] != '\0' &&
                   compatibility.front_door_provider[0] != '\0' &&
                   compatibility.carrier_provider[0] != '\0' &&
                   std::strcmp(compatibility.session_component,
                               "ytp1-hybrid") == 0 &&
                   std::strcmp(compatibility.session_security_provider,
                               "unwired") == 0,
               "compatibility manifest is incomplete or inconsistent")) {
        return 3;
    }

    yume_runtime_options options{};
    options.struct_size = sizeof(options);
    options.abi_version = YUME_ABI_VERSION;
    options.executor_threads = 1U;
    options.max_pending_callbacks = 16U;
    yume_runtime* runtime_raw = nullptr;
    if (!check(yume_runtime_create(&options, &runtime_raw) == YUME_STATUS_OK &&
                   runtime_raw != nullptr,
               "runtime creation failed")) {
        return 4;
    }
    Runtime runtime(runtime_raw, &yume_runtime_destroy);

    yume_config* config_raw = nullptr;
    if (!check(yume_config_parse_json(runtime.get(), kConfigJson.data(),
                                      kConfigJson.size(), &config_raw) ==
                       YUME_STATUS_OK &&
                   config_raw != nullptr,
               "strict schema-1 client config parsing failed")) {
        return 5;
    }
    Config config(config_raw, &yume_config_destroy);
    if (!check(yume_config_role(config.get()) == YUME_ROLE_CLIENT,
               "parsed config did not retain the client role")) {
        return 6;
    }

    yume_endpoint* endpoint_raw = nullptr;
    if (!check(yume_endpoint_create(runtime.get(), config.get(),
                                    &endpoint_raw) == YUME_STATUS_OK &&
                   endpoint_raw != nullptr,
               "endpoint creation failed")) {
        return 7;
    }
    Endpoint endpoint(endpoint_raw, &yume_endpoint_destroy);

    if (!check(yume_endpoint_start(endpoint.get(), 0U) ==
                   YUME_STATUS_UNSUPPORTED,
               "unwired endpoint start did not fail closed as unsupported") ||
        !check(yume_endpoint_state(endpoint.get()) == YUME_ENDPOINT_FAILED,
               "unsupported endpoint start did not enter FAILED")) {
        return 8;
    }

    yume_diagnostic diagnostic{};
    diagnostic.struct_size = sizeof(diagnostic);
    diagnostic.abi_version = YUME_ABI_VERSION;
    if (!check(yume_handle_get_diagnostic(endpoint.get(), &diagnostic,
                                          sizeof(diagnostic)) ==
                   YUME_STATUS_OK &&
                   diagnostic.status == YUME_STATUS_UNSUPPORTED &&
                   diagnostic.message[0] != '\0' &&
                   std::strstr(diagnostic.message,
                               "provider is not linked") != nullptr,
               "endpoint diagnostic did not preserve typed provider failure")) {
        return 9;
    }

    if (!check(yume_endpoint_stop(endpoint.get(), 0U) == YUME_STATUS_OK &&
                   yume_endpoint_state(endpoint.get()) ==
                       YUME_ENDPOINT_STOPPED,
               "endpoint stop after failed start was not clean")) {
        return 10;
    }

    std::cout << "C++ installed-ABI consumer passed\n";
    return 0;
}
