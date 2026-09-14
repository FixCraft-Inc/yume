/*
 * Clean-prefix C consumer for the YUME C ABI v1 candidate.
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <yume/yume.h>

#include <stddef.h>
#include <stdio.h>
#include <string.h>

static const char kConfigJson[] =
    "{"
    "\"schema\":1,"
    "\"role\":\"client\","
    "\"endpoint\":{\"host\":\"origin.example.com\",\"port\":443},"
    "\"suite\":{"
      "\"id\":\"ytp1-tls13-h2\","
      "\"secure_channel\":\"tls13-native\","
      "\"front_door\":\"h2-web\","
      "\"carrier\":\"h2-duplex\","
      "\"session\":\"ytp1-hybrid\""
    "},"
    "\"credentials\":{"
      "\"composite_key\":{\"file\":\"credentials/client-composite.pem\"},"
      "\"access_psk\":{\"file\":\"credentials/client-access.psk\"},"
      "\"admission_key\":{\"file\":\"credentials/admission.key\"},"
      "\"server_trust\":{\"file\":\"credentials/server-trust.pem\"},"
      "\"server_identity\":{\"file\":\"credentials/server-composite.pub.pem\"},"
      "\"server_mlkem\":{\"file\":\"credentials/server-mlkem.pub\"}"
    "},"
    "\"cover\":{\"profile\":\"chrome151-node24-v1\"},"
    "\"services\":[{\"name\":\"echo\",\"kind\":\"stream\","
      "\"max_concurrent_streams\":8}],"
    "\"adapters\":[],"
    "\"limits\":{"
      "\"max_frame_bytes\":262144,"
      "\"max_streams\":256,"
      "\"max_queued_bytes\":4194304,"
      "\"max_pending_opens\":64,"
      "\"max_rekey_jobs\":4,"
      "\"max_control_messages\":128,"
      "\"max_packet_bytes\":65535,"
      "\"max_packet_batch\":64"
    "}"
    "}";

static int fail(const char* message, int code) {
    (void)fprintf(stderr, "C installed-ABI consumer: %s\n", message);
    return code;
}

int main(void) {
    yume_runtime* runtime = NULL;
    yume_config* config = NULL;
    yume_endpoint* endpoint = NULL;
    int endpoint_stopped = 0;
    int native_backend = 0;
    yume_status started = YUME_STATUS_OK;
    int result = 1;

    yume_build_info build = {0};
    build.struct_size = sizeof(build);
    build.abi_version = YUME_ABI_VERSION;
    if (yume_get_build_info(&build, sizeof(build)) != YUME_STATUS_OK) {
        result = fail("build metadata query failed", 2);
        goto cleanup;
    }
    if (yume_abi_version() != YUME_ABI_VERSION ||
        build.abi_version != YUME_ABI_VERSION ||
        build.struct_size != sizeof(build) ||
        build.crypto_backend[0] == '\0') {
        result = fail("build metadata is incomplete", 3);
        goto cleanup;
    }

    yume_compatibility compatibility = {0};
    compatibility.struct_size = sizeof(compatibility);
    compatibility.abi_version = YUME_ABI_VERSION;
    if (yume_get_compatibility(&compatibility, sizeof(compatibility)) !=
        YUME_STATUS_OK) {
        result = fail("compatibility metadata query failed", 4);
        goto cleanup;
    }
    if (compatibility.abi_version != YUME_ABI_VERSION ||
        compatibility.ytp_version != 1U ||
        compatibility.config_schema != 1U ||
        strcmp(compatibility.product_version, build.product_version) != 0 ||
        strcmp(compatibility.ytp_name, "YTP/1") != 0 ||
        strcmp(compatibility.suite, "ytp1-tls13-h2") != 0 ||
        strcmp(compatibility.crypto_backend, build.crypto_backend) != 0 ||
        compatibility.secure_channel_provider[0] == '\0' ||
        compatibility.front_door_provider[0] == '\0' ||
        compatibility.carrier_provider[0] == '\0' ||
        strcmp(compatibility.session_component, "ytp1-hybrid") != 0) {
        result = fail("compatibility manifest is incomplete or inconsistent", 5);
        goto cleanup;
    }
    /* The manifest names the composition this library links. An unwired
     * build reports both fields as unwired. A linked schema-1 backend names
     * its concrete provider and cryptographic backend. */
    native_backend = strcmp(compatibility.session_security_provider, "unwired") != 0;
    if (native_backend
            ? strcmp(compatibility.session_security_provider,
                     "openssl35.ytp1-security") != 0 ||
                  strcmp(build.crypto_backend, "unwired") == 0
            : strcmp(build.crypto_backend, "unwired") != 0) {
        result = fail("manifest does not describe one consistent YTP/1 composition", 5);
        goto cleanup;
    }

    yume_runtime_options options = {0};
    options.struct_size = sizeof(options);
    options.abi_version = YUME_ABI_VERSION;
    options.max_pending_callbacks = 16U;
    if (yume_runtime_create(&options, &runtime) != YUME_STATUS_OK ||
        runtime == NULL) {
        result = fail("runtime creation failed", 6);
        goto cleanup;
    }

    if (yume_config_parse_json(runtime, kConfigJson,
                               sizeof(kConfigJson) - 1U, &config) !=
            YUME_STATUS_OK ||
        config == NULL || yume_config_role(config) != YUME_ROLE_CLIENT) {
        result = fail("strict schema-1 client config parsing failed", 7);
        goto cleanup;
    }

    if (yume_endpoint_create(runtime, config, &endpoint) != YUME_STATUS_OK ||
        endpoint == NULL) {
        result = fail("endpoint creation failed", 8);
        goto cleanup;
    }
    /* The fixture names credential files that do not exist. An unwired build
     * refuses before reading them, and a linked backend refuses when it
     * cannot read them. Neither may start. */
    started = yume_endpoint_start(endpoint, 0U);
    if (started == YUME_STATUS_OK ||
        (!native_backend && started != YUME_STATUS_UNSUPPORTED) ||
        (native_backend && (started == YUME_STATUS_UNSUPPORTED ||
                            started == YUME_STATUS_INTERNAL_ERROR))) {
        result = fail("endpoint start did not fail closed", 9);
        goto cleanup;
    }
    if (yume_endpoint_state(endpoint) != YUME_ENDPOINT_FAILED) {
        result = fail("failed endpoint start did not enter FAILED", 10);
        goto cleanup;
    }

    yume_diagnostic diagnostic = {0};
    diagnostic.struct_size = sizeof(diagnostic);
    diagnostic.abi_version = YUME_ABI_VERSION;
    if (yume_handle_get_diagnostic(endpoint, &diagnostic,
                                   sizeof(diagnostic)) != YUME_STATUS_OK ||
        diagnostic.status != started ||
        diagnostic.message[0] == '\0' ||
        (!native_backend &&
         strstr(diagnostic.message, "provider is not linked") == NULL)) {
        result = fail("endpoint diagnostic did not preserve the typed start failure", 11);
        goto cleanup;
    }

    if (yume_endpoint_stop(endpoint, 0U) != YUME_STATUS_OK ||
        yume_endpoint_state(endpoint) != YUME_ENDPOINT_STOPPED) {
        result = fail("endpoint stop after failed start was not clean", 12);
        goto cleanup;
    }
    endpoint_stopped = 1;
    result = 0;

cleanup:
    if (endpoint != NULL) {
        if (!endpoint_stopped) {
            (void)yume_endpoint_stop(endpoint, 0U);
        }
        yume_endpoint_destroy(endpoint);
    }
    if (config != NULL) {
        yume_config_destroy(config);
    }
    if (runtime != NULL) {
        yume_runtime_destroy(runtime);
    }

    if (result == 0) {
        (void)puts("C installed-ABI consumer passed");
    }
    return result;
}
