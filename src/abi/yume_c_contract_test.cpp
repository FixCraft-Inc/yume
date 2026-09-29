/*
 * YUME C ABI v1 prefix, ownership, and runtime-affinity contract test.
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "yume/yume.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>

#if defined(YUME_TEST_ABI_ALLOCATIONS)
#include "test_support/allocation_failure.hpp"
#endif

namespace {

[[noreturn]] void fail(const char* message) {
    std::cerr << message << '\n';
    std::exit(1);
}

void require(bool condition, const char* message) {
    if (!condition) fail(message);
}

std::string read_file(const char* path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) fail("failed to open config fixture");
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

void ignored_event(const yume_event*, void* user_data) {
    auto* count = static_cast<std::uint32_t*>(user_data);
    if (count) ++*count;
}

struct ReentryContext {
    yume_runtime* runtime{nullptr};
    yume_endpoint* endpoint{nullptr};
    std::uint32_t event_count{0};
    yume_status reentry_status{YUME_STATUS_OK};
    yume_status diagnostic_status{YUME_STATUS_OK};
    bool throw_once{true};
};

void reentry_event(const yume_event* event, void* user_data) {
    auto* context = static_cast<ReentryContext*>(user_data);
    require(event != nullptr && context != nullptr,
            "callback received invalid borrowed arguments");
    require(event->struct_size == sizeof(*event) &&
                event->abi_version == YUME_ABI_VERSION,
            "callback event did not describe its complete layout");
    ++context->event_count;
    context->reentry_status = yume_endpoint_stop(context->endpoint, 0);

    yume_diagnostic diagnostic{};
    diagnostic.struct_size = sizeof(diagnostic);
    diagnostic.abi_version = YUME_ABI_VERSION;
    require(yume_handle_get_diagnostic(context->endpoint, &diagnostic,
                                       sizeof(diagnostic)) == YUME_STATUS_OK,
            "callback diagnostic re-entry was rejected");
    context->diagnostic_status = diagnostic.status;

    // Void destruction is explicitly ignored during a callback. These calls
    // must not invalidate either handle when control returns to the initiator.
    yume_endpoint_destroy(context->endpoint);
    yume_runtime_destroy(context->runtime);
    if (context->throw_once) {
        context->throw_once = false;
        throw std::runtime_error("application callback failure");
    }
}

yume_runtime* make_runtime(std::size_t options_size,
                           std::uint32_t* event_count = nullptr,
                           yume_event_callback callback = ignored_event) {
    yume_runtime_options options{};
    options.struct_size = options_size;
    options.abi_version = YUME_ABI_VERSION;
    options.event_callback = callback;
    options.callback_user_data = event_count;
    yume_runtime* runtime = nullptr;
    require(yume_runtime_create(&options, &runtime) == YUME_STATUS_OK,
            "runtime creation failed");
    require(runtime != nullptr, "runtime was not published");
    return runtime;
}

#if defined(YUME_TEST_ABI_ALLOCATIONS)
struct StartupAllocationContext {
    yume_endpoint* endpoint{nullptr};
    std::array<yume_event, 8U> events{};
    std::size_t event_count{0U};
    yume_status reentry_status{YUME_STATUS_OK};
    bool arm_next_start{true};
    bool sustained{false};
};

void startup_allocation_event(const yume_event* event, void* user_data) {
    auto* context = static_cast<StartupAllocationContext*>(user_data);
    if (!event || !context || context->event_count == context->events.size()) {
        std::abort();
    }
    context->events[context->event_count++] = *event;
    if (event->endpoint_state == YUME_ENDPOINT_STARTING &&
        context->arm_next_start) {
        context->arm_next_start = false;
        if (context->sustained) {
            yume::test::fail_allocations.store(true);
        } else {
            yume::test::arm_allocation_failure(1U);
        }
    } else if (event->endpoint_state == YUME_ENDPOINT_FAILED) {
        // This forbidden call writes its own diagnostic. Startup must restore
        // its final failure after callback delivery, including under pressure.
        context->reentry_status = yume_endpoint_stop(context->endpoint, 0U);
    }
}

void test_startup_allocation_settlement(std::string_view server_text) {
    for (const bool sustained : {false, true}) {
        StartupAllocationContext context;
        context.sustained = sustained;
        yume_runtime_options options{};
        options.struct_size = sizeof(options);
        options.abi_version = YUME_ABI_VERSION;
        options.event_callback = startup_allocation_event;
        options.callback_user_data = &context;
        yume_runtime* runtime = nullptr;
        require(yume_runtime_create(&options, &runtime) == YUME_STATUS_OK,
                "allocation test runtime creation failed");
        yume_config* config = nullptr;
        require(yume_config_parse_json(runtime, server_text.data(),
                                       server_text.size(),
                                       &config) == YUME_STATUS_OK,
                "allocation test config parsing failed");
        require(yume_endpoint_create(runtime, config, &context.endpoint) ==
                    YUME_STATUS_OK,
                "allocation test endpoint creation failed");
        yume_config_destroy(config);
        yume_service_descriptor service{};
        service.struct_size = sizeof(service);
        service.abi_version = YUME_ABI_VERSION;
        service.name = {"tcp", 3U};
        service.kind = YUME_SERVICE_BYTE_STREAM;
        require(yume_endpoint_register_service(context.endpoint, &service) ==
                    YUME_STATUS_OK,
                "allocation test service registration failed");

        // Arm only after STARTING was published. The registered service forces
        // startup to allocate before the fixture's adapters are refused.
        const yume_status status = yume_endpoint_start(context.endpoint, 0U);
        yume::test::fail_allocations.store(false);
        const bool fired = sustained || yume::test::disarm_allocation_failure();
        require(fired && status == YUME_STATUS_RESOURCE_EXHAUSTED,
                "startup allocation failure lost its typed status");
        require(
            yume_endpoint_state(context.endpoint) == YUME_ENDPOINT_FAILED &&
                context.event_count == 2U &&
                context.events[0].endpoint_state == YUME_ENDPOINT_STARTING &&
                context.events[0].status == YUME_STATUS_OK &&
                context.events[1].endpoint_state == YUME_ENDPOINT_FAILED &&
                context.events[1].status == status,
            "startup allocation failure did not settle its state and events");
        require(context.reentry_status == YUME_STATUS_INVALID_STATE,
                "allocation-failure event allowed lifecycle re-entry");
        yume_diagnostic diagnostic{};
        diagnostic.struct_size = sizeof(diagnostic);
        diagnostic.abi_version = YUME_ABI_VERSION;
        require(
            yume_handle_get_diagnostic(context.endpoint, &diagnostic,
                                       sizeof(diagnostic)) == YUME_STATUS_OK &&
                diagnostic.status == status && diagnostic.message[0] != '\0',
            "startup allocation failure lost its final diagnostic");
        require(yume_endpoint_start(context.endpoint, 0U) ==
                        YUME_STATUS_INVALID_STATE &&
                    context.event_count == 2U,
                "allocation-failed start bypassed the stop-before-retry rule");
        require(
            yume_endpoint_stop(context.endpoint, 0U) == YUME_STATUS_OK &&
                yume_endpoint_state(context.endpoint) ==
                    YUME_ENDPOINT_STOPPED &&
                context.event_count == 4U &&
                context.events[2].endpoint_state == YUME_ENDPOINT_STOPPING &&
                context.events[3].endpoint_state == YUME_ENDPOINT_STOPPED,
            "allocation-failed endpoint did not stop cleanly");
        // The unchanged fixture declares adapters: a fresh retry must reach
        // that expected refusal instead of retaining STARTING or a half-start.
        require(
            yume_endpoint_start(context.endpoint, 0U) ==
                    YUME_STATUS_UNSUPPORTED &&
                yume_endpoint_state(context.endpoint) == YUME_ENDPOINT_FAILED &&
                context.event_count == 6U &&
                context.events[4].endpoint_state == YUME_ENDPOINT_STARTING &&
                context.events[5].endpoint_state == YUME_ENDPOINT_FAILED &&
                context.events[5].status == YUME_STATUS_UNSUPPORTED,
            "allocation-failed endpoint could not retry after stop");
        yume_endpoint_destroy(context.endpoint);
        yume_runtime_destroy(runtime);
    }
}
#endif

}  // namespace

int main(int argc, char** argv) {
    if (argc != 3) {
        fail("usage: yume_c_contract_test CLIENT_CONFIG SERVER_CONFIG");
    }

    require(yume_abi_version() == YUME_ABI_VERSION,
            "runtime ABI version disagrees with the public header");
    require(yume_get_build_info(nullptr, sizeof(yume_build_info)) ==
                YUME_STATUS_INVALID_ARGUMENT,
            "null build-info output was accepted");

    yume_build_info build{};
    build.struct_size = sizeof(build);
    build.abi_version = YUME_ABI_VERSION;
    require(yume_get_build_info(&build, sizeof(build)) == YUME_STATUS_OK,
            "full build-info query failed");
    require(build.struct_size == sizeof(build),
            "build-info layout size was not reported");

    yume_compatibility compatibility{};
    compatibility.struct_size = sizeof(compatibility);
    compatibility.abi_version = YUME_ABI_VERSION;
    require(yume_get_compatibility(&compatibility, sizeof(compatibility)) ==
                YUME_STATUS_OK,
            "compatibility query failed");
    require(std::string_view(compatibility.crypto_backend) ==
                std::string_view(build.crypto_backend),
            "compatibility manifest omitted the cryptographic backend");
    require(std::string_view(compatibility.session_component) ==
                "ytp1-hybrid",
            "compatibility manifest omitted the logical session component");
    require(std::string_view(compatibility.session_security_provider) ==
                "openssl35.ytp1-security",
            "linked YTP/1 backend did not report its security provider");
    require(std::string_view(build.crypto_backend).starts_with("openssl-3."),
            "linked YTP/1 backend did not report its OpenSSL release");

    yume_build_info prefix{};
    auto* prefix_bytes = reinterpret_cast<unsigned char*>(&prefix);
    for (std::size_t index = 0; index < sizeof(prefix); ++index) {
        prefix_bytes[index] = 0xa5U;
    }
    constexpr std::size_t kOddPrefix = YUME_BUILD_INFO_MIN_SIZE + 1U;
    prefix.struct_size = kOddPrefix;
    prefix.abi_version = YUME_ABI_VERSION;
    require(yume_get_build_info(&prefix, kOddPrefix) ==
                YUME_STATUS_BUFFER_TOO_SMALL,
            "partial build-info query did not report truncation");
    require(prefix.struct_size == sizeof(prefix),
            "partial build-info query omitted the known layout size");
    require(prefix_bytes[YUME_BUILD_INFO_MIN_SIZE] == 0xa5U,
            "partial trailing field was overwritten");

    yume_status_info status_info{};
    status_info.struct_size = sizeof(status_info);
    status_info.abi_version = YUME_ABI_VERSION;
    require(yume_get_status_info(YUME_STATUS_CANCELLED, &status_info,
                                 sizeof(status_info)) == YUME_STATUS_OK &&
                status_info.code == YUME_STATUS_CANCELLED &&
                std::string_view(status_info.name) == "cancelled",
            "typed status metadata was incomplete");
    require(yume_get_status_info(-9999, &status_info, sizeof(status_info)) ==
                YUME_STATUS_INVALID_ARGUMENT,
            "unknown status code was accepted");

    yume_runtime_options invalid_runtime_options{};
    invalid_runtime_options.struct_size = YUME_RUNTIME_OPTIONS_MIN_SIZE - 1U;
    invalid_runtime_options.abi_version = YUME_ABI_VERSION;
    yume_runtime* rejected_runtime =
        reinterpret_cast<yume_runtime*>(static_cast<std::uintptr_t>(1));
    require(yume_runtime_create(&invalid_runtime_options, &rejected_runtime) ==
                YUME_STATUS_INVALID_ARGUMENT &&
                rejected_runtime == nullptr,
            "truncated runtime options published a handle");
    invalid_runtime_options.struct_size = sizeof(invalid_runtime_options);
    invalid_runtime_options.max_pending_callbacks = UINT32_MAX;
    require(yume_runtime_create(&invalid_runtime_options, &rejected_runtime) ==
                YUME_STATUS_RESOURCE_EXHAUSTED &&
                rejected_runtime == nullptr,
            "unbounded callback request was accepted");

    std::uint32_t omitted_event_count = 0;
    yume_runtime* first = make_runtime(YUME_RUNTIME_OPTIONS_MIN_SIZE,
                                       &omitted_event_count);
    yume_runtime* second = make_runtime(sizeof(yume_runtime_options));

    const std::string config_text = read_file(argv[1]);
    yume_config* config = nullptr;
    require(yume_config_parse_json(first, config_text.data(), config_text.size(),
                                   &config) == YUME_STATUS_OK,
            "config parse failed");
    require(config != nullptr, "config was not published");

    yume_config* rejected_config =
        reinterpret_cast<yume_config*>(static_cast<std::uintptr_t>(1));
    require(yume_config_parse_json(first, "{}", 2, &rejected_config) ==
                YUME_STATUS_PARSE_ERROR &&
                rejected_config == nullptr,
            "invalid schema-1 input published a config");
    const std::string oversized_config(1024U * 1024U + 1U, ' ');
    require(yume_config_parse_json(
                first, oversized_config.data(), oversized_config.size(),
                &rejected_config) == YUME_STATUS_RESOURCE_EXHAUSTED &&
                rejected_config == nullptr,
            "oversized JSON reached a DOM parser");
    const std::string nested_config =
        std::string(17U, '[') + std::string(17U, ']');
    require(yume_config_parse_json(
                first, nested_config.data(), nested_config.size(),
                &rejected_config) == YUME_STATUS_PARSE_ERROR &&
                rejected_config == nullptr,
            "excessively nested JSON reached a DOM parser");
    yume_diagnostic runtime_diagnostic{};
    runtime_diagnostic.struct_size = sizeof(runtime_diagnostic);
    runtime_diagnostic.abi_version = YUME_ABI_VERSION;
    require(yume_handle_get_diagnostic(first, &runtime_diagnostic,
                                       sizeof(runtime_diagnostic)) ==
                YUME_STATUS_OK &&
                runtime_diagnostic.status == YUME_STATUS_PARSE_ERROR &&
                runtime_diagnostic.message[0] != '\0',
            "config parse failure did not record a typed diagnostic");

    // The header check runs before the strict parser, so every document must
    // name its role and may not claim an unknown schema.
    require(yume_config_parse_json(first, "{\"schema\":1}", 12,
                                   &rejected_config) ==
                YUME_STATUS_PARSE_ERROR &&
                rejected_config == nullptr,
            "role-less document was accepted");
    runtime_diagnostic = {};
    runtime_diagnostic.struct_size = sizeof(runtime_diagnostic);
    runtime_diagnostic.abi_version = YUME_ABI_VERSION;
    require(yume_handle_get_diagnostic(first, &runtime_diagnostic,
                                       sizeof(runtime_diagnostic)) ==
                YUME_STATUS_OK &&
                std::string_view(runtime_diagnostic.json_pointer) == "/role",
            "role-less document did not report /role");

    const char kBadRole[] = "{\"schema\":1,\"role\":\"operator\"}";
    require(yume_config_parse_json(first, kBadRole, sizeof(kBadRole) - 1U,
                                   &rejected_config) ==
                YUME_STATUS_PARSE_ERROR &&
                rejected_config == nullptr,
            "unknown role was accepted");

    const char kBadSchema[] = "{\"schema\":2,\"role\":\"client\"}";
    require(yume_config_parse_json(first, kBadSchema, sizeof(kBadSchema) - 1U,
                                   &rejected_config) ==
                YUME_STATUS_PARSE_ERROR &&
                rejected_config == nullptr,
            "unknown schema was accepted");
    runtime_diagnostic = {};
    runtime_diagnostic.struct_size = sizeof(runtime_diagnostic);
    runtime_diagnostic.abi_version = YUME_ABI_VERSION;
    require(yume_handle_get_diagnostic(first, &runtime_diagnostic,
                                       sizeof(runtime_diagnostic)) ==
                YUME_STATUS_OK &&
                std::string_view(runtime_diagnostic.json_pointer) == "/schema",
            "unknown schema did not report /schema");

    // The document must pass the header check so the long unknown key reaches
    // the strict parser and produces a pointer long enough to be truncated.
    const std::string long_key(YUME_MAX_JSON_POINTER + 32U, 'a');
    const std::string long_pointer_config =
        "{\"schema\":1,\"role\":\"client\",\"" + long_key + "\":0}";
    require(yume_config_parse_json(first, long_pointer_config.data(),
                                   long_pointer_config.size(),
                                   &rejected_config) ==
                YUME_STATUS_PARSE_ERROR &&
                rejected_config == nullptr,
            "long invalid config key published a config");
    runtime_diagnostic = {};
    runtime_diagnostic.struct_size = sizeof(runtime_diagnostic);
    runtime_diagnostic.abi_version = YUME_ABI_VERSION;
    require(yume_handle_get_diagnostic(first, &runtime_diagnostic,
                                       sizeof(runtime_diagnostic)) ==
                YUME_STATUS_OK &&
                (runtime_diagnostic.flags &
                 YUME_DIAGNOSTIC_JSON_POINTER_TRUNCATED) != 0,
            "truncated JSON pointer was not marked in the diagnostic");

    yume_endpoint* endpoint = nullptr;
    require(yume_endpoint_create(second, config, &endpoint) ==
                YUME_STATUS_INVALID_ARGUMENT,
            "cross-runtime config was accepted");
    require(endpoint == nullptr, "cross-runtime endpoint was published");

    require(yume_endpoint_create(first, config, &endpoint) == YUME_STATUS_OK,
            "same-runtime endpoint creation failed");
    require(endpoint != nullptr, "endpoint was not published");
    yume_config_destroy(config);
    config = nullptr;

    runtime_diagnostic = {};
    runtime_diagnostic.struct_size = sizeof(runtime_diagnostic);
    runtime_diagnostic.abi_version = YUME_ABI_VERSION;
    require(yume_handle_get_diagnostic(first, &runtime_diagnostic,
                                       sizeof(runtime_diagnostic)) ==
                YUME_STATUS_OK &&
                runtime_diagnostic.status == YUME_STATUS_OK,
            "successful endpoint creation did not clear runtime diagnostics");

    yume_service_descriptor truncated_service{};
    truncated_service.struct_size = YUME_SERVICE_DESCRIPTOR_MIN_SIZE - 1U;
    truncated_service.abi_version = YUME_ABI_VERSION;
    truncated_service.kind = YUME_SERVICE_BYTE_STREAM;
    require(yume_endpoint_register_service(endpoint, &truncated_service) ==
                YUME_STATUS_INVALID_ARGUMENT,
            "truncated service descriptor was accepted");

    const char invalid_utf8[] = {static_cast<char>(0xc0),
                                 static_cast<char>(0xaf)};
    yume_service_descriptor service{};
    service.struct_size = sizeof(service);
    service.abi_version = YUME_ABI_VERSION;
    service.name = {invalid_utf8, sizeof(invalid_utf8)};
    service.kind = YUME_SERVICE_BYTE_STREAM;
    require(yume_endpoint_register_service(endpoint, &service) ==
                YUME_STATUS_INVALID_ARGUMENT,
            "invalid UTF-8 service name was accepted");

    constexpr char kNoncanonicalService[] = "Uppercase";
    service.name = {kNoncanonicalService,
                    sizeof(kNoncanonicalService) - 1U};
    require(yume_endpoint_register_service(endpoint, &service) ==
                YUME_STATUS_INVALID_ARGUMENT,
            "noncanonical ASCII service name was accepted");

    constexpr char kStreamService[] = "tcp";
    service.name = {kStreamService, sizeof(kStreamService) - 1U};
    // A client has no accept path. Registering a service there would change
    // nothing, so it is refused instead of succeeding as a no-op.
    require(yume_endpoint_register_service(endpoint, &service) ==
                YUME_STATUS_INVALID_ARGUMENT,
            "client service registration was accepted");

    {
        // A circuits section is refused at start: circuits may need the
        // user's consent to a shorter route, which the ABI cannot ask for.
        std::string circuits_text = config_text;
        const std::size_t adapters = circuits_text.find("\"adapters\"");
        const std::size_t open_bracket = circuits_text.find('[', adapters);
        std::size_t close_bracket = open_bracket;
        for (int depth = 0; close_bracket < circuits_text.size();
             ++close_bracket) {
            if (circuits_text[close_bracket] == '[') ++depth;
            if (circuits_text[close_bracket] == ']' && --depth == 0) break;
        }
        require(adapters != std::string::npos &&
                    open_bracket != std::string::npos &&
                    close_bracket < circuits_text.size(),
                "client config fixture omitted its adapter array");
        // Adapters are refused first, so the section alone is what start meets.
        circuits_text.replace(open_bracket, close_bracket - open_bracket + 1U,
                              "[]");
        circuits_text.insert(
            adapters,
            R"("circuits":{"hops":3,"operator_key":{"file":"circuits/operator.pub.pem"},)"
            R"("routes":{"file":"circuits/routes.json"},)"
            R"("routes_signature":{"file":"circuits/routes.sig"},)"
            R"("state":{"file":"circuits-state.json"}},)");
        yume_config* circuits_config = nullptr;
        require(yume_config_parse_json(first, circuits_text.data(),
                                       circuits_text.size(),
                                       &circuits_config) == YUME_STATUS_OK,
                "circuits config fixture was rejected");
        yume_endpoint* circuits_endpoint = nullptr;
        require(yume_endpoint_create(first, circuits_config,
                                     &circuits_endpoint) == YUME_STATUS_OK,
                "circuits endpoint creation failed");
        require(yume_endpoint_start(circuits_endpoint, 0U) ==
                    YUME_STATUS_UNSUPPORTED,
                "an embedded endpoint started with circuits");
        yume_diagnostic circuits_diagnostic{};
        circuits_diagnostic.struct_size = sizeof(circuits_diagnostic);
        circuits_diagnostic.abi_version = YUME_ABI_VERSION;
        require(yume_handle_get_diagnostic(
                    circuits_endpoint, &circuits_diagnostic,
                    sizeof(circuits_diagnostic)) == YUME_STATUS_OK &&
                    std::string(circuits_diagnostic.message).find("circuits") !=
                        std::string::npos,
                "the circuits refusal diagnostic did not name them");
        yume_endpoint_destroy(circuits_endpoint);
        yume_config_destroy(circuits_config);
    }

    const std::string server_text = read_file(argv[2]);
#if defined(YUME_TEST_ABI_ALLOCATIONS)
    test_startup_allocation_settlement(server_text);
#endif
    {
        // A cluster section is refused at start rather than accepting the
        // peers without keeping links to them.
        std::string cluster_text = server_text;
        const std::size_t server_adapters = cluster_text.find("\"adapters\"");
        const std::size_t open_bracket =
            cluster_text.find('[', server_adapters);
        std::size_t close_bracket = open_bracket;
        for (int depth = 0; close_bracket < cluster_text.size();
             ++close_bracket) {
            if (cluster_text[close_bracket] == '[') ++depth;
            if (cluster_text[close_bracket] == ']' && --depth == 0) break;
        }
        require(server_adapters != std::string::npos &&
                    open_bracket != std::string::npos &&
                    close_bracket < cluster_text.size(),
                "server config fixture omitted its adapter array");
        cluster_text.replace(open_bracket, close_bracket - open_bracket + 1U,
                             "[]");
        cluster_text.insert(
            server_adapters,
            R"("cluster":{"operator_key":{"file":"cluster/operator.pub.pem"},)"
            R"("list":{"file":"cluster/list.json"},"signature":{"file":"cluster/list.sig"},)"
            R"("peers":{"file":"cluster/peers.json"},)"
            R"("routes":{"file":"cluster/routes.json"},)"
            R"("routes_signature":{"file":"cluster/routes.sig"},)"
            R"("state":{"file":"cluster-state.json"}},)");
        yume_config* cluster_config = nullptr;
        require(yume_config_parse_json(first, cluster_text.data(),
                                       cluster_text.size(),
                                       &cluster_config) == YUME_STATUS_OK,
                "cluster config fixture was rejected");
        yume_endpoint* cluster_endpoint = nullptr;
        require(yume_endpoint_create(first, cluster_config,
                                     &cluster_endpoint) == YUME_STATUS_OK,
                "cluster endpoint creation failed");
        require(yume_endpoint_start(cluster_endpoint, 0U) ==
                    YUME_STATUS_UNSUPPORTED,
                "an embedded endpoint started as a cluster member");
        yume_diagnostic cluster_diagnostic{};
        cluster_diagnostic.struct_size = sizeof(cluster_diagnostic);
        cluster_diagnostic.abi_version = YUME_ABI_VERSION;
        require(yume_handle_get_diagnostic(
                    cluster_endpoint, &cluster_diagnostic,
                    sizeof(cluster_diagnostic)) == YUME_STATUS_OK &&
                    std::string(cluster_diagnostic.message).find("cluster") !=
                        std::string::npos,
                "the cluster refusal diagnostic did not name it");
        yume_endpoint_destroy(cluster_endpoint);
        yume_config_destroy(cluster_config);
    }
    yume_config* server_config = nullptr;
    require(yume_config_parse_json(first, server_text.data(),
                                   server_text.size(), &server_config) ==
                YUME_STATUS_OK &&
                yume_config_role(server_config) == YUME_ROLE_SERVER,
            "server config parse failed");
    yume_endpoint* server_endpoint = nullptr;
    require(yume_endpoint_create(first, server_config, &server_endpoint) ==
                YUME_STATUS_OK,
            "server endpoint creation failed");
    yume_config_destroy(server_config);
    require(yume_endpoint_register_service(server_endpoint, &service) ==
                YUME_STATUS_OK,
            "valid service registration was rejected");
    require(yume_endpoint_register_service(server_endpoint, &service) ==
                YUME_STATUS_INVALID_ARGUMENT,
            "duplicate service registration was accepted");
    service.kind = YUME_SERVICE_PACKET;
    require(yume_endpoint_register_service(server_endpoint, &service) ==
                YUME_STATUS_PERMISSION_DENIED,
            "service kind absent from immutable config was accepted");
    service.kind = YUME_SERVICE_BYTE_STREAM;

    std::string dual_kind_text = server_text;
    const std::size_t services_key = dual_kind_text.find("\"services\"");
    const std::size_t services_array = dual_kind_text.find('[', services_key);
    require(services_key != std::string::npos &&
                services_array != std::string::npos,
            "config fixture omitted its service array");
    dual_kind_text.insert(
        services_array + 1U,
        R"({"name":"tcp","kind":"packet","max_concurrent_streams":8},)");
    yume_config* dual_kind_config = nullptr;
    require(yume_config_parse_json(first, dual_kind_text.data(),
                                   dual_kind_text.size(),
                                   &dual_kind_config) == YUME_STATUS_OK,
            "dual-kind config fixture was rejected");
    yume_endpoint* dual_kind_endpoint = nullptr;
    require(yume_endpoint_create(first, dual_kind_config,
                                 &dual_kind_endpoint) == YUME_STATUS_OK,
            "dual-kind endpoint creation failed");
    require(yume_endpoint_register_service(dual_kind_endpoint, &service) ==
                YUME_STATUS_OK,
            "dual-kind stream service registration failed");
    service.kind = YUME_SERVICE_PACKET;
    require(yume_endpoint_register_service(dual_kind_endpoint, &service) ==
                YUME_STATUS_OK,
            "same-name packet service collided with the stream service");
    require(yume_endpoint_register_service(dual_kind_endpoint, &service) ==
                YUME_STATUS_INVALID_ARGUMENT,
            "duplicate service name and kind was accepted");
    service.kind = YUME_SERVICE_BYTE_STREAM;
    yume_endpoint_destroy(dual_kind_endpoint);
    yume_config_destroy(dual_kind_config);

    // Server start has no caller-bounded deadline. The refusal happens before
    // the endpoint leaves CREATED.
    require(yume_endpoint_start(server_endpoint, 1U) ==
                YUME_STATUS_UNSUPPORTED &&
                yume_endpoint_state(server_endpoint) == YUME_ENDPOINT_CREATED,
            "bounded server start was not refused before starting");
    require(yume_endpoint_start(server_endpoint, 0U) ==
                YUME_STATUS_UNSUPPORTED,
            "example server configuration started without its adapters");

    require(yume_endpoint_start(endpoint, 0) == YUME_STATUS_UNSUPPORTED,
            "schema-1 endpoint start did not fail with unsupported");
    require(yume_endpoint_state(endpoint) == YUME_ENDPOINT_FAILED,
            "unsupported endpoint start did not settle in failed state");
    yume_diagnostic diagnostic{};
    diagnostic.struct_size = sizeof(diagnostic);
    diagnostic.abi_version = YUME_ABI_VERSION;
    require(yume_handle_get_diagnostic(endpoint, &diagnostic,
                                       sizeof(diagnostic)) == YUME_STATUS_OK,
            "endpoint start diagnostic query failed");
    require(diagnostic.status == YUME_STATUS_UNSUPPORTED,
            "endpoint start diagnostic had the wrong typed status");
    // The example declares a SOCKS adapter. The embedding backend composes
    // named services only, and refuses instead of dropping the adapter.
    require(std::string(diagnostic.message).find("adapters") !=
                std::string::npos,
            "schema-1 start diagnostic omitted the uncomposed adapters");

    // Without adapters, a control socket is refused the same way.
    std::string control_text = config_text;
    const std::size_t adapters_key = control_text.find("\"adapters\"");
    const std::size_t adapters_open = control_text.find('[', adapters_key);
    const std::size_t adapters_close = control_text.find(']', adapters_open);
    require(adapters_key != std::string::npos &&
                adapters_open != std::string::npos &&
                adapters_close != std::string::npos,
            "config fixture omitted its adapter array");
    control_text.replace(adapters_open, adapters_close - adapters_open + 1U,
                         "[]");
    control_text.insert(
        adapters_key,
        R"("control":{"socket":"/run/user/1000/yume/control.sock"},)");
    yume_config* control_config = nullptr;
    require(
        yume_config_parse_json(first, control_text.data(), control_text.size(),
                               &control_config) == YUME_STATUS_OK,
        "control socket config fixture was rejected");
    yume_endpoint* control_endpoint = nullptr;
    require(yume_endpoint_create(first, control_config, &control_endpoint) ==
                YUME_STATUS_OK,
            "control socket endpoint creation failed");
    require(
        yume_endpoint_start(control_endpoint, 0U) == YUME_STATUS_UNSUPPORTED,
        "an embedded endpoint started without its control socket");
    yume_diagnostic control_diagnostic{};
    control_diagnostic.struct_size = sizeof(control_diagnostic);
    control_diagnostic.abi_version = YUME_ABI_VERSION;
    require(
        yume_handle_get_diagnostic(control_endpoint, &control_diagnostic,
                                   sizeof(control_diagnostic)) ==
                YUME_STATUS_OK &&
            std::string(control_diagnostic.message).find("control socket") !=
                std::string::npos,
        "the control socket refusal diagnostic did not name it");
    yume_endpoint_destroy(control_endpoint);
    yume_config_destroy(control_config);

    yume_open_options open{};
    open.struct_size = YUME_OPEN_OPTIONS_MIN_SIZE + 1U;
    open.abi_version = YUME_ABI_VERSION;
    open.service = {kStreamService, sizeof(kStreamService) - 1U};
    open.kind = YUME_SERVICE_BYTE_STREAM;
    yume_stream* stream =
        reinterpret_cast<yume_stream*>(static_cast<std::uintptr_t>(1));
    require(yume_endpoint_open_stream(endpoint, &open, 0, &stream) ==
                YUME_STATUS_INVALID_ARGUMENT &&
                stream == nullptr,
            "open options ending inside destination published a stream");

    constexpr char kInvalidIpv4[] = "999.0.2.1";
    open.struct_size = sizeof(open);
    open.destination.struct_size = sizeof(open.destination);
    open.destination.abi_version = YUME_ABI_VERSION;
    open.destination.kind = YUME_DESTINATION_IPV4;
    open.destination.host = {kInvalidIpv4, sizeof(kInvalidIpv4) - 1U};
    open.destination.port = 443;
    require(yume_endpoint_open_stream(endpoint, &open, 0, &stream) ==
                YUME_STATUS_INVALID_ARGUMENT &&
                stream == nullptr,
            "destination text inconsistent with its type was accepted");

    constexpr char kValidIpv4[] = "192.0.2.1";
    open.destination.host = {kValidIpv4, sizeof(kValidIpv4) - 1U};
    require(yume_endpoint_open_stream(endpoint, &open, 0, &stream) ==
                YUME_STATUS_INVALID_STATE &&
                stream == nullptr,
            "valid open options bypassed the failed endpoint state");

    constexpr char kUppercaseDns[] = "Origin.Example";
    open.destination.kind = YUME_DESTINATION_HOSTNAME;
    open.destination.host = {kUppercaseDns, sizeof(kUppercaseDns) - 1U};
    require(yume_endpoint_open_stream(endpoint, &open, 0, &stream) ==
                YUME_STATUS_INVALID_ARGUMENT &&
                stream == nullptr,
            "non-canonical uppercase DNS destination was accepted");

    yume_runtime_destroy(first);
    require(yume_endpoint_state(endpoint) == YUME_ENDPOINT_STOPPED &&
                yume_endpoint_state(server_endpoint) == YUME_ENDPOINT_STOPPED,
            "runtime destruction did not stop its live endpoints");
    yume_endpoint_destroy(server_endpoint);
    require(omitted_event_count == 0,
            "runtime read callback fields beyond its declared prefix");

    yume_endpoint_destroy(endpoint);
    yume_runtime_destroy(second);

    std::uint32_t delivered_event_count = 0;
    yume_runtime* callback_runtime = make_runtime(
        sizeof(yume_runtime_options), &delivered_event_count);
    yume_config* callback_config = nullptr;
    require(yume_config_parse_json(callback_runtime, config_text.data(),
                                   config_text.size(), &callback_config) ==
                YUME_STATUS_OK,
            "callback-runtime config parse failed");
    yume_endpoint* callback_endpoint = nullptr;
    require(yume_endpoint_create(callback_runtime, callback_config,
                                 &callback_endpoint) == YUME_STATUS_OK,
            "callback-runtime endpoint creation failed");
    yume_runtime_destroy(callback_runtime);
    require(delivered_event_count == 2,
            "runtime destruction did not synchronously deliver stop events");
    yume_endpoint_destroy(callback_endpoint);
    require(delivered_event_count == 2,
            "a callback ran after runtime destruction completed");
    yume_config_destroy(callback_config);

    ReentryContext reentry{};
    yume_runtime_options reentry_options{};
    reentry_options.struct_size = sizeof(reentry_options);
    reentry_options.abi_version = YUME_ABI_VERSION;
    reentry_options.max_pending_callbacks = 8;
    reentry_options.event_callback = reentry_event;
    reentry_options.callback_user_data = &reentry;
    require(yume_runtime_create(&reentry_options, &reentry.runtime) ==
                YUME_STATUS_OK,
            "re-entry test runtime creation failed");
    yume_config* reentry_config = nullptr;
    require(yume_config_parse_json(reentry.runtime, config_text.data(),
                                   config_text.size(), &reentry_config) ==
                YUME_STATUS_OK,
            "re-entry test config parse failed");
    require(yume_endpoint_create(reentry.runtime, reentry_config,
                                 &reentry.endpoint) == YUME_STATUS_OK,
            "re-entry test endpoint creation failed");
    yume_config_destroy(reentry_config);

    require(yume_endpoint_start(reentry.endpoint, 0) ==
                YUME_STATUS_UNSUPPORTED,
            "callback exception escaped or changed endpoint start status");
    require(reentry.event_count == 2 &&
                reentry.reentry_status == YUME_STATUS_INVALID_STATE &&
                reentry.diagnostic_status == YUME_STATUS_INVALID_STATE,
            "forbidden callback re-entry was not contained and diagnosed");
    require(yume_endpoint_state(reentry.endpoint) == YUME_ENDPOINT_FAILED,
            "destroy re-entry invalidated the endpoint handle");
    diagnostic = {};
    diagnostic.struct_size = sizeof(diagnostic);
    diagnostic.abi_version = YUME_ABI_VERSION;
    require(yume_handle_get_diagnostic(reentry.endpoint, &diagnostic,
                                       sizeof(diagnostic)) == YUME_STATUS_OK &&
                diagnostic.status == YUME_STATUS_UNSUPPORTED,
            "callback re-entry overwrote the initiating operation diagnostic");
    require(yume_endpoint_start(reentry.endpoint, 0) ==
                YUME_STATUS_INVALID_STATE &&
                yume_endpoint_state(reentry.endpoint) == YUME_ENDPOINT_FAILED &&
                reentry.event_count == 2,
            "restart from FAILED bypassed stop or emitted lifecycle events");
    require(yume_endpoint_stop(reentry.endpoint, 0) == YUME_STATUS_OK &&
                reentry.event_count == 4,
            "endpoint was unusable after callback exception containment");
    yume_endpoint_destroy(reentry.endpoint);
    yume_runtime_destroy(reentry.runtime);

    // Schema 1 is the only configuration. A document without "schema" is
    // refused by that member before the strict parser sees its other keys.
    {
        yume_runtime_options options{};
        options.struct_size = sizeof(options);
        options.abi_version = YUME_ABI_VERSION;
        options.config_base_dir = ".";
        yume_runtime* runtime = nullptr;
        require(yume_runtime_create(&options, &runtime) == YUME_STATUS_OK,
                "schema-less document runtime creation failed");

        const char kSchemaless[] =
            "{\"role\":\"client\",\"server\":\"127.0.0.1\",\"port\":1}";
        yume_config* schemaless = nullptr;
        require(yume_config_parse_json(runtime, kSchemaless,
                                       sizeof(kSchemaless) - 1U,
                                       &schemaless) ==
                    YUME_STATUS_PARSE_ERROR &&
                    schemaless == nullptr,
                "a document without a schema was accepted");
        yume_diagnostic schema_diagnostic{};
        schema_diagnostic.struct_size = sizeof(schema_diagnostic);
        schema_diagnostic.abi_version = YUME_ABI_VERSION;
        require(yume_handle_get_diagnostic(runtime, &schema_diagnostic,
                                           sizeof(schema_diagnostic)) ==
                    YUME_STATUS_OK &&
                    schema_diagnostic.status == YUME_STATUS_PARSE_ERROR &&
                    std::string_view(schema_diagnostic.json_pointer) ==
                        "/schema",
                "a document without a schema did not report /schema");
        yume_runtime_destroy(runtime);
    }

    std::cout << "C ABI v1 contract test passed\n";
    return 0;
}
