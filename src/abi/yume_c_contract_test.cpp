/*
 * YUME C ABI v1 prefix, ownership, and runtime-affinity contract test.
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "yume/yume.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <string_view>

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

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2) fail("usage: yume_c_contract_test CONFIG");

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
                "unwired",
            "unwired YTP/1 backend claimed a concrete security provider");

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

    // Dialect selection happens before either parser runs, so every document
    // must name its role and may not claim an unknown schema.
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

    // The document must classify as schema 1 so the long unknown key reaches
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
    require(yume_endpoint_register_service(endpoint, &service) ==
                YUME_STATUS_OK,
            "valid service registration was rejected");
    require(yume_endpoint_register_service(endpoint, &service) ==
                YUME_STATUS_INVALID_ARGUMENT,
            "duplicate service registration was accepted");
    service.kind = YUME_SERVICE_PACKET;
    require(yume_endpoint_register_service(endpoint, &service) ==
                YUME_STATUS_PERMISSION_DENIED,
            "service kind absent from immutable config was accepted");
    service.kind = YUME_SERVICE_BYTE_STREAM;

    std::string dual_kind_text = config_text;
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

    require(yume_endpoint_start(endpoint, 0) == YUME_STATUS_UNSUPPORTED,
            "unwired endpoint provider did not fail with unsupported");
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
    require(std::string(diagnostic.message).find("provider is not linked") !=
                std::string::npos,
            "endpoint start diagnostic omitted the unwired provider boundary");

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
            "valid open options bypassed the unwired endpoint state");

    constexpr char kUppercaseDns[] = "Origin.Example";
    open.destination.kind = YUME_DESTINATION_HOSTNAME;
    open.destination.host = {kUppercaseDns, sizeof(kUppercaseDns) - 1U};
    require(yume_endpoint_open_stream(endpoint, &open, 0, &stream) ==
                YUME_STATUS_INVALID_ARGUMENT &&
                stream == nullptr,
            "non-canonical uppercase DNS destination was accepted");

    yume_runtime_destroy(first);
    require(yume_endpoint_state(endpoint) == YUME_ENDPOINT_STOPPED,
            "runtime destruction did not stop its live endpoint");
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
    require(yume_endpoint_stop(reentry.endpoint, 0) == YUME_STATUS_OK &&
                reentry.event_count == 4,
            "endpoint was unusable after callback exception containment");
    yume_endpoint_destroy(reentry.endpoint);
    yume_runtime_destroy(reentry.runtime);

    // The transport-v2 dialect must reach a real runtime, not a stub. This
    // config is valid enough to parse and start, and deliberately incomplete
    // enough that the transport itself rejects it, so a typed transport
    // failure here is the proof the backend is genuinely wired.
    {
        yume_runtime_options options{};
        options.struct_size = sizeof(options);
        options.abi_version = YUME_ABI_VERSION;
        options.config_base_dir = ".";
        yume_runtime* runtime = nullptr;
        require(yume_runtime_create(&options, &runtime) == YUME_STATUS_OK,
                "transport dialect runtime creation failed");

        const char kClient[] =
            "{\"role\":\"client\",\"server\":\"127.0.0.1\",\"port\":1}";
        yume_config* transport_config = nullptr;
        const yume_status parsed = yume_config_parse_json(
            runtime, kClient, sizeof(kClient) - 1U, &transport_config);

#if defined(YUME_ABI_TRANSPORT_V2) && YUME_ABI_TRANSPORT_V2
        require(parsed == YUME_STATUS_OK && transport_config != nullptr,
                "transport-v2 dialect was not accepted");
        require(yume_config_role(transport_config) == YUME_ROLE_CLIENT,
                "transport-v2 client config reported the wrong role");

        yume_endpoint* transport_endpoint = nullptr;
        require(yume_endpoint_create(runtime, transport_config,
                                     &transport_endpoint) == YUME_STATUS_OK,
                "transport-v2 endpoint creation failed");
        require(yume_endpoint_state(transport_endpoint) ==
                    YUME_ENDPOINT_CREATED,
                "transport-v2 endpoint did not start in CREATED");

        // A transport-v2 service is registered with the running runtime, so
        // registering before start must be refused rather than queued.
        yume_service_descriptor service{};
        service.struct_size = sizeof(service);
        service.abi_version = YUME_ABI_VERSION;
        service.name = yume_string_view{"tcp", 3};
        service.kind = YUME_SERVICE_BYTE_STREAM;
        require(yume_endpoint_register_service(transport_endpoint, &service) ==
                    YUME_STATUS_INVALID_STATE,
                "service registration before start was not refused");

        // Packet channels are not implemented on either backend yet, and a
        // stream open before start must fail on state rather than on kind.
        yume_open_options packet_open{};
        packet_open.struct_size = YUME_OPEN_OPTIONS_MIN_SIZE;
        packet_open.abi_version = YUME_ABI_VERSION;
        packet_open.service = yume_string_view{"tcp", 3};
        packet_open.kind = YUME_SERVICE_PACKET;
        yume_packet* refused_packet = nullptr;
        require(yume_endpoint_open_packet(transport_endpoint, &packet_open, 0,
                                          &refused_packet) !=
                    YUME_STATUS_OK &&
                refused_packet == nullptr,
                "packet open unexpectedly succeeded");

        const yume_status started = yume_endpoint_start(transport_endpoint, 5000);
        require(started != YUME_STATUS_UNSUPPORTED,
                "transport-v2 start still reports an unlinked provider");
        require(started != YUME_STATUS_OK,
                "an incomplete transport config started successfully");
        yume_diagnostic transport_diagnostic{};
        transport_diagnostic.struct_size = sizeof(transport_diagnostic);
        transport_diagnostic.abi_version = YUME_ABI_VERSION;
        require(yume_handle_get_diagnostic(transport_endpoint,
                                           &transport_diagnostic,
                                           sizeof(transport_diagnostic)) ==
                    YUME_STATUS_OK &&
                    transport_diagnostic.message[0] != '\0',
                "failed transport start recorded no diagnostic");
        require(yume_endpoint_state(transport_endpoint) == YUME_ENDPOINT_FAILED,
                "failed transport start did not reach FAILED");
        require(yume_endpoint_stop(transport_endpoint, 0) == YUME_STATUS_OK,
                "transport endpoint stop failed");
        require(yume_endpoint_state(transport_endpoint) ==
                    YUME_ENDPOINT_STOPPED,
                "stopped transport endpoint did not reach STOPPED");
        yume_endpoint_destroy(transport_endpoint);
        yume_config_destroy(transport_config);
#else
        require(parsed == YUME_STATUS_UNSUPPORTED &&
                    transport_config == nullptr,
                "a runtime-free ABI accepted the transport-v2 dialect");
#endif
        yume_runtime_destroy(runtime);
    }

    std::cout << "C ABI v1 contract test passed\n";
    return 0;
}
