/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_cli.hpp"

#include <csignal>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

#include <boost/asio/basic_signal_set.hpp>
#include <boost/asio/post.hpp>

#include "config/v1/config.hpp"
#include "core/runtime/bounded_file.hpp"
#include "core/version.hpp"
#include "providers/asio_execution_context.hpp"
#include "providers/ytp1_security_provider.hpp"
#include "runtime/native_client_runtime.hpp"
#include "runtime/native_credentials.hpp"
#include "runtime/native_egress_policy.hpp"
#include "runtime/native_server_runtime.hpp"

namespace yume::runtime {
namespace {
using engine::Status;
using engine::StatusCode;
using SignalSet = boost::asio::basic_signal_set<providers::AsioExecutionContext::Executor>;

constexpr int kExitStopped = 0;
constexpr int kExitFailure = 1;
constexpr int kExitUsage = 2;

struct Arguments final {
    std::optional<std::filesystem::path> config;
    bool validate{false};
    bool version{false};
    bool help{false};
};

std::string_view program(NativeCliRole role) noexcept {
    return role == NativeCliRole::Server ? "yumed-ytp1" : "yume-ytp1";
}

void say(NativeCliRole role, std::string_view text) noexcept {
    const auto name = program(role);
    std::fprintf(stderr, "%.*s: %.*s\n", static_cast<int>(name.size()), name.data(),
                 static_cast<int>(text.size()), text.data());
    std::fflush(stderr);
}

std::string describe(std::string_view prefix, const Status& status) {
    std::string text(prefix);
    text += ": ";
    text += status.message().empty() ? "status " + std::to_string(static_cast<int>(status.code()))
                                     : status.message();
    return text;
}

int exit_for(const Status& status) noexcept {
    switch (status.code()) {
    case StatusCode::InvalidArgument:
    case StatusCode::FailedPrecondition:
    case StatusCode::NotFound:
    case StatusCode::PermissionDenied:
        return kExitUsage;
    default:
        return kExitFailure;
    }
}

void usage(NativeCliRole role, std::FILE* out) noexcept {
    const auto name = program(role);
    std::fprintf(out,
        "Usage: %.*s --config PATH [--validate]\n"
        "       %.*s --version\n"
        "Network and security policy come only from the schema-1 configuration.\n"
        "This development runtime is not qualified for production use.\n",
        static_cast<int>(name.size()), name.data(), static_cast<int>(name.size()), name.data());
}

std::optional<Arguments> parse(int argc, char** argv, std::string& error) {
    Arguments arguments;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--config") {
            if (index + 1 >= argc || arguments.config) {
                error = "--config needs exactly one path";
                return std::nullopt;
            }
            arguments.config = std::filesystem::path(argv[++index]);
        } else if (argument == "--validate") {
            arguments.validate = true;
        } else if (argument == "--version") {
            arguments.version = true;
        } else if (argument == "--help" || argument == "-h") {
            arguments.help = true;
        } else {
            error = "unknown argument: " + std::string(argument);
            return std::nullopt;
        }
    }
    if (!arguments.help && !arguments.version && !arguments.config) {
        error = "--config is required";
        return std::nullopt;
    }
    return arguments;
}

void print_version(NativeCliRole role) {
    const auto name = program(role);
    const auto backend = providers::ytp1_openssl_crypto_backend();
    std::printf("%.*s %s\n", static_cast<int>(name.size()), name.data(), kVersion);
    std::printf("transport %.*s, config schema %u, suite %.*s\n",
                static_cast<int>(kYtpVersion.size()), kYtpVersion.data(), kConfigSchema,
                static_cast<int>(kTransportSuite.size()), kTransportSuite.data());
    std::printf("session security %.*s, crypto backend %.*s\n",
                static_cast<int>(providers::kYtp1OpenSslSecurityProviderId.size()),
                providers::kYtp1OpenSslSecurityProviderId.data(),
                static_cast<int>(backend.size()), backend.data());
    std::printf("evidence profile %.*s\n", static_cast<int>(kEvidenceProfile.size()),
                kEvidenceProfile.data());
    std::printf("development runtime, not qualified for production use\n");
}

std::optional<config::v1::Config> load(const std::filesystem::path& path, NativeCliRole role,
                                       std::string& error) {
    std::string text;
    if (!read_text_file_bounded(path, config::v1::kMaxDocumentBytes, &text)) {
        error = "cannot read the configuration file";
        return std::nullopt;
    }
    try {
        auto config = config::v1::ParseJson(text);
        const bool server = config.role() == config::v1::Role::Server;
        if (server != (role == NativeCliRole::Server)) {
            error = server ? "a server configuration runs with yumed-ytp1"
                           : "a client configuration runs with yume-ytp1";
            return std::nullopt;
        }
        return config;
    } catch (const std::exception& thrown) {
        error = thrown.what();
        return std::nullopt;
    }
}

int validate(NativeCliRole role, const config::v1::Config& config,
             const std::filesystem::path& base) {
    const std::string_view server_name = role == NativeCliRole::Client
        ? std::string_view(std::get<config::v1::ClientEndpoint>(config.endpoint()).host())
        : std::string_view{};
    const auto credentials = load_native_credentials(config, base, server_name);
    if (!credentials.ok()) {
        say(role, describe("credentials are invalid", credentials.status()));
        return exit_for(credentials.status());
    }
    const auto egress = NativeEgressPolicy::create(config.adapters());
    if (!egress.ok()) {
        say(role, describe("destinations are invalid", egress.status()));
        return exit_for(egress.status());
    }
    say(role, "configuration and credentials are valid");
    return kExitStopped;
}

int serve(NativeCliRole role, const config::v1::Config& config,
          const std::filesystem::path& base) {
    auto created = providers::AsioExecutionContext::create(engine::ExecutorAffinity(0x5954503152554e31ULL));
    if (!created.ok()) {
        say(role, describe("execution context unavailable", created.status()));
        return kExitFailure;
    }
    const auto context = std::move(created).take_value();
    SignalSet signals(context->executor(), SIGINT, SIGTERM);
    std::shared_ptr<NativeServerRuntime> server;
    std::shared_ptr<NativeClientRuntime> client;
    int exit_code = kExitStopped;
    bool stopping = false;

    const auto stop = [&](int code) noexcept {
        if (stopping) return;
        stopping = true;
        exit_code = code;
        boost::system::error_code ignored;
        signals.cancel(ignored);
        if (server) server->close();
        if (client) client->close();
        context->finish();
    };

    boost::asio::post(context->executor(), [&]() noexcept {
        try {
            signals.async_wait([&](const boost::system::error_code& error, int) noexcept {
                if (error) return;
                say(role, "stopping");
                stop(kExitStopped);
            });
            if (role == NativeCliRole::Server) {
                auto runtime = NativeServerRuntime::create(context, config, base, [&](Status status) {
                    say(role, describe("stopped accepting", status));
                    stop(kExitFailure);
                });
                if (!runtime.ok()) {
                    say(role, describe("cannot start", runtime.status()));
                    stop(exit_for(runtime.status()));
                    return;
                }
                server = std::move(runtime).take_value();
                const auto started = server->start();
                if (!started.ok()) {
                    say(role, describe("cannot accept", started));
                    stop(exit_for(started));
                    return;
                }
                for (const auto& endpoint : server->listener_endpoints()) {
                    say(role, "listening on " + endpoint.address().to_string() + " port " +
                                  std::to_string(endpoint.port()));
                }
                return;
            }
            auto runtime = NativeClientRuntime::create(context, config, base,
                [role](std::string_view text) { say(role, text); });
            if (!runtime.ok()) {
                say(role, describe("cannot start", runtime.status()));
                stop(exit_for(runtime.status()));
                return;
            }
            client = std::move(runtime).take_value();
            const auto started = client->start();
            if (!started.ok()) {
                say(role, describe("cannot open SOCKS5 listeners", started));
                stop(exit_for(started));
                return;
            }
            for (const auto& endpoint : client->socks5_endpoints()) {
                say(role, "SOCKS5 on " + endpoint.address().to_string() + " port " +
                              std::to_string(endpoint.port()));
            }
        } catch (...) {
            say(role, "startup failed");
            stop(kExitFailure);
        }
    });

    for (;;) {
        try {
            context->run();
            break;
        } catch (...) {
            // A delivery exception cannot identify its owner. Stop everything
            // and resume so accepted work still drains.
            say(role, "runner exception, stopping");
            try {
                boost::asio::post(context->executor(), [&]() noexcept { stop(kExitFailure); });
            } catch (...) {
                exit_code = kExitFailure;
                context->finish();
            }
        }
    }
    return exit_code;
}

}  // namespace

int run_native_cli(NativeCliRole role, int argc, char** argv) noexcept {
    try {
        std::signal(SIGPIPE, SIG_IGN);
        std::string error;
        const auto arguments = parse(argc, argv, error);
        if (!arguments) {
            say(role, error);
            usage(role, stderr);
            return kExitUsage;
        }
        if (arguments->help) {
            usage(role, stdout);
            return kExitStopped;
        }
        if (arguments->version) {
            print_version(role);
            return kExitStopped;
        }
        const auto config = load(*arguments->config, role, error);
        if (!config) {
            say(role, error);
            return kExitUsage;
        }
        const auto base = std::filesystem::absolute(*arguments->config).parent_path();
        return arguments->validate ? validate(role, *config, base) : serve(role, *config, base);
    } catch (const std::exception& thrown) {
        say(role, thrown.what());
    } catch (...) {
        say(role, "unexpected failure");
    }
    return kExitFailure;
}

}  // namespace yume::runtime
