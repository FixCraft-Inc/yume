/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_cli.hpp"

#include <chrono>
#include <csignal>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>

#include <fcntl.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include <boost/asio/basic_signal_set.hpp>
#include <boost/asio/post.hpp>

#include "common/secure_erase.hpp"
#include "common/version.hpp"
#include "config/v1/config.hpp"
#include "fs/bounded_file.hpp"
#include "providers/asio_execution_context.hpp"
#include "providers/child_process.hpp"
#include "providers/system_resolver_helper.hpp"
#include "providers/openssl_security_provider.hpp"
#include "runtime/control_socket.hpp"
#include "runtime/module_launcher.hpp"
#include "runtime/native_client_runtime.hpp"
#include "runtime/native_credentials.hpp"
#include "runtime/native_egress_policy.hpp"
#include "runtime/native_run_loop.hpp"
#include "runtime/native_server_runtime.hpp"
#include "runtime/outer_carrier_evidence.hpp"
#include "runtime/sealed_kit.hpp"
#include "runtime/yume_help_text.hpp"
#include "runtime/yumed_help_text.hpp"

namespace yume::runtime {
namespace {
using engine::Status;
using engine::StatusCode;
using SignalSet = boost::asio::basic_signal_set<providers::AsioExecutionContext::Executor>;

constexpr int kExitStopped = 0;
constexpr int kExitFailure = 1;
constexpr int kExitUsage = 2;
// These programs are their own resolver helper and module launcher, so a
// single-file release needs nothing installed beside it.
constexpr std::string_view kSelfHelperProgram = "/proc/self/exe";

struct Arguments final {
    std::optional<std::filesystem::path> config;
    std::optional<std::filesystem::path> outer_carrier_evidence;
    config::v1::RunSettings run;
    bool validate{false};
    bool version{false};
    bool help{false};
    bool completion{false};
    bool status{false};
    std::optional<std::filesystem::path> seal_kit;
    std::optional<std::filesystem::path> output;
    std::optional<std::filesystem::path> import_kit;
    std::optional<std::filesystem::path> into;
};

// A flag that takes one path, and the client-only flags among them.
struct PathFlag final {
    std::string_view flag;
    std::optional<std::filesystem::path> Arguments::* value;
};
constexpr PathFlag kKitFlags[] = {
    {"--seal-kit", &Arguments::seal_kit},
    {"--output", &Arguments::output},
    {"--import-kit", &Arguments::import_kit},
    {"--into", &Arguments::into},
};

// The client's per-run flags. Each sets one schema-1 key through
// config::v1::RunSettings, whose comment says why these keys are safe.
struct RunFlag final {
    std::string_view flag;
    std::string_view value;
    std::optional<std::string> config::v1::RunSettings::* setting;
};
constexpr RunFlag kRunFlags[] = {
    {"--connect", "IP address", &config::v1::RunSettings::connect_address},
    {"--socks-address", "IP address",
     &config::v1::RunSettings::socks5_listen_address},
    {"--socks-port", "port", &config::v1::RunSettings::socks5_listen_port},
};

std::string_view program(NativeCliRole role) noexcept {
    return role == NativeCliRole::Server ? "yumed" : "yume";
}

void say(NativeCliRole role, std::string_view text) noexcept {
    const auto name = program(role);
    std::fprintf(stderr, "%.*s: %.*s\n", static_cast<int>(name.size()), name.data(),
                 static_cast<int>(text.size()), text.data());
    std::fflush(stderr);
}

void say_stopped(NativeCliRole role, const Status& status) noexcept {
    const auto name = program(role);
    const auto& message = status.message();
    std::fprintf(stderr, "%.*s: runtime stopped (status %d): %.*s\n",
                 static_cast<int>(name.size()), name.data(), static_cast<int>(status.code()),
                 static_cast<int>(message.size()), message.data());
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
    std::fputs(role == NativeCliRole::Server ? yumed_cli::kHelpBody : yume_cli::kHelpBody, out);
}

const PathFlag* find_kit_flag(std::string_view argument) noexcept {
    for (const auto& flag : kKitFlags) {
        if (flag.flag == argument) return &flag;
    }
    return nullptr;
}

const RunFlag* find_run_flag(NativeCliRole role,
                             std::string_view argument) noexcept {
    if (role != NativeCliRole::Client) return nullptr;
    for (const auto& flag : kRunFlags) {
        if (flag.flag == argument) return &flag;
    }
    return nullptr;
}

std::optional<Arguments> parse(NativeCliRole role, int argc, char** argv,
                               std::string& error) {
    Arguments arguments;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (const auto* flag = find_run_flag(role, argument)) {
            auto& setting = arguments.run.*(flag->setting);
            if (index + 1 >= argc || setting) {
                error = std::string(flag->flag) + " needs exactly one " +
                        std::string(flag->value);
                return std::nullopt;
            }
            setting = std::string(argv[++index]);
        } else if (argument == "--config") {
            if (index + 1 >= argc || arguments.config) {
                error = "--config needs exactly one path";
                return std::nullopt;
            }
            arguments.config = std::filesystem::path(argv[++index]);
        } else if (role == NativeCliRole::Client &&
                   argument == "--outer-carrier-evidence") {
            if (index + 1 >= argc || arguments.outer_carrier_evidence) {
                error = "--outer-carrier-evidence needs exactly one path";
                return std::nullopt;
            }
            arguments.outer_carrier_evidence =
                std::filesystem::path(argv[++index]);
        } else if (argument == "--validate") {
            arguments.validate = true;
        } else if (argument == "--status") {
            arguments.status = true;
        } else if (const auto* kit_flag = role == NativeCliRole::Client
                                              ? find_kit_flag(argument)
                                              : nullptr) {
            auto& value = arguments.*(kit_flag->value);
            if (index + 1 >= argc || value) {
                error = std::string(kit_flag->flag) + " needs exactly one path";
                return std::nullopt;
            }
            value = std::filesystem::path(argv[++index]);
        } else if (argument == "--version") {
            arguments.version = true;
        } else if (argument == "--completion") {
            if (index + 1 >= argc || arguments.completion ||
                std::string_view(argv[index + 1]) != "bash") {
                error = "--completion needs bash";
                return std::nullopt;
            }
            ++index;
            arguments.completion = true;
        } else if (argument == "--help" || argument == "-h") {
            arguments.help = true;
        } else {
            error = "unknown argument: " + std::string(argument);
            return std::nullopt;
        }
    }
    const bool kit_action = arguments.seal_kit || arguments.output ||
                            arguments.import_kit || arguments.into;
    if (kit_action) {
        const bool seal = arguments.seal_kit && arguments.output &&
                          !arguments.import_kit && !arguments.into;
        const bool import = arguments.import_kit && arguments.into &&
                            !arguments.seal_kit && !arguments.output;
        if ((!seal && !import) || arguments.config || arguments.validate ||
            arguments.status || arguments.outer_carrier_evidence ||
            arguments.run.connect_address ||
            arguments.run.socks5_listen_address ||
            arguments.run.socks5_listen_port) {
            error =
                "use --seal-kit DIR --output FILE or --import-kit FILE --into "
                "DIR alone";
            return std::nullopt;
        }
    }
    if (!arguments.help && !arguments.version && !arguments.completion &&
        !kit_action && !arguments.config) {
        error = "--config is required";
        return std::nullopt;
    }
    if (arguments.validate && arguments.outer_carrier_evidence) {
        error = "--outer-carrier-evidence needs a run, not --validate";
        return std::nullopt;
    }
    if (arguments.status &&
        (arguments.validate || arguments.outer_carrier_evidence ||
         arguments.run.connect_address || arguments.run.socks5_listen_address ||
         arguments.run.socks5_listen_port)) {
        error = "--status takes only --config";
        return std::nullopt;
    }
    return arguments;
}

void print_version(NativeCliRole role) {
    const auto name = program(role);
    const auto backend = providers::openssl_crypto_backend();
    std::printf("%.*s %s\n", static_cast<int>(name.size()), name.data(), kVersion);
    std::printf("transport %.*s, config schema %u, suite %.*s\n",
                static_cast<int>(kYtpVersion.size()), kYtpVersion.data(), kConfigSchema,
                static_cast<int>(kTransportSuite.size()), kTransportSuite.data());
    std::printf("session security %.*s, crypto backend %.*s\n",
                static_cast<int>(providers::kOpenSslSecurityProviderId.size()),
                providers::kOpenSslSecurityProviderId.data(),
                static_cast<int>(backend.size()), backend.data());
    std::printf("evidence profile %.*s\n", static_cast<int>(kEvidenceProfile.size()),
                kEvidenceProfile.data());
    std::printf("development runtime, not qualified for production use\n");
}

std::optional<config::v1::Config> load(const std::filesystem::path& path,
                                       NativeCliRole role,
                                       const config::v1::RunSettings& run,
                                       std::string& error) {
    std::string text;
    if (!read_text_file_bounded(path, config::v1::kMaxDocumentBytes, &text)) {
        error = "cannot read the configuration file";
        return std::nullopt;
    }
    try {
        auto config = config::v1::ParseJson(text, run);
        const bool server = config.role() == config::v1::Role::Server;
        if (server != (role == NativeCliRole::Server)) {
            error = server ? "a server configuration runs with yumed"
                           : "a client configuration runs with yume";
            return std::nullopt;
        }
        return config;
    } catch (const std::exception& thrown) {
        error = thrown.what();
        return std::nullopt;
    }
}

std::string origin(const std::optional<std::string>& setting,
                   std::string_view flag) {
    return setting ? " (from " + std::string(flag) + ")"
                   : std::string(" (from the configuration)");
}

// Every key a per-run flag can set, with its value and where it came from, so
// a service manager's validation step shows what the command line changed.
void report_run_settings(NativeCliRole role, const config::v1::Config& config,
                         const config::v1::RunSettings& run) {
    const auto* endpoint =
        std::get_if<config::v1::ClientEndpoint>(&config.endpoint());
    if (!endpoint) return;
    if (endpoint->connect_address()) {
        say(role, "/endpoint/connect_address " + *endpoint->connect_address() +
                      origin(run.connect_address, "--connect"));
    }
    const config::v1::Socks5Adapter* socks5 = nullptr;
    std::size_t socks5_index = 0;
    std::size_t socks5_count = 0;
    for (std::size_t index = 0; index < config.adapters().size(); ++index) {
        if (const auto* adapter = std::get_if<config::v1::Socks5Adapter>(
                &config.adapters()[index])) {
            socks5 = adapter;
            socks5_index = index;
            ++socks5_count;
        }
    }
    if (socks5_count != 1U) return;
    const std::string pointer = "/adapters/" + std::to_string(socks5_index);
    say(role, pointer + "/listen_address " + socks5->listen_address() +
                  origin(run.socks5_listen_address, "--socks-address"));
    say(role, pointer + "/listen_port " +
                  std::to_string(socks5->listen_port()) +
                  origin(run.socks5_listen_port, "--socks-port"));
}

int validate(NativeCliRole role, const config::v1::Config& config,
             const config::v1::RunSettings& run,
             const std::filesystem::path& base) {
    report_run_settings(role, config, run);
    const std::string_view server_name = role == NativeCliRole::Client
        ? std::string_view(std::get<config::v1::ClientEndpoint>(config.endpoint()).host())
        : std::string_view{};
    const auto credentials = load_native_credentials(config, base, server_name);
    if (!credentials.ok()) {
        say(role, describe("credentials are invalid", credentials.status()));
        return exit_for(credentials.status());
    }
    const auto egress = NativeEgressPolicy::create(config.adapters(), base);
    if (!egress.ok()) {
        say(role, describe("destinations are invalid", egress.status()));
        return exit_for(egress.status());
    }
    // The same check a module supervisor makes at start, so a service
    // manager's validation step reports a program the daemon would refuse.
    for (const auto& adapter : config.adapters()) {
        const auto* module = std::get_if<config::v1::ModuleAdapter>(&adapter);
        if (!module) continue;
        const auto program = providers::validate_program(module->program(), "module program");
        if (!program.ok()) {
            say(role, describe("module '" + module->service() + "' is invalid", program));
            return exit_for(program);
        }
    }
    say(role, "configuration and credentials are valid");
    return kExitStopped;
}

// A kit's yume.json must be a client configuration, so a server's private
// keys are never sealed or imported as a client kit.
bool client_kit(const kit::Kit& contents, std::string& error) {
    for (const auto& file : contents.files) {
        if (file.path != "yume.json") continue;
        try {
            const auto config = config::v1::ParseJson(std::string_view(
                reinterpret_cast<const char*>(file.bytes.data()),
                file.bytes.size()));
            if (config.role() == config::v1::Role::Client) return true;
            error = "the kit's yume.json is a server configuration";
        } catch (const std::exception& thrown) {
            error =
                std::string("the kit's yume.json is invalid: ") + thrown.what();
        }
        return false;
    }
    error = "the kit has no yume.json";
    return false;
}

// yume --seal-kit DIR --output FILE: prints the new code on standard output.
int seal_kit(NativeCliRole role, const std::filesystem::path& directory,
             const std::filesystem::path& output) {
    auto contents = kit::read_directory(directory);
    if (!contents.ok()) {
        say(role, describe("cannot read the kit", contents.status()));
        return kExitUsage;
    }
    std::string error;
    if (!client_kit(contents.value(), error)) {
        say(role, error);
        return kExitUsage;
    }
    auto code = kit::generate_code();
    if (!code.ok()) {
        say(role, describe("cannot make a kit code", code.status()));
        return kExitFailure;
    }
    const auto sealed = kit::seal(contents.value(), code.value());
    if (!sealed.ok()) {
        say(role, describe("cannot seal the kit", sealed.status()));
        return kExitFailure;
    }
    const int fd =
        ::open(output.c_str(),
               O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        say(role, errno == EEXIST ? "the output file exists"
                                  : "cannot create the output file");
        return kExitUsage;
    }
    const auto& bytes = sealed.value();
    std::size_t written = 0U;
    bool ok = true;
    while (ok && written < bytes.size()) {
        const auto count =
            ::write(fd, bytes.data() + written, bytes.size() - written);
        if (count < 0 && errno == EINTR) continue;
        ok = count > 0;
        if (ok) written += static_cast<std::size_t>(count);
    }
    ok = ok && ::fsync(fd) == 0;
    ok = ::close(fd) == 0 && ok;
    if (!ok) {
        std::error_code ignored;
        std::filesystem::remove(output, ignored);
        say(role, "cannot write the output file");
        return kExitFailure;
    }
    std::printf("%s\n", kit::display_code(code.value()).c_str());
    std::fflush(stdout);
    return kExitStopped;
}

// Reads one line of at most 256 bytes from standard input, with echo off on
// a terminal.
std::optional<std::string> read_code_line(NativeCliRole role) {
    const bool terminal = ::isatty(STDIN_FILENO) == 1;
    termios saved{};
    const bool quiet = terminal && ::tcgetattr(STDIN_FILENO, &saved) == 0;
    if (terminal) {
        std::fputs("kit code: ", stderr);
        std::fflush(stderr);
    }
    if (quiet) {
        termios silent = saved;
        silent.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        static_cast<void>(::tcsetattr(STDIN_FILENO, TCSAFLUSH, &silent));
    }
    std::string line;
    bool ended = false;
    for (;;) {
        char ch = 0;
        const auto count = ::read(STDIN_FILENO, &ch, 1U);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0 || ch == '\n') {
            ended = count > 0 || !line.empty();
            break;
        }
        if (line.size() >= 256U) break;
        line.push_back(ch);
    }
    if (quiet) {
        static_cast<void>(::tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved));
        std::fputs("\n", stderr);
    }
    if (!ended) {
        security::secure_erase(line);
        say(role, "no kit code on standard input");
        return std::nullopt;
    }
    return line;
}

// yume --import-kit FILE --into DIR: reads the code from standard input.
int import_kit(NativeCliRole role, const std::filesystem::path& file,
               const std::filesystem::path& directory) {
    std::vector<std::uint8_t> sealed;
    std::string error;
    if (!read_file_bounded(file, kit::kMaxSealedBytes, &sealed, &error)) {
        say(role, "cannot read the sealed kit: " + error);
        return kExitUsage;
    }
    auto typed = read_code_line(role);
    if (!typed) return kExitUsage;
    const security::ScopedErase typed_guard(*typed);
    auto code = kit::normalize_code(*typed);
    if (!code) {
        say(role, "the kit code is not 25 code characters");
        return kExitUsage;
    }
    const security::ScopedErase code_guard(*code);
    const auto contents = kit::open(sealed, *code);
    if (!contents.ok()) {
        say(role, describe("cannot open the kit", contents.status()));
        return kExitFailure;
    }
    if (!client_kit(contents.value(), error)) {
        say(role, error);
        return kExitFailure;
    }
    const auto written = kit::write_directory(contents.value(), directory);
    if (!written.ok()) {
        say(role, describe("cannot write the kit", written));
        return exit_for(written);
    }
    say(role, "imported the kit into " + directory.string() +
                  ", run yume --config " + (directory / "yume.json").string());
    return kExitStopped;
}

// yume --status and yumed --status: one request to the running program's
// control socket.
int print_status(NativeCliRole role, const config::v1::Config& config) {
    if (!config.control()) {
        say(role, "the configuration has no control socket (control.socket)");
        return kExitUsage;
    }
    const auto& path = config.control()->socket_path;
    const auto reply = query_control_status(path, std::chrono::seconds(5));
    if (!reply.ok()) {
        say(role, reply.status().code() == StatusCode::NotFound
                      ? "no " + std::string(program(role)) +
                            " is running on the control socket " + path
                      : describe("status request failed", reply.status()));
        return kExitFailure;
    }
    const auto text = status_reply_text(reply.value());
    if (!text.ok()) {
        say(role, describe("status reply refused", text.status()));
        return kExitFailure;
    }
    std::fputs(text.value().c_str(), stdout);
    return kExitStopped;
}

int serve(NativeCliRole role, const config::v1::Config& config,
          const std::filesystem::path& base,
          const std::optional<std::filesystem::path>& evidence_path) {
    // The evidence file is reserved before anything connects, so a bad path
    // fails the run instead of a finished session.
    std::unique_ptr<OuterCarrierEvidence> evidence;
    if (evidence_path) {
        std::string error;
        evidence = OuterCarrierEvidence::reserve(*evidence_path, error);
        if (!evidence) {
            say(role, error);
            return kExitUsage;
        }
    }
    auto created = providers::AsioExecutionContext::create(engine::ExecutorAffinity(0x5954503152554e31ULL));
    if (!created.ok()) {
        say(role, describe("execution context unavailable", created.status()));
        return kExitFailure;
    }
    const auto context = std::move(created).take_value();
    SignalSet signals(context->executor(), SIGINT, SIGTERM);
    // SIGHUP asks the daemon to reload its credential stores.
    if (role == NativeCliRole::Server) signals.add(SIGHUP);
    std::shared_ptr<NativeServerRuntime> server;
    std::shared_ptr<NativeClientRuntime> client;
    std::shared_ptr<ControlServer> control;
    int exit_code = kExitStopped;
    bool stopping = false;

    const auto stop = [&](int code) noexcept {
        if (stopping) {
            if (code != kExitStopped) exit_code = code;
            return;
        }
        stopping = true;
        exit_code = code;
        boost::system::error_code ignored;
        signals.cancel(ignored);
        if (control) control->close();
        if (server) server->close();
        if (client) client->close();
        context->finish();
    };

    // Opens the control socket, or stops the program when it cannot.
    const auto open_control = [&](const std::string& path,
                                  ControlStatusSource source) {
        auto opened = ControlServer::open(
            context, path, std::move(source), [role](Status status) noexcept {
                say(role, describe("control socket stopped", status));
            });
        if (!opened.ok()) {
            say(role,
                describe("cannot open the control socket", opened.status()));
            stop(exit_for(opened.status()));
            return false;
        }
        control = std::move(opened).take_value();
        say(role, "control socket on " + path);
        return true;
    };

    std::function<void()> wait_for_signal;
    wait_for_signal = [&]() {
        signals.async_wait([&](const boost::system::error_code& error, int number) noexcept {
            if (error) return;
            if (number != SIGHUP) {
                say(role, "stopping");
                stop(kExitStopped);
                return;
            }
            try {
                if (server) {
                    const auto reloaded = server->reload();
                    say(role, reloaded.ok() ? std::string("credentials reloaded")
                                            : describe("credential reload refused", reloaded));
                }
                wait_for_signal();
            } catch (...) {
                say(role, "signal handling failed, stopping");
                stop(kExitFailure);
            }
        });
    };

    boost::asio::post(context->executor(), [&]() noexcept {
        try {
            wait_for_signal();
            if (role == NativeCliRole::Server) {
                NativeServerRuntimeOptions server_options;
                server_options.resolver_program = std::string(kSelfHelperProgram);
                server_options.module_launcher = std::string(kSelfHelperProgram);
                server_options.report = [role](std::string_view text) { say(role, text); };
                auto runtime = NativeServerRuntime::create(context, config, base, [&](Status status) noexcept {
                    say_stopped(role, status);
                    stop(kExitFailure);
                }, std::move(server_options));
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
                if (config.control()) {
                    const std::weak_ptr<NativeServerRuntime> weak = server;
                    if (!open_control(config.control()->socket_path, [weak] {
                            const auto runtime = weak.lock();
                            if (!runtime)
                                throw std::runtime_error(
                                    "the server has stopped");
                            return server_status_reply(
                                runtime->status(),
                                std::chrono::steady_clock::now());
                        }))
                        return;
                }
                return;
            }
            NativeClientRuntimeOptions client_options;
            client_options.resolver_program = std::string(kSelfHelperProgram);
            if (evidence)
                client_options.outer_carrier_trace = evidence->trace();
            auto runtime = NativeClientRuntime::create(context, config, base,
                [role](std::string_view text) { say(role, text); }, std::move(client_options),
                [&](Status status) noexcept {
                    say_stopped(role, status);
                    stop(kExitFailure);
                });
            if (!runtime.ok()) {
                say(role, describe("cannot start", runtime.status()));
                stop(exit_for(runtime.status()));
                return;
            }
            client = std::move(runtime).take_value();
            const auto started = client->start();
            if (!started.ok()) {
                say(role, describe("cannot start client adapters", started));
                stop(exit_for(started));
                return;
            }
            for (const auto& endpoint : client->socks5_endpoints()) {
                say(role, "SOCKS5 on " + endpoint.address().to_string() + " port " +
                              std::to_string(endpoint.port()));
            }
            for (const auto& endpoint : client->forward_endpoints()) {
                say(role, "forward on " + endpoint.address().to_string() + " port " +
                              std::to_string(endpoint.port()));
            }
            ClientControlView view;
            const auto& endpoint =
                std::get<config::v1::ClientEndpoint>(config.endpoint());
            view.server_host = endpoint.host();
            view.server_port = endpoint.port();
            view.socks5 = client->socks5_endpoints();
            view.forwards = client->forward_endpoints();
            for (const auto& adapter : config.adapters()) {
                const auto* forward = std::get_if<config::v1::ForwardAdapter>(&adapter);
                const auto* local = forward
                    ? std::get_if<config::v1::UnixListener>(&forward->listener()) : nullptr;
                if (!local) continue;
                say(role, "forward on " + local->path);
                view.unix_forwards.push_back(local->path);
            }
            if (config.control()) {
                const std::weak_ptr<NativeClientRuntime> weak = client;
                static_cast<void>(open_control(
                    config.control()->socket_path,
                    [weak, view = std::move(view)] {
                        const auto runtime = weak.lock();
                        if (!runtime)
                            throw std::runtime_error("the client has stopped");
                        return client_status_reply(
                            runtime->status(), view,
                            std::chrono::steady_clock::now());
                    }));
            }
        } catch (...) {
            say(role, "startup failed");
            stop(kExitFailure);
        }
    });

    run_native_context(context, [&]() noexcept {
        say(role, "runner exception, stopping");
        stop(kExitFailure);
    });
    if (evidence) {
        std::string error;
        if (!evidence->finalize(exit_code == kExitStopped, error)) {
            say(role, error);
            if (exit_code == kExitStopped) exit_code = kExitFailure;
        }
    }
    return exit_code;
}

}  // namespace

int run_native_cli(NativeCliRole role, int argc, char** argv) noexcept {
    // Name lookups and modules re-execute this program as their helpers.
    if (providers::is_system_resolver_helper(argc, argv)) {
        return providers::run_system_resolver_helper();
    }
    if (role == NativeCliRole::Server && is_module_launcher(argc, argv)) {
        return run_module_launcher(argc, argv);
    }
    try {
        std::signal(SIGPIPE, SIG_IGN);
        std::string error;
        const auto arguments = parse(role, argc, argv, error);
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
        if (arguments->completion) {
            std::fputs(role == NativeCliRole::Server
                           ? yumed_cli::kBashCompletion
                           : yume_cli::kBashCompletion,
                       stdout);
            return kExitStopped;
        }
        if (arguments->seal_kit)
            return seal_kit(role, *arguments->seal_kit, *arguments->output);
        if (arguments->import_kit) {
            return import_kit(role, *arguments->import_kit, *arguments->into);
        }
        const auto config =
            load(*arguments->config, role, arguments->run, error);
        if (!config) {
            say(role, error);
            return kExitUsage;
        }
        if (arguments->status) return print_status(role, *config);
        const auto base = std::filesystem::absolute(*arguments->config).parent_path();
        return arguments->validate
                   ? validate(role, *config, arguments->run, base)
                   : serve(role, *config, base,
                           arguments->outer_carrier_evidence);
    } catch (const std::exception& thrown) {
        say(role, thrown.what());
    } catch (...) {
        say(role, "unexpected failure");
    }
    return kExitFailure;
}

}  // namespace yume::runtime
