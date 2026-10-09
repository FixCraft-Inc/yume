/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// yume-setup: kits, client bundles and cluster lists. Exit status 0 on
// success, 1 when the action fails and 2 for a usage error.

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <limits>
#include <map>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <sys/stat.h>

#include "setup/actions.hpp"
#include "setup/files.hpp"
#include "setup/provision.hpp"
#include "setup/yume_setup_help_text.hpp"

namespace {

using namespace yume::setup;

constexpr int kExitFailure = 1;
constexpr int kExitUsage = 2;

struct Action final {
    std::string_view name;
    // Options with a value, options without one, and the required ones.
    std::vector<std::string_view> values;
    std::vector<std::string_view> flags;
    std::vector<std::string_view> required;
};

const std::array<Action, 7> kActions{{
    {"init",
     {"--host", "--output", "--port", "--client-name", "--max-sessions",
      "--weight", "--max-egress-mbps", "--preset"},
     {},
     {"--host", "--output"}},
    {"add-client",
     {"--server", "--host", "--output", "--client-name", "--max-sessions",
      "--weight"},
     {"--circuits"},
     {"--server", "--host", "--output", "--client-name"}},
    {"remove-client",
     {"--server", "--client-name"},
     {},
     {"--server", "--client-name"}},
    {"cluster-init", {"--output"}, {}, {"--output"}},
    {"cluster-add",
     {"--cluster", "--server", "--name", "--host", "--address"},
     {"--exit"},
     {"--cluster", "--server", "--name", "--host"}},
    {"cluster-remove", {"--cluster", "--name"}, {}, {"--cluster", "--name"}},
    {"cluster-sign", {"--cluster", "--days"}, {}, {"--cluster"}},
}};

struct UsageError final {
    std::string message;
};

struct Arguments final {
    const Action* action{nullptr};
    std::map<std::string, std::string, std::less<>> values;
    std::map<std::string, bool, std::less<>> flags;
    bool help{false};
};

bool contains(const std::vector<std::string_view>& list,
              std::string_view item) {
    return std::find(list.begin(), list.end(), item) != list.end();
}

// A negative number is a value, as it was for the earlier tool, while any
// other word that starts with a dash is an option.
bool looks_like_value(std::string_view text) {
    if (!text.starts_with("-")) return true;
    text.remove_prefix(1);
    return !text.empty() && std::all_of(text.begin(), text.end(), [](char ch) {
        return ch >= '0' && ch <= '9';
    });
}

bool known_option(std::string_view name) {
    return std::any_of(kActions.begin(), kActions.end(),
                       [&](const Action& action) {
                           return contains(action.values, name) ||
                                  contains(action.flags, name);
                       });
}

Arguments parse(int argc, char** argv) {
    Arguments arguments;
    for (int index = 1; index < argc; ++index) {
        const std::string_view word(argv[index]);
        if (word == "-h" || word == "--help") {
            arguments.help = true;
            continue;
        }
        if (!word.starts_with("-")) {
            if (arguments.action != nullptr)
                throw UsageError{"unexpected argument: " + std::string(word)};
            const auto found = std::find_if(
                kActions.begin(), kActions.end(),
                [&](const Action& action) { return action.name == word; });
            if (found == kActions.end())
                throw UsageError{"unknown action: " + std::string(word)};
            arguments.action = &*found;
            continue;
        }
        const auto equals = word.find('=');
        const std::string name(word.substr(0, equals));
        if (!known_option(name))
            throw UsageError{"unknown argument: " + std::string(word)};
        if (arguments.action == nullptr)
            throw UsageError{"an action comes before " + name};
        const auto& action = *arguments.action;
        if (arguments.values.count(name) != 0U ||
            arguments.flags.count(name) != 0U) {
            throw UsageError{name + " is given more than once"};
        }
        if (contains(action.flags, name)) {
            if (equals != std::string_view::npos)
                throw UsageError{name + " takes no value"};
            arguments.flags[name] = true;
        } else if (contains(action.values, name)) {
            if (equals != std::string_view::npos) {
                arguments.values[name] = std::string(word.substr(equals + 1U));
            } else if (index + 1 < argc && looks_like_value(argv[index + 1])) {
                arguments.values[name] = argv[++index];
            } else {
                throw UsageError{name + " needs a value"};
            }
        } else {
            throw UsageError{std::string(action.name) + " does not take " +
                             name};
        }
    }
    if (arguments.help) return arguments;
    if (arguments.action == nullptr) throw UsageError{"an action is required"};
    for (const auto required : arguments.action->required) {
        if (arguments.values.count(required) == 0U) {
            throw UsageError{std::string(required) + " is required for " +
                             std::string(arguments.action->name)};
        }
    }
    return arguments;
}

// An integer as the earlier tool read one: optional sign and decimal digits.
// A value beyond int64 saturates, so the action's own range check refuses it.
std::optional<std::int64_t> integer(const Arguments& arguments,
                                    std::string_view name) {
    const auto found = arguments.values.find(name);
    if (found == arguments.values.end()) return std::nullopt;
    std::string_view text = found->second;
    const bool negative = text.starts_with("-");
    if (negative || text.starts_with("+")) text.remove_prefix(1);
    if (text.empty() || !std::all_of(text.begin(), text.end(), [](char ch) {
            return ch >= '0' && ch <= '9';
        })) {
        throw UsageError{std::string(name) + " needs an integer"};
    }
    constexpr auto kMax = std::numeric_limits<std::int64_t>::max();
    std::int64_t value = 0;
    for (const char ch : text) {
        const int digit = ch - '0';
        value = value > (kMax - digit) / 10 ? kMax : value * 10 + digit;
    }
    return negative ? -value : value;
}

std::optional<double> number(const Arguments& arguments,
                             std::string_view name) {
    const auto found = arguments.values.find(name);
    if (found == arguments.values.end()) return std::nullopt;
    const auto& text = found->second;
    char* end = nullptr;
    errno = 0;
    const double value = std::strtod(text.c_str(), &end);
    if (text.empty() || end != text.c_str() + text.size()) {
        throw UsageError{std::string(name) + " needs a number"};
    }
    return value;
}

std::optional<std::string> text(const Arguments& arguments,
                                std::string_view name) {
    const auto found = arguments.values.find(name);
    if (found == arguments.values.end()) return std::nullopt;
    return found->second;
}

bool flag(const Arguments& arguments, std::string_view name) {
    return arguments.flags.count(name) != 0U;
}

std::string preset_choice(const Arguments& arguments) {
    const auto chosen = text(arguments, "--preset").value_or(default_preset());
    if (find_preset(chosen) != nullptr) return chosen;
    std::string names;
    for (const auto& preset : presets()) {
        names += (names.empty() ? "" : ", ") + preset.id;
    }
    throw UsageError{"--preset must be one of " + names};
}

int run(const Arguments& arguments) {
    const auto action = arguments.action->name;
    if (action == "init") {
        InitOptions options;
        options.host = *text(arguments, "--host");
        options.output = *text(arguments, "--output");
        options.port = integer(arguments, "--port").value_or(443);
        options.client_name =
            text(arguments, "--client-name").value_or("client1");
        options.max_sessions = integer(arguments, "--max-sessions");
        options.weight = number(arguments, "--weight");
        options.max_egress_mbps = integer(arguments, "--max-egress-mbps");
        options.preset = preset_choice(arguments);
        const auto output = init_kit(options);
        std::printf("Created YUME server kit and client bundle: %s\n",
                    output.c_str());
        std::printf("Server config: %s\n",
                    (output / "server" / "yumed.json").c_str());
        std::printf("Client config: %s\n",
                    (output / "client" / "yume.json").c_str());
        std::printf("Tuning preset: %s\n", options.preset.c_str());
        std::printf(
            "To move the client to its device: yume --seal-kit %s --output "
            "FILE\n",
            (output / "client").c_str());
    } else if (action == "add-client") {
        AddClientOptions options;
        options.server = *text(arguments, "--server");
        options.host = *text(arguments, "--host");
        options.output = *text(arguments, "--output");
        options.client_name = *text(arguments, "--client-name");
        options.max_sessions = integer(arguments, "--max-sessions");
        options.weight = number(arguments, "--weight");
        options.circuits = flag(arguments, "--circuits");
        const auto output = add_client(options);
        std::printf("Created YUME client bundle: %s\n", output.c_str());
        std::printf("Client config: %s\n", (output / "yume.json").c_str());
        std::printf(
            "Reload yumed (SIGHUP, or systemctl reload yumed) to accept the "
            "new client.\n");
        std::printf(
            "To move it to the client's device: yume --seal-kit %s --output "
            "FILE\n",
            output.c_str());
    } else if (action == "remove-client") {
        const auto name = *text(arguments, "--client-name");
        const auto store = remove_client(*text(arguments, "--server"), name);
        std::printf("Removed %s from %s\n", name.c_str(), store.c_str());
        std::printf(
            "Reload yumed (SIGHUP, or systemctl reload yumed) to end its "
            "sessions.\n");
    } else if (action == "cluster-init") {
        const auto [output, cluster] =
            cluster_init(*text(arguments, "--output"));
        std::printf("Created cluster operator directory: %s\n", output.c_str());
        std::printf("Cluster ID: %s\n", cluster.c_str());
        std::printf(
            "Keep this directory off the nodes. Add nodes with cluster-add.\n");
    } else if (action == "cluster-add") {
        ClusterAddOptions options;
        options.cluster = *text(arguments, "--cluster");
        options.server = *text(arguments, "--server");
        options.name = *text(arguments, "--name");
        options.host = *text(arguments, "--host");
        options.address = text(arguments, "--address");
        options.exit = flag(arguments, "--exit");
        const auto server = cluster_add(options);
        std::printf("Added %s (%s) to the cluster\n", options.name.c_str(),
                    server.c_str());
        std::printf(
            "Sign the list with cluster-sign, then deploy the nodes' "
            "credentials/cluster.\n");
    } else if (action == "cluster-remove") {
        const auto name = *text(arguments, "--name");
        const auto server = cluster_remove(*text(arguments, "--cluster"), name);
        std::printf("Removed %s (%s) from the cluster\n", name.c_str(),
                    server.c_str());
        std::printf(
            "Sign a new list with cluster-sign and reload the other nodes "
            "(SIGHUP).\n");
    } else {
        const auto days =
            integer(arguments, "--days").value_or(kDefaultClusterDays);
        const auto [serial, not_after] =
            cluster_sign(*text(arguments, "--cluster"), days);
        std::printf(
            "Signed cluster list and routes view serial %llu, valid until %s\n",
            static_cast<unsigned long long>(serial), not_after.c_str());
        std::printf(
            "Deploy each node's credentials/cluster and reload it (SIGHUP).\n");
    }
    return 0;
}

void usage_error(const std::string& message) {
    std::fprintf(stderr, "yume-setup: %s\n%s", message.c_str(),
                 setup_cli::kHelpBody);
}

}  // namespace

int main(int argc, char** argv) {
    // Every file and directory setup creates is owner-only unless it says
    // otherwise.
    ::umask(077);
    remove_staging_on_terminate();
    try {
        const auto arguments = parse(argc, argv);
        if (arguments.help) {
            std::fputs(setup_cli::kHelpBody, stdout);
            return 0;
        }
        return run(arguments);
    } catch (const UsageError& error) {
        usage_error(error.message);
        return kExitUsage;
    } catch (const std::bad_alloc&) {
        std::fputs("yume-setup: out of memory\n", stderr);
    } catch (const std::exception& error) {
        std::fprintf(stderr, "yume-setup: %s\n", error.what());
    }
    return kExitFailure;
}
