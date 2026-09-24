/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/local_listener.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <sys/stat.h>
#include <unistd.h>

#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/post.hpp>

namespace {
using namespace yume::engine;
using yume::providers::AsioExecutionContext;
using yume::providers::AsioTcpAcceptedChannelOwner;
using yume::runtime::LocalListener;
using Unix = boost::asio::local::stream_protocol;

void check(bool condition, const char* description) {
    if (!condition) throw std::runtime_error(description);
}

template <typename T>
T require(Result<T> result) {
    check(result.ok(), "unexpected failure result");
    return std::move(result).take_value();
}

// A private directory under /tmp. Socket paths must stay short.
class Directory final {
public:
    Directory() {
        std::string pattern = "/tmp/yume-listener-XXXXXX";
        check(::mkdtemp(pattern.data()) != nullptr, "mkdtemp failed");
        path = pattern;
    }
    ~Directory() {
        std::error_code ignored;
        std::filesystem::permissions(path, std::filesystem::perms::owner_all,
                                     std::filesystem::perm_options::replace, ignored);
        std::filesystem::remove_all(path, ignored);
    }
    std::filesystem::path path;
};

struct Harness final {
    Harness()
        : context(require(AsioExecutionContext::create(ExecutorAffinity(5U)))),
          channels(require(AsioTcpAcceptedChannelOwner::create(context))) {}
    ~Harness() {
        context->finish();
        context->run();
    }
    template <typename Action>
    auto on_context(Action action) {
        std::optional<std::invoke_result_t<Action>> result;
        boost::asio::post(context->executor(), [&] { result.emplace(action()); });
        while (!result) context->poll();
        return std::move(*result);
    }
    Result<std::shared_ptr<LocalListener>> open(const LocalListener::Address& address) {
        return on_context([&] { return LocalListener::open(context, address, channels, "test listener"); });
    }
    std::shared_ptr<AsioExecutionContext> context;
    std::shared_ptr<AsioTcpAcceptedChannelOwner> channels;
};

mode_t mode_of(const std::filesystem::path& path) {
    struct stat info{};
    check(::lstat(path.c_str(), &info) == 0, "lstat failed");
    return info.st_mode;
}

// Leaves a socket file with nothing listening, as a crashed run would.
void leave_stale_socket(const std::filesystem::path& path) {
    boost::asio::io_context io;
    Unix::acceptor stale(io);
    stale.open();
    stale.bind(Unix::endpoint(path.string()));
    stale.close();
}

void test_unix_listener_accepts_this_user_only_through_a_private_file() {
    Directory directory;
    const auto path = directory.path / "local.sock";
    Harness harness;
    auto listener = require(harness.open(LocalListener::Unix{path}));
    check(S_ISSOCK(mode_of(path)) && (mode_of(path) & 0777U) == 0600U,
          "the socket file is not private");
    check(harness.channels->limits().max_active_channels > 0U, "owner limits missing");
    std::vector<LocalListener::Connection> accepted;
    harness.on_context([&] {
        listener->start([&](LocalListener::Connection connection) {
            accepted.push_back(std::move(connection));
        }, [] { return false; }, [](Status) { throw std::runtime_error("listener failed"); });
        return true;
    });
    boost::asio::io_context io;
    Unix::socket client(io);
    client.connect(Unix::endpoint(path.string()));
    for (int turn = 0; accepted.empty() && turn < 1000; ++turn) {
        harness.context->poll();
        ::usleep(1000);
    }
    check(accepted.size() == 1U && accepted.front().channel && !accepted.front().peer_address,
          "a same-user connection was not accepted");
    check(harness.on_context([&] { return listener->tcp_endpoint().port(); }) == 0U,
          "a UNIX listener reported a TCP endpoint");
    harness.on_context([&] {
        accepted.clear();
        listener->close();
        return true;
    });
    check(!std::filesystem::exists(path), "close left the socket file");
}

void test_unix_listener_path_rules() {
    Directory directory;
    Harness harness;
    const auto stale = directory.path / "stale.sock";
    leave_stale_socket(stale);
    auto replaced = require(harness.open(LocalListener::Unix{stale}));
    check((mode_of(stale) & 0777U) == 0600U, "a stale socket was not replaced");
    check(harness.open(LocalListener::Unix{stale}).status().code() == StatusCode::AddressInUse,
          "a live listener's path was taken over");

    // Close removes only the file this listener created.
    check(::unlink(stale.c_str()) == 0, "unlink failed");
    leave_stale_socket(stale);
    harness.on_context([&] {
        replaced->close();
        return true;
    });
    check(std::filesystem::exists(stale), "close removed a socket file it did not create");

    const auto regular = directory.path / "regular";
    std::ofstream(regular) << "data";
    check(harness.open(LocalListener::Unix{regular}).status().code() == StatusCode::AlreadyExists,
          "a regular file was replaced");
    const auto link = directory.path / "link.sock";
    std::filesystem::create_symlink(stale, link);
    check(harness.open(LocalListener::Unix{link}).status().code() == StatusCode::AlreadyExists,
          "a symbolic link was followed");

    const auto shared = directory.path / "shared";
    std::filesystem::create_directory(shared);
    std::filesystem::permissions(shared, std::filesystem::perms::all,
                                 std::filesystem::perm_options::replace);
    check(harness.open(LocalListener::Unix{shared / "x.sock"}).status().code() ==
              StatusCode::FailedPrecondition,
          "a directory others can write was accepted");
    std::filesystem::permissions(shared, std::filesystem::perms::owner_all |
                                             std::filesystem::perms::group_read |
                                             std::filesystem::perms::group_exec |
                                             std::filesystem::perms::others_read |
                                             std::filesystem::perms::others_exec,
                                 std::filesystem::perm_options::replace);
    auto readable = require(harness.open(LocalListener::Unix{shared / "x.sock"}));
    harness.on_context([&] {
        readable->close();
        return true;
    });
    check(harness.open(LocalListener::Unix{directory.path / "missing" / "x.sock"}).status().code() ==
              StatusCode::FailedPrecondition,
          "a missing directory was accepted");
    check(harness.open(LocalListener::Unix{"relative.sock"}).status().code() ==
              StatusCode::InvalidArgument,
          "a relative path was accepted");
}

void test_loopback_listener_rules() {
    Harness harness;
    check(harness.open(LocalListener::Loopback{boost::asio::ip::make_address("0.0.0.0"), 0U})
              .status().code() == StatusCode::InvalidArgument,
          "a wildcard address was accepted");
    auto first = require(harness.open(
        LocalListener::Loopback{boost::asio::ip::make_address("127.0.0.1"), 0U}));
    const auto endpoint = harness.on_context([&] { return first->tcp_endpoint(); });
    check(endpoint.port() != 0U, "the bound port was not reported");
    check(harness.open(LocalListener::Loopback{endpoint.address(), endpoint.port()})
              .status().code() == StatusCode::AddressInUse,
          "a port in use was taken");
    harness.on_context([&] {
        first->close();
        return true;
    });
}

}  // namespace

int main() {
    try {
        test_unix_listener_accepts_this_user_only_through_a_private_file();
        test_unix_listener_path_rules();
        test_loopback_listener_rules();
        std::cout << "local listener tests passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "local listener test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
