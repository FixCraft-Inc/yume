/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/transport/chrome_tls_helper.hpp"

#include <boost/asio.hpp>

#include <array>
#include <atomic>
#include <cassert>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <span>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

class ScopedEnvironment {
public:
    ScopedEnvironment(const char* name, const std::string& value) : name_(name) {
        const char* previous = std::getenv(name);
        if (previous != nullptr) {
            previous_ = previous;
            had_previous_ = true;
        }
        if (::setenv(name, value.c_str(), 1) != 0) {
            throw std::system_error(errno, std::generic_category(), "set test environment");
        }
    }

    ~ScopedEnvironment() {
        if (had_previous_) {
            (void)::setenv(name_.c_str(), previous_.c_str(), 1);
        } else {
            (void)::unsetenv(name_.c_str());
        }
    }

    ScopedEnvironment(const ScopedEnvironment&) = delete;
    ScopedEnvironment& operator=(const ScopedEnvironment&) = delete;

private:
    std::string name_;
    std::string previous_;
    bool had_previous_{false};
};

class ScopedTempDirectory {
public:
    ScopedTempDirectory() {
        std::string pattern =
            (std::filesystem::temp_directory_path() /
             "yume-chrome-helper-files-XXXXXX").string();
        std::vector<char> writable(pattern.begin(), pattern.end());
        writable.push_back('\0');
        const char* created = ::mkdtemp(writable.data());
        if (created == nullptr) {
            throw std::system_error(errno, std::generic_category(),
                                    "create helper test directory");
        }
        path_ = created;
    }

    ~ScopedTempDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    ScopedTempDirectory(const ScopedTempDirectory&) = delete;
    ScopedTempDirectory& operator=(const ScopedTempDirectory&) = delete;

    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

std::size_t OpenFdCount() {
    std::size_t count = 0;
    for (const auto& entry : std::filesystem::directory_iterator("/proc/self/fd")) {
        (void)entry;
        ++count;
    }
    return count;
}

pid_t ReadPid(const std::filesystem::path& path) {
    std::ifstream input(path);
    pid_t pid = -1;
    input >> pid;
    assert(pid > 0);
    return pid;
}

void ExpectReaped(pid_t pid) {
    int status = 0;
    errno = 0;
    assert(::waitpid(pid, &status, WNOHANG) == -1);
    assert(errno == ECHILD);
}

boost::asio::ip::tcp::socket ConnectedSocket(
        boost::asio::io_context& io,
        boost::asio::ip::tcp::socket* peer) {
    using boost::asio::ip::tcp;
    tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 0));
    tcp::socket client(io);
    client.connect(acceptor.local_endpoint());
    *peer = acceptor.accept();
    return client;
}

std::filesystem::path PidPath(const std::string& mode) {
    return std::filesystem::temp_directory_path() /
           ("yume-chrome-helper-test-" + std::to_string(::getpid()) + "-" + mode + ".pid");
}

void RunFailureCase(const std::filesystem::path& helper_path,
                    const std::string& mode,
                    const std::string& expected) {
    const auto pid_path = PidPath(mode);
    std::error_code ignored;
    std::filesystem::remove(pid_path, ignored);
    ScopedEnvironment mode_environment("YUME_TEST_HELPER_MODE", mode);
    ScopedEnvironment pid_environment("YUME_TEST_HELPER_PID_FILE", pid_path.string());

    boost::asio::io_context io;
    boost::asio::ip::tcp::socket peer(io);
    auto connected = ConnectedSocket(io, &peer);
    yume::client::ChromeTlsHelperOptions options;
    options.helper_path = helper_path;
    options.server_name = "localhost";
    options.handshake_timeout = std::chrono::milliseconds(1000);
    try {
        (void)yume::client::LaunchChromeTlsHelper(io, std::move(connected), options);
    } catch (const std::runtime_error& error) {
        if (std::string(error.what()).find(expected) == std::string::npos) {
            throw std::runtime_error(
                "helper mode " + mode + " returned unexpected error: " + error.what());
        }
        const pid_t pid = ReadPid(pid_path);
        ExpectReaped(pid);
        std::filesystem::remove(pid_path, ignored);
        return;
    }
    assert(false && "expected helper launch failure");
}

void RunSuccessCase(const std::filesystem::path& helper_path,
                    const std::string& mode) {
    const auto pid_path = PidPath(mode);
    std::error_code ignored;
    std::filesystem::remove(pid_path, ignored);
    ScopedEnvironment mode_environment("YUME_TEST_HELPER_MODE", mode);
    ScopedEnvironment pid_environment("YUME_TEST_HELPER_PID_FILE", pid_path.string());
    pid_t pid = -1;
    {
        boost::asio::io_context io;
        boost::asio::ip::tcp::socket peer(io);
        auto connected = ConnectedSocket(io, &peer);
        yume::client::ChromeTlsHelperOptions options;
        options.helper_path = helper_path;
        options.server_name = "localhost";
        options.handshake_timeout = std::chrono::milliseconds(1000);
        auto stream = yume::client::LaunchChromeTlsHelper(
            io, std::move(connected), options);
        assert(stream.is_helper());
        assert(stream.metadata().alpn == "h2");
        assert(stream.metadata().exporter.size() == 32);
        pid = ReadPid(pid_path);
    }
    ExpectReaped(pid);
    std::filesystem::remove(pid_path, ignored);
}

void ExpectPathFailure(const std::filesystem::path& helper_path,
                       const std::string& expected) {
    boost::asio::io_context io;
    boost::asio::ip::tcp::socket peer(io);
    auto connected = ConnectedSocket(io, &peer);
    yume::client::ChromeTlsHelperOptions options;
    options.helper_path = helper_path;
    options.server_name = "localhost";
    options.handshake_timeout = std::chrono::milliseconds(1000);
    try {
        (void)yume::client::LaunchChromeTlsHelper(
            io, std::move(connected), options);
    } catch (const std::exception& error) {
        if (std::string(error.what()).find(expected) == std::string::npos) {
            throw std::runtime_error(
                "helper path returned unexpected error: " +
                std::string(error.what()));
        }
        return;
    }
    assert(false && "expected helper path validation failure");
}

void RunPathValidationCases(const std::filesystem::path& helper_path) {
    ScopedTempDirectory temporary;
    const auto executable = temporary.path() / "helper";
    std::filesystem::copy_file(helper_path, executable);
    assert(::chmod(executable.c_str(), 0755) == 0);

    ExpectPathFailure("relative-helper", "must be absolute");
    ExpectPathFailure(temporary.path(), "not a regular file");

    const auto symlink = temporary.path() / "helper-link";
    std::filesystem::create_symlink(executable, symlink);
    ExpectPathFailure(symlink, "not a regular file");

    assert(::chmod(executable.c_str(), 0644) == 0);
    ExpectPathFailure(executable, "execute Chrome TLS helper");
    assert(::chmod(executable.c_str(), 0775) == 0);
    ExpectPathFailure(executable, "group- or world-writable");
    assert(::chmod(executable.c_str(), 0757) == 0);
    ExpectPathFailure(executable, "group- or world-writable");
}

void RunEchoCase(const std::filesystem::path& helper_path) {
    const auto pid_path = PidPath("echo-partial");
    std::error_code ignored;
    std::filesystem::remove(pid_path, ignored);
    ScopedEnvironment mode_environment("YUME_TEST_HELPER_MODE", "echo-partial");
    ScopedEnvironment pid_environment("YUME_TEST_HELPER_PID_FILE", pid_path.string());
    pid_t pid = -1;
    {
        boost::asio::io_context io;
        boost::asio::ip::tcp::socket peer(io);
        auto connected = ConnectedSocket(io, &peer);
        yume::client::ChromeTlsHelperOptions options;
        options.helper_path = helper_path;
        options.server_name = "localhost";
        options.handshake_timeout = std::chrono::milliseconds(1000);
        auto stream = yume::client::LaunchChromeTlsHelper(
            io, std::move(connected), options);
        pid = ReadPid(pid_path);
        std::array<std::uint8_t, 4096> sent{};
        for (std::size_t index = 0; index < sent.size(); ++index) {
            sent[index] = static_cast<std::uint8_t>(index & 0xffU);
        }
        std::array<std::uint8_t, 4096> received{};
        boost::asio::write(stream, boost::asio::buffer(sent));
        boost::asio::read(stream, boost::asio::buffer(received));
        assert(sent == received);
        stream.cancel_and_close();
    }
    ExpectReaped(pid);
    std::filesystem::remove(pid_path, ignored);
}

void RunChildHalfCloseCase(const std::filesystem::path& helper_path) {
    const auto pid_path = PidPath("ready-half-close");
    std::error_code ignored;
    std::filesystem::remove(pid_path, ignored);
    ScopedEnvironment mode_environment("YUME_TEST_HELPER_MODE", "ready-half-close");
    ScopedEnvironment pid_environment("YUME_TEST_HELPER_PID_FILE", pid_path.string());
    pid_t pid = -1;
    {
        boost::asio::io_context io;
        boost::asio::ip::tcp::socket peer(io);
        auto connected = ConnectedSocket(io, &peer);
        yume::client::ChromeTlsHelperOptions options;
        options.helper_path = helper_path;
        options.server_name = "localhost";
        options.handshake_timeout = std::chrono::milliseconds(1000);
        auto stream = yume::client::LaunchChromeTlsHelper(
            io, std::move(connected), options);
        pid = ReadPid(pid_path);
        std::array<std::uint8_t, 1> byte{};
        boost::system::error_code error;
        const std::size_t received = stream.read_some(
            boost::asio::buffer(byte), error);
        assert(received == 0);
        assert(error == boost::asio::error::eof);
        stream.cancel_and_close();
    }
    ExpectReaped(pid);
    std::filesystem::remove(pid_path, ignored);
}

void RunParentHalfCloseCase(const std::filesystem::path& helper_path) {
    const auto pid_path = PidPath("ready-wait-eof");
    std::error_code ignored;
    std::filesystem::remove(pid_path, ignored);
    ScopedEnvironment mode_environment("YUME_TEST_HELPER_MODE", "ready-wait-eof");
    ScopedEnvironment pid_environment("YUME_TEST_HELPER_PID_FILE", pid_path.string());
    pid_t pid = -1;
    {
        boost::asio::io_context io;
        boost::asio::ip::tcp::socket peer(io);
        auto connected = ConnectedSocket(io, &peer);
        yume::client::ChromeTlsHelperOptions options;
        options.helper_path = helper_path;
        options.server_name = "localhost";
        options.handshake_timeout = std::chrono::milliseconds(1000);
        auto stream = yume::client::LaunchChromeTlsHelper(
            io, std::move(connected), options);
        pid = ReadPid(pid_path);
        stream.shutdown_and_close();
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    ExpectReaped(pid);
    std::filesystem::remove(pid_path, ignored);
}

void RunCancellationCase(const std::filesystem::path& helper_path) {
    const auto pid_path = PidPath("ready-hang");
    std::error_code ignored;
    std::filesystem::remove(pid_path, ignored);
    ScopedEnvironment mode_environment("YUME_TEST_HELPER_MODE", "ready-hang");
    ScopedEnvironment pid_environment("YUME_TEST_HELPER_PID_FILE", pid_path.string());
    pid_t pid = -1;
    {
        boost::asio::io_context io;
        boost::asio::ip::tcp::socket peer(io);
        auto connected = ConnectedSocket(io, &peer);
        yume::client::ChromeTlsHelperOptions options;
        options.helper_path = helper_path;
        options.server_name = "localhost";
        options.handshake_timeout = std::chrono::milliseconds(1000);
        auto stream = yume::client::LaunchChromeTlsHelper(
            io, std::move(connected), options);
        pid = ReadPid(pid_path);
        std::array<std::uint8_t, 1> byte{};
        bool completed = false;
        boost::system::error_code completion_error;
        stream.async_read_some(boost::asio::buffer(byte),
            [&](const boost::system::error_code& error, std::size_t) {
                completed = true;
                completion_error = error;
            });
        stream.cancel_and_close();
        io.run();
        assert(completed);
        assert(completion_error);
    }
    ExpectReaped(pid);
    std::filesystem::remove(pid_path, ignored);
}

void RunHandshakeCancellationCase(const std::filesystem::path& helper_path) {
    using namespace std::chrono_literals;
    const auto pid_path = PidPath("hang-cancelled");
    std::error_code ignored;
    std::filesystem::remove(pid_path, ignored);
    ScopedEnvironment mode_environment("YUME_TEST_HELPER_MODE", "hang");
    ScopedEnvironment pid_environment(
        "YUME_TEST_HELPER_PID_FILE", pid_path.string());

    boost::asio::io_context io;
    boost::asio::ip::tcp::socket peer(io);
    auto connected = ConnectedSocket(io, &peer);
    std::atomic<bool> stop{false};
    yume::client::ChromeTlsHelperOptions options;
    options.helper_path = helper_path;
    options.server_name = "localhost";
    options.handshake_timeout = 5s;
    options.should_stop = [&]() {
        return stop.load(std::memory_order_acquire);
    };
    std::thread canceller([&]() {
        std::this_thread::sleep_for(30ms);
        stop.store(true, std::memory_order_release);
    });
    const auto started = std::chrono::steady_clock::now();
    try {
        (void)yume::client::LaunchChromeTlsHelper(
            io, std::move(connected), options);
    } catch (const std::runtime_error& error) {
        const auto elapsed = std::chrono::steady_clock::now() - started;
        canceller.join();
        if (std::string(error.what()).find("cancelled") == std::string::npos ||
            elapsed >= 500ms) {
            throw;
        }
        const pid_t pid = ReadPid(pid_path);
        ExpectReaped(pid);
        std::filesystem::remove(pid_path, ignored);
        return;
    }
    canceller.join();
    assert(false && "expected helper handshake cancellation");
}

void RunRepeatedLifecycleCases(const std::filesystem::path& helper_path,
                               std::size_t expected_fd_count) {
    constexpr int kIterations = 64;
    for (int iteration = 0; iteration < kIterations; ++iteration) {
        RunSuccessCase(helper_path, "ready");
        assert(OpenFdCount() == expected_fd_count);
    }
}

}  // namespace

int main(int argc, char** argv) {
    assert(argc == 2);
    const std::filesystem::path helper_path =
        std::filesystem::absolute(argv[1]);
    const std::size_t fd_count = OpenFdCount();

    RunSuccessCase(helper_path, "partial-ready");
    RunFailureCase(helper_path, "error", "synthetic helper rejection");
    RunFailureCase(helper_path, "wrong-build", "build identity");
    RunFailureCase(helper_path, "wrong-alpn", "negotiate h2");
    RunFailureCase(helper_path, "wrong-id", "connection ID");
    RunFailureCase(helper_path, "wrong-version", "version");
    RunFailureCase(helper_path, "truncated", "closed early");
    RunFailureCase(helper_path, "oversized", "exceeds cap");
    RunFailureCase(helper_path, "crash", "closed early");
    RunFailureCase(helper_path, "hang", "timed out");
    RunHandshakeCancellationCase(helper_path);

    RunPathValidationCases(helper_path);
    RunEchoCase(helper_path);
    RunChildHalfCloseCase(helper_path);
    RunParentHalfCloseCase(helper_path);
    RunCancellationCase(helper_path);
    RunRepeatedLifecycleCases(helper_path, fd_count);

    assert(OpenFdCount() == fd_count);
    return 0;
}
