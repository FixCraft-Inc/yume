/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/session/client_session.hpp"
#include "facade/session/inproc_client.hpp"
#include "facade/session/server_session.hpp"
#include "facade/logging/log_sink.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <future>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "core/runtime/operation_status.hpp"
#include "core/security/secret_file.hpp"
#include "server/runtime/controller.hpp"

namespace {

using namespace std::chrono_literals;

void Expect(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        const auto stamp = std::chrono::steady_clock::now()
                               .time_since_epoch()
                               .count();
        path_ = std::filesystem::temp_directory_path() /
                ("yume-lifecycle-test-" + std::to_string(stamp));
        std::error_code error;
        if (!std::filesystem::create_directory(path_, error) || error) {
            throw std::runtime_error(
                "failed to create lifecycle test temporary directory");
        }
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    TemporaryDirectory(TemporaryDirectory const&) = delete;
    TemporaryDirectory& operator=(TemporaryDirectory const&) = delete;

    std::filesystem::path const& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

void WriteTestSecret(std::filesystem::path const& path, std::uint8_t digit) {
    std::vector<std::uint8_t> encoded(64, digit);
    std::string error;
    if (!yume::security::WriteFileExclusive0600(path, encoded, &error)) {
        throw std::runtime_error(
            error.empty() ? "failed to create test secret" : error);
    }
}

void TestLogSubscriberReentryAndExceptions() {
    auto& sink = yume::facade::LogSink::instance();
    int token = 0;
    std::atomic<int> calls{0};
    token = sink.subscribe([&](yume::facade::LogEntry const& entry) {
        calls.fetch_add(1, std::memory_order_relaxed);
        if (entry.message == "outer") {
            sink.unsubscribe(token);
            sink.push(yume::facade::LogLevel::Info, "test", "inner");
            throw std::runtime_error("intentional log subscriber failure");
        }
    });
    sink.push(yume::facade::LogLevel::Info, "test", "outer");
    Expect(calls.load(std::memory_order_relaxed) == 1,
           "log subscriber could not unsubscribe and re-enter safely");
}

void TestInProcPreReadyCancellation() {
#if defined(_WIN32)
    return;
#else
    TemporaryDirectory temp;
    const auto identity_path = temp.path() / "identity.key";
    const auto obfs_path = temp.path() / "obfs.hex";
    const auto inner_path = temp.path() / "inner.hex";
    // Validation only checks that the identity exists before the TLS
    // handshake. The deliberately stalled peer prevents this placeholder from
    // ever reaching the composite-key parser.
    WriteTestSecret(identity_path, static_cast<std::uint8_t>('2'));
    WriteTestSecret(obfs_path, static_cast<std::uint8_t>('0'));
    WriteTestSecret(inner_path, static_cast<std::uint8_t>('1'));

    boost::asio::io_context server_io;
    boost::asio::ip::tcp::acceptor acceptor(
        server_io,
        boost::asio::ip::tcp::endpoint(
            boost::asio::ip::address_v4::loopback(), 0));
    const auto endpoint = acceptor.local_endpoint();
    std::promise<void> accepted_promise;
    auto accepted = accepted_promise.get_future();
    std::atomic<bool> release_server{false};
    std::thread server([&]() {
        boost::system::error_code error;
        boost::asio::ip::tcp::socket peer(server_io);
        acceptor.accept(peer, error);
        accepted_promise.set_value();
        while (!error && !release_server.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(1ms);
        }
    });

    yume::client::ClientConfig cfg;
    cfg.server = "127.0.0.1";
    cfg.port = endpoint.port();
    cfg.io_threads = 1;
    cfg.identity = identity_path.string();
    cfg.obfs_secret_file = obfs_path.string();
    cfg.inner_psk_file = inner_path.string();
    cfg.anonym_ca_material_id.clear();
    cfg.auto_attach_local = false;
    cfg.instance_name = "lifecycle-pre-ready";

    yume::facade::InProcClient client;
    std::atomic<bool> start_result{true};
    yume::runtime::OperationStatus start_status =
        yume::runtime::OperationStatus::InternalError;
    std::string start_error;
    std::thread starter([&]() {
        start_result.store(
            client.start(cfg, &start_error, 10s, &start_status),
            std::memory_order_release);
    });

    if (accepted.wait_for(5s) != std::future_status::ready) {
        client.request_stop("test setup failed");
        client.stop();
        release_server.store(true, std::memory_order_release);
        boost::asio::io_context wake_io;
        boost::asio::ip::tcp::socket wake(wake_io);
        boost::system::error_code ignored;
        wake.connect(endpoint, ignored);
        acceptor.close(ignored);
        starter.join();
        server.join();
        throw std::runtime_error(
            "in-process client did not reach the stalled TLS peer");
    }

    std::atomic<bool> stop_requests{false};
    std::thread requester([&]() {
        while (!stop_requests.load(std::memory_order_acquire)) {
            std::string error;
            yume::runtime::OperationStatus status =
                yume::runtime::OperationStatus::InternalError;
            (void)client.request(
                "runtime.status", nlohmann::json::object(), &error, 1,
                &status);
        }
    });

    const auto stop_started = std::chrono::steady_clock::now();
    std::thread first_stop([&]() { client.stop(nullptr, "race stop one"); });
    std::thread second_stop([&]() { client.stop(nullptr, "race stop two"); });
    first_stop.join();
    second_stop.join();
    starter.join();
    const auto stop_elapsed = std::chrono::steady_clock::now() - stop_started;

    stop_requests.store(true, std::memory_order_release);
    requester.join();
    release_server.store(true, std::memory_order_release);
    server.join();

    Expect(!start_result.load(std::memory_order_acquire),
           "cancelled in-process startup unexpectedly succeeded");
    Expect(start_status == yume::runtime::OperationStatus::NotRunning,
           "cancelled in-process startup returned the wrong typed status");
    Expect(!client.running(),
           "in-process client remained running after concurrent stop");
    Expect(!client.status().ipc_available,
           "in-process client published readiness after cancellation");
    Expect(stop_elapsed < 1s,
           "pre-ready TLS cancellation did not stop promptly");
#endif
}

void TestInProcAdmissionCancellation() {
    yume::facade::InProcClient client;
    auto cancelled = std::make_shared<std::atomic<bool>>(true);
    yume::runtime::OperationStatus status =
        yume::runtime::OperationStatus::InternalError;
    std::string error;
    Expect(!client.start({}, &error, 1s, &status, cancelled),
           "pre-cancelled in-process startup unexpectedly succeeded");
    Expect(status == yume::runtime::OperationStatus::NotRunning,
           "pre-cancelled in-process startup returned the wrong status");
    Expect(!client.running(),
           "pre-cancelled in-process startup published running state");
}

yume::client::ClientConfig InvalidClientConfig() {
    yume::client::ClientConfig cfg;
    cfg.server = "127.0.0.1";
    cfg.port = 443;
    cfg.anonym_ca_material_id.clear();
    cfg.auth_key_material_id = "missing-lifecycle-test-material";
    return cfg;
}

void TestClientFacadeReentrantStopAndThrowingCallbacks() {
    {
        yume::facade::ClientSession session(InvalidClientConfig());
        std::atomic<bool> requested_stop{false};
        std::atomic<bool> late_connected{false};
        session.set_status_callback(
            [&](yume::facade::ClientStatus const& status) {
                if (requested_stop.load(std::memory_order_acquire) &&
                    status.state == yume::facade::ConnectionState::Connected) {
                    late_connected.store(true, std::memory_order_release);
                }
                if (status.message == "starting yume client runtime" &&
                    !requested_stop.exchange(true, std::memory_order_acq_rel)) {
                    session.stop();
                }
            });
        std::string error;
        Expect(session.start(&error),
               "client facade failed to admit a reentrant-stop test start");
        session.stop();
        Expect(!late_connected.load(std::memory_order_acquire),
               "client facade emitted Connected after stop intent");
    }

    {
        yume::facade::ClientSession session(InvalidClientConfig());
        session.set_status_callback(
            [](yume::facade::ClientStatus const&) {
                throw std::runtime_error("intentional client callback failure");
            });
        std::string error;
        Expect(session.start(&error),
               "throwing client callback escaped start()");
        session.stop();
    }
}

yume::server::ServerConfig InvalidServerConfig() {
    yume::server::ServerConfig cfg;
    cfg.listen_port = 18443;
    return cfg;
}

void TestServerFacadeReentrantStopAndThrowingCallbacks() {
    {
        yume::facade::ServerSession session(InvalidServerConfig());
        std::atomic<bool> requested_stop{false};
        std::atomic<bool> late_running{false};
        session.set_status_callback(
            [&](yume::facade::ServerStatus const& status) {
                if (requested_stop.load(std::memory_order_acquire) &&
                    status.running) {
                    late_running.store(true, std::memory_order_release);
                }
                if (status.message == "starting server" &&
                    !requested_stop.exchange(true, std::memory_order_acq_rel)) {
                    session.stop();
                }
            });
        std::string error;
        Expect(session.start(&error),
               "server facade failed to admit a reentrant-stop test start");
        session.stop();
        Expect(!late_running.load(std::memory_order_acquire),
               "server facade emitted Running after stop intent");
    }

    {
        yume::facade::ServerSession session(InvalidServerConfig());
        session.set_status_callback(
            [](yume::facade::ServerStatus const&) {
                throw std::runtime_error("intentional server callback failure");
            });
        std::string error;
        Expect(session.start(&error),
               "throwing server callback escaped start()");
        session.stop();
    }
}

void TestFacadeStartStopStress() {
    for (int iteration = 0; iteration < 40; ++iteration) {
        yume::facade::ClientSession client(InvalidClientConfig());
        std::atomic<bool> go{false};
        std::thread starter([&]() {
            while (!go.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            (void)client.start();
        });
        std::thread stopper([&]() {
            while (!go.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            client.stop();
        });
        go.store(true, std::memory_order_release);
        starter.join();
        stopper.join();
        client.stop();

        yume::facade::ServerSession server(InvalidServerConfig());
        go.store(false, std::memory_order_release);
        std::thread server_starter([&]() {
            while (!go.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            (void)server.start();
        });
        std::thread server_stopper([&]() {
            while (!go.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            server.stop();
        });
        go.store(true, std::memory_order_release);
        server_starter.join();
        server_stopper.join();
        server.stop();
    }
}

void TestServerControllerStartStopReloadStress() {
    yume::server::RuntimeController controller;
    const auto cfg = InvalidServerConfig();
    for (int iteration = 0; iteration < 60; ++iteration) {
        std::atomic<bool> go{false};
        std::thread starter([&]() {
            while (!go.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            std::string error;
            (void)controller.start(cfg, &error);
        });
        std::thread stopper([&]() {
            while (!go.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            (void)controller.stop();
        });
        std::thread reloader([&]() {
            while (!go.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }
            std::string error;
            (void)controller.reload_auth(&error);
        });
        go.store(true, std::memory_order_release);
        starter.join();
        stopper.join();
        reloader.join();
        (void)controller.stop();
    }
    Expect(!controller.running(),
           "server controller remained running after lifecycle stress");
}

}  // namespace

int main() {
    TestLogSubscriberReentryAndExceptions();
    TestInProcAdmissionCancellation();
    TestInProcPreReadyCancellation();
    TestClientFacadeReentrantStopAndThrowingCallbacks();
    TestServerFacadeReentrantStopAndThrowingCallbacks();
    TestFacadeStartStopStress();
    TestServerControllerStartStopReloadStress();
    return 0;
}
