#include "server/host/http_backend_client.hpp"
#include "server/session/h2_cover_fetches.hpp"

#include <cassert>
#include <chrono>
#include <functional>
#include <memory>
#include <string>

#include <boost/asio.hpp>

namespace {

using boost::asio::ip::tcp;
using yume::server::host::BackendFetch;
using yume::server::host::BackendHttpLimits;
using yume::server::host::fetch_loopback_http;
using yume::server::detail::H2CoverFetches;

void CancellationCompletesExactlyOnce() {
    boost::asio::io_context io;
    tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 0));
    std::shared_ptr<tcp::socket> accepted;
    std::shared_ptr<BackendFetch> fetch;
    int callbacks = 0;
    bool cancellation_was_prompt = false;
    const auto started = std::chrono::steady_clock::now();

    acceptor.async_accept([&](const boost::system::error_code& ec,
                              tcp::socket socket) {
        assert(!ec);
        accepted = std::make_shared<tcp::socket>(std::move(socket));
        fetch->cancel();
        fetch->cancel();
    });

    BackendHttpLimits limits;
    limits.connect_timeout = std::chrono::seconds(5);
    limits.response_timeout = std::chrono::seconds(5);
    fetch = fetch_loopback_http(
        io.get_executor(), "127.0.0.1", acceptor.local_endpoint().port(),
        "GET", "/slow", limits,
        [&](std::string error, auto) {
            ++callbacks;
            assert(error == "backend request cancelled");
            cancellation_was_prompt =
                std::chrono::steady_clock::now() - started <
                std::chrono::seconds(1);
        });

    io.run();
    assert(accepted);
    assert(callbacks == 1);
    assert(cancellation_was_prompt);
}

void SuccessfulFetchAfterCancellation() {
    boost::asio::io_context io;
    tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 0));
    std::shared_ptr<tcp::socket> accepted;
    std::shared_ptr<std::string> response;
    bool complete = false;

    acceptor.async_accept([&](const boost::system::error_code& ec,
                              tcp::socket socket) {
        assert(!ec);
        accepted = std::make_shared<tcp::socket>(std::move(socket));
        response = std::make_shared<std::string>(
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
            "Connection: close\r\n\r\nok");
        boost::asio::async_write(
            *accepted, boost::asio::buffer(*response),
            [accepted, response](const boost::system::error_code& write_ec,
                                 std::size_t) {
                assert(!write_ec);
            });
    });

    auto fetch = fetch_loopback_http(
        io.get_executor(), "127.0.0.1", acceptor.local_endpoint().port(),
        "GET", "/healthy", {},
        [&](std::string error, auto backend_response) {
            assert(error.empty());
            assert(backend_response.status == 200);
            assert((backend_response.body ==
                    std::vector<std::uint8_t>{'o', 'k'}));
            complete = true;
        });
    assert(fetch);

    io.run();
    assert(complete);
}

void SlowBackendSaturatesCancelsAndRecovers() {
    boost::asio::io_context io;
    tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 0));
    std::vector<std::shared_ptr<tcp::socket>> accepted_sockets;
    H2CoverFetches fetches;
    int accepted_count = 0;
    int cancelled_callbacks = 0;
    boost::asio::steady_timer watchdog(io, std::chrono::seconds(2));
    watchdog.async_wait([](const boost::system::error_code& ec) {
        assert(ec == boost::asio::error::operation_aborted);
    });

    auto start_fetch = [&](std::int32_t stream_id, bool already_admitted) {
        if (!already_admitted) {
            assert(fetches.admit(stream_id));
        }
        auto fetch = fetch_loopback_http(
            io.get_executor(), "127.0.0.1",
            acceptor.local_endpoint().port(), "GET", "/slow", {},
            [&, stream_id](std::string error, auto) {
                assert(error == "backend request cancelled");
                assert(!fetches.complete_fetch(stream_id));
                ++cancelled_callbacks;
                if (cancelled_callbacks == 5) {
                    watchdog.cancel();
                }
            });
        assert(fetches.attach_cancel(
            stream_id, [fetch = std::move(fetch)]() { fetch->cancel(); }));
    };

    std::function<void()> accept_next;
    accept_next = [&]() {
        acceptor.async_accept(
            [&](const boost::system::error_code& ec, tcp::socket socket) {
                assert(!ec);
                accepted_sockets.push_back(
                    std::make_shared<tcp::socket>(std::move(socket)));
                ++accepted_count;
                if (accepted_count < 5) {
                    accept_next();
                }
                if (accepted_count == 4) {
                    assert(fetches.size() ==
                           H2CoverFetches::kPerConnectionLimit);
                    assert(!fetches.admit(99));
                    assert(fetches.close_stream(1));
                    assert(fetches.admit(5));
                    start_fetch(5, true);
                } else if (accepted_count == 5) {
                    fetches.cancel_all();
                    assert(fetches.size() == 0);
                }
            });
    };
    accept_next();
    for (std::int32_t stream_id = 1;
         stream_id <=
             static_cast<std::int32_t>(H2CoverFetches::kPerConnectionLimit);
         ++stream_id) {
        start_fetch(stream_id, false);
    }

    io.run();
    assert(accepted_count == 5);
    assert(cancelled_callbacks == 5);
}

}  // namespace

int main() {
    CancellationCompletesExactlyOnce();
    SuccessfulFetchAfterCancellation();
    // Reuse the process-wide registry across cycles. Any missed reset/close
    // release would make a later cycle fail admission before process teardown.
    for (int cycle = 0; cycle < 20; ++cycle) {
        SlowBackendSaturatesCancelsAndRecovers();
    }
    return 0;
}
