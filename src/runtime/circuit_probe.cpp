/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// A test client for circuit 1 against running daemons. It connects with a
// client kit to the entry, fetches and verifies the routes view on
// yume.routes, builds circuits through the hops it is told by name and
// carries TCP streams through the exit to a target that echoes. It prints one
// JSON line saying what happened, for tests/run_native_circuit_test.py. It is
// not installed.

#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/post.hpp>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <future>
#include <iostream>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "common/service_name.hpp"
#include "config/v1/config.hpp"
#include "fs/bounded_file.hpp"
#include "providers/circuit_crypto.hpp"
#include "runtime/circuit_client.hpp"
#include "runtime/cluster_list.hpp"
#include "runtime/native_endpoint.hpp"

namespace {

using namespace std::chrono_literals;
using yume::engine::Buffer;
using yume::engine::ReceivedRecord;
using yume::engine::Result;
using yume::engine::ServiceKind;
using yume::engine::SessionEngine;
using yume::engine::Status;
using yume::engine::StatusCode;
using yume::engine::StreamResponder;
using yume::runtime::circuit::ClientCircuit;
using Json = nlohmann::json;
using Clock = std::chrono::steady_clock;
namespace circuit1 = yume::circuit1;
namespace cc = yume::providers::circuit;
namespace keys = yume::providers::keys;

class Failure final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct Options final {
    std::filesystem::path config;
    std::string connect;
    std::filesystem::path operator_key;
    std::vector<std::string> hops;
    std::string target_host;
    std::uint16_t target_port{0U};
    std::size_t bytes{65536U};
    std::size_t circuits{1U};
    std::chrono::milliseconds load{0};
    std::filesystem::path ready_file;
};

std::size_t number(std::string_view text, std::size_t maximum) {
    std::size_t value = 0U;
    const auto [end, error] =
        std::from_chars(text.data(), text.data() + text.size(), value);
    if (error != std::errc() || end != text.data() + text.size() ||
        value > maximum)
        throw Failure("bad number: " + std::string(text));
    return value;
}

Options parse(int argc, char** argv) {
    Options options;
    for (int index = 1; index < argc; ++index) {
        const std::string_view flag = argv[index];
        if (index + 1 >= argc)
            throw Failure("missing value for " + std::string(flag));
        const std::string value = argv[++index];
        if (flag == "--config") {
            options.config = value;
        } else if (flag == "--connect") {
            options.connect = value;
        } else if (flag == "--operator-key") {
            options.operator_key = value;
        } else if (flag == "--hops") {
            for (std::size_t start = 0U; start <= value.size();) {
                const auto comma =
                    std::min(value.find(',', start), value.size());
                options.hops.push_back(value.substr(start, comma - start));
                start = comma + 1U;
            }
        } else if (flag == "--target") {
            const auto colon = value.rfind(':');
            if (colon == std::string::npos)
                throw Failure("--target needs HOST:PORT");
            options.target_host = value.substr(0U, colon);
            options.target_port = static_cast<std::uint16_t>(
                number(std::string_view(value).substr(colon + 1U), 65535U));
        } else if (flag == "--bytes") {
            options.bytes = number(value, std::size_t{64} * 1024U * 1024U);
        } else if (flag == "--circuits") {
            options.circuits = number(value, 16U);
        } else if (flag == "--load-ms") {
            options.load = std::chrono::milliseconds(number(value, 600'000U));
        } else if (flag == "--ready-file") {
            options.ready_file = value;
        } else {
            throw Failure("unknown flag " + std::string(flag));
        }
    }
    if (options.config.empty() || options.operator_key.empty() ||
        options.hops.empty() || options.target_host.empty() ||
        options.circuits == 0U)
        throw Failure(
            "usage: yume_circuit_probe --config FILE --operator-key FILE "
            "--hops A,B[,C] --target HOST:PORT [--connect ADDRESS] [--bytes N] "
            "[--circuits N] [--load-ms N --ready-file FILE]");
    return options;
}

// The names the control protocol gives status codes.
std::string code_name(const Status& status) {
    switch (status.code()) {
        case StatusCode::Ok:
            return "ok";
        case StatusCode::InvalidArgument:
            return "invalid-argument";
        case StatusCode::ResourceExhausted:
            return "resource-exhausted";
        case StatusCode::Cancelled:
            return "cancelled";
        case StatusCode::Closed:
            return "closed";
        case StatusCode::FailedPrecondition:
            return "failed-precondition";
        case StatusCode::NotFound:
            return "not-found";
        case StatusCode::AlreadyExists:
            return "already-exists";
        case StatusCode::ProviderMismatch:
            return "provider-mismatch";
        case StatusCode::Internal:
            return "internal";
        case StatusCode::EndOfStream:
            return "end-of-stream";
        case StatusCode::PermissionDenied:
            return "permission-denied";
        case StatusCode::AddressInUse:
            return "address-in-use";
    }
    return "unknown";
}

// The probe offers its kit's services only so the session can start, and
// accepts no stream the server opens.
class RefusingHandler final : public yume::engine::StreamHandler {
public:
    RefusingHandler(yume::engine::ProviderDescriptor descriptor,
                    ServiceKind kind) noexcept
        : descriptor_(std::move(descriptor)), kind_(kind) {}
    const yume::engine::ProviderDescriptor& descriptor()
        const noexcept override {
        return descriptor_;
    }
    ServiceKind service_kind() const noexcept override { return kind_; }
    Status authorize(const yume::engine::StreamOpenContext&) override {
        return Status(StatusCode::FailedPrecondition);
    }
    void on_open(yume::engine::StreamOpenContext,
                 std::shared_ptr<StreamResponder> stream) override {
        if (stream) stream->close(Status(StatusCode::FailedPrecondition));
    }

private:
    yume::engine::ProviderDescriptor descriptor_;
    ServiceKind kind_;
};

std::string read_text(const std::filesystem::path& path, std::size_t maximum) {
    std::string text;
    if (!yume::runtime::read_text_file_bounded(path, maximum, &text))
        throw Failure("cannot read " + path.string());
    return text;
}

// One execution context on its own thread, and a way to run work there and
// wait for its result.
class Runner final {
public:
    Runner()
        : context_(take(yume::providers::AsioExecutionContext::create(
              yume::engine::ExecutorAffinity(311U)))),
          worker_([this] {
              for (;;) {
                  try {
                      context_->run();
                      return;
                  } catch (...) {
                  }
              }
          }) {}
    ~Runner() { join(); }
    // Ends the thread once its work is done. OpenSSL frees a library
    // context's per-thread state when the thread exits while the context is
    // still alive, so run() joins before its contexts go.
    void join() {
        context_->finish();
        if (worker_.joinable()) worker_.join();
    }
    const std::shared_ptr<yume::providers::AsioExecutionContext>& context()
        const {
        return context_;
    }
    template <typename Value>
    static Value take(Result<Value> result) {
        if (!result.ok())
            throw Failure(code_name(result.status()) + " " +
                          result.status().message());
        return std::move(result).take_value();
    }
    // Runs start on the context with a promise for its answer, and waits.
    template <typename Value, typename Start>
    Value wait(Start start, std::chrono::milliseconds limit = 30s) {
        auto promise = std::make_shared<std::promise<Value>>();
        auto future = promise->get_future();
        boost::asio::post(
            context_->executor(),
            [promise, start = std::move(start)]() mutable {
                try {
                    start(promise);
                } catch (...) {
                    promise->set_exception(std::current_exception());
                }
            });
        if (future.wait_for(limit) != std::future_status::ready)
            throw Failure("timed out");
        return future.get();
    }

private:
    std::shared_ptr<yume::providers::AsioExecutionContext> context_;
    std::thread worker_;
};

std::string reason_name(circuit1::CircuitReason reason) {
    switch (reason) {
        case circuit1::CircuitReason::Unreachable:
            return "unreachable";
        case circuit1::CircuitReason::Busy:
            return "busy";
        case circuit1::CircuitReason::Timeout:
            return "timeout";
        case circuit1::CircuitReason::Protocol:
            return "protocol";
        case circuit1::CircuitReason::Refused:
            return "refused";
        case circuit1::CircuitReason::Closing:
            return "closing";
    }
    return "unknown";
}

yume::ytp1::Destination target(const Options& options) {
    yume::ytp1::Destination destination;
    destination.transport = yume::ytp1::TransportProtocol::Tcp;
    destination.port = options.target_port;
    const auto address = boost::asio::ip::make_address_v4(options.target_host);
    const auto bytes = address.to_bytes();
    destination.address_kind = yume::ytp1::AddressKind::Ipv4;
    destination.address_length = 4U;
    std::copy(bytes.begin(), bytes.end(), destination.address.begin());
    return destination;
}

// Reads a stream to its end, up to maximum bytes.
std::vector<std::byte> read_all(Runner& runner,
                                const std::shared_ptr<StreamResponder>& stream,
                                std::size_t maximum) {
    return runner.wait<std::vector<std::byte>>([stream, maximum](auto promise) {
        auto received = std::make_shared<std::vector<std::byte>>();
        auto next = std::make_shared<std::function<void()>>();
        *next = [stream, maximum, promise, received, next] {
            stream->async_read({}, [stream, maximum, promise, received,
                                    next](Result<ReceivedRecord> result) {
                if (!result.ok()) {
                    *next = nullptr;
                    if (result.status().code() == StatusCode::EndOfStream)
                        promise->set_value(std::move(*received));
                    else
                        promise->set_exception(std::make_exception_ptr(Failure(
                            "read failed: " + code_name(result.status()))));
                    return;
                }
                const auto bytes = result.value().payload().bytes();
                if (received->size() + bytes.size() > maximum) {
                    *next = nullptr;
                    promise->set_exception(
                        std::make_exception_ptr(Failure("stream too long")));
                    return;
                }
                received->insert(received->end(), bytes.begin(), bytes.end());
                (*next)();
            });
        };
        (*next)();
    });
}

// Writes data in pieces, ends the write direction, and reads the echo back.
Status echo(Runner& runner, const std::shared_ptr<StreamResponder>& stream,
            std::shared_ptr<const std::vector<std::byte>> source,
            std::size_t* echoed) {
    auto received = std::make_shared<std::size_t>(0U);
    auto status = runner.wait<Status>(
        [stream, source, received](auto promise) {
            const auto& data = *source;
            auto offset = std::make_shared<std::size_t>(0U);
            auto write = std::make_shared<std::function<void()>>();
            *write = [stream, source, offset, write] {
                const auto& data = *source;
                if (*offset == data.size()) {
                    // Clearing *write destroys this very function, so nothing
                    // it captured is touched after that.
                    const auto ending = stream;
                    (void)ending->shutdown_write();
                    *write = nullptr;
                    return;
                }
                const auto size =
                    std::min<std::size_t>(data.size() - *offset, 16384U);
                auto piece = Buffer::copy_from(
                    std::span(data).subspan(*offset, size), size);
                if (!piece.ok()) {
                    *write = nullptr;
                    return;
                }
                *offset += size;
                // The function holds itself, so a failed write, such as to
                // a destination the exit refused, clears it too.
                stream->async_write(std::move(piece).take_value(), {},
                                    [write](Status status, std::size_t) {
                                        if (!status.ok()) {
                                            *write = nullptr;
                                        } else if (*write) {
                                            (*write)();
                                        }
                                    });
            };
            (*write)();
            (void)data;
            auto read = std::make_shared<std::function<void()>>();
            *read = [stream, source, promise, received, read] {
                stream->async_read({}, [source, promise, received,
                                        read](Result<ReceivedRecord> result) {
                    const auto& data = *source;
                    if (!result.ok()) {
                        *read = nullptr;
                        promise->set_value(
                            result.status().code() == StatusCode::EndOfStream &&
                                    *received == data.size()
                                ? Status::success()
                                : result.status());
                        return;
                    }
                    const auto bytes = result.value().payload().bytes();
                    if (*received + bytes.size() > data.size() ||
                        !std::equal(bytes.begin(), bytes.end(),
                                    data.begin() + static_cast<std::ptrdiff_t>(
                                                       *received))) {
                        *read = nullptr;
                        promise->set_value(
                            Status(StatusCode::Internal, "echo mismatch"));
                        return;
                    }
                    *received += bytes.size();
                    (*read)();
                });
            };
            (*read)();
        },
        std::chrono::minutes(5));
    *echoed = *received;
    return status;
}

// Echoes pieces for as long as limit allows or until the stream fails.
Status load(Runner& runner, const std::shared_ptr<StreamResponder>& stream,
            std::chrono::milliseconds limit, std::size_t* echoed) {
    const auto until = Clock::now() + limit;
    std::vector<std::byte> piece(16384U);
    for (std::size_t index = 0U; index < piece.size(); ++index)
        piece[index] = static_cast<std::byte>(index * 13U + 1U);
    while (Clock::now() < until) {
        auto echo_piece = [stream, &piece](auto promise) {
            auto buffer = Buffer::copy_from(piece, piece.size());
            if (!buffer.ok()) return promise->set_value(buffer.status());
            stream->async_write(
                std::move(buffer).take_value(), {},
                [stream, promise, received = std::make_shared<std::size_t>(0U),
                 size = piece.size()](Status written, std::size_t) {
                    if (!written.ok()) return promise->set_value(written);
                    auto read = std::make_shared<std::function<void()>>();
                    *read = [stream, promise, received, size, read] {
                        stream->async_read(
                            {}, [promise, received, size,
                                 read](Result<ReceivedRecord> result) {
                                if (!result.ok()) {
                                    *read = nullptr;
                                    return promise->set_value(result.status());
                                }
                                *received += result.value().payload().size();
                                if (*received >= size) {
                                    *read = nullptr;
                                    return promise->set_value(
                                        Status::success());
                                }
                                (*read)();
                            });
                    };
                    (*read)();
                });
        };
        // A piece may wait longer than the nodes' 30-second stall and rekey
        // bounds, so the hop that sees a break reports it before this gives
        // up.
        const auto status = runner.wait<Status>(echo_piece, 60s);
        if (!status.ok()) return status;
        *echoed += piece.size();
    }
    return Status::success();
}

int run(const Options& options) {
    Runner runner;
    Json report = Json::object();
    const auto config = yume::config::v1::ParseJson(
        read_text(options.config, yume::config::v1::kMaxDocumentBytes));
    const auto base = options.config.parent_path();
    const auto operator_key = read_text(options.operator_key, 64U * 1024U);

    yume::runtime::NativeEndpointOptions endpoint_options;
    endpoint_options.max_sessions = 1U;
    endpoint_options.max_pending_starts = 1U;
    endpoint_options.connection_address = options.connect;
    endpoint_options.caller_runs_socks5_adapters = std::any_of(
        config.adapters().begin(), config.adapters().end(),
        [](const auto& adapter) {
            return std::holds_alternative<yume::config::v1::Socks5Adapter>(
                adapter);
        });
    endpoint_options.caller_runs_forward_adapters = std::any_of(
        config.adapters().begin(), config.adapters().end(),
        [](const auto& adapter) {
            return std::holds_alternative<yume::config::v1::ForwardAdapter>(
                adapter);
        });
    auto endpoint = runner.wait<std::shared_ptr<yume::runtime::NativeEndpoint>>(
        [&](auto promise) {
            std::vector<yume::runtime::NativeServiceBinding> bindings;
            for (const auto& service : config.services()) {
                const bool packet =
                    service.kind() == yume::config::v1::ServiceKind::Packet;
                auto capabilities = yume::engine::mandatory_capabilities(
                    yume::engine::ProviderKind::StreamHandler);
                if (packet)
                    capabilities = capabilities.with(
                        yume::engine::Capability::PacketChannels);
                bindings.push_back(
                    {service.name(),
                     std::make_shared<RefusingHandler>(
                         Runner::take(yume::engine::ProviderDescriptor::create(
                             "yume.probe-refuse",
                             yume::engine::ProviderKind::StreamHandler, 1U,
                             capabilities)),
                         packet ? ServiceKind::PacketChannel
                                : ServiceKind::ByteStream)});
            }
            promise->set_value(
                Runner::take(yume::runtime::NativeEndpoint::create(
                    runner.context(), config, base, std::move(bindings),
                    std::move(endpoint_options))));
        });
    const auto session =
        runner.wait<std::shared_ptr<SessionEngine>>([&](auto promise) {
            const auto started = endpoint->async_start_session(
                [promise](Result<std::shared_ptr<SessionEngine>> result) {
                    if (result.ok())
                        promise->set_value(std::move(result).take_value());
                    else
                        promise->set_exception(std::make_exception_ptr(Failure(
                            "session failed: " + code_name(result.status()))));
                });
            if (!started.ok())
                throw Failure("session refused: " + code_name(started));
        });
    const auto entry_identity =
        Runner::take(session->authenticated_peer()).identity();

    // The routes view: the signature, then the view, then the end.
    auto routes_stream =
        runner.wait<std::shared_ptr<StreamResponder>>([&](auto promise) {
            session->async_open(
                yume::common::kRoutesServiceName, ServiceKind::ByteStream,
                [promise](Result<std::shared_ptr<StreamResponder>> result) {
                    if (result.ok())
                        promise->set_value(std::move(result).take_value());
                    else
                        promise->set_exception(std::make_exception_ptr(
                            Failure("yume.routes refused: " +
                                    code_name(result.status()))));
                });
        });
    const auto fetched = read_all(runner, routes_stream,
                                  yume::ytp1::kCompositeSignatureSize +
                                      yume::runtime::cluster::kMaxListBytes);
    runner.wait<bool>([&](auto promise) {
        routes_stream->close(Status(StatusCode::Closed));
        promise->set_value(true);
    });
    if (fetched.size() <= yume::ytp1::kCompositeSignatureSize)
        throw Failure("short routes view");
    const auto signature =
        std::span(fetched).first(yume::ytp1::kCompositeSignatureSize);
    const auto view_bytes =
        std::span(fetched).subspan(yume::ytp1::kCompositeSignatureSize);
    const auto routes = Runner::take(yume::runtime::cluster::verify_routes(
        view_bytes, signature, operator_key, std::chrono::system_clock::now()));
    report["routes_serial"] = routes.serial;
    std::vector<keys::CompositePublic> hops;
    for (const auto& name : options.hops) {
        const auto found =
            std::find_if(routes.nodes.begin(), routes.nodes.end(),
                         [&](const auto& node) { return node.name == name; });
        if (found == routes.nodes.end())
            throw Failure("the routes view has no node " + name);
        hops.push_back(found->identity);
    }
    if (hops.front().fingerprint != entry_identity)
        throw Failure("the first hop is not the server this kit reached");

    auto crypto = std::make_shared<const cc::CircuitCrypto>();
    std::vector<std::shared_ptr<ClientCircuit>> circuits;
    Json built = Json::array();
    for (std::size_t index = 0U; index < options.circuits; ++index) {
        auto opened = runner.wait<Result<std::shared_ptr<StreamResponder>>>(
            [&](auto promise) {
                session->async_open(
                    yume::common::kCircuitServiceName,
                    ServiceKind::PacketChannel,
                    [promise](Result<std::shared_ptr<StreamResponder>> result) {
                        promise->set_value(std::move(result));
                    });
            });
        if (!opened.ok()) {
            built.push_back(
                {{"built", false}, {"open", code_name(opened.status())}});
            continue;
        }
        auto circuit = Runner::take(ClientCircuit::create(
            runner.context(), crypto, std::move(opened).take_value(), hops,
            yume::runtime::circuit::ClientLimits{}));
        const auto status = runner.wait<Status>([circuit](auto promise) {
            circuit->build([promise](Status done) {
                promise->set_value(std::move(done));
            });
        });
        Json entry{{"built", status.ok()}};
        if (!status.ok()) entry["status"] = code_name(status);
        const auto [failure, times] = runner.wait<
            std::pair<std::optional<yume::runtime::circuit::CircuitFailure>,
                      std::vector<std::chrono::milliseconds>>>(
            [circuit](auto promise) {
                promise->set_value({circuit->failure(), circuit->hop_times()});
            });
        if (failure)
            entry["failure"] = {{"hop", failure->hop},
                                {"reason", reason_name(failure->reason)}};
        Json hop_ms = Json::array();
        for (const auto& time : times) hop_ms.push_back(time.count());
        entry["hop_ms"] = std::move(hop_ms);
        built.push_back(std::move(entry));
        circuits.push_back(std::move(circuit));
    }
    report["circuits"] = built;

    // Streams go through the first circuit that was built.
    const auto usable = std::find_if(
        circuits.begin(), circuits.end(), [&](const auto& circuit) {
            return runner.wait<bool>([circuit](auto promise) {
                promise->set_value(circuit->ready());
            });
        });
    if (usable != circuits.end()) {
        const auto circuit = *usable;
        auto stream = runner.wait<Result<std::shared_ptr<StreamResponder>>>(
            [&](auto promise) {
                circuit->open_stream(
                    target(options),
                    [promise](Result<std::shared_ptr<StreamResponder>> result) {
                        promise->set_value(std::move(result));
                    });
            });
        if (!stream.ok()) {
            report["stream"] = code_name(stream.status());
        } else if (options.load.count() > 0) {
            if (!options.ready_file.empty())
                std::ofstream(options.ready_file) << "ready\n";
            std::size_t echoed = 0U;
            const auto status =
                load(runner, stream.value(), options.load, &echoed);
            report["stream"] = status.ok() ? "ok" : code_name(status);
            report["echoed"] = echoed;
            // The hop that saw the break reports it before the circuit ends.
            std::this_thread::sleep_for(500ms);
            const auto failure = runner.wait<
                std::optional<yume::runtime::circuit::CircuitFailure>>(
                [circuit](auto promise) {
                    promise->set_value(circuit->failure());
                });
            if (failure)
                report["failure"] = {{"hop", failure->hop},
                                     {"reason", reason_name(failure->reason)}};
        } else {
            auto data = std::make_shared<std::vector<std::byte>>(options.bytes);
            for (std::size_t index = 0U; index < data->size(); ++index)
                (*data)[index] = static_cast<std::byte>(index * 7U + 3U);
            std::size_t echoed = 0U;
            const auto status = echo(runner, stream.value(), data, &echoed);
            report["stream"] = status.ok() ? "ok" : code_name(status);
            report["echoed"] = echoed;
        }
    }
    runner.wait<bool>([&](auto promise) {
        for (const auto& circuit : circuits) circuit->close();
        endpoint->close();
        promise->set_value(true);
    });
    runner.join();
    std::cout << report.dump() << std::endl;
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    try {
        return run(parse(argc, argv));
    } catch (const std::exception& error) {
        std::cout << Json({{"error", error.what()}}).dump() << std::endl;
        return 2;
    }
}
