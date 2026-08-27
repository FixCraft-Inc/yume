#include "client/cli/connect/outer_carrier_capture.hpp"
#include "client/cli/connect/secondary_tunnel.hpp"
#include "client/cli/config/args.hpp"
#include "client/cli/commands/bench.hpp"
#include "client/proxy/outbound_proxy.hpp"
#include "client/transport/client_stream.hpp"
#include "client/transport/core.hpp"
#include "client/transport/tunnel.hpp"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <utility>

#include <nlohmann/json.hpp>

#if !defined(_WIN32)
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "core/stealth/cover_profile.hpp"
#include "core/stealth/h2_carrier.hpp"
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/local/connect_pair.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/ssl/context.hpp>

namespace yume::client {

struct TunnelCloseStateTestPeer {
    static void Begin(const std::shared_ptr<Tunnel>& tunnel,
                      std::string reason) {
        tunnel->orderly_close_pending_ = true;
        tunnel->orderly_close_write_complete_ = false;
        tunnel->orderly_close_peer_closed_ = false;
        tunnel->orderly_close_wire_result_recorded_ = false;
        tunnel->orderly_close_reason_ = std::move(reason);
        tunnel->wire_write_active_ = true;
    }

    static void ObservePeerClose(const std::shared_ptr<Tunnel>& tunnel) {
        tunnel->observe_orderly_peer_close();
    }

    static void CompleteWrite(const std::shared_ptr<Tunnel>& tunnel,
                              const boost::system::error_code& error,
                              std::size_t written,
                              std::size_t expected) {
        tunnel->complete_orderly_close_write(
            error, written, expected);
    }

    static void Timeout(const std::shared_ptr<Tunnel>& tunnel) {
        tunnel->handle_orderly_close_timeout({});
    }
};

}  // namespace yume::client

namespace {

using yume::client::OuterCarrierCapture;
using yume::client::OuterCarrierCapturePolicy;
using yume::client::ValidateOuterCarrierCapturePolicy;
using yume::obfs::OuterCarrierDirection;
using yume::obfs::OuterCarrierEvent;
using yume::obfs::OuterCarrierEventKind;
using yume::obfs::OuterCarrierHeader;
using yume::obfs::OuterCarrierSetting;
using yume::obfs::OuterCarrierStreamClass;
using yume::obfs::OuterCarrierTrace;

void PumpCarrier(yume::obfs::H2Carrier& from,
                 yume::obfs::H2Carrier& to) {
    for (int iteration = 0; iteration < 16; ++iteration) {
        auto wire = from.TakeOutbound();
        if (wire.empty()) return;
        to.Feed(wire);
        assert(!to.failed());
    }
    assert(false && "HTTP/2 pump did not quiesce");
}

void OpenCarrier(yume::obfs::H2Carrier& client,
                 yume::obfs::H2Carrier& server) {
    assert(client.StartClient("cover.example"));
    PumpCarrier(client, server);
    PumpCarrier(server, client);
    auto requests = server.TakeRequests();
    assert(requests.size() == 1);
    assert(server.RespondHttp(
        requests[0].stream_id, 200,
        {{"content-type", "text/html"}}, {}));
    PumpCarrier(server, client);
    PumpCarrier(client, server);
    requests = server.TakeRequests();
    assert(requests.size() == 2);
    for (const auto& request : requests) {
        assert(server.RespondHttp(
            request.stream_id, 200,
            {{"content-type", "application/octet-stream"}}, {}));
    }
    PumpCarrier(server, client);
    PumpCarrier(client, server);
    assert(client.priming_complete());
    assert(client.SubmitExtendedConnect("/carrier"));
    PumpCarrier(client, server);
    requests = server.TakeRequests();
    assert(requests.size() == 1);
    assert(server.AcceptCarrier(requests[0].stream_id));
    PumpCarrier(server, client);
    PumpCarrier(client, server);
    assert(client.carrier_active() && server.carrier_active());
}

#if !defined(_WIN32)

class TemporaryDirectory final {
public:
    TemporaryDirectory() {
        std::string pattern = "/tmp/yume-outer-capture-test-XXXXXX";
        path_ = ::mkdtemp(pattern.data());
        assert(!path_.empty());
        assert(::chmod(path_.c_str(), 0700) == 0);
    }

    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }

    const std::filesystem::path& path() const noexcept { return path_; }

private:
    std::filesystem::path path_;
};

nlohmann::json ReadJson(const std::filesystem::path& path) {
    std::ifstream input(path);
    assert(input.good());
    return nlohmann::json::parse(input);
}

OuterCarrierCapturePolicy ValidPolicy() {
    const auto& profile = yume::cover_profile::active();
    OuterCarrierCapturePolicy policy;
    policy.endpoint_bench = true;
    policy.bench_mib = 1;
    policy.bench_chunk_kib = 16;
    policy.bench_streams = 1;
    policy.bench_direction = "both";
    policy.tunnel_count = 1;
    policy.transport_profile = std::string(profile.id);
    policy.tls_backend = "openssl-chrome151";
    policy.required_tls_backend = "openssl-chrome151";
    policy.obfuscation = true;
    policy.non_interactive = true;
    return policy;
}

void PolicyIsExactAndFailClosed() {
    auto policy = ValidPolicy();
    assert(ValidateOuterCarrierCapturePolicy(policy).empty());
    policy.endpoint_bench = false;
    assert(!ValidateOuterCarrierCapturePolicy(policy).empty());
    policy = ValidPolicy();
    policy.full_bench = true;
    assert(!ValidateOuterCarrierCapturePolicy(policy).empty());
    policy = ValidPolicy();
    policy.bench_mib = 2;
    assert(!ValidateOuterCarrierCapturePolicy(policy).empty());
    policy = ValidPolicy();
    policy.bench_chunk_kib = 32;
    assert(!ValidateOuterCarrierCapturePolicy(policy).empty());
    policy = ValidPolicy();
    policy.bench_streams = 2;
    assert(!ValidateOuterCarrierCapturePolicy(policy).empty());
    policy = ValidPolicy();
    policy.bench_direction = "up";
    assert(!ValidateOuterCarrierCapturePolicy(policy).empty());
    policy = ValidPolicy();
    policy.tunnel_count = 2;
    assert(!ValidateOuterCarrierCapturePolicy(policy).empty());
    policy = ValidPolicy();
    policy.outbound_proxy = true;
    assert(!ValidateOuterCarrierCapturePolicy(policy).empty());
    policy = ValidPolicy();
    policy.transport_profile = "unrecognized-profile";
    assert(!ValidateOuterCarrierCapturePolicy(policy).empty());
    policy = ValidPolicy();
    policy.tls_backend = "openssl-diagnostic";
    assert(!ValidateOuterCarrierCapturePolicy(policy).empty());
    policy = ValidPolicy();
    policy.tls_backend =
        std::string(yume::cover_profile::active().tls_backend);
    assert(!ValidateOuterCarrierCapturePolicy(policy).empty());
    policy = ValidPolicy();
    policy.obfuscation = false;
    assert(!ValidateOuterCarrierCapturePolicy(policy).empty());
    policy = ValidPolicy();
    policy.non_interactive = false;
    assert(!ValidateOuterCarrierCapturePolicy(policy).empty());
    policy = ValidPolicy();
    policy.obfs_pad_multiple = 16;
    assert(!ValidateOuterCarrierCapturePolicy(policy).empty());
    policy = ValidPolicy();
    policy.obfs_jitter_ms = 1;
    assert(!ValidateOuterCarrierCapturePolicy(policy).empty());
    policy = ValidPolicy();
    policy.conflicting_mode = true;
    assert(!ValidateOuterCarrierCapturePolicy(policy).empty());
}

void CliFlagIsOneShotOnly() {
    char program[] = "yume";
    char flag[] = "--outer-carrier-evidence";
    char destination[] = "/tmp/yume-private/behavior.json";
    char* argv[] = {program, flag, destination};
    const auto args = yume::client::parse_args(3, argv);
    assert(args.parse_error.empty());
    assert(args.outer_carrier_evidence == destination);
    assert(args.non_interactive);

    char* missing_argv[] = {program, flag};
    const auto missing = yume::client::parse_args(2, missing_argv);
    assert(!missing.parse_error.empty());
}

void CaptureSelectsMatchedMessageEchoOnly() {
    yume::client::EndpointBenchOptions options;
    assert(yume::client::select_endpoint_bench_workload(options) ==
           yume::client::EndpointBenchWorkload::SequentialDirections);
    options.matched_message_echo = true;
    assert(yume::client::select_endpoint_bench_workload(options) ==
           yume::client::EndpointBenchWorkload::MatchedMessageEcho);

    yume::client::EndpointEchoReplyContract exact(1024U * 1024U, 16384U);
    const std::vector<std::uint8_t> message(16384U, 0x59U);
    for (std::size_t index = 0; index < 64; ++index) {
        assert(exact.Accept(message));
        assert(exact.complete() == (index == 63));
    }
    assert(exact.received_messages() == 64);
    assert(!exact.Accept(message));

    yume::client::EndpointEchoReplyContract split(1024U * 1024U, 16384U);
    assert(!split.Accept(std::vector<std::uint8_t>(8192U, 0x59U)));
    yume::client::EndpointEchoReplyContract merged(1024U * 1024U, 16384U);
    assert(!merged.Accept(std::vector<std::uint8_t>(32768U, 0x59U)));
    yume::client::EndpointEchoReplyContract corrupt(1024U * 1024U, 16384U);
    auto bad = message;
    bad.back() = 0x58U;
    assert(!corrupt.Accept(bad));
    yume::client::EndpointEchoReplyContract invalid(0, 0);
    assert(!invalid.complete());
    assert(!invalid.Accept({}));
}

void RecordH2(OuterCarrierTrace& trace,
              OuterCarrierDirection direction,
              OuterCarrierStreamClass stream_class,
              std::uint8_t type,
              std::uint8_t flags = 0) {
    OuterCarrierEvent event;
    event.kind = OuterCarrierEventKind::H2Frame;
    event.direction = direction;
    event.stream_class = stream_class;
    event.h2_stream_id =
        stream_class == OuterCarrierStreamClass::Connection ? 0 : 7;
    event.h2_type = type;
    event.flags = flags;
    if (type == 0x04 && flags == 0) {
        event.settings.push_back(OuterCarrierSetting{1, 65536});
    }
    if (type == 0x08) event.value = 1024;
    trace.Record(std::move(event));
}

void RecordHeaders(OuterCarrierTrace& trace,
                   OuterCarrierDirection direction,
                   OuterCarrierStreamClass stream_class) {
    OuterCarrierEvent event;
    event.kind = OuterCarrierEventKind::H2Frame;
    event.direction = direction;
    event.stream_class = stream_class;
    switch (stream_class) {
        case OuterCarrierStreamClass::Priming: event.h2_stream_id = 1; break;
        case OuterCarrierStreamClass::AssetCss: event.h2_stream_id = 3; break;
        case OuterCarrierStreamClass::AssetJs: event.h2_stream_id = 5; break;
        case OuterCarrierStreamClass::Carrier: event.h2_stream_id = 7; break;
        default: event.h2_stream_id = 0; break;
    }
    event.h2_type = 0x01;
    event.headers.push_back(OuterCarrierHeader{
        direction == OuterCarrierDirection::Sent ? ":method" : ":status",
        direction == OuterCarrierDirection::Sent ? "GET" : "200"});
    trace.Record(std::move(event));
}

void RecordWebSocket(OuterCarrierTrace& trace,
                     OuterCarrierDirection direction,
                     std::uint8_t opcode,
                     std::uint64_t payload_bytes) {
    OuterCarrierEvent event;
    event.kind = OuterCarrierEventKind::WebSocketFrame;
    event.direction = direction;
    event.stream_class = OuterCarrierStreamClass::Carrier;
    event.websocket_opcode = opcode;
    event.websocket_final = true;
    event.websocket_masked =
        direction == OuterCarrierDirection::Sent;
    event.websocket_payload_bytes = payload_bytes;
    event.h2_ping_immediately_before = opcode == 0x08;
    trace.Record(std::move(event));
}

void RecordStreamClose(OuterCarrierTrace& trace,
                       OuterCarrierStreamClass stream_class,
                       std::int32_t stream_id) {
    OuterCarrierEvent event;
    event.kind = OuterCarrierEventKind::StreamClose;
    event.direction = OuterCarrierDirection::Received;
    event.stream_class = stream_class;
    event.h2_stream_id = stream_id;
    event.error_code = 0;
    event.completed = true;
    trace.Record(std::move(event));
}

void PopulateCompleteTrace(OuterCarrierTrace& trace) {
    trace.SetTlsAlpn("h2");
    RecordH2(trace, OuterCarrierDirection::Sent,
             OuterCarrierStreamClass::Connection, 0x04);
    RecordH2(trace, OuterCarrierDirection::Received,
             OuterCarrierStreamClass::Connection, 0x04);
    RecordH2(trace, OuterCarrierDirection::Sent,
             OuterCarrierStreamClass::Connection, 0x08);
    RecordHeaders(trace, OuterCarrierDirection::Sent,
                  OuterCarrierStreamClass::Priming);
    RecordHeaders(trace, OuterCarrierDirection::Received,
                  OuterCarrierStreamClass::Priming);
    RecordStreamClose(trace, OuterCarrierStreamClass::Priming, 1);
    RecordHeaders(trace, OuterCarrierDirection::Sent,
                  OuterCarrierStreamClass::AssetCss);
    RecordHeaders(trace, OuterCarrierDirection::Sent,
                  OuterCarrierStreamClass::AssetJs);
    RecordHeaders(trace, OuterCarrierDirection::Received,
                  OuterCarrierStreamClass::AssetCss);
    RecordStreamClose(trace, OuterCarrierStreamClass::AssetCss, 3);
    RecordHeaders(trace, OuterCarrierDirection::Received,
                  OuterCarrierStreamClass::AssetJs);
    RecordStreamClose(trace, OuterCarrierStreamClass::AssetJs, 5);
    RecordHeaders(trace, OuterCarrierDirection::Sent,
                  OuterCarrierStreamClass::Carrier);
    RecordHeaders(trace, OuterCarrierDirection::Received,
                  OuterCarrierStreamClass::Carrier);
    RecordH2(trace, OuterCarrierDirection::Sent,
             OuterCarrierStreamClass::Carrier, 0x00);
    RecordH2(trace, OuterCarrierDirection::Received,
             OuterCarrierStreamClass::Carrier, 0x08);
    RecordWebSocket(trace, OuterCarrierDirection::Sent, 0x02, 16384);
    RecordWebSocket(trace, OuterCarrierDirection::Received, 0x02, 16384);

    OuterCarrierEvent idle;
    idle.kind = OuterCarrierEventKind::IdleInterval;
    idle.direction = OuterCarrierDirection::Sent;
    idle.stream_class = OuterCarrierStreamClass::Carrier;
    idle.value = 42000;
    idle.completed = true;
    trace.Record(std::move(idle));

    RecordH2(trace, OuterCarrierDirection::Sent,
             OuterCarrierStreamClass::Connection, 0x06);
    RecordWebSocket(trace, OuterCarrierDirection::Sent, 0x08, 2);
    RecordH2(trace, OuterCarrierDirection::Sent,
             OuterCarrierStreamClass::Connection, 0x07);

    OuterCarrierEvent close_wire;
    close_wire.kind = OuterCarrierEventKind::CloseWire;
    close_wire.direction = OuterCarrierDirection::Sent;
    close_wire.stream_class = OuterCarrierStreamClass::Carrier;
    close_wire.completed = true;
    trace.Record(std::move(close_wire));
}

void SecureWriterProducesTerminalDocuments() {
    TemporaryDirectory directory;
    const auto incomplete_path = directory.path() / "incomplete.json";
    {
        std::string error;
        auto capture = OuterCarrierCapture::Reserve(incomplete_path, &error);
        assert(capture && error.empty());
    }
    auto incomplete = ReadJson(incomplete_path);
    assert(incomplete["capture_status"] == "incomplete");

    const auto complete_path = directory.path() / "complete.json";
    std::string error;
    auto capture = OuterCarrierCapture::Reserve(complete_path, &error);
    assert(capture && error.empty());
    PopulateCompleteTrace(*capture->trace());
    assert(capture->Finalize(true, &error));
    assert(error.empty());
    const auto complete = ReadJson(complete_path);
    assert(complete["capture_status"] == "complete");
    assert(complete["capture_source"] == "live-production-carrier");
    assert(complete["flow_control_fixture"]
                   ["client_stream_send_stalls"] == 0);
    assert(complete["flow_control_fixture"]
                   ["window_update_recovery_observed"] == true);
    assert(complete["idle_and_close"]
                   ["graceful_websocket_close_observed"] == false);
    const auto& events = complete["observations"]["outer_events"];
    const auto stream_close = std::find_if(
        events.begin(), events.end(), [](const auto& event) {
            return event.value("kind", "") == "stream-close";
        });
    assert(stream_close != events.end());
    assert((*stream_close)["stream_id"] == 1);
    assert((*stream_close)["error_code"] == 0);
    assert((*stream_close)["completed"] == true);

    struct stat info {};
    assert(::stat(complete_path.c_str(), &info) == 0);
    assert(S_ISREG(info.st_mode));
    assert((info.st_mode & 0777) == 0600);
    assert(info.st_uid == ::geteuid());

    auto duplicate = OuterCarrierCapture::Reserve(complete_path, &error);
    assert(!duplicate);

    const auto truncated_path = directory.path() / "truncated.json";
    auto truncated = OuterCarrierCapture::Reserve(truncated_path, &error);
    assert(truncated);
    truncated->trace()->SetTlsAlpn("h2");
    for (std::size_t index = 0;
         index <= OuterCarrierTrace::kMaxEvents; ++index) {
        OuterCarrierEvent event;
        event.kind = OuterCarrierEventKind::FlowWindowStalled;
        truncated->trace()->Record(std::move(event));
    }
    assert(!truncated->Finalize(true, &error));
    assert(ReadJson(truncated_path)["capture_status"] == "incomplete");
}

void ProductionRatchetGeometryIsReportedTruthfully() {
#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
    auto trace = std::make_shared<OuterCarrierTrace>();
    yume::obfs::H2Carrier client(
        yume::obfs::H2CarrierRole::Client, trace);
    yume::obfs::H2Carrier server(yume::obfs::H2CarrierRole::Server);
    OpenCarrier(client, server);

    std::string close_reason;
    yume::client::TransportCore transport(
        [&](std::shared_ptr<std::vector<std::uint8_t>> wire,
            yume::client::TransportCore::WriteCompletion completion) {
            assert(client.SendBinary(*wire));
            PumpCarrier(client, server);
            const auto received = server.TakeTunnelBytes();
            assert(server.ConsumeTunnelBytes(received.size()));
            if (completion) completion(true, wire->size(), {});
        },
        [&](const std::string& reason) { close_reason = reason; });
    const yume::ratchet::Bytes root(32, 0x51);
    const yume::ratchet::Bytes psk(32, 0x62);
    transport.set_ratchet(
        std::make_unique<yume::ratchet::SessionRatchet>(
            yume::ratchet::EndpointRole::Client, root, psk));
    transport.start();
    transport.send_data(1, std::vector<std::uint8_t>(16384, 0x73));
    assert(close_reason.empty());

    std::size_t binary_frames = 0;
    std::uint64_t outer_payload_bytes = 0;
    for (const auto& event : trace->Snapshot().events) {
        if (event.kind == OuterCarrierEventKind::WebSocketFrame &&
            event.direction == OuterCarrierDirection::Sent &&
            event.websocket_opcode == 0x02) {
            ++binary_frames;
            outer_payload_bytes += event.websocket_payload_bytes;
        }
    }
    // A 16-KiB application write is carried inside the authenticated ratchet
    // and YUME frame. The live observer must report that real outer geometry,
    // not synthesize one browser-shaped 16-KiB WebSocket message.
    assert(binary_frames >= 2);
    assert(outer_payload_bytes > 16384);
#endif
}

std::shared_ptr<yume::client::Tunnel> MakeCloseStateTunnel(
        boost::asio::io_context& io,
        boost::asio::local::stream_protocol::socket* peer,
        const std::shared_ptr<OuterCarrierTrace>& trace,
        bool* close_called) {
    boost::asio::local::stream_protocol::socket local(io);
    boost::asio::local::connect_pair(local, *peer);
    yume::client::ClientTransportStream stream(
        std::move(local), {}, {});
    auto tunnel = std::make_shared<yume::client::Tunnel>(
        std::move(stream),
        std::make_unique<yume::obfs::H2Carrier>(
            yume::obfs::H2CarrierRole::Client, trace));
    tunnel->set_close_handler([close_called](const std::string&) {
        *close_called = true;
    });
    return tunnel;
}

bool SingleCloseWireResult(const OuterCarrierTrace& trace) {
    const auto snapshot = trace.Snapshot();
    const auto matching = std::count_if(
        snapshot.events.begin(), snapshot.events.end(),
        [](const OuterCarrierEvent& event) {
            return event.kind == OuterCarrierEventKind::CloseWire;
        });
    if (matching != 1) return false;
    return std::find_if(
        snapshot.events.begin(), snapshot.events.end(),
        [](const OuterCarrierEvent& event) {
            return event.kind == OuterCarrierEventKind::CloseWire;
        })->completed;
}

void TunnelCloseStateIsRaceSafeAndFailClosed() {
    using yume::client::TunnelCloseStateTestPeer;

    {
        boost::asio::io_context io;
        boost::asio::local::stream_protocol::socket peer(io);
        auto trace = std::make_shared<OuterCarrierTrace>();
        bool close_called = false;
        auto tunnel = MakeCloseStateTunnel(
            io, &peer, trace, &close_called);
        TunnelCloseStateTestPeer::Begin(tunnel, "race-test");
        // Deterministically exercise the ordering that caused the race: the
        // read handler observes the peer CLOSE before the async terminal-write
        // completion handler becomes runnable.
        TunnelCloseStateTestPeer::ObservePeerClose(tunnel);
        assert(tunnel->is_alive());
        assert(trace->Snapshot().events.empty());
        TunnelCloseStateTestPeer::CompleteWrite(tunnel, {}, 32, 32);
        assert(!tunnel->is_alive());
        assert(close_called);
        assert(SingleCloseWireResult(*trace));
    }

    for (const bool timeout : {false, true}) {
        boost::asio::io_context io;
        boost::asio::local::stream_protocol::socket peer(io);
        auto trace = std::make_shared<OuterCarrierTrace>();
        bool close_called = false;
        auto tunnel = MakeCloseStateTunnel(
            io, &peer, trace, &close_called);
        TunnelCloseStateTestPeer::Begin(tunnel, "failure-test");
        if (timeout) {
            TunnelCloseStateTestPeer::Timeout(tunnel);
        } else {
            TunnelCloseStateTestPeer::CompleteWrite(
                tunnel, boost::asio::error::broken_pipe, 0, 32);
        }
        assert(!tunnel->is_alive());
        assert(close_called);
        assert(!SingleCloseWireResult(*trace));
    }
}

void SecondaryTunnelStartupCancellationDrainsIo() {
    using boost::asio::ip::tcp;

    boost::asio::io_context server_io;
    tcp::acceptor acceptor(server_io, tcp::endpoint(tcp::v4(), 0));
    acceptor.non_blocking(true);
    std::atomic<bool> accepted{false};
    std::atomic<bool> release_server{false};
    std::thread server([&]() {
        tcp::socket socket(server_io);
        const auto accept_deadline = std::chrono::steady_clock::now() +
                                     std::chrono::seconds(2);
        while (!release_server.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < accept_deadline) {
            boost::system::error_code error;
            acceptor.accept(socket, error);
            if (!error) {
                accepted.store(true, std::memory_order_release);
                break;
            }
            assert(error == boost::asio::error::would_block ||
                   error == boost::asio::error::try_again);
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        while (!release_server.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        boost::system::error_code ignored;
        socket.close(ignored);
    });

    std::atomic<bool> stop_requested{false};
    std::thread interrupter([&]() {
        const auto accept_deadline = std::chrono::steady_clock::now() +
                                     std::chrono::seconds(1);
        while (!accepted.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < accept_deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        stop_requested.store(true, std::memory_order_release);
    });

    boost::asio::io_context client_io;
    boost::asio::ssl::context tls_context(
        boost::asio::ssl::context::tls_client);
    tls_context.set_verify_mode(boost::asio::ssl::verify_none);
    yume::client::ClientConfig config;
    config.server = "127.0.0.1";
    config.tls_server_name = "localhost";
    config.port = acceptor.local_endpoint().port();
    config.obfuscation = false;
    const yume::client::outbound_proxy::Config no_proxy;

    bool cancelled = false;
    const auto started = std::chrono::steady_clock::now();
    try {
        (void)yume::client::connect_secondary_tunnel(
            client_io, tls_context, config, no_proxy, 2, std::nullopt,
            nullptr, [&]() {
                return stop_requested.load(std::memory_order_acquire);
            });
    } catch (const std::runtime_error& error) {
        cancelled = std::string(error.what()).find("cancelled") !=
                    std::string::npos;
    }
    const auto elapsed = std::chrono::steady_clock::now() - started;

    interrupter.join();
    release_server.store(true, std::memory_order_release);
    server.join();
    if (!accepted.load(std::memory_order_acquire)) {
        throw std::runtime_error(
            "secondary cancellation fixture never reached the TLS stall");
    }
    if (!cancelled) {
        throw std::runtime_error(
            "secondary TLS startup did not report cancellation");
    }
    if (elapsed >= std::chrono::seconds(2)) {
        throw std::runtime_error(
            "secondary TLS startup did not cancel promptly");
    }

    // Every timer/socket completion used stack-bound state. A clean poll after
    // the exception proves cancellation drained those handlers before the
    // setup frame unwound; ASan then checks the same invariant dynamically.
    client_io.restart();
    if (client_io.poll() != 0) {
        throw std::runtime_error(
            "secondary TLS cancellation left completion handlers queued");
    }
}

void SocksProxyHandshakeCancellationDrainsIo() {
    using boost::asio::ip::tcp;
    using namespace std::chrono_literals;

    boost::asio::io_context server_io;
    tcp::acceptor acceptor(server_io, tcp::endpoint(tcp::v4(), 0));
    std::atomic<bool> accepted{false};
    std::atomic<bool> release_server{false};
    std::thread server([&]() {
        boost::system::error_code error;
        tcp::socket socket(server_io);
        acceptor.accept(socket, error);
        if (!error) accepted.store(true, std::memory_order_release);
        while (!error && !release_server.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(1ms);
        }
    });

    std::atomic<bool> stop_requested{false};
    std::thread interrupter([&]() {
        const auto deadline = std::chrono::steady_clock::now() + 1s;
        while (!accepted.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(1ms);
        }
        stop_requested.store(true, std::memory_order_release);
    });

    boost::asio::io_context client_io;
    tcp::socket client(client_io);
    yume::client::outbound_proxy::Config proxy;
    proxy.type = yume::client::outbound_proxy::Type::Socks5;
    proxy.host = "127.0.0.1";
    proxy.port = acceptor.local_endpoint().port();
    const auto started = std::chrono::steady_clock::now();
    const auto result = yume::client::outbound_proxy::socks5_dial(
        client, client_io, proxy, "target.example", 443, 2s, {},
        [&]() { return stop_requested.load(std::memory_order_acquire); });
    const auto elapsed = std::chrono::steady_clock::now() - started;

    interrupter.join();
    release_server.store(true, std::memory_order_release);
    server.join();
    if (!accepted.load(std::memory_order_acquire)) {
        throw std::runtime_error(
            "proxy cancellation fixture never reached SOCKS negotiation");
    }
    if (!result.cancelled || result.ok || result.timed_out || elapsed >= 500ms) {
        throw std::runtime_error(
            "stalled SOCKS negotiation did not cancel promptly");
    }
    client_io.restart();
    if (client_io.poll() != 0) {
        throw std::runtime_error(
            "SOCKS cancellation left completion handlers queued");
    }
}

void UnsafeDestinationsAreRejected() {
    TemporaryDirectory directory;
    std::string error;

    const auto git_parent = directory.path() / "git-parent";
    std::filesystem::create_directories(git_parent / ".git");
    assert(!OuterCarrierCapture::Reserve(
        git_parent / "evidence.json", &error));

    const auto unsafe_parent = directory.path() / "unsafe-parent";
    std::filesystem::create_directory(unsafe_parent);
    assert(::chmod(unsafe_parent.c_str(), 0777) == 0);
    assert(!OuterCarrierCapture::Reserve(
        unsafe_parent / "evidence.json", &error));

    const auto actual_parent = directory.path() / "actual-parent";
    const auto linked_parent = directory.path() / "linked-parent";
    std::filesystem::create_directory(actual_parent);
    std::filesystem::create_directory_symlink(actual_parent, linked_parent);
    assert(!OuterCarrierCapture::Reserve(
        linked_parent / "evidence.json", &error));

    const auto fifo_path = directory.path() / "evidence.fifo";
    assert(::mkfifo(fifo_path.c_str(), 0600) == 0);
    assert(!OuterCarrierCapture::Reserve(fifo_path, &error));

    const auto file_link = directory.path() / "evidence-link.json";
    std::filesystem::create_symlink(fifo_path, file_link);
    assert(!OuterCarrierCapture::Reserve(file_link, &error));
}

#endif

}  // namespace

int main() {
#if !defined(_WIN32)
    PolicyIsExactAndFailClosed();
    CliFlagIsOneShotOnly();
    CaptureSelectsMatchedMessageEchoOnly();
    SecureWriterProducesTerminalDocuments();
    ProductionRatchetGeometryIsReportedTruthfully();
    TunnelCloseStateIsRaceSafeAndFailClosed();
    SecondaryTunnelStartupCancellationDrainsIo();
    SocksProxyHandshakeCancellationDrainsIo();
    UnsafeDestinationsAreRejected();
#endif
    return 0;
}
