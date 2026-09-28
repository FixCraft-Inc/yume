/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/outer_carrier_evidence.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>

#include <nlohmann/json.hpp>

#include "stealth/cover_profile.hpp"
#include "stealth/h2_carrier.hpp"

namespace {

using yume::obfs::H2Bytes;
using yume::obfs::H2Carrier;
using yume::obfs::H2CarrierRole;
using yume::runtime::OuterCarrierEvidence;

#define CHECK(condition)                                           \
    do {                                                           \
        if (!(condition)) {                                        \
            std::cerr << __FILE__ << ':' << __LINE__               \
                      << ": check failed: " << #condition << '\n'; \
            std::exit(1);                                          \
        }                                                          \
    } while (false)

std::chrono::steady_clock::time_point manual_now{};

std::chrono::steady_clock::time_point manual_clock() noexcept {
    return manual_now;
}

void pump(H2Carrier& from, H2Carrier& to) {
    for (int round = 0; round < 32; ++round) {
        const auto bytes = from.TakeOutbound();
        if (bytes.empty()) return;
        to.Feed(bytes);
        CHECK(!to.failed());
        const auto tunnel = to.TakeTunnelBytes();
        if (!tunnel.empty()) CHECK(to.ConsumeTunnelBytes(tunnel.size()));
    }
    CHECK(false && "pump did not quiesce");
}

void exchange(H2Carrier& client, H2Carrier& server) {
    for (int round = 0; round < 8; ++round) {
        pump(client, server);
        pump(server, client);
    }
}

// One traced carrier through the captured lifecycle: priming, assets,
// extended CONNECT, data both ways, a 42-second quiet interval and the close.
void run_traced_session(
    const std::shared_ptr<yume::obfs::OuterCarrierTrace>& trace) {
    const auto& profile = yume::cover_profile::active();
    manual_now = {};
    trace->SetTlsAlpn("h2");
    H2Carrier client(H2CarrierRole::Client, trace, &manual_clock);
    H2Carrier server(H2CarrierRole::Server);
    CHECK(client.StartClient("cover.example"));
    exchange(client, server);
    auto requests = server.TakeRequests();
    CHECK(requests.size() == 1U);
    CHECK(server.RespondHttp(requests[0].stream_id, 200,
                             {{"content-type", "text/html"}},
                             H2Bytes{'o', 'k'}));
    exchange(client, server);
    requests = server.TakeRequests();
    CHECK(requests.size() == profile.assets.size());
    for (const auto& request : requests) {
        CHECK(server.RespondHttp(request.stream_id, 200,
                                 {{"content-type", "text/plain"}},
                                 H2Bytes{'a'}));
    }
    exchange(client, server);
    CHECK(client.priming_complete());
    CHECK(client.SubmitExtendedConnect("/carrier"));
    exchange(client, server);
    requests = server.TakeRequests();
    CHECK(requests.size() == 1U);
    CHECK(server.AcceptCarrier(requests[0].stream_id));
    exchange(client, server);
    CHECK(client.carrier_active() && server.carrier_active());
    CHECK(server.EnableAdmittedReceiveWindow(
        yume::obfs::kAdmittedH2ReceiveWindowBytes));
    CHECK(client.EnableAdmittedReceiveWindow(
        yume::obfs::kAdmittedH2ReceiveWindowBytes));

    const H2Bytes up(64U * 1024U, 0x59);
    CHECK(client.SendBinary(up));
    exchange(client, server);
    const H2Bytes down(profile.websocket_message_bytes * 2U, 0x59);
    CHECK(server.SendBinary(down));
    exchange(client, server);

    manual_now += std::chrono::seconds(42);
    CHECK(client.GracefulClose());
    exchange(client, server);
    CHECK(client.websocket_close_received());
    client.RecordCloseWireResult(true);
}

std::filesystem::path make_directory(const std::filesystem::path& parent,
                                     const char* name, mode_t mode) {
    const auto path = parent / name;
    std::filesystem::create_directory(path);
    CHECK(::chmod(path.c_str(), mode) == 0);
    return path;
}

nlohmann::json read_json(const std::filesystem::path& path) {
    std::ifstream input(path);
    CHECK(input.good());
    return nlohmann::json::parse(
        std::string(std::istreambuf_iterator<char>(input), {}));
}

void test_reservation_rules(const std::filesystem::path& root) {
    std::string error;
    CHECK(!OuterCarrierEvidence::reserve("relative/behavior.json", error));
    CHECK(!error.empty());
    CHECK(!OuterCarrierEvidence::reserve(
        root / "private" / ".." / "behavior.json", error));

    const auto open = make_directory(root, "group-writable", 0770);
    CHECK(!OuterCarrierEvidence::reserve(open / "behavior.json", error));
    CHECK(!std::filesystem::exists(open / "behavior.json"));

    const auto worktree = make_directory(root, "worktree", 0700);
    make_directory(worktree, ".git", 0700);
    const auto inside = make_directory(worktree, "runs", 0700);
    CHECK(!OuterCarrierEvidence::reserve(inside / "behavior.json", error));
    CHECK(error.find("Git") != std::string::npos);

    const auto owned = make_directory(root, "private", 0700);
    {
        std::ofstream(owned / "taken.json") << "{}";
    }
    CHECK(!OuterCarrierEvidence::reserve(owned / "taken.json", error));
    std::filesystem::create_symlink(owned / "taken.json", owned / "link.json");
    CHECK(!OuterCarrierEvidence::reserve(owned / "link.json", error));
}

void test_complete_report(const std::filesystem::path& root) {
    const auto& profile = yume::cover_profile::active();
    const auto path = root / "private" / "behavior.json";
    std::string error;
    auto evidence = OuterCarrierEvidence::reserve(path, error);
    CHECK(evidence && error.empty());
    struct stat info{};
    CHECK(::stat(path.c_str(), &info) == 0 && (info.st_mode & 0777) == 0600);
    run_traced_session(evidence->trace());
    CHECK(evidence->finalize(true, error));
    CHECK(!evidence->finalize(true, error));

    const auto report = read_json(path);
    CHECK(report["schema"] == 2);
    CHECK(report["capture_status"] == "complete");
    CHECK(report["capture_source"] == "live-production-carrier");
    CHECK(!report.contains("incomplete_reasons"));
    CHECK(report["tls_observation"]["alpn"] == "h2");
    CHECK(report["authority"] == "<cover-authority>");
    CHECK(report["asset_sequence"].size() == 2U);
    CHECK(report["extended_connect"]["requires_completed_priming_get"] == true);
    const auto& websocket = report["websocket_fixture"];
    CHECK(websocket["application_bytes_each_direction"].is_null());
    CHECK(websocket["close"]["payload_bytes"] ==
          profile.websocket_close_payload_bytes);
    CHECK(websocket["close"]["client_masked"] == true);
    CHECK(websocket["close"]["server_masked"] == false);
    CHECK(websocket["close"]["h2_ping_immediately_before_close"] == true);
    CHECK(websocket["close"]["h2_ping_originator"] == "client");
    CHECK(websocket["server_fragmented_binary_message"].size() == 2U);
    const auto& idle = report["idle_and_close"];
    CHECK(idle["requested_idle_ms"] == 42000);
    CHECK(idle["graceful_websocket_close_observed"] == true);
    CHECK(idle["h2_pings"].size() == 2U);
    CHECK(idle["h2_pings"][0]["type"] == "sent" &&
          idle["h2_pings"][0]["is_ack"] == false);
    CHECK(idle["h2_pings"][1]["type"] == "received" &&
          idle["h2_pings"][1]["is_ack"] == true);
    CHECK(idle["h2_pings"][0]["unique_id"] == idle["h2_pings"][1]["unique_id"]);
    std::size_t idle_events = 0;
    for (const auto& event : report["observations"]["outer_events"]) {
        CHECK(!(event["kind"] == "h2-frame" && event["h2_type"] == 7));
        if (event["kind"] == "idle-interval") {
            ++idle_events;
            CHECK(event["requested_ms"] == 42000 && event["completed"] == true);
        }
    }
    CHECK(idle_events == 1U);
}

void test_incomplete_reports(const std::filesystem::path& root) {
    std::string error;
    const auto failed = root / "private" / "failed.json";
    {
        auto evidence = OuterCarrierEvidence::reserve(failed, error);
        CHECK(evidence);
        run_traced_session(evidence->trace());
        CHECK(!evidence->finalize(false, error));
        CHECK(!error.empty());
    }
    auto report = read_json(failed);
    CHECK(report["capture_status"] == "incomplete");
    CHECK(report["incomplete_reasons"][0] == "run-failed");

    // A writer destroyed before finalize still leaves one document behind.
    const auto abandoned = root / "private" / "abandoned.json";
    {
        auto evidence = OuterCarrierEvidence::reserve(abandoned, error);
        CHECK(evidence);
    }
    report = read_json(abandoned);
    CHECK(report["capture_status"] == "incomplete");
}

}  // namespace

int main() {
    const char* parent = std::getenv("TMPDIR");
    std::string pattern = std::string(parent && *parent ? parent : "/tmp") +
                          "/yume-outer-evidence-XXXXXX";
    CHECK(::mkdtemp(pattern.data()) != nullptr);
    const std::filesystem::path root(pattern);
    test_reservation_rules(root);
    test_complete_report(root);
    test_incomplete_reports(root);
    std::filesystem::remove_all(root);
    return 0;
}
