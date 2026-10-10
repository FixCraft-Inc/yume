/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/control_status_text.hpp"

#include <cstdint>
#include <cstdio>
#include <iterator>
#include <new>
#include <string>

#include <nlohmann/json.hpp>

#include "runtime/control_socket.hpp"

namespace yume::runtime {
namespace {
using engine::Result;
using engine::Status;
using engine::StatusCode;
using Json = nlohmann::json;

std::string byte_text(std::uint64_t bytes) {
    if (bytes < 1024U) return std::to_string(bytes) + " bytes";
    constexpr const char* units[] = {"KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(bytes) / 1024.0;
    std::size_t unit = 0U;
    while (value >= 1024.0 && unit + 1U < std::size(units)) {
        value /= 1024.0;
        ++unit;
    }
    char text[32];
    static_cast<void>(
        std::snprintf(text, sizeof(text), "%.1f %s", value, units[unit]));
    return text;
}

std::string duration_text(std::uint64_t milliseconds) {
    const std::uint64_t seconds = milliseconds / 1000U;
    const std::uint64_t hours = seconds / 3600U;
    const std::uint64_t minutes = seconds / 60U % 60U;
    std::string text;
    if (hours) text += std::to_string(hours) + " h ";
    if (hours || minutes) text += std::to_string(minutes) + " min ";
    return text + std::to_string(seconds % 60U) + " s";
}

std::string failure_text(const Json& failure) {
    std::string text = failure.at("code").get<std::string>();
    const auto message = failure.at("message").get<std::string>();
    if (!message.empty()) text += ", " + message;
    return text;
}

// A client's circuits: the length in use against the configured one, each
// route by name and any proposal of a shorter route.
std::string circuits_client_text(const Json& circuits) {
    const auto count = [&](const Json& value, const char* key) {
        return std::to_string(value.at(key).get<std::uint64_t>());
    };
    const auto names = [](const Json& nodes) {
        std::string text;
        for (const auto& node : nodes) {
            if (!text.empty()) text += " > ";
            text += node.get<std::string>();
        }
        return text;
    };
    const auto hops = [&](const Json& value, const char* key) {
        const auto number = value.at(key).get<std::uint64_t>();
        return std::to_string(number) + (number == 1U ? " hop" : " hops");
    };
    std::string text = circuits.at("current_hops").get<std::uint64_t>() == 0U
                           ? "circuits: no route in use, " +
                                 hops(circuits, "hops") + " configured"
                           : "circuits: " + hops(circuits, "current_hops") +
                                 " in use of " + count(circuits, "hops") +
                                 " configured";
    if (circuits.at("accepted_hops").get<std::uint64_t>() != 0U)
        text += ", " + count(circuits, "accepted_hops") + " accepted";
    if (circuits.at("min_hops").get<std::uint64_t>() <
        circuits.at("hops").get<std::uint64_t>())
        text += ", down to " + count(circuits, "min_hops") +
                " approved in the configuration";
    text += ", plain HTTP " +
            std::string(circuits.at("plain_http") == "allow" ? "allowed"
                                                             : "refused") +
            ", routes view serial " + count(circuits, "serial") + "\n";
    if (const auto& stopped = circuits.at("stopped"); !stopped.is_null())
        text += "circuits stopped: " + stopped.get<std::string>() + "\n";
    for (const auto& route : circuits.at("routes")) {
        text += "circuit " + names(route.at("nodes")) + ": " +
                duration_text(route.at("age_ms").get<std::uint64_t>()) +
                " old, " + count(route, "streams") + " streams\n";
    }
    if (const auto& proposal = circuits.at("proposal"); !proposal.is_null()) {
        text += "proposed route of " + hops(proposal, "hops") + ": " +
                names(proposal.at("nodes"));
        if (const auto latency = proposal.find("latency_ms");
            latency != proposal.end())
            text += ", measured " +
                    std::to_string(latency->get<std::uint64_t>()) + " ms";
        text += "\n  " + proposal.at("gives_up").get<std::string>() +
                "\n  accept it with: yume --config <path> --accept-route " +
                proposal.at("id").get<std::string>() + "\n";
    }
    return text;
}

std::string client_text(const Json& status) {
    const auto& server = status.at("server");
    const auto& traffic = status.at("traffic");
    const std::string state = status.at("state").get<std::string>();
    std::string text = status.at("program").get<std::string>() + " " +
                       status.at("version").get<std::string>() + "\n";
    text += "state: " + state;
    if (state == "connected") {
        text += " for " +
                duration_text(status.at("connected_ms").get<std::uint64_t>());
    } else if (state == "waiting") {
        text += ", next attempt in " +
                duration_text(status.at("retry_ms").get<std::uint64_t>());
    }
    text += "\nserver: " + server.at("host").get<std::string>() + " port " +
            std::to_string(server.at("port").get<std::uint32_t>()) + "\n";
    if (const auto identity = status.find("server_identity");
        identity != status.end()) {
        text += "server identity: " + identity->get<std::string>() + "\n";
    }
    text += "sessions: " +
            std::to_string(status.at("sessions").get<std::uint64_t>()) +
            ", failed attempts since the last: " +
            std::to_string(status.at("failed_attempts").get<std::uint64_t>()) +
            "\n";
    text += "sent: " +
            byte_text(traffic.at("payload_bytes_sent").get<std::uint64_t>()) +
            " of payload in " +
            byte_text(traffic.at("record_bytes_sent").get<std::uint64_t>()) +
            " of records\n";
    text +=
        "received: " +
        byte_text(traffic.at("payload_bytes_received").get<std::uint64_t>()) +
        " of payload in " +
        byte_text(traffic.at("record_bytes_received").get<std::uint64_t>()) +
        " of records\n";
    for (const auto& endpoint : status.at("socks5")) {
        text += "SOCKS5: " + endpoint.get<std::string>() + "\n";
    }
    for (const auto& forward : status.at("forwards")) {
        text += "forward: " + forward.get<std::string>() + "\n";
    }
    if (const auto& failure = status.at("last_failure"); !failure.is_null()) {
        text += "last failure: " + failure_text(failure) + "\n";
    }
    if (const auto circuits = status.find("circuits");
        circuits != status.end() && !circuits->is_null()) {
        text += circuits_client_text(*circuits);
    }
    return text;
}

std::string link_text(const Json& link) {
    const auto& outbound = link.at("outbound");
    const auto& inbound = link.at("inbound");
    const std::string state = outbound.at("state").get<std::string>();
    std::string text =
        "link " + link.at("peer").get<std::string>() + ": outbound " + state;
    if (state == "connected") {
        text += " for " +
                duration_text(outbound.at("connected_ms").get<std::uint64_t>());
    } else if (state == "waiting") {
        text += ", next attempt in " +
                duration_text(outbound.at("retry_ms").get<std::uint64_t>());
    }
    if (const auto& failure = outbound.at("last_failure");
        !failure.is_null() && state != "connected") {
        text += " (last failure: " + failure_text(failure) + ")";
    }
    const auto sessions = inbound.at("sessions").get<std::uint64_t>();
    if (sessions == 0U) {
        text += ", inbound none";
    } else {
        text +=
            ", inbound " + std::to_string(sessions) +
            (sessions == 1U ? " session for " : " sessions, the oldest for ") +
            duration_text(inbound.at("connected_ms").get<std::uint64_t>());
    }
    const auto& circuits = link.at("circuits");
    text += ", circuits in " +
            std::to_string(circuits.at("in").get<std::uint64_t>()) + " out " +
            std::to_string(circuits.at("out").get<std::uint64_t>());
    return text + "\n";
}

std::string circuits_text(const Json& circuits) {
    const auto count = [&](const Json& value, const char* key) {
        return std::to_string(value.at(key).get<std::uint64_t>());
    };
    const auto& refused = circuits.at("refused");
    return "circuits: " + count(circuits, "open") + " open, " +
           count(circuits, "entry") + " as entry, " +
           count(circuits, "relayed") + " relayed, " +
           (circuits.at("exit").get<bool>()
                ? count(circuits, "exit_streams") + " exit streams"
                : std::string("not an exit")) +
           "\ncircuits refused: " + count(refused, "total") +
           " (client circuits " + count(refused, "client_circuits") +
           ", circuit rate " + count(refused, "circuit_rate") +
           ", handshakes " + count(refused, "handshakes") + ", streams " +
           count(refused, "streams") + "), failed " +
           count(circuits, "failed") + "\n";
}

std::string server_text(const Json& status) {
    std::string text = status.at("program").get<std::string>() + " " +
                       status.at("version").get<std::string>() + "\n";
    for (const auto& listener : status.at("listeners")) {
        text += "listening: " + listener.get<std::string>() + "\n";
    }
    text += "client sessions: " +
            std::to_string(status.at("client_sessions").get<std::uint64_t>()) +
            "\n";
    const auto& loops = status.at("loops");
    text += "event loops: " + std::to_string(loops.size()) + ", sessions";
    for (std::size_t index = 0U; index < loops.size(); ++index) {
        text += (index == 0U ? " " : ", ") +
                std::to_string(loops.at(index).get<std::uint64_t>());
    }
    text += "\n";
    const auto& cluster = status.at("cluster");
    if (cluster.is_null()) return text;
    text += "cluster: " + cluster.at("id").get<std::string>() + " serial " +
            std::to_string(cluster.at("serial").get<std::uint64_t>()) +
            (cluster.at("expired").get<bool>() ? ", expired at "
                                               : ", valid until ") +
            cluster.at("not_after").get<std::string>() + "\n";
    text += "this node: " + cluster.at("self").get<std::string>() + "\n";
    text += circuits_text(cluster.at("circuits"));
    for (const auto& link : cluster.at("links")) text += link_text(link);
    return text;
}

}  // namespace

Result<std::string> status_reply_text(std::string_view reply) {
    using Text = Result<std::string>;
    const Json status = Json::parse(reply, nullptr, false);
    const auto version =
        status.is_object() ? status.find("control") : status.end();
    if (status.is_discarded() || !status.is_object() ||
        version == status.end() || !version->is_number_unsigned() ||
        version->get<std::uint64_t>() != kControlProtocol) {
        return Text(
            Status::diagnostic(StatusCode::FailedPrecondition,
                               "the control reply is not control protocol 1"));
    }
    if (const auto error = status.find("error"); error != status.end()) {
        return Text(Status::diagnostic(
            StatusCode::FailedPrecondition,
            "the control socket refused the request: " +
                (error->is_string() ? error->get<std::string>()
                                    : std::string("?"))));
    }
    if (const auto accepted = status.find("accepted");
        accepted != status.end() && accepted->is_string()) {
        return Text("accepted route " + accepted->get<std::string>() + "\n");
    }
    try {
        const auto& program = status.at("program");
        return Text(program == "yumed" ? server_text(status)
                                       : client_text(status));
    } catch (const std::bad_alloc&) {
        return Text(Status(StatusCode::ResourceExhausted));
    } catch (...) {
        return Text(
            Status::diagnostic(StatusCode::FailedPrecondition,
                               "the control reply is missing a status field"));
    }
}

}  // namespace yume::runtime
