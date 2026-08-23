/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#ifdef NDEBUG
#undef NDEBUG
#endif

#include "core/protocol/control_command_policy.hpp"

#include <deque>
#include <stdexcept>
#include <string>

namespace {

void Check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

nlohmann::json ValidLifecycleCommand() {
    return {
        {"cmd", "client.lifecycle"},
        {"request_id", "request-1"},
        {"state", "traffic_flowing"},
        {"message", "success, traffic flowing"},
        {"detail", "first usable traffic observed"},
        {"client_platform", "linux"},
        {"client_variant", "cli"},
        {"client_version", "0.2.0-alpha"},
        {"effective_protection", "ratchet+composite-auth"},
        {"traffic_verified", true},
        {"exit_ip", "2001:db8::1"},
        {"error_code", ""},
    };
}

std::size_t LifecycleStringBytes(
    const yume::control::ClientLifecycleEvent& event) {
    return event.state.size() + event.message.size() + event.detail.size() +
           event.client_platform.size() + event.client_variant.size() +
           event.client_version.size() + event.effective_protection.size() +
           event.exit_ip.size() + event.error_code.size();
}

void CheckLifecyclePolicy() {
    std::string error;
    const auto valid = ValidLifecycleCommand();
    auto parsed = yume::control::try_lifecycle_command_from_json(
        valid, &error);
    Check(parsed.has_value(), "valid lifecycle command was rejected");
    Check(error.empty(), "valid lifecycle command populated an error");
    Check(parsed->state == "traffic_flowing", "lifecycle state changed");
    Check(parsed->traffic_verified, "lifecycle boolean changed");
    Check(parsed->exit_ip == "2001:db8::1", "lifecycle IPv6 changed");

    auto minimal = nlohmann::json{
        {"cmd", "client.lifecycle"},
        {"state", "connecting"},
        {"message", "connecting"},
    };
    parsed = yume::control::try_lifecycle_command_from_json(minimal, &error);
    Check(parsed.has_value(), "compatible minimal lifecycle was rejected");
    Check(parsed->client_platform == "unknown",
          "minimal lifecycle platform default changed");
    Check(parsed->client_variant == "unknown",
          "minimal lifecycle variant default changed");

    auto malformed = valid;
    malformed["state"] = 1;
    Check(!yume::control::try_lifecycle_command_from_json(malformed),
          "numeric lifecycle state was accepted");
    malformed = valid;
    malformed["message"] = false;
    Check(!yume::control::try_lifecycle_command_from_json(malformed),
          "boolean lifecycle message was accepted");
    malformed = valid;
    malformed["traffic_verified"] = "true";
    Check(!yume::control::try_lifecycle_command_from_json(malformed),
          "string lifecycle boolean was accepted");
    malformed = valid;
    malformed["state"] = "TRAFFIC_FLOWING";
    Check(!yume::control::try_lifecycle_command_from_json(malformed),
          "non-canonical lifecycle state was accepted");
    malformed = valid;
    malformed["state"] = "ready";
    Check(!yume::control::try_lifecycle_command_from_json(malformed),
          "unknown lifecycle state was accepted");
    malformed = valid;
    malformed["client_platform"] = "ios";
    Check(!yume::control::try_lifecycle_command_from_json(malformed),
          "unknown lifecycle platform was accepted");
    malformed = valid;
    malformed["client_variant"] = "gui";
    Check(!yume::control::try_lifecycle_command_from_json(malformed),
          "unknown lifecycle variant was accepted");
    malformed = valid;
    malformed["exit_ip"] = "not-an-ip";
    Check(!yume::control::try_lifecycle_command_from_json(malformed),
          "invalid lifecycle exit IP was accepted");
    malformed = valid;
    malformed["future_field"] = "surprise";
    Check(!yume::control::try_lifecycle_command_from_json(malformed),
          "unknown lifecycle field was accepted");
    malformed = valid;
    malformed["message"] = std::string(
        yume::control::kMaxLifecycleMessageBytes + 1U, 'm');
    Check(!yume::control::try_lifecycle_command_from_json(malformed),
          "oversized lifecycle message was accepted");
    malformed = valid;
    malformed["detail"] = "line one\nline two";
    Check(!yume::control::try_lifecycle_command_from_json(malformed),
          "lifecycle control character was accepted");

    // Every field remains individually legal, but their retained total is
    // above the command budget.
    malformed = minimal;
    malformed["message"] = std::string(
        yume::control::kMaxLifecycleMessageBytes, 'm');
    malformed["detail"] = std::string(
        yume::control::kMaxLifecycleDetailBytes, 'd');
    malformed["effective_protection"] = std::string(
        yume::control::kMaxLifecycleProtectionBytes, 'p');
    Check(!yume::control::try_lifecycle_command_from_json(malformed),
          "aggregate-oversized lifecycle command was accepted");

    yume::control::ClientLifecycleEvent event = *
        yume::control::try_lifecycle_command_from_json(valid);
    auto emitted = yume::control::try_lifecycle_command_to_json(event, &error);
    Check(emitted.has_value(), "valid lifecycle event did not serialize");
    Check(error.empty(), "valid lifecycle serialization populated an error");
    Check(yume::control::try_lifecycle_command_from_json(*emitted).has_value(),
          "serialized lifecycle command violates server policy");
    event.message.assign(yume::control::kMaxLifecycleMessageBytes + 1U, 'm');
    Check(!yume::control::try_lifecycle_command_to_json(event),
          "client serialized an oversized lifecycle event");

    // The manager retains at most 512 copies.  Populate that exact history
    // shape with the largest aggregate-valid command and prove the retained
    // client-controlled strings stay within the shared fixed budget.
    auto bounded = minimal;
    bounded["detail"] = std::string(
        yume::control::kMaxLifecycleDetailBytes, 'd');
    bounded["message"] = std::string(200U, 'm');
    bounded["effective_protection"] = std::string(200U, 'p');
    auto bounded_event =
        yume::control::try_lifecycle_command_from_json(bounded);
    Check(bounded_event.has_value(), "bounded lifecycle fixture was rejected");
    std::deque<yume::control::ClientLifecycleEvent> history;
    for (std::size_t index = 0; index < 512U; ++index) {
        history.push_back(*bounded_event);
    }
    std::size_t retained = 0;
    for (const auto& item : history) retained += LifecycleStringBytes(item);
    Check(retained <=
              512U * yume::control::kMaxLifecycleAggregateStringBytes,
          "lifecycle history exceeded its retained string budget");
}

void CheckLegacyRegistrationPolicy() {
    std::string error;
    const nlohmann::json valid{
        {"cmd", "register"},
        {"hostname", "workstation.local"},
        {"wan_ip", "203.0.113.7"},
        {"server_in_charge", true},
        {"allow_exec", false},
    };
    auto registration =
        yume::control::try_legacy_control_registration_from_json(
            valid, &error);
    Check(registration.has_value(), "valid legacy registration was rejected");
    Check(error.empty(), "valid legacy registration populated an error");
    Check(registration->hostname == "workstation.local",
          "legacy hostname changed");
    Check(registration->wan_ip == "203.0.113.7", "legacy IP changed");
    Check(registration->server_in_charge,
          "legacy server-in-charge boolean changed");
    Check(!registration->allow_exec, "legacy allow-exec boolean changed");

    registration =
        yume::control::try_legacy_control_registration_from_json(
            {{"cmd", "register"}});
    Check(registration.has_value(), "minimal legacy registration was rejected");
    Check(registration->hostname.empty() && registration->wan_ip.empty() &&
              !registration->server_in_charge && !registration->allow_exec,
          "legacy registration defaults changed");

    auto malformed = valid;
    malformed["hostname"] = 1;
    Check(!yume::control::try_legacy_control_registration_from_json(malformed),
          "numeric legacy hostname was accepted");
    malformed = valid;
    malformed["wan_ip"] = true;
    Check(!yume::control::try_legacy_control_registration_from_json(malformed),
          "boolean legacy IP was accepted");
    malformed = valid;
    malformed["server_in_charge"] = "yes";
    Check(!yume::control::try_legacy_control_registration_from_json(malformed),
          "string legacy permission was accepted");
    malformed = valid;
    malformed["allow_exec"] = 1;
    Check(!yume::control::try_legacy_control_registration_from_json(malformed),
          "numeric legacy allow-exec was accepted");
    malformed = valid;
    malformed["hostname"] = std::string(
        yume::control::kMaxLegacyHostnameBytes + 1U, 'h');
    Check(!yume::control::try_legacy_control_registration_from_json(malformed),
          "oversized legacy hostname was accepted");
    malformed = valid;
    malformed["wan_ip"] = "203.0.113.999";
    Check(!yume::control::try_legacy_control_registration_from_json(malformed),
          "invalid legacy IP was accepted");
    malformed = valid;
    malformed["hostname"] = "host\nname";
    Check(!yume::control::try_legacy_control_registration_from_json(malformed),
          "legacy hostname control character was accepted");
    malformed = valid;
    malformed["future_field"] = true;
    Check(!yume::control::try_legacy_control_registration_from_json(malformed),
          "unknown legacy registration field was accepted");

    malformed = valid;
    malformed["hostname"] = std::string(
        yume::control::kMaxLegacyHostnameBytes, 'h');
    malformed["wan_ip"] = "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff";
    Check(!yume::control::try_legacy_control_registration_from_json(malformed),
          "aggregate-oversized legacy registration was accepted");
}

}  // namespace

int main() {
    CheckLifecyclePolicy();
    CheckLegacyRegistrationPolicy();
    Check(yume::control::is_valid_control_command_name("directory.list"),
          "valid command name was rejected");
    Check(!yume::control::is_valid_control_command_name("bad\ncommand"),
          "command control character was accepted");
    Check(!yume::control::is_valid_control_command_name(std::string(
              yume::control::kMaxControlCommandBytes + 1U, 'c')),
          "oversized command name was accepted");
    return 0;
}
