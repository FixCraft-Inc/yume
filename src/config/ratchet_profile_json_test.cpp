#include "config/ratchet_profile_json.hpp"

#include <chrono>
#include <stdexcept>
#include <string>
#include <string_view>

namespace {

template <typename Fn>
bool Throws(Fn&& fn) {
    try {
        fn();
        return false;
    } catch (const std::exception&) {
        return true;
    }
}

void Check(bool condition, std::string_view message) {
    if (!condition) {
        throw std::runtime_error(std::string(message));
    }
}

}  // namespace

int main() {
    using namespace std::chrono_literals;
    using namespace yume;

    const auto normal = config::ParseSecurityProfile(
        nlohmann::json{{"security_mode", "normal"}});
    Check(normal.mode == ratchet::SecurityMode::Normal,
          "normal mode was not parsed");
    Check(ratchet::ResolveSecurityProfile(normal) == ratchet::kNormalPolicy,
          "normal mode did not resolve to its preset");

    const nlohmann::json ultimate_json{
        {"security_mode", "ultimate"},
        {"security_custom",
         {{"epoch_bytes", 4ULL * 1024ULL * 1024ULL},
          {"epoch_frames", 4096},
          {"epoch_active_ms", 4281}}},
    };
    const auto ultimate = config::ParseSecurityProfile(ultimate_json);
    Check(ultimate.mode == ratchet::SecurityMode::Ultimate,
          "ultimate mode was not parsed");
    Check(ultimate.custom_policy.has_value(),
          "ultimate custom policy was not parsed");
    Check(ultimate.custom_policy->epoch_active_limit == 4281ms,
          "exact custom active time was not preserved");

    nlohmann::json round_trip;
    config::WriteSecurityProfile(round_trip, ultimate);
    Check(config::ParseSecurityProfile(round_trip).custom_policy ==
              ultimate.custom_policy,
          "custom policy did not survive JSON round-trip");

    Check(Throws([] {
        (void)config::ParseSecurityProfile(
            nlohmann::json{{"security_mode", "ultimate"}});
    }), "ultimate without custom values was accepted");
    Check(Throws([] {
        (void)config::ParseSecurityProfile(nlohmann::json{
            {"security_mode", "ultimate"},
            {"security_custom",
             {{"epoch_bytes", 1},
              {"epoch_frames", 1},
              {"epoch_active_ms", 1}}},
        });
    }), "out-of-range custom values were accepted");
    Check(Throws([] {
        (void)config::ParseSecurityProfile(nlohmann::json{
            {"security_mode", "ultimate"},
            {"security_custom",
             {{"epoch_bytes", 262144},
              {"epoch_frames", 512},
              {"epoch_active_ms", -1}}},
        });
    }), "negative custom values were accepted");
    Check(Throws([] {
        (void)config::ParseSecurityProfile(
            nlohmann::json{{"security_mode", "unknown"}});
    }), "unknown security mode was accepted");
    return 0;
}
