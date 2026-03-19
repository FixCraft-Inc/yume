#pragma once

#include <cctype>
#include <algorithm>
#include <string>
#include <string_view>

namespace yume::policy {

inline constexpr int kReversePortMinDefault = 4100;
inline constexpr int kReversePortMaxDefault = 8600;
inline constexpr int kServerInChargeManualMinPort = 3000;
inline constexpr int kServerInChargeManualMaxPort = 30000;

inline constexpr int kAnonymProofWindowSeconds = 600;
inline constexpr int kAnonymRefreshSeconds = 300;
inline constexpr int kAnonymRefreshLeadSeconds = 120;
inline constexpr int kAnonymRefreshMinSeconds = 30;

inline constexpr std::string_view kAnonymProofModeAuto = "auto";
inline constexpr std::string_view kAnonymProofModeLocal = "local";
inline constexpr std::string_view kAnonymProofModeFixcraft = "fixcraft";

inline constexpr std::string_view kAnonymProofSourceFixcraft = "fixcraft";
inline constexpr std::string_view kAnonymProofSourceCa = "ca";
inline constexpr std::string_view kAnonymProofSourceSubCa = "sub-ca";

inline std::string normalize_anonym_proof_mode(std::string mode) {
    std::transform(mode.begin(), mode.end(), mode.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    if (mode == kAnonymProofModeLocal) {
        return std::string(kAnonymProofModeLocal);
    }
    if (mode == kAnonymProofModeFixcraft) {
        return std::string(kAnonymProofModeFixcraft);
    }
    return std::string(kAnonymProofModeAuto);
}

inline bool anonym_proof_mode_allows_remote(std::string_view mode) {
    return mode == kAnonymProofModeAuto || mode == kAnonymProofModeFixcraft;
}

inline bool anonym_proof_mode_requires_remote(std::string_view mode) {
    return mode == kAnonymProofModeFixcraft;
}

inline bool anonym_proof_mode_requires_local(std::string_view mode) {
    return mode == kAnonymProofModeLocal;
}

}  // namespace yume::policy
