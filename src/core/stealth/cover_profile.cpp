/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/stealth/cover_profile.hpp"

#include <array>
#include <algorithm>
#include <stdexcept>

#include "core/version.hpp"

namespace yume::cover_profile {

#include "core/stealth/transport_profiles.inc"

static_assert(generated_profiles::kActiveProfileId == yume::kTransportProfile,
              "generated active profile must match authenticated profile");

Headers Profile::render_headers(const RequestTemplate& request,
                                std::string_view authority,
                                std::string_view carrier_path) const {
    Headers rendered;
    rendered.reserve(request.headers.size());
    for (const auto& header : request.headers) {
        std::string value;
        switch (header.value_source) {
            case HeaderValueSource::Literal:
                value = header.literal;
                break;
            case HeaderValueSource::Authority:
                value = authority;
                break;
            case HeaderValueSource::CarrierPath:
                if (carrier_path.empty()) {
                    throw std::invalid_argument(
                        "cover profile carrier path must not be empty");
                }
                value = carrier_path;
                break;
            case HeaderValueSource::UserAgent:
                value = user_agent;
                break;
            case HeaderValueSource::ClientHintBrand:
                value = client_hint_brand;
                break;
            case HeaderValueSource::ClientHintMobile:
                value = client_hint_mobile;
                break;
            case HeaderValueSource::ClientHintPlatform:
                value = client_hint_platform;
                break;
            case HeaderValueSource::Origin:
                value = "https://" + std::string(authority);
                break;
            case HeaderValueSource::RootReferer:
                value = "https://" + std::string(authority) + "/";
                break;
        }
        rendered.emplace_back(header.name, std::move(value));
    }
    return rendered;
}

std::span<const Profile> all() {
    return generated_profiles::kProfiles;
}

const Profile* find_by_id(std::string_view id) {
    const auto profiles = all();
    const auto it = std::find_if(profiles.begin(), profiles.end(),
                                 [id](const Profile& profile) {
                                     return profile.id == id;
                                 });
    return it == profiles.end() ? nullptr : &*it;
}

const Profile* find_by_registry_name(std::string_view name) {
    const auto profiles = all();
    const auto it = std::find_if(profiles.begin(), profiles.end(),
                                 [name](const Profile& profile) {
                                     return profile.registry_name == name;
                                 });
    return it == profiles.end() ? nullptr : &*it;
}

const Profile& active() {
    const Profile* profile = find_by_id(yume::kTransportProfile);
    if (profile == nullptr) {
        throw std::logic_error(
            "authenticated transport profile is absent from the build registry");
    }
    return *profile;
}

}  // namespace yume::cover_profile
