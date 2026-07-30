/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "core/stealth/cover_profile.hpp"

#include <array>
#include <stdexcept>

namespace yume::cover_profile {
namespace {

using Source = HeaderValueSource;

constexpr std::array kClientSettings{
    H2Setting{1, 65536},
    H2Setting{2, 0},
    H2Setting{4, 6U * 1024U * 1024U},
    H2Setting{6, 256U * 1024U},
};

constexpr std::array kServerSettings{
    H2Setting{8, 1},
};

constexpr std::array kPrimingHeaders{
    HeaderTemplate{":method", Source::Literal, "GET"},
    HeaderTemplate{":authority", Source::Authority, {}},
    HeaderTemplate{":scheme", Source::Literal, "https"},
    HeaderTemplate{":path", Source::Literal, "/"},
    HeaderTemplate{"sec-ch-ua", Source::ClientHintBrand, {}},
    HeaderTemplate{"sec-ch-ua-mobile", Source::ClientHintMobile, {}},
    HeaderTemplate{"sec-ch-ua-platform", Source::ClientHintPlatform, {}},
    HeaderTemplate{"upgrade-insecure-requests", Source::Literal, "1"},
    HeaderTemplate{"user-agent", Source::UserAgent, {}},
    HeaderTemplate{"accept", Source::Literal,
                   "text/html,application/xhtml+xml,application/xml;q=0.9,"
                   "image/avif,image/webp,image/apng,*/*;q=0.8,"
                   "application/signed-exchange;v=b3;q=0.7"},
    HeaderTemplate{"sec-fetch-site", Source::Literal, "none"},
    HeaderTemplate{"sec-fetch-mode", Source::Literal, "navigate"},
    HeaderTemplate{"sec-fetch-user", Source::Literal, "?1"},
    HeaderTemplate{"sec-fetch-dest", Source::Literal, "document"},
    HeaderTemplate{"accept-encoding", Source::Literal, "gzip, deflate, br, zstd"},
    HeaderTemplate{"accept-language", Source::Literal, "en-US,en;q=0.9"},
    HeaderTemplate{"priority", Source::Literal, "u=0, i"},
};

constexpr std::array kConnectHeaders{
    HeaderTemplate{":method", Source::Literal, "CONNECT"},
    HeaderTemplate{":authority", Source::Authority, {}},
    HeaderTemplate{":scheme", Source::Literal, "https"},
    HeaderTemplate{":path", Source::CarrierPath, {}},
    HeaderTemplate{":protocol", Source::Literal, "websocket"},
    HeaderTemplate{"pragma", Source::Literal, "no-cache"},
    HeaderTemplate{"cache-control", Source::Literal, "no-cache"},
    HeaderTemplate{"user-agent", Source::UserAgent, {}},
    HeaderTemplate{"origin", Source::Origin, {}},
    HeaderTemplate{"sec-websocket-version", Source::Literal, "13"},
    HeaderTemplate{"accept-encoding", Source::Literal, "gzip, deflate, br, zstd"},
    HeaderTemplate{"accept-language", Source::Literal, "en-US,en;q=0.9"},
    HeaderTemplate{"sec-websocket-extensions", Source::Literal,
                   "permessage-deflate; client_max_window_bits"},
};

constexpr std::array kCssHeaders{
    HeaderTemplate{":method", Source::Literal, "GET"},
    HeaderTemplate{":authority", Source::Authority, {}},
    HeaderTemplate{":scheme", Source::Literal, "https"},
    HeaderTemplate{":path", Source::Literal, "/assets/site.css"},
    HeaderTemplate{"sec-ch-ua-platform", Source::ClientHintPlatform, {}},
    HeaderTemplate{"user-agent", Source::UserAgent, {}},
    HeaderTemplate{"sec-ch-ua", Source::ClientHintBrand, {}},
    HeaderTemplate{"sec-ch-ua-mobile", Source::ClientHintMobile, {}},
    HeaderTemplate{"accept", Source::Literal, "text/css,*/*;q=0.1"},
    HeaderTemplate{"sec-fetch-site", Source::Literal, "same-origin"},
    HeaderTemplate{"sec-fetch-mode", Source::Literal, "no-cors"},
    HeaderTemplate{"sec-fetch-dest", Source::Literal, "style"},
    HeaderTemplate{"referer", Source::RootReferer, {}},
    HeaderTemplate{"accept-encoding", Source::Literal, "gzip, deflate, br, zstd"},
    HeaderTemplate{"accept-language", Source::Literal, "en-US,en;q=0.9"},
    HeaderTemplate{"priority", Source::Literal, "u=0"},
};

constexpr std::array kJsHeaders{
    HeaderTemplate{":method", Source::Literal, "GET"},
    HeaderTemplate{":authority", Source::Authority, {}},
    HeaderTemplate{":scheme", Source::Literal, "https"},
    HeaderTemplate{":path", Source::Literal, "/assets/site.js"},
    HeaderTemplate{"sec-ch-ua-platform", Source::ClientHintPlatform, {}},
    HeaderTemplate{"user-agent", Source::UserAgent, {}},
    HeaderTemplate{"sec-ch-ua", Source::ClientHintBrand, {}},
    HeaderTemplate{"sec-ch-ua-mobile", Source::ClientHintMobile, {}},
    HeaderTemplate{"accept", Source::Literal, "*/*"},
    HeaderTemplate{"sec-fetch-site", Source::Literal, "same-origin"},
    HeaderTemplate{"sec-fetch-mode", Source::Literal, "no-cors"},
    HeaderTemplate{"sec-fetch-dest", Source::Literal, "script"},
    HeaderTemplate{"referer", Source::RootReferer, {}},
    HeaderTemplate{"accept-encoding", Source::Literal, "gzip, deflate, br, zstd"},
    HeaderTemplate{"accept-language", Source::Literal, "en-US,en;q=0.9"},
};

constexpr std::array kAssets{
    AssetTemplate{
        "/assets/site.css",
        RequestTemplate{kCssHeaders, H2Priority{0, 256, true}}},
    AssetTemplate{
        "/assets/site.js",
        RequestTemplate{kJsHeaders, H2Priority{-1, 147, true}}},
};

const Profile kChrome150Debian13Node24{
    "chrome",
    "Google Chrome",
    "150.0.7871.114",
    "Debian GNU/Linux 13 (trixie)",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36",
    "\"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"150\", "
    "\"Google Chrome\";v=\"150\"",
    "?0",
    "\"Linux\"",
    tls_fingerprint::BrowserProfile::CHROME_150,
    0x0304,
    0x0304,
    "Node.js",
    "24.18.0",
    kClientSettings,
    kServerSettings,
    15663105,
    RequestTemplate{kPrimingHeaders, H2Priority{0, 256, true}},
    RequestTemplate{kConnectHeaders, H2Priority{0, 147, true}},
    kAssets,
    16U * 1024U,
};

}  // namespace

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

const Profile& chrome150_debian13_node24() {
    return kChrome150Debian13Node24;
}

}  // namespace yume::cover_profile
