#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

namespace yume::obfs {

enum class Mode {
    kOff,
    kLegacyJitter,
    kH2Carrier,
};

struct ObfsConfig {
    bool enabled{false};
    Mode mode{Mode::kH2Carrier};
    size_t max_padding{32};
    int max_jitter_ms{15};
    bool send_dummy_http{false};
    std::uint32_t padding_mean{24};
    std::uint32_t padding_max{200};
    std::uint32_t ping_interval_s{25};
    std::string secret;
};

boost::asio::ssl::context create_server_context(const std::string& cert_path,
                                               const std::string& key_path,
                                               bool allow_h2 = true);
boost::asio::ssl::context create_client_context();
void configure_alpn(boost::asio::ssl::context& ctx, bool is_server, bool allow_h2 = true);

void apply_jitter(int max_jitter_ms);

void send_dummy_http_response(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream);

template <typename SyncStream>
std::size_t write_obfs(SyncStream& stream, const uint8_t* data, std::size_t len, const ObfsConfig& cfg) {
    if (!cfg.enabled) {
        return boost::asio::write(stream, boost::asio::buffer(data, len));
    }

    std::size_t total = 0;
    while (total < len) {
        apply_jitter(cfg.max_jitter_ms);
        std::size_t remaining = len - total;
        std::size_t chunk = std::min<std::size_t>(remaining, 1024);
        total += boost::asio::write(stream, boost::asio::buffer(data + total, chunk));
    }
    return total;
}

template <typename SyncStream>
std::size_t read_obfs(SyncStream& stream, uint8_t* data, std::size_t len, const ObfsConfig& cfg) {
    if (cfg.enabled) {
        apply_jitter(cfg.max_jitter_ms);
    }
    return boost::asio::read(stream, boost::asio::buffer(data, len));
}

}  // namespace yume::obfs
