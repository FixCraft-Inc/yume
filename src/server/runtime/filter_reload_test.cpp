/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */
#include "server/runtime/manager.hpp"
#include "test_support/tls_identity.hpp"

#include <atomic>
#include <barrier>
#include <cassert>
#include <thread>

#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace {
namespace fs = std::filesystem;

struct Fixture {
    fs::path root;
    Fixture() {
#if defined(_WIN32)
        root = fs::temp_directory_path() / ("yume-filter-reload-" + std::to_string(
            std::chrono::steady_clock::now().time_since_epoch().count()));
        assert(fs::create_directory(root));
#else
        auto pattern = (fs::temp_directory_path() / "yume-filter-reload-XXXXXX").string();
        assert(::mkdtemp(pattern.data()));
        root = pattern;
#endif
    }
    ~Fixture() { std::error_code ec; fs::remove_all(root, ec); }
    void list(std::string_view text) const {
        std::ofstream output(root / "rules.json");
        output << text;
        output.close();
        assert(output);
    }
};
}  // namespace

int main() {
    Fixture fixture;
    fixture.list(R"({"ips":["192.0.2.1"]})");
    yume::server::ServerConfig config;
    config.tls_cert = (fixture.root / "cert.pem").string();
    config.tls_key = (fixture.root / "key.pem").string();
    yume::test::write_tls_identity(config.tls_cert, config.tls_key);
    config.filter_lists = {"egress:deny:" + (fixture.root / "rules.json").string()};
    boost::asio::io_context io;
    yume::server::Manager manager(io, config);
    const auto first = boost::asio::ip::make_address("192.0.2.1");
    const auto second = boost::asio::ip::make_address("198.51.100.1");
    std::string error;
    assert(!manager.egress_allowed(first, nullptr));
    fixture.list("{");
    assert(!manager.reload_client_filter(&error));
    assert(!manager.egress_allowed(first, nullptr));
    assert(manager.egress_allowed(second, nullptr));
    fixture.list(R"({"ips":["198.51.100.1"]})");
    assert(manager.reload_client_filter(&error));
    assert(manager.egress_allowed(first, nullptr));
    assert(!manager.egress_allowed(second, nullptr));

    // Every candidate denies second. Readers must never see a partially loaded
    // default-allow filter, or data freed/reallocated by the reload thread.
    std::atomic<bool> done{false};
    std::atomic<unsigned> reads{0};
    std::barrier start(3);
    const auto read = [&] {
        start.arrive_and_wait();
        do {
            assert(!manager.egress_allowed(second, nullptr));
            reads.fetch_add(1, std::memory_order_relaxed);
        } while (!done.load(std::memory_order_acquire));
    };
    std::jthread one(read);
    std::jthread two(read);
    start.arrive_and_wait();
    for (unsigned iteration = 0; iteration < 100; ++iteration) {
        fixture.list(iteration % 2 ? R"({"ips":["198.51.100.1","192.0.2.1"]})"
                                  : R"({"ips":["198.51.100.1"]})");
        assert(manager.reload_client_filter(&error));
    }
    done.store(true, std::memory_order_release);
    one.join();
    two.join();
    assert(reads.load() > 0);
    assert(!manager.egress_allowed(first, nullptr));
}
