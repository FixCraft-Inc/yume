/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/runtime/controller.hpp"

#include <array>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <thread>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <unistd.h>

#include "core/security/secret_file.hpp"

namespace {

using boost::asio::ip::tcp;
namespace fs = std::filesystem;

void check(bool condition, const char* message) {
    if (!condition) {
        std::fprintf(stderr, "server teardown: %s\n", message);
        std::exit(EXIT_FAILURE);
    }
}

struct AllocationFailure {
    bool persistent{false};
    std::size_t failures{0};
};

// Fail the caller's allocations, leaving Asio workers and the cover fixture
// alone. This deterministically reaches Manager::stop's real promise/post
// allocation with joinable controller workers and an outstanding accept.
thread_local AllocationFailure* active_failure = nullptr;

class FailureScope {
public:
    explicit FailureScope(AllocationFailure& failure) noexcept {
        active_failure = &failure;
    }
    ~FailureScope() { active_failure = nullptr; }
    FailureScope(const FailureScope&) = delete;
    FailureScope& operator=(const FailureScope&) = delete;
};

void inject_allocation_failure() {
    if (active_failure &&
        (active_failure->persistent || active_failure->failures == 0U)) {
        ++active_failure->failures;
        throw std::bad_alloc();
    }
}

class TemporaryDirectory {
public:
    TemporaryDirectory() {
        std::string pattern =
            (fs::temp_directory_path() / "yume-stop-XXXXXX").string();
        check(::mkdtemp(pattern.data()) != nullptr, "mkdtemp failed");
        path_ = pattern;
    }
    ~TemporaryDirectory() {
        std::error_code ignored;
        fs::remove_all(path_, ignored);
    }
    TemporaryDirectory(const TemporaryDirectory&) = delete;
    TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;
    const fs::path& path() const noexcept { return path_; }

private:
    fs::path path_;
};

void write_private_file(const fs::path& path, std::string_view contents) {
    std::string error;
    check(yume::security::WriteFileExclusive0600(
              path, std::span<const std::uint8_t>(
                        reinterpret_cast<const std::uint8_t*>(contents.data()),
                        contents.size()), &error),
          "could not create fixture file");
}

void write_tls_identity(const fs::path& certificate_path,
                        const fs::path& private_key_path) {
    using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using Certificate = std::unique_ptr<X509, decltype(&X509_free)>;
    using Bio = std::unique_ptr<BIO, decltype(&BIO_free)>;
    Key key(EVP_EC_gen("P-256"), EVP_PKEY_free);
    Certificate certificate(X509_new(), X509_free);
    check(key && certificate, "could not create TLS identity");
    check(X509_set_version(certificate.get(), 2) == 1 &&
              ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1) == 1 &&
              X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0) &&
              X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600) &&
              X509_set_pubkey(certificate.get(), key.get()) == 1,
          "could not initialize TLS certificate");
    auto* name = X509_get_subject_name(certificate.get());
    check(name && X509_NAME_add_entry_by_txt(
                      name, "CN", MBSTRING_ASC,
                      reinterpret_cast<const unsigned char*>("localhost"),
                      -1, -1, 0) == 1 &&
              X509_set_issuer_name(certificate.get(), name) == 1 &&
              X509_sign(certificate.get(), key.get(), EVP_sha256()) > 0,
          "could not sign TLS certificate");
    Bio certificate_bio(BIO_new(BIO_s_mem()), BIO_free);
    Bio key_bio(BIO_new(BIO_s_mem()), BIO_free);
    check(certificate_bio && key_bio &&
              PEM_write_bio_X509(certificate_bio.get(), certificate.get()) == 1 &&
              PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr,
                                       nullptr, 0, nullptr, nullptr) == 1,
          "could not encode TLS identity");
    char* certificate_bytes = nullptr;
    char* key_bytes = nullptr;
    const long certificate_size =
        BIO_get_mem_data(certificate_bio.get(), &certificate_bytes);
    const long key_size = BIO_get_mem_data(key_bio.get(), &key_bytes);
    check(certificate_size > 0 && key_size > 0, "TLS PEM is empty");
    write_private_file(certificate_path,
                       {certificate_bytes, static_cast<std::size_t>(certificate_size)});
    write_private_file(private_key_path,
                       {key_bytes, static_cast<std::size_t>(key_size)});
    OPENSSL_cleanse(key_bytes, static_cast<std::size_t>(key_size));
}

class CoverBackend {
public:
    CoverBackend() {
        accept();
        worker_ = std::jthread([this] { io_.run(); });
    }
    ~CoverBackend() { io_.stop(); }
    CoverBackend(const CoverBackend&) = delete;
    CoverBackend& operator=(const CoverBackend&) = delete;

    unsigned short port() const { return acceptor_.local_endpoint().port(); }

private:
    void accept() {
        auto socket = std::make_shared<tcp::socket>(io_);
        acceptor_.async_accept(*socket, [this, socket](boost::system::error_code error) {
            if (error) return;
            accept();
            auto request = std::make_shared<std::string>();
            boost::asio::async_read_until(
                *socket, boost::asio::dynamic_buffer(*request, 32768), "\r\n\r\n",
                [socket, request](boost::system::error_code read_error, std::size_t) {
                    if (read_error) return;
                    static constexpr std::string_view kResponse =
                        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                    boost::asio::async_write(*socket, boost::asio::buffer(kResponse),
                        [socket](boost::system::error_code, std::size_t) {});
                });
        });
    }

    boost::asio::io_context io_;
    tcp::acceptor acceptor_{io_, {boost::asio::ip::address_v4::loopback(), 0}};
    // Joins before the acceptor and context destruct.
    std::jthread worker_;
};

yume::server::ServerConfig make_config(const fs::path& directory,
                                       unsigned short backend_port) {
    yume::server::ServerConfig config;
    config.listen_address = "127.0.0.1";
    config.listen_port = 0;
    config.threads = 2;
    config.tls_cert = (directory / "tls.crt").string();
    config.tls_key = (directory / "tls.key").string();
    config.auth_keys = (directory / "authorized.pem").string();
    config.obfs_secret_file = (directory / "admission.hex").string();
    config.inner_psk_file = (directory / "inner.hex").string();
    config.real_index_path = (directory / "index.html").string();
    config.ipc_path = (directory / "runtime.sock").string();
    config.real_http = true;
    config.real_backend = "loopback://127.0.0.1:" + std::to_string(backend_port);
    write_tls_identity(config.tls_cert, config.tls_key);
    write_private_file(config.auth_keys, "");
    write_private_file(config.obfs_secret_file, std::string(64, '0'));
    write_private_file(config.inner_psk_file, std::string(64, '1'));
    write_private_file(config.real_index_path, "ordinary test cover");
    return config;
}

void start(yume::server::RuntimeController& controller,
           const yume::server::ServerConfig& config) {
    std::string error;
    if (!controller.start(config, &error)) {
        std::fprintf(stderr, "server teardown fixture start: %s\n", error.c_str());
        std::exit(EXIT_FAILURE);
    }
    check(controller.running(), "fixture did not publish running state");
    check(fs::exists(config.ipc_path), "fixture IPC socket was not created");
}

void test_allocation_failure(const yume::server::ServerConfig& config,
                              bool persistent, bool destruct) {
    auto controller = std::make_unique<yume::server::RuntimeController>();
    start(*controller, config);
    AllocationFailure failure{persistent, 0};
    {
        FailureScope scope(failure);
        if (destruct) {
            controller.reset();
        } else {
            check(controller->stop(), "stop did not settle the running controller");
        }
    }
    check(failure.failures != 0, "teardown did not reach injected allocation failure");
    check(!fs::exists(config.ipc_path), "teardown left its IPC socket behind");
    if (controller) {
        check(!controller->running(), "failed teardown left running set");
        const auto status = controller->status();
        check(status.message.find("teardown error: manager stop") != std::string::npos,
              "teardown failure was reported as clean success");
        check(!controller->stop(), "settled teardown retained live worker resources");
    }
}

void test_graceful_drain(yume::server::ServerConfig config) {
    boost::asio::io_context io;
    tcp::acceptor reservation(io, {boost::asio::ip::address_v4::loopback(), 0});
    const auto endpoint = reservation.local_endpoint();
    config.listen_port = endpoint.port();
    reservation.close();
    yume::server::RuntimeController controller;
    start(controller, config);

    boost::asio::ssl::context tls(boost::asio::ssl::context::tls_client);
    tls.set_verify_mode(boost::asio::ssl::verify_none);
    boost::asio::ssl::stream<tcp::socket> peer(io, tls);
    peer.next_layer().connect(endpoint);
    peer.handshake(boost::asio::ssl::stream_base::client);
    static constexpr std::string_view kRequest =
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
    boost::asio::write(peer, boost::asio::buffer(kRequest));
    std::string response;
    boost::asio::read_until(peer, boost::asio::dynamic_buffer(response, 32768), "\r\n\r\n");
    check(response.starts_with("HTTP/1.1 200"), "cover request did not reach live session");
    boost::system::error_code close_error;
    std::jthread reader([&] {
        std::array<char, 1> byte{};
        (void)peer.read_some(boost::asio::buffer(byte), close_error);
        boost::system::error_code ignored;
        peer.shutdown(ignored);
    });
    check(controller.stop(), "normal controller stop failed");
    reader.join();
    // EOF from SSL means close_notify; stopping the context before the real
    // session shutdown handler drains instead yields stream_truncated/reset.
    check(close_error == boost::asio::error::eof,
          "normal stop abandoned TLS shutdown instead of draining handlers");
    check(controller.status().message == "stopped", "normal stop reported a teardown failure");
    check(!fs::exists(config.ipc_path), "normal stop left its IPC socket behind");
}

}  // namespace

// Interposition is confined to this executable; fixtures are built before it
// is armed, and every allocation-failure scope ends before test reporting.
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmismatched-new-delete"
#endif
void* operator new(std::size_t size) {
    inject_allocation_failure();
    if (void* data = std::malloc(size == 0 ? 1 : size)) return data;
    throw std::bad_alloc();
}
void* operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void* data) noexcept { std::free(data); }
void operator delete[](void* data) noexcept { ::operator delete(data); }
void operator delete(void* data, std::size_t) noexcept { ::operator delete(data); }
void operator delete[](void* data, std::size_t) noexcept { ::operator delete(data); }
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

int main(int argc, char** argv) {
    check(argc == 2, "expected one teardown case name");
    const std::string_view test = argv[1];
    check(test == "drain" || test == "stop-once" || test == "stop-persistent" ||
              test == "destruct-once" || test == "destruct-persistent",
          "unknown teardown case name");
    TemporaryDirectory directory;
    CoverBackend backend;
    const auto config = make_config(directory.path(), backend.port());
    if (test == "drain") {
        test_graceful_drain(config);
    } else {
        test_allocation_failure(config, test.ends_with("persistent"),
                                  test.starts_with("destruct"));
    }
    std::printf("server teardown: %s passed\n", argv[1]);
}
