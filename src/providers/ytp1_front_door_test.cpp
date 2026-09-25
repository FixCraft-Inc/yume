/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/ytp1_front_door.hpp"
#include "providers/ytp1_h2_admission.hpp"
#include "stealth/cover_profile.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/v6_only.hpp>
#include <boost/asio/post.hpp>
#include <nghttp2/nghttp2.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <sys/socket.h>

#ifdef YUME_TEST_WRAP_BIND
namespace {
// Only the runner thread that arms the next bind failure observes it. Every
// other bind, including the ordinary cover/promotion tests, calls the OS.
thread_local int injected_bind_error = 0;
}
extern "C" int __real_bind(int, const sockaddr*, socklen_t);
extern "C" int __wrap_bind(int socket, const sockaddr* address, socklen_t length) {
    if (const int failure = std::exchange(injected_bind_error, 0)) {
        errno = failure;
        return -1;
    }
    return __real_bind(socket, address, length);
}
#endif

namespace yume::providers {
namespace {

using namespace engine;
using namespace std::chrono_literals;
using Tcp = boost::asio::ip::tcp;

#define CHECK(expression)                                                      \
    do {                                                                       \
        if (!(expression)) {                                                   \
            throw std::runtime_error(std::string("check failed at line ") +   \
                                     std::to_string(__LINE__) + ": " +        \
                                     #expression);                             \
        }                                                                      \
    } while (false)

template <typename T>
T take(Result<T> result) {
    if (!result.ok()) throw std::runtime_error(result.status().message());
    return std::move(result).take_value();
}

template <typename T>
T await(std::future<T>& future) {
    CHECK(future.wait_for(5s) == std::future_status::ready);
    return future.get();
}

Buffer buffer(std::string_view value) {
    return take(Buffer::copy_from(
        {reinterpret_cast<const std::byte*>(value.data()), value.size()},
        std::max<std::size_t>(value.size(), 1U)));
}

std::string text(const Buffer& value) {
    return {reinterpret_cast<const char*>(value.bytes().data()), value.size()};
}

constexpr std::array<std::byte, 32U> kAdmissionKey{
    std::byte{0x4a}, std::byte{0x98}, std::byte{0xe1}};
constexpr std::string_view kIndex = "<!doctype html><title>Field notes</title><p>Ordinary site.</p>";
constexpr std::string_view kNotFound = "<!doctype html><title>Not found</title><p>This page is absent.</p>";

class IoRuntime final {
public:
    IoRuntime()
        : context_(take(AsioExecutionContext::create(ExecutorAffinity(191U)))),
          worker_([this] {
              for (;;) {
                  try {
                      context_->run();
                      return;
                  } catch (...) {
                      // An Asio delivery failure does not cancel its operation;
                      // resume the runner so reserved failure delivery can drain.
                      ++runner_exceptions_;
                  }
              }
          }) {}
    ~IoRuntime() noexcept { finish_and_join(); }
    void finish_and_join() noexcept {
        context_->finish();
        if (worker_.joinable()) worker_.join();
    }
    IoRuntime(const IoRuntime&) = delete;
    IoRuntime& operator=(const IoRuntime&) = delete;

    const std::shared_ptr<AsioExecutionContext>& context() const noexcept {
        return context_;
    }
    template <typename Function>
    auto sync(Function&& function) -> std::invoke_result_t<Function> {
        using Value = std::invoke_result_t<Function>;
        auto task = std::make_shared<std::packaged_task<Value()>>(
            std::forward<Function>(function));
        auto future = task->get_future();
        boost::asio::post(context_->executor(), [task] { (*task)(); });
        return await(future);
    }
    std::size_t runner_exceptions() const noexcept {
        return runner_exceptions_.load();
    }

private:
    std::shared_ptr<AsioExecutionContext> context_;
    std::atomic<std::size_t> runner_exceptions_{0U};
    std::thread worker_;
};

struct PemIdentity final {
    std::vector<std::byte> certificate;
    std::vector<std::byte> key;
};

PemIdentity make_identity() {
    using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using Cert = std::unique_ptr<X509, decltype(&X509_free)>;
    using Bio = std::unique_ptr<BIO, decltype(&BIO_free)>;
    using Extension = std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)>;
    Key key(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"), EVP_PKEY_free);
    Cert certificate(X509_new(), X509_free);
    CHECK(key && certificate);
    CHECK(X509_set_version(certificate.get(), 2L) == 1);
    CHECK(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1L) == 1);
    CHECK(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -60L));
    CHECK(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600L));
    CHECK(X509_set_pubkey(certificate.get(), key.get()) == 1);
    X509_NAME* name = X509_get_subject_name(certificate.get());
    CHECK(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0) == 1);
    CHECK(X509_set_issuer_name(certificate.get(), name) == 1);
    X509V3_CTX context{};
    X509V3_set_ctx(&context, certificate.get(), certificate.get(), nullptr, nullptr, 0);
    Extension san(X509V3_EXT_conf_nid(nullptr, &context, NID_subject_alt_name,
                                    const_cast<char*>("DNS:localhost")),
                  X509_EXTENSION_free);
    Extension ca(X509V3_EXT_conf_nid(nullptr, &context, NID_basic_constraints,
                                   const_cast<char*>("critical,CA:TRUE")),
                 X509_EXTENSION_free);
    CHECK(san && ca);
    CHECK(X509_add_ext(certificate.get(), san.get(), -1) == 1);
    CHECK(X509_add_ext(certificate.get(), ca.get(), -1) == 1);
    CHECK(X509_sign(certificate.get(), key.get(), EVP_sha256()) > 0);
    Bio cert_bio(BIO_new(BIO_s_mem()), BIO_free);
    Bio key_bio(BIO_new(BIO_s_mem()), BIO_free);
    CHECK(cert_bio && key_bio);
    CHECK(PEM_write_bio_X509(cert_bio.get(), certificate.get()) == 1);
    CHECK(PEM_write_bio_PrivateKey(key_bio.get(), key.get(), nullptr, nullptr,
                                 0, nullptr, nullptr) == 1);
    const auto contents = [](BIO* bio) {
        BUF_MEM* memory = nullptr;
        BIO_get_mem_ptr(bio, &memory);
        CHECK(memory && memory->length > 0U);
        const auto* begin = reinterpret_cast<const std::byte*>(memory->data);
        return std::vector<std::byte>(begin, begin + memory->length);
    };
    return {contents(cert_bio.get()), contents(key_bio.get())};
}

class CoverFiles final {
public:
    CoverFiles() {
        std::array<char, 40U> pattern{};
        constexpr std::string_view prefix = "/tmp/yume-frontdoor-test.XXXXXX";
        std::copy(prefix.begin(), prefix.end(), pattern.begin());
        const char* created = ::mkdtemp(pattern.data());
        CHECK(created);
        root_ = created;
        write("index.html", kIndex);
        write("404.html", kNotFound);
        write("asset.css", "body { color: #243; }");
    }
    ~CoverFiles() noexcept {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }
    std::shared_ptr<const Ytp1CoverSite> load() const {
        std::vector<Ytp1CoverFile> routes{
            {"/", "index.html", "text/html; charset=utf-8"},
            {"/asset.css", "asset.css", "text/css"}};
        for (const auto& asset : cover_profile::active().assets)
            routes.push_back({std::string(asset.path), "asset.css", "text/css"});
        return take(Ytp1CoverSite::load(root_, routes, "404.html"));
    }

private:
    void write(std::string_view name, std::string_view value) {
        std::ofstream out(root_ / name, std::ios::binary);
        out.write(value.data(), static_cast<std::streamsize>(value.size()));
        out.close();
        CHECK(out);
    }
    std::filesystem::path root_;
};

// These clients deliberately use an independent HTTP/2 parser. Comparing the
// raw peer's response bodies observes the public boundary rather than a server
// helper's classification of admission failure.
class TlsPeer final {
public:
    TlsPeer(std::uint16_t port, std::span<const std::byte> certificate,
            int tls_version = TLS1_3_VERSION, std::string_view alpn = "h2",
            boost::asio::ip::address address = boost::asio::ip::address_v4::loopback())
        : socket_(io_), context_(SSL_CTX_new(TLS_client_method()), SSL_CTX_free),
          ssl_(nullptr, SSL_free) {
        CHECK(context_);
        CHECK(SSL_CTX_set_min_proto_version(context_.get(), tls_version) == 1);
        CHECK(SSL_CTX_set_max_proto_version(context_.get(), tls_version) == 1);
        SSL_CTX_set_verify(context_.get(), SSL_VERIFY_PEER, nullptr);
        std::unique_ptr<BIO, decltype(&BIO_free)> input(
            BIO_new_mem_buf(certificate.data(), static_cast<int>(certificate.size())), BIO_free);
        std::unique_ptr<X509, decltype(&X509_free)> trust(
            PEM_read_bio_X509(input.get(), nullptr, nullptr, nullptr), X509_free);
        CHECK(trust && X509_STORE_add_cert(SSL_CTX_get_cert_store(context_.get()), trust.get()) == 1);
        ssl_.reset(SSL_new(context_.get()));
        CHECK(ssl_);
        CHECK(SSL_set_tlsext_host_name(ssl_.get(), "localhost") == 1);
        CHECK(SSL_set1_host(ssl_.get(), "localhost") == 1);
        if (!alpn.empty()) {
            std::string wire(1U, static_cast<char>(alpn.size()));
            wire += alpn;
            CHECK(SSL_set_alpn_protos(ssl_.get(),
                reinterpret_cast<const unsigned char*>(wire.data()),
                static_cast<unsigned int>(wire.size())) == 0);
        }
        socket_.connect({address, port});
        const timeval timeout{3, 0};
        CHECK(::setsockopt(socket_.native_handle(), SOL_SOCKET, SO_RCVTIMEO,
                           &timeout, sizeof(timeout)) == 0);
        CHECK(::setsockopt(socket_.native_handle(), SOL_SOCKET, SO_SNDTIMEO,
                           &timeout, sizeof(timeout)) == 0);
        CHECK(SSL_set_fd(ssl_.get(), socket_.native_handle()) == 1);
        CHECK(SSL_connect(ssl_.get()) == 1);
        CHECK(SSL_version(ssl_.get()) == tls_version);
    }
    void write(std::span<const std::uint8_t> value) {
        while (!value.empty()) {
            std::size_t written = 0U;
            CHECK(SSL_write_ex(ssl_.get(), value.data(), value.size(), &written) == 1);
            CHECK(written > 0U);
            value = value.subspan(written);
        }
    }
    void write(std::string_view value) {
        write({reinterpret_cast<const std::uint8_t*>(value.data()), value.size()});
    }
    std::vector<std::uint8_t> read() {
        std::vector<std::uint8_t> value(64U * 1024U);
        std::size_t count = 0U;
        CHECK(SSL_read_ex(ssl_.get(), value.data(), value.size(), &count) == 1);
        CHECK(count > 0U);
        value.resize(count);
        return value;
    }
    std::string admission_path(const admission::Nonce& nonce) {
        std::array<std::byte, 32U> exporter{};
        CHECK(SSL_export_keying_material(ssl_.get(),
            reinterpret_cast<unsigned char*>(exporter.data()), exporter.size(),
            kYtp1H2AdmissionExporterLabel.data(), kYtp1H2AdmissionExporterLabel.size(),
            nullptr, 0U, 0) == 1);
        auto path = build_ytp1_h2_admission_path(kAdmissionKey, "localhost", exporter, nonce);
        CHECK(path);
        return *path;
    }

private:
    boost::asio::io_context io_;
    Tcp::socket socket_;
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> context_;
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl_;
};

struct HttpResponse final {
    std::map<std::string, std::string> headers;
    std::string body;
    bool complete{false};
};

class H2Peer final {
public:
    explicit H2Peer(TlsPeer& tls, std::uint16_t port)
        : tls_(tls), authority_("localhost:" + std::to_string(port)),
          session_(nullptr, nghttp2_session_del) {
        nghttp2_session_callbacks* raw_callbacks = nullptr;
        CHECK(nghttp2_session_callbacks_new(&raw_callbacks) == 0);
        std::unique_ptr<nghttp2_session_callbacks, decltype(&nghttp2_session_callbacks_del)>
            callbacks(raw_callbacks, nghttp2_session_callbacks_del);
        nghttp2_session_callbacks_set_on_header_callback(callbacks.get(),
            [](nghttp2_session*, const nghttp2_frame* frame,
               const std::uint8_t* name, std::size_t name_size,
               const std::uint8_t* value, std::size_t value_size,
               std::uint8_t, void* opaque) noexcept -> int {
                try {
                    auto& self = *static_cast<H2Peer*>(opaque);
                    self.responses_[frame->hd.stream_id].headers.emplace(
                        std::string(reinterpret_cast<const char*>(name), name_size),
                        std::string(reinterpret_cast<const char*>(value), value_size));
                    return 0;
                } catch (...) { return NGHTTP2_ERR_CALLBACK_FAILURE; }
            });
        nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks.get(),
            [](nghttp2_session*, std::uint8_t, std::int32_t stream,
               const std::uint8_t* data, std::size_t size, void* opaque) noexcept -> int {
                try {
                    auto& self = *static_cast<H2Peer*>(opaque);
                    if (self.responses_[stream].body.size() + size > 2U * 1024U * 1024U)
                        return NGHTTP2_ERR_CALLBACK_FAILURE;
                    self.responses_[stream].body.append(
                        reinterpret_cast<const char*>(data), size);
                    return 0;
                } catch (...) { return NGHTTP2_ERR_CALLBACK_FAILURE; }
            });
        nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks.get(),
            [](nghttp2_session*, const nghttp2_frame* frame, void* opaque) noexcept -> int {
                try {
                    auto& self = *static_cast<H2Peer*>(opaque);
                    if (frame->hd.type == NGHTTP2_SETTINGS && !(frame->hd.flags & NGHTTP2_FLAG_ACK))
                        self.settings_received_ = true;
                    if ((frame->hd.type == NGHTTP2_DATA || frame->hd.type == NGHTTP2_HEADERS) &&
                        (frame->hd.flags & NGHTTP2_FLAG_END_STREAM))
                        self.responses_[frame->hd.stream_id].complete = true;
                    return 0;
                } catch (...) { return NGHTTP2_ERR_CALLBACK_FAILURE; }
            });
        nghttp2_session* raw_session = nullptr;
        CHECK(nghttp2_session_client_new(&raw_session, callbacks.get(), this) == 0);
        session_.reset(raw_session);
        CHECK(nghttp2_submit_settings(session_.get(), NGHTTP2_FLAG_NONE, nullptr, 0U) == 0);
        flush();
        while (!settings_received_) receive();
    }
    std::int32_t submit(std::string method, std::string path, bool extended = false) {
        std::vector<std::pair<std::string, std::string>> values{
            {":method", std::move(method)}, {":scheme", "https"},
            {":authority", authority_}, {":path", std::move(path)}};
        if (extended) {
            values.emplace_back(":protocol", "websocket");
            values.emplace_back("sec-websocket-version", "13");
        }
        std::vector<nghttp2_nv> headers;
        for (auto& [name, value] : values)
            headers.push_back({reinterpret_cast<std::uint8_t*>(name.data()),
                reinterpret_cast<std::uint8_t*>(value.data()), name.size(), value.size(),
                NGHTTP2_NV_FLAG_NONE});
        nghttp2_data_provider data{};
        data.read_callback = [](nghttp2_session*, std::int32_t, std::uint8_t*,
                                std::size_t, std::uint32_t*, nghttp2_data_source*, void*) -> ssize_t {
            return NGHTTP2_ERR_DEFERRED;
        };
        const auto stream = nghttp2_submit_request(session_.get(), nullptr,
            headers.data(), headers.size(), extended ? &data : nullptr, nullptr);
        CHECK(stream > 0);
        flush();
        return stream;
    }
    HttpResponse response(std::int32_t stream) {
        while (!responses_[stream].complete) receive();
        return responses_[stream];
    }
    HttpResponse response_headers(std::int32_t stream) {
        while (!responses_[stream].headers.contains(":status")) receive();
        return responses_[stream];
    }
    void receive() {
        const auto value = tls_.read();
        const auto consumed = nghttp2_session_mem_recv(session_.get(), value.data(), value.size());
        CHECK(consumed == static_cast<ssize_t>(value.size()));
        flush();
    }
    void flush() {
        const std::uint8_t* data = nullptr;
        for (;;) {
            const auto count = nghttp2_session_mem_send(session_.get(), &data);
            CHECK(count >= 0);
            if (count == 0) return;
            tls_.write({data, static_cast<std::size_t>(count)});
        }
    }

private:
    TlsPeer& tls_;
    std::string authority_;
    std::unique_ptr<nghttp2_session, decltype(&nghttp2_session_del)> session_;
    std::map<std::int32_t, HttpResponse> responses_;
    bool settings_received_{false};
};

}  // namespace
}  // namespace yume::providers

namespace yume::providers {
namespace {

class Fixture final {
public:
    explicit Fixture(Ytp1FrontDoorLimits limits = {},
                     std::size_t replay_entries = 64U,
                     std::uint64_t replay_ttl_seconds = 3600U)
        : identity(make_identity()), cover(files.load()),
          replay(std::make_shared<admission::ReplayCache>(replay_entries, replay_ttl_seconds)),
          tls(take(Ytp1Tls13SecureChannelProvider::create_server(
              {identity.certificate, identity.key, {}, {}}))) {
        Ytp1FrontDoorConfig config;
        config.listen_endpoint = {boost::asio::ip::address_v4::loopback(), 0U};
        config.limits = limits;
        door = runtime.sync([&] {
            return take(Ytp1FrontDoor::create(runtime.context(), config, tls,
                cover, replay, kAdmissionKey));
        });
        CHECK(door->local_endpoint().address().is_loopback());
        CHECK(door->local_endpoint().port() != 0U);
        CHECK(door->executor_affinity() == runtime.context()->affinity());
    }
    ~Fixture() noexcept {
        if (door) door->close();
        door.reset();
    }
    Ytp1H2Dispatch post() const {
        return {
            [context = runtime.context()](std::function<void()> task) {
                boost::asio::post(context->executor(), std::move(task));
            },
            [context = runtime.context()](ControlTask& task, std::shared_ptr<void> owner) noexcept {
                context->submit(task, std::move(owner));
            }};
    }
    std::uint16_t port() const { return door->local_endpoint().port(); }
    std::future<Result<AcceptedCarrier>> accept(CancellationToken token = {}) {
        auto promise = std::make_shared<std::promise<Result<AcceptedCarrier>>>();
        auto result = promise->get_future();
        runtime.sync([&] {
            door->async_accept(token, [promise, context = runtime.context()](Result<AcceptedCarrier> accepted) {
                if (!context->running_in_this_thread()) {
                    promise->set_exception(std::make_exception_ptr(
                        std::runtime_error("accept completion escaped executor affinity")));
                    return;
                }
                promise->set_value(std::move(accepted));
            });
        });
        return result;
    }
    void destroy_door() {
        door->close();
        door.reset();
        runtime.sync([] {});
    }

    IoRuntime runtime;
    CoverFiles files;
    PemIdentity identity;
    std::shared_ptr<const Ytp1CoverSite> cover;
    std::shared_ptr<admission::ReplayCache> replay;
    std::shared_ptr<Ytp1Tls13SecureChannelProvider> tls;
    std::shared_ptr<Ytp1FrontDoor> door;
};

void check_cover(const HttpResponse& response) {
    CHECK(response.headers.at(":status") == "404");
    CHECK(response.headers.at("content-type") == "text/html");
    CHECK(response.headers.at("content-length") == std::to_string(kNotFound.size()));
    CHECK(response.body == kNotFound);
    for (const auto& [name, value] : response.headers) {
        CHECK(name.find("yume") == std::string::npos);
        CHECK(value.find("YUME") == std::string::npos);
    }
}

void test_http_cover_and_failed_admission() {
    Fixture fixture;
    auto pending_accept = fixture.accept();
    for (const auto& [version, alpn] :
         {std::pair{TLS1_3_VERSION, std::string_view("http/1.1")},
          std::pair{TLS1_2_VERSION, std::string_view("http/1.1")},
          std::pair{TLS1_3_VERSION, std::string_view{}}}) {
        TlsPeer peer(fixture.port(), fixture.identity.certificate, version, alpn);
        peer.write("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        std::string response;
        while (response.find(kIndex) == std::string::npos) {
            const auto chunk = peer.read();
            response.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            CHECK(response.size() < 64U * 1024U);
        }
        CHECK(response.starts_with("HTTP/1.1 200 "));
        CHECK(response.substr(response.find("\r\n\r\n") + 4U) == kIndex);
    }
    for (const auto request : {
             std::string_view("POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n"
                              "Connection: close\r\n\r\ndata"),
             std::string_view("POST / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n"
                              "Connection: close\r\n\r\n4\r\ndata\r\n0\r\n\r\n")}) {
        TlsPeer peer(fixture.port(), fixture.identity.certificate,
                     TLS1_3_VERSION, "http/1.1");
        peer.write(request);
        std::string response;
        while (response.find(kNotFound) == std::string::npos) {
            const auto chunk = peer.read();
            response.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            CHECK(response.size() < 64U * 1024U);
        }
        CHECK(response.starts_with("HTTP/1.1 404 "));
        CHECK(response.substr(response.find("\r\n\r\n") + 4U) == kNotFound);
    }
    TlsPeer tls(fixture.port(), fixture.identity.certificate);
    H2Peer h2(tls, fixture.port());
    const auto index = h2.response(h2.submit("GET", "/"));
    CHECK(index.headers.at(":status") == "200");
    CHECK(index.body == kIndex);
    const auto head = h2.response(h2.submit("HEAD", "/"));
    CHECK(head.headers.at(":status") == "200");
    CHECK(head.headers.at("content-length") == std::to_string(kIndex.size()));
    CHECK(head.body.empty());
    check_cover(h2.response(h2.submit("GET", "/absent")));
    check_cover(h2.response(h2.submit("CONNECT", "/", true)));
    check_cover(h2.response(h2.submit("CONNECT", "/not-a-proof", true)));
    admission::Nonce nonce{};
    nonce[0] = std::byte{1U};
    std::string invalid = tls.admission_path(nonce);
    invalid[1] = invalid[1] == '0' ? '1' : '0';
    check_cover(h2.response(h2.submit("CONNECT", invalid, true)));
    CHECK(pending_accept.wait_for(0ms) == std::future_status::timeout);
    CHECK(fixture.replay->size() == 0U);

    // A genuine proof from one SSL connection cannot be moved to another SSL
    // connection, even when SNI, authority and key all remain identical.
    const auto transferred = tls.admission_path(nonce);
    TlsPeer other_tls(fixture.port(), fixture.identity.certificate);
    H2Peer other_h2(other_tls, fixture.port());
    check_cover(other_h2.response(other_h2.submit("CONNECT", transferred, true)));
    CHECK(fixture.replay->size() == 0U);
    {
        // An authentic proof on legacy TLS still has only cover provenance.
        TlsPeer legacy_tls(fixture.port(), fixture.identity.certificate, TLS1_2_VERSION);
        H2Peer legacy_h2(legacy_tls, fixture.port());
        check_cover(legacy_h2.response(legacy_h2.submit(
            "CONNECT", legacy_tls.admission_path(nonce), true)));
        CHECK(fixture.replay->size() == 0U);
    }
    fixture.door->cancel();
    auto cancelled = await(pending_accept);
    CHECK(!cancelled.ok() && cancelled.status().code() == StatusCode::Cancelled);
    check_cover(h2.response(h2.submit("CONNECT", tls.admission_path(nonce), true)));
    CHECK(fixture.replay->size() == 0U);
    CHECK(fixture.runtime.runner_exceptions() == 0U);
}

class CarrierPair final {
public:
    explicit CarrierPair(Fixture& fixture) : fixture_(fixture) {
        auto accepted = fixture.accept();
        tcp_owner_ = take(AsioTcpAcceptedChannelOwner::create(fixture.runtime.context()));
        AsioTcpSocket socket(fixture.runtime.context()->executor());
        socket.connect({boost::asio::ip::address_v4::loopback(), fixture.port()});
        auto channel = take(tcp_owner_->adopt(std::move(socket)));
        client_tls_ = take(Ytp1Tls13SecureChannelProvider::create_client(
            {"localhost", fixture.identity.certificate, {}, {}, {}}));
        client_h2_ = take(Ytp1H2CarrierProvider::create(
            fixture.runtime.context()->affinity(), fixture.post(),
            {"localhost", fixture.port(), {}}, kAdmissionKey));
        auto promise = std::make_shared<std::promise<Result<std::unique_ptr<Carrier>>>>();
        auto connected = promise->get_future();
        fixture.runtime.sync([&] {
            client_tls_->async_wrap(std::move(channel), EndpointRole::Client, {},
                [h2 = client_h2_, promise](Result<std::unique_ptr<SecureChannel>> secure) {
                    if (!secure.ok()) {
                        promise->set_value(Result<std::unique_ptr<Carrier>>(secure.status()));
                        return;
                    }
                    h2->async_create(std::move(secure).take_value(), EndpointRole::Client, {},
                        [promise](Result<std::unique_ptr<Carrier>> carrier) {
                            promise->set_value(std::move(carrier));
                        });
                });
        });
        client = take(await(connected));
        auto server_result = take(await(accepted));
        CHECK(server_result.descriptor().provider_id() == kYtp1H2CarrierProviderId);
        server = std::move(server_result).take_carrier();
        CHECK(server->executor_affinity() == fixture.runtime.context()->affinity());
        CHECK(server->secure_channel().executor_affinity() == server->executor_affinity());
        CHECK(server->secure_channel().descriptor().provider_id() == kYtp1Tls13SecureChannelProviderId);
    }
    ~CarrierPair() noexcept {
        if (client) client->close();
        if (server) server->close();
    }
    void exchange(Carrier& sender, Carrier& receiver, std::string_view payload) {
        auto sent = std::make_shared<std::promise<std::pair<Status, std::size_t>>>();
        auto sent_future = sent->get_future();
        auto received = std::make_shared<std::promise<Result<ReceivedRecord>>>();
        auto received_future = received->get_future();
        fixture_.runtime.sync([&] {
            receiver.async_receive({}, [received](Result<ReceivedRecord> record) {
                received->set_value(std::move(record));
            });
            sender.async_send(buffer(payload), {}, [sent](Status status, std::size_t count) {
                sent->set_value({std::move(status), count});
            });
        });
        const auto write = await(sent_future);
        CHECK(write.first.ok() && write.second == payload.size());
        auto record = take(await(received_future));
        CHECK(text(record.payload()) == payload);
        auto credit = record.take_credit();
        CHECK(credit.size() == payload.size());
        credit.release_now();
    }

    std::unique_ptr<Carrier> client;
    std::unique_ptr<Carrier> server;

private:
    Fixture& fixture_;
    std::shared_ptr<AsioTcpAcceptedChannelOwner> tcp_owner_;
    std::shared_ptr<Ytp1Tls13SecureChannelProvider> client_tls_;
    std::shared_ptr<Ytp1H2CarrierProvider> client_h2_;
};

void test_native_promotion_record_credit_and_owner_lifetime() {
    Fixture fixture;
    CarrierPair pair(fixture);
    std::string payload(256U * 1024U, 'q');
    for (std::size_t i = 0U; i < payload.size(); ++i)
        payload[i] = static_cast<char>('a' + i % 23U);
    pair.exchange(*pair.client, *pair.server, payload);
    pair.exchange(*pair.server, *pair.client, payload);
    CHECK(fixture.replay->size() == 1U);

    CancellationSource cancellation;
    auto cancelled = std::make_shared<std::promise<Result<ReceivedRecord>>>();
    auto cancellation_result = cancelled->get_future();
    fixture.runtime.sync([&] {
        pair.server->async_receive(cancellation.token(),
            [cancelled](Result<ReceivedRecord> result) {
                cancelled->set_value(std::move(result));
            });
    });
    cancellation.cancel();
    auto received = await(cancellation_result);
    CHECK(!received.ok() && received.status().code() == StatusCode::Cancelled);
    pair.exchange(*pair.client, *pair.server, "after cancelled receive");

    // Removing the listener must not cancel the TCP owner of an already
    // published carrier or invalidate the cover/parser state it retains.
    std::weak_ptr<Ytp1FrontDoor> weak_door = fixture.door;
    fixture.destroy_door();
    CHECK(weak_door.expired());
    pair.exchange(*pair.client, *pair.server, payload);
    pair.exchange(*pair.server, *pair.client, "after listener destruction");
    CHECK(fixture.runtime.runner_exceptions() == 0U);
}

void test_replay_and_cache_saturation_use_cover() {
    Fixture fixture({}, 1U);
    auto accept = fixture.accept();
    admission::Nonce nonce{};
    nonce[0] = std::byte{13U};
    const auto now = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    CHECK(fixture.replay->reserve(nonce, now) == admission::ReplayDecision::Accepted);
    TlsPeer tls(fixture.port(), fixture.identity.certificate);
    H2Peer h2(tls, fixture.port());
    check_cover(h2.response(h2.submit("CONNECT", tls.admission_path(nonce), true)));
    nonce[0] = std::byte{14U};
    check_cover(h2.response(h2.submit("CONNECT", tls.admission_path(nonce), true)));
    CHECK(fixture.replay->size() == 1U);
    CHECK(accept.wait_for(0ms) == std::future_status::timeout);
    fixture.door->cancel();
    auto result = await(accept);
    CHECK(!result.ok() && result.status().code() == StatusCode::Cancelled);
}

void test_one_promotion_per_tls_lifetime_after_replay_expiry() {
    Fixture fixture({}, 64U, 1U);
    auto accepted = fixture.accept();
    TlsPeer tls(fixture.port(), fixture.identity.certificate);
    H2Peer h2(tls, fixture.port());
    admission::Nonce nonce{};
    nonce[0] = std::byte{31U};
    check_cover(h2.response(h2.submit("CONNECT", "/invalid-before-promotion", true)));
    const auto path = tls.admission_path(nonce);
    const auto stream = h2.submit("CONNECT", path, true);
    CHECK(h2.response_headers(stream).headers.at(":status") == "200");
    auto server = std::move(take(await(accepted))).take_carrier();
    auto second_accept = fixture.accept();

    // A one-second cache TTL has certainly expired after this bounded wait.
    // Both the old proof and a fresh proof on the original live TLS session
    // still use ordinary cover; the promoted connection can never re-admit.
    std::this_thread::sleep_for(1100ms);
    check_cover(h2.response(h2.submit("CONNECT", path, true)));
    nonce[0] = std::byte{32U};
    check_cover(h2.response(h2.submit("CONNECT", tls.admission_path(nonce), true)));
    CHECK(h2.response(h2.submit("GET", "/")).body == kIndex);
    CHECK(second_accept.wait_for(0ms) == std::future_status::timeout);
    fixture.door->cancel();
    const auto cancelled = await(second_accept);
    CHECK(!cancelled.ok() && cancelled.status().code() == StatusCode::Cancelled);
    server->close();
}

void test_cross_connection_replay_after_promotion() {
    // Keep this replay probe separate from the one-second expiry test: its
    // validity must not depend on which side of a clock tick TLS completes.
    Fixture fixture;
    auto accepted = fixture.accept();
    TlsPeer tls(fixture.port(), fixture.identity.certificate);
    H2Peer h2(tls, fixture.port());
    admission::Nonce nonce{};
    nonce[0] = std::byte{33U};
    CHECK(h2.response_headers(h2.submit("CONNECT", tls.admission_path(nonce), true))
              .headers.at(":status") == "200");
    auto server = std::move(take(await(accepted))).take_carrier();
    auto pending = fixture.accept();
    TlsPeer replay_tls(fixture.port(), fixture.identity.certificate);
    H2Peer replay_h2(replay_tls, fixture.port());
    check_cover(replay_h2.response(replay_h2.submit(
        "CONNECT", replay_tls.admission_path(nonce), true)));
    CHECK(pending.wait_for(0ms) == std::future_status::timeout);
    fixture.door->cancel();
    CHECK(!await(pending).ok());
    server->close();
}

void test_configuration_and_initiation_bounds() {
    Fixture fixture;
    fixture.runtime.sync([&] {
        Ytp1FrontDoorConfig config;
        config.listen_endpoint = {boost::asio::ip::address_v4::loopback(), 0U};
        config.carrier_limits.max_record_bytes = 0U;
        const auto invalid = Ytp1FrontDoor::create(fixture.runtime.context(), config,
            fixture.tls, fixture.cover, fixture.replay, kAdmissionKey);
        CHECK(!invalid.ok() && invalid.status().code() == StatusCode::InvalidArgument);
        config.carrier_limits = {};
        config.limits.max_connections = 0U;
        CHECK(!Ytp1FrontDoor::create(fixture.runtime.context(), config,
            fixture.tls, fixture.cover, fixture.replay, kAdmissionKey).ok());
        config.limits = {};
        auto client_tls = take(Ytp1Tls13SecureChannelProvider::create_client(
            {"localhost", fixture.identity.certificate, {}, {}, {}}));
        CHECK(!Ytp1FrontDoor::create(fixture.runtime.context(), config,
            client_tls, fixture.cover, fixture.replay, kAdmissionKey).ok());
    });
    bool rejected = false;
    bool called = false;
    try { fixture.door->async_accept({}, [&](Result<AcceptedCarrier>) { called = true; }); }
    catch (const std::logic_error&) { rejected = true; }
    CHECK(rejected && !called);
}

void test_listener_conflict_preserves_existing_listener() {
    Fixture fixture;
    fixture.runtime.sync([&] {
        Ytp1FrontDoorConfig config;
        config.listen_endpoint = fixture.door->local_endpoint();
        const auto conflict = Ytp1FrontDoor::create(fixture.runtime.context(), config,
            fixture.tls, fixture.cover, fixture.replay, kAdmissionKey);
        CHECK(!conflict.ok() && conflict.status().code() == StatusCode::AddressInUse);
    });
    // A refused second listener must not close or take over the first one.
    TlsPeer tls(fixture.port(), fixture.identity.certificate);
    H2Peer h2(tls, fixture.port());
    CHECK(h2.response(h2.submit("GET", "/")).body == kIndex);
    CHECK(fixture.runtime.runner_exceptions() == 0U);
}

#ifdef YUME_TEST_WRAP_BIND
void test_listener_os_failure_classification_and_retry() {
    Fixture fixture;
    for (const auto& [error, expected] : {
             std::pair{EACCES, StatusCode::PermissionDenied},
             std::pair{EPERM, StatusCode::PermissionDenied},
             std::pair{EMFILE, StatusCode::ResourceExhausted},
             std::pair{ENFILE, StatusCode::ResourceExhausted},
             std::pair{ENOBUFS, StatusCode::ResourceExhausted},
             std::pair{ENOMEM, StatusCode::ResourceExhausted},
             std::pair{EADDRNOTAVAIL, StatusCode::InvalidArgument},
             std::pair{EINVAL, StatusCode::InvalidArgument},
             std::pair{EIO, StatusCode::Internal}}) {
        fixture.runtime.sync([&] {
            Ytp1FrontDoorConfig config;
            config.listen_endpoint = {boost::asio::ip::address_v4::loopback(), 0U};
            injected_bind_error = error;
            const auto failed = Ytp1FrontDoor::create(fixture.runtime.context(), config,
                fixture.tls, fixture.cover, fixture.replay, kAdmissionKey);
            const int unconsumed = std::exchange(injected_bind_error, 0);
            CHECK(unconsumed == 0 && !failed.ok() && failed.status().code() == expected);
            auto retry = take(Ytp1FrontDoor::create(fixture.runtime.context(), config,
                fixture.tls, fixture.cover, fixture.replay, kAdmissionKey));
            CHECK(retry->local_endpoint().port() != 0U);
            retry->close();
        });
        fixture.runtime.sync([] {});
    }
    CHECK(fixture.runtime.runner_exceptions() == 0U);
}
#endif

void test_promoted_capacity_uses_cover_and_recovers() {
    Ytp1FrontDoorLimits limits;
    limits.max_promoted_carriers = 1U;
    Fixture fixture(limits);
    {
        CarrierPair pair(fixture);
        auto pending_accept = fixture.accept();
        TlsPeer tls(fixture.port(), fixture.identity.certificate);
        H2Peer h2(tls, fixture.port());
        admission::Nonce nonce{};
        nonce[0] = std::byte{21U};
        check_cover(h2.response(h2.submit("CONNECT", tls.admission_path(nonce), true)));
        CHECK(fixture.replay->size() == 1U);
        CHECK(pending_accept.wait_for(0ms) == std::future_status::timeout);
        fixture.door->cancel();
        auto result = await(pending_accept);
        CHECK(!result.ok() && result.status().code() == StatusCode::Cancelled);
    }
    fixture.runtime.sync([] {});
    CarrierPair replacement(fixture);
    replacement.exchange(*replacement.client, *replacement.server, "capacity released");
}

void test_overlapping_admission_reserves_capacity_before_publication() {
    Ytp1FrontDoorLimits limits;
    limits.max_promoted_carriers = 1U;
    Fixture fixture(limits);
    auto first_accept = fixture.accept();
    auto second_accept = fixture.accept();
    TlsPeer first_tls(fixture.port(), fixture.identity.certificate);
    H2Peer first_h2(first_tls, fixture.port());
    TlsPeer second_tls(fixture.port(), fixture.identity.certificate);
    H2Peer second_h2(second_tls, fixture.port());
    admission::Nonce first_nonce{};
    first_nonce[0] = std::byte{41U};
    admission::Nonce second_nonce{};
    second_nonce[0] = std::byte{42U};
    // Submit both requests before waiting for either response. Capacity must
    // include an in-flight promotion whose final write/timer has not drained.
    const auto first_stream = first_h2.submit(
        "CONNECT", first_tls.admission_path(first_nonce), true);
    const auto second_stream = second_h2.submit(
        "CONNECT", second_tls.admission_path(second_nonce), true);
    const auto first_status = first_h2.response_headers(first_stream).headers.at(":status");
    const auto second_status = second_h2.response_headers(second_stream).headers.at(":status");
    CHECK((first_status == "200" && second_status == "404") ||
          (first_status == "404" && second_status == "200"));
    if (first_status == "404") check_cover(first_h2.response(first_stream));
    else check_cover(second_h2.response(second_stream));
    auto server = std::move(take(await(first_accept))).take_carrier();
    CHECK(second_accept.wait_for(0ms) == std::future_status::timeout);
    CHECK(fixture.replay->size() == 1U);
    fixture.door->cancel();
    const auto cancelled = await(second_accept);
    CHECK(!cancelled.ok() && cancelled.status().code() == StatusCode::Cancelled);
    server->close();
}

void test_accept_cancellation_bounds_and_close() {
    Ytp1FrontDoorLimits limits;
    limits.max_pending_accepts = 1U;
    Fixture fixture(limits);
    CancellationSource cancellation;
    auto first = fixture.accept(cancellation.token());
    auto excess = fixture.accept();
    auto excess_result = await(excess);
    CHECK(!excess_result.ok() && excess_result.status().code() == StatusCode::ResourceExhausted);
    cancellation.cancel();
    auto first_result = await(first);
    CHECK(!first_result.ok() && first_result.status().code() == StatusCode::Cancelled);

    // A user completion may throw after settlement without losing listener
    // ownership or preventing future cover and accept operations.
    CancellationSource throwing;
    fixture.runtime.sync([&] {
        fixture.door->async_accept(throwing.token(), [](Result<AcceptedCarrier>) {
            throw std::runtime_error("intentional callback exception");
        });
    });
    throwing.cancel();
    fixture.runtime.sync([] {});
    auto pending_close = fixture.accept();
    fixture.door->close();
    auto close_result = await(pending_close);
    CHECK(!close_result.ok() && close_result.status().code() == StatusCode::Closed);
    auto after_close = fixture.accept();
    auto closed_result = await(after_close);
    CHECK(!closed_result.ok() && closed_result.status().code() == StatusCode::Closed);
    fixture.door->close();
    CHECK(fixture.runtime.runner_exceptions() == 0U);
}

void test_stalled_handshake_deadline_releases_connection_capacity() {
    Ytp1FrontDoorLimits limits;
    limits.max_connections = 1U;
    limits.connection_timeout = 500ms;
    Fixture fixture(limits);
    boost::asio::io_context client_io;
    Tcp::socket stalled(client_io);
    stalled.connect({boost::asio::ip::address_v4::loopback(), fixture.port()});
    const timeval timeout{3, 0};
    CHECK(::setsockopt(stalled.native_handle(), SOL_SOCKET, SO_RCVTIMEO,
                       &timeout, sizeof(timeout)) == 0);
    // The second socket waits in the normal TCP listen backlog. The absolute
    // handshake deadline releases the first accepted channel and admits it.
    TlsPeer tls(fixture.port(), fixture.identity.certificate);
    H2Peer h2(tls, fixture.port());
    CHECK(h2.response(h2.submit("GET", "/")).body == kIndex);
    boost::system::error_code error;
    std::array<char, 1U> byte{};
    CHECK(stalled.read_some(boost::asio::buffer(byte), error) == 0U);
    CHECK(error == boost::asio::error::eof || error == boost::asio::error::connection_reset);
    CHECK(fixture.runtime.runner_exceptions() == 0U);
}

void test_closed_listener_destruction_after_final_drain() {
    Fixture fixture;
    CancellationSource cancellation;
    auto accept = fixture.accept(cancellation.token());
    fixture.door->close();
    fixture.runtime.finish_and_join();
    auto closed = await(accept);
    CHECK(!closed.ok() && closed.status().code() == StatusCode::Closed);
    std::weak_ptr<const Ytp1CoverSite> cover = fixture.cover;
    std::weak_ptr<Ytp1Tls13SecureChannelProvider> tls = fixture.tls;
    fixture.cover.reset();
    fixture.tls.reset();
    fixture.door->close();
    fixture.door->cancel();
    cancellation.cancel();
    fixture.door.reset();
    // Check lifetime before polling: a cleanup drain could conceal the cycle.
    CHECK(cover.expired() && tls.expired());
    CHECK(fixture.runtime.context()->poll() == 0U);
    CHECK(fixture.runtime.runner_exceptions() == 0U);
}

void test_closed_native_carriers_destruction_after_final_drain() {
    Fixture fixture;
    CarrierPair pair(fixture);
    pair.exchange(*pair.client, *pair.server, "before final shutdown");
    pair.client->close();
    pair.server->close();
    fixture.door->close();
    fixture.runtime.finish_and_join();
    pair.client->cancel();
    pair.server->close();
    pair.client.reset();
    pair.server.reset();
    fixture.door.reset();
    CHECK(fixture.runtime.context()->poll() == 0U);
    CHECK(fixture.runtime.runner_exceptions() == 0U);
}

void test_ipv4_ipv6_wildcard_pair_shares_port() {
    boost::asio::io_context io;
    Tcp::acceptor probe(io);
    boost::system::error_code error;
    probe.open(Tcp::v6(), error);
    if (!error) probe.set_option(boost::asio::ip::v6_only(true), error);
    if (!error) probe.bind({boost::asio::ip::address_v6::loopback(), 0U}, error);
    if (error == boost::asio::error::address_family_not_supported ||
        error == boost::system::errc::protocol_not_supported ||
        error == boost::system::errc::address_not_available) {
        std::cout << "SKIP IPv4/IPv6 wildcard pair: IPv6 unavailable: "
                  << error.message() << " (" << error.value() << ")\n";
        return;
    }
    CHECK(!error);
    probe.close(error);
    CHECK(!error);

    Fixture fixture;
    fixture.destroy_door();
    Ytp1FrontDoorConfig config;
    config.listen_endpoint = {boost::asio::ip::address_v4::any(), 0U};
    fixture.door = fixture.runtime.sync([&] {
        return take(Ytp1FrontDoor::create(fixture.runtime.context(), config,
            fixture.tls, fixture.cover, fixture.replay, kAdmissionKey));
    });
    const auto port = fixture.port();
    config.listen_endpoint = {boost::asio::ip::address_v6::any(), port};
    auto ipv6 = fixture.runtime.sync([&] {
        return take(Ytp1FrontDoor::create(fixture.runtime.context(), config,
            fixture.tls, fixture.cover, fixture.replay, kAdmissionKey));
    });
    CHECK(ipv6->local_endpoint().address().is_v6());
    CHECK(ipv6->local_endpoint().port() == port);
    // Each family must reach genuine cover on its own wildcard listener.
    for (const boost::asio::ip::address& address : {
             boost::asio::ip::address(boost::asio::ip::address_v4::loopback()),
             boost::asio::ip::address(boost::asio::ip::address_v6::loopback())}) {
        TlsPeer tls(port, fixture.identity.certificate, TLS1_3_VERSION, "h2", address);
        H2Peer h2(tls, port);
        CHECK(h2.response(h2.submit("GET", "/")).body == kIndex);
    }
    ipv6->close();
    CHECK(fixture.runtime.runner_exceptions() == 0U);
}

}  // namespace
}  // namespace yume::providers

int main() {
    std::signal(SIGPIPE, SIG_IGN);
    try {
        yume::providers::test_http_cover_and_failed_admission();
        yume::providers::test_native_promotion_record_credit_and_owner_lifetime();
        yume::providers::test_replay_and_cache_saturation_use_cover();
        yume::providers::test_one_promotion_per_tls_lifetime_after_replay_expiry();
        yume::providers::test_cross_connection_replay_after_promotion();
        yume::providers::test_configuration_and_initiation_bounds();
        yume::providers::test_listener_conflict_preserves_existing_listener();
#ifdef YUME_TEST_WRAP_BIND
        yume::providers::test_listener_os_failure_classification_and_retry();
#endif
        yume::providers::test_promoted_capacity_uses_cover_and_recovers();
        yume::providers::test_overlapping_admission_reserves_capacity_before_publication();
        yume::providers::test_accept_cancellation_bounds_and_close();
        yume::providers::test_stalled_handshake_deadline_releases_connection_capacity();
        yume::providers::test_closed_listener_destruction_after_final_drain();
        yume::providers::test_closed_native_carriers_destruction_after_final_drain();
        yume::providers::test_ipv4_ipv6_wildcard_pair_shares_port();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
