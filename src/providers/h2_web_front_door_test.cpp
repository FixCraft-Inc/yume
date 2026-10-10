/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/h2_web_front_door.hpp"
#include "providers/ytp1_h2_admission.hpp"
#include "stealth/cover_profile.hpp"
#include "test_support/allocation_failure.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <condition_variable>
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
    explicit IoRuntime(std::uint64_t affinity = 191U)
        : context_(
              take(AsioExecutionContext::create(ExecutorAffinity(affinity)))),
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
    std::shared_ptr<const CoverSite> load() const {
        std::vector<CoverFile> routes{
            {"/", "index.html", "text/html; charset=utf-8"},
            {"/asset.css", "asset.css", "text/css"}};
        for (const auto& asset : cover_profile::active().assets)
            routes.push_back({std::string(asset.path), "asset.css", "text/css"});
        return take(CoverSite::load(root_, routes, "404.html"));
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
    explicit Fixture(H2WebFrontDoorLimits limits = {},
                     std::size_t replay_entries = 64U,
                     std::uint64_t replay_ttl_seconds = 3600U)
        : identity(make_identity()), cover(files.load()),
          replay(std::make_shared<admission::ReplayCache>(replay_entries, replay_ttl_seconds)),
          tls(take(Tls13SecureChannelProvider::create_server(
              {identity.certificate, identity.key, {}, {}}))) {
        H2WebFrontDoorConfig config;
        config.listen_endpoint = {boost::asio::ip::address_v4::loopback(), 0U};
        config.limits = limits;
        door = runtime.sync([&] {
            return take(H2WebFrontDoor::create(runtime.context(), config, tls,
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
    H2Dispatch post() const { return make_asio_h2_dispatch(runtime.context()); }
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
    std::shared_ptr<const CoverSite> cover;
    std::shared_ptr<admission::ReplayCache> replay;
    std::shared_ptr<Tls13SecureChannelProvider> tls;
    std::shared_ptr<H2WebFrontDoor> door;
};

// One listener on its own context hands each connection to the served front
// door the test names, on one of two other contexts. Both serve from one
// replay cache and the listener's share.
class ServedFixture final {
public:
    explicit ServedFixture(H2WebFrontDoorLimits limits = {})
        : identity(make_identity()),
          cover(files.load()),
          replay(std::make_shared<admission::ReplayCache>(64U, 3600U)),
          tls(take(Tls13SecureChannelProvider::create_server(
              {identity.certificate, identity.key, {}, {}}))) {
        listener = listening.sync([&] {
            return take(H2WebListener::create(
                listening.context(),
                {boost::asio::ip::address_v4::loopback(), 0U}, limits,
                [this](int descriptor) {
                    std::lock_guard lock(mutex);
                    const int index = target.load();
                    if (index < 0 ||
                        static_cast<std::size_t>(index) >= doors.size())
                        return false;
                    ++handed[static_cast<std::size_t>(index)];
                    // A test may fail one allocation of the hand-off itself.
                    const std::size_t nth = fail_in_serve.exchange(0U);
                    if (nth != 0U) yume::test::arm_allocation_failure(nth);
                    doors[static_cast<std::size_t>(index)]->serve(descriptor);
                    if (nth != 0U)
                        serve_failed = yume::test::disarm_allocation_failure();
                    return true;
                },
                [] {}));
        });
        H2WebFrontDoorConfig config;
        const auto share = listener->share();
        for (IoRuntime* runtime : {&first, &second}) {
            auto door = runtime->sync([&] {
                return take(H2WebFrontDoor::create_served(
                    runtime->context(), config, tls, cover, replay,
                    kAdmissionKey, share));
            });
            CHECK(door->local_endpoint() == listener->local_endpoint());
            std::lock_guard lock(mutex);
            doors.push_back(std::move(door));
        }
    }
    ~ServedFixture() noexcept {
        listener->close();
        for (const auto& door : doors) door->close();
    }
    std::uint16_t port() const { return listener->local_endpoint().port(); }
    IoRuntime& runtime(std::size_t index) {
        return index == 0U ? first : second;
    }
    std::future<Result<AcceptedCarrier>> accept(std::size_t index) {
        auto promise =
            std::make_shared<std::promise<Result<AcceptedCarrier>>>();
        auto result = promise->get_future();
        auto& serving = runtime(index);
        serving.sync([&] {
            doors[index]->async_accept(
                {}, [promise, context = serving.context()](
                        Result<AcceptedCarrier> accepted) {
                    if (!context->running_in_this_thread()) {
                        promise->set_exception(
                            std::make_exception_ptr(std::runtime_error(
                                "accept completion escaped its context")));
                        return;
                    }
                    promise->set_value(std::move(accepted));
                });
        });
        return result;
    }

    IoRuntime listening{301U};
    IoRuntime first{302U};
    IoRuntime second{303U};
    CoverFiles files;
    PemIdentity identity;
    std::shared_ptr<const CoverSite> cover;
    std::shared_ptr<admission::ReplayCache> replay;
    std::shared_ptr<Tls13SecureChannelProvider> tls;
    std::shared_ptr<H2WebListener> listener;
    std::mutex mutex;
    std::vector<std::shared_ptr<H2WebFrontDoor>> doors;
    std::array<std::size_t, 2U> handed{};
    std::atomic<int> target{0};
    std::atomic<std::size_t> fail_in_serve{0U};
    std::atomic<bool> serve_failed{false};
};

// After the encoded proof input, verification uses only OpenSSL's C
// allocations. The next C++ allocation is the promotion reservation, before
// its constructor takes a slot. Gate that existing allocation seam rather
// than adding a test hook to the front door. Its one-shared_ptr layout gives
// make_shared the same allocation size on each supported standard library.
class PromotionAllocationGate final {
public:
    explicit PromotionAllocationGate(ServedFixture& fixture,
                                     bool fail_first_allocation)
        : fixture_(fixture) {
        yume::test::before_allocate = [](std::size_t size) {
            captured_allocation_bytes_ = size;
        };
        auto layout = std::make_shared<std::shared_ptr<void>>();
        yume::test::before_allocate = nullptr;
        yume::test::keep_contents(layout.get());
        reservation_bytes_ = captured_allocation_bytes_;
        CHECK(reservation_bytes_ != 0U);
        for (std::size_t index = 0U; index < 2U; ++index) {
            fixture_.runtime(index).sync([this, index, fail_first_allocation] {
                active_gate_ = this;
                saw_input_ = false;
                fail_reservation_ = fail_first_allocation && index == 0U;
                yume::test::before_allocate = observe;
            });
        }
    }
    ~PromotionAllocationGate() noexcept {
        release();
        for (std::size_t index = 0U; index < 2U; ++index) {
            try {
                fixture_.runtime(index).sync([] {
                    yume::test::before_allocate = nullptr;
                    active_gate_ = nullptr;
                });
            } catch (...) {
            }
        }
    }
    bool await_arrivals(std::size_t count) {
        std::unique_lock lock(mutex_);
        return changed_.wait_for(lock, 5s, [&] { return arrivals_ >= count; });
    }
    bool observed_reservations() {
        std::lock_guard lock(mutex_);
        return matching_allocations_ == arrivals_;
    }
    void release() noexcept {
        std::lock_guard lock(mutex_);
        released_ = true;
        changed_.notify_all();
    }

private:
    static void observe(std::size_t size) {
        constexpr std::size_t kInputBytes =
            2U + kYtp1H2AdmissionDomain.size() + 2U +
            std::string_view("localhost").size() + 2U +
            kYtp1H2AdmissionExporterBytes + admission::Nonce{}.size();
        if (!saw_input_) {
            saw_input_ = size == kInputBytes;
            return;
        }
        yume::test::before_allocate = nullptr;
        auto& gate = *active_gate_;
        std::unique_lock lock(gate.mutex_);
        ++gate.arrivals_;
        if (size == gate.reservation_bytes_) ++gate.matching_allocations_;
        gate.changed_.notify_all();
        gate.changed_.wait(lock, [&] { return gate.released_; });
        if (fail_reservation_) throw std::bad_alloc();
    }

    ServedFixture& fixture_;
    std::mutex mutex_;
    std::condition_variable changed_;
    std::size_t arrivals_{0U};
    std::size_t matching_allocations_{0U};
    std::size_t reservation_bytes_{0U};
    bool released_{false};
    static inline thread_local std::size_t captured_allocation_bytes_{0U};
    static inline thread_local PromotionAllocationGate* active_gate_{nullptr};
    static inline thread_local bool saw_input_{false};
    static inline thread_local bool fail_reservation_{false};
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
        client_tls_ = take(Tls13SecureChannelProvider::create_client(
            {"localhost", fixture.identity.certificate, {}, {}, {}}));
        client_h2_ = take(H2DuplexCarrierProvider::create(
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
        CHECK(server_result.descriptor().provider_id() == kH2DuplexCarrierProviderId);
        server = std::move(server_result).take_carrier();
        CHECK(server->executor_affinity() == fixture.runtime.context()->affinity());
        CHECK(server->secure_channel().executor_affinity() == server->executor_affinity());
        CHECK(server->secure_channel().descriptor().provider_id() == kTls13SecureChannelProviderId);
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
    std::shared_ptr<Tls13SecureChannelProvider> client_tls_;
    std::shared_ptr<H2DuplexCarrierProvider> client_h2_;
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
    std::weak_ptr<H2WebFrontDoor> weak_door = fixture.door;
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
    // The replay lifetime must outlast the connection deadline, so a short
    // deadline lets a short lifetime expire within the test.
    H2WebFrontDoorLimits limits;
    limits.connection_timeout = 1500ms;
    Fixture fixture(limits, 64U, 3U);
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

    // A three-second cache TTL has certainly expired after this bounded wait.
    // Both the old proof and a fresh proof on the original live TLS session
    // still use ordinary cover; the promoted connection can never re-admit.
    std::this_thread::sleep_for(3100ms);
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
        H2WebFrontDoorConfig config;
        config.listen_endpoint = {boost::asio::ip::address_v4::loopback(), 0U};
        config.carrier_limits.max_record_bytes = 0U;
        const auto invalid = H2WebFrontDoor::create(fixture.runtime.context(), config,
            fixture.tls, fixture.cover, fixture.replay, kAdmissionKey);
        CHECK(!invalid.ok() && invalid.status().code() == StatusCode::InvalidArgument);
        config.carrier_limits = {};
        config.limits.max_connections = 0U;
        CHECK(!H2WebFrontDoor::create(fixture.runtime.context(), config,
            fixture.tls, fixture.cover, fixture.replay, kAdmissionKey).ok());
        config.limits = {};
        auto client_tls = take(Tls13SecureChannelProvider::create_client(
            {"localhost", fixture.identity.certificate, {}, {}, {}}));
        CHECK(!H2WebFrontDoor::create(fixture.runtime.context(), config,
            client_tls, fixture.cover, fixture.replay, kAdmissionKey).ok());
    });
    bool rejected = false;
    bool called = false;
    try { fixture.door->async_accept({}, [&](Result<AcceptedCarrier>) { called = true; }); }
    catch (const std::logic_error&) { rejected = true; }
    CHECK(rejected && !called);
}

// A nonce must stay reserved while its connection may still present a
// proof, so a replay lifetime that does not outlast the connection deadline
// in whole seconds is refused.
void test_replay_lifetime_must_outlast_connection_deadline() {
    Fixture fixture;
    fixture.runtime.sync([&] {
        const auto create = [&](std::chrono::milliseconds deadline, std::uint64_t ttl) {
            H2WebFrontDoorConfig config;
            config.listen_endpoint = {boost::asio::ip::address_v4::loopback(), 0U};
            config.limits.connection_timeout = deadline;
            return H2WebFrontDoor::create(fixture.runtime.context(), config, fixture.tls,
                fixture.cover, std::make_shared<admission::ReplayCache>(64U, ttl),
                kAdmissionKey);
        };
        for (const auto& [deadline, ttl] : {std::pair{30'000ms, std::uint64_t{30U}},
                                            std::pair{1500ms, std::uint64_t{2U}},
                                            std::pair{1ms, std::uint64_t{1U}}}) {
            const auto refused = create(deadline, ttl);
            CHECK(!refused.ok() && refused.status().code() == StatusCode::InvalidArgument);
        }
        for (const auto& [deadline, ttl] : {std::pair{30'000ms, std::uint64_t{31U}},
                                            std::pair{1500ms, std::uint64_t{3U}}}) {
            auto created = create(deadline, ttl);
            CHECK(created.ok());
            created.value()->close();
        }
    });
}

void test_listener_conflict_preserves_existing_listener() {
    Fixture fixture;
    fixture.runtime.sync([&] {
        H2WebFrontDoorConfig config;
        config.listen_endpoint = fixture.door->local_endpoint();
        const auto conflict = H2WebFrontDoor::create(fixture.runtime.context(), config,
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
            H2WebFrontDoorConfig config;
            config.listen_endpoint = {boost::asio::ip::address_v4::loopback(), 0U};
            injected_bind_error = error;
            const auto failed = H2WebFrontDoor::create(fixture.runtime.context(), config,
                fixture.tls, fixture.cover, fixture.replay, kAdmissionKey);
            const int unconsumed = std::exchange(injected_bind_error, 0);
            CHECK(unconsumed == 0 && !failed.ok() && failed.status().code() == expected);
            auto retry = take(H2WebFrontDoor::create(fixture.runtime.context(), config,
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
    H2WebFrontDoorLimits limits;
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
    H2WebFrontDoorLimits limits;
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
    H2WebFrontDoorLimits limits;
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
    H2WebFrontDoorLimits limits;
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
    std::weak_ptr<const CoverSite> cover = fixture.cover;
    std::weak_ptr<Tls13SecureChannelProvider> tls = fixture.tls;
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
    H2WebFrontDoorConfig config;
    // IPv4 and IPv6 allocate ports separately, so the port the IPv4 wildcard
    // got may already be held on IPv6 by another process, which a parallel
    // CTest run showed once. That says nothing about the pair, so the test
    // takes another port.
    std::shared_ptr<H2WebFrontDoor> ipv6;
    std::uint16_t port = 0U;
    for (int attempt = 0; attempt < 16 && !ipv6; ++attempt) {
        fixture.destroy_door();
        config.listen_endpoint = {boost::asio::ip::address_v4::any(), 0U};
        fixture.door = fixture.runtime.sync([&] {
            return take(H2WebFrontDoor::create(
                fixture.runtime.context(), config, fixture.tls, fixture.cover,
                fixture.replay, kAdmissionKey));
        });
        port = fixture.port();
        config.listen_endpoint = {boost::asio::ip::address_v6::any(), port};
        auto created = fixture.runtime.sync([&] {
            return H2WebFrontDoor::create(fixture.runtime.context(), config,
                                          fixture.tls, fixture.cover,
                                          fixture.replay, kAdmissionKey);
        });
        if (created.ok()) {
            ipv6 = std::move(created).take_value();
        } else {
            CHECK(created.status().code() == StatusCode::AddressInUse);
        }
    }
    CHECK(ipv6 != nullptr);
    if (!ipv6) return;
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

namespace yume::providers {
namespace {

// A carrier promoted on a served front door belongs to that door's context,
// and a proof's nonce used there cannot admit again on the other context.
void test_served_doors_share_replay_and_keep_their_context() {
    ServedFixture fixture;
    fixture.target = 1;
    auto accepted = fixture.accept(1U);
    TlsPeer tls(fixture.port(), fixture.identity.certificate);
    H2Peer h2(tls, fixture.port());
    CHECK(h2.response(h2.submit("GET", "/")).body == kIndex);
    admission::Nonce nonce{};
    nonce[0] = std::byte{71U};
    CHECK(h2.response_headers(
                h2.submit("CONNECT", tls.admission_path(nonce), true))
              .headers.at(":status") == "200");
    auto carrier = std::move(take(await(accepted))).take_carrier();
    CHECK(carrier->executor_affinity() == fixture.second.context()->affinity());

    fixture.target = 0;
    auto pending = fixture.accept(0U);
    TlsPeer replay_tls(fixture.port(), fixture.identity.certificate);
    H2Peer replay_h2(replay_tls, fixture.port());
    check_cover(replay_h2.response(
        replay_h2.submit("CONNECT", replay_tls.admission_path(nonce), true)));
    CHECK(pending.wait_for(0ms) == std::future_status::timeout);
    nonce[0] = std::byte{72U};
    CHECK(replay_h2
              .response_headers(replay_h2.submit(
                  "CONNECT", replay_tls.admission_path(nonce), true))
              .headers.at(":status") == "200");
    auto second = std::move(take(await(pending))).take_carrier();
    CHECK(second->executor_affinity() == fixture.first.context()->affinity());
    CHECK(fixture.handed[0] == 1U && fixture.handed[1] == 1U);
    CHECK(fixture.replay->size() == 2U);
    carrier->close();
    second->close();
}

// The listener stops accepting while max_connections connections wait for
// promotion on any served door, and resumes when one ends there.
void test_served_doors_share_the_connection_bound() {
    H2WebFrontDoorLimits limits;
    limits.max_connections = 1U;
    ServedFixture fixture(limits);
    fixture.target = 1;
    boost::asio::io_context io;
    Tcp::socket waiting(io);
    waiting.connect({boost::asio::ip::address_v4::loopback(), fixture.port()});
    auto blocked = std::async(std::launch::async, [&] {
        TlsPeer tls(fixture.port(), fixture.identity.certificate);
        H2Peer h2(tls, fixture.port());
        return h2.response(h2.submit("GET", "/")).body;
    });
    CHECK(blocked.wait_for(500ms) == std::future_status::timeout);
    waiting.close();
    CHECK(blocked.get() == kIndex);
    CHECK(fixture.handed[1] == 2U);
}

// One promotion budget spans the served doors: with room for one carrier, a
// valid admission on the other door gets cover until the first one ends.
void test_served_doors_share_the_promotion_budget() {
    H2WebFrontDoorLimits limits;
    limits.max_promoted_carriers = 1U;
    ServedFixture fixture(limits);
    fixture.target = 0;
    auto accepted = fixture.accept(0U);
    TlsPeer first_tls(fixture.port(), fixture.identity.certificate);
    H2Peer first_h2(first_tls, fixture.port());
    admission::Nonce nonce{};
    nonce[0] = std::byte{81U};
    CHECK(first_h2
              .response_headers(first_h2.submit(
                  "CONNECT", first_tls.admission_path(nonce), true))
              .headers.at(":status") == "200");
    auto carrier = std::move(take(await(accepted))).take_carrier();

    fixture.target = 1;
    auto pending = fixture.accept(1U);
    TlsPeer second_tls(fixture.port(), fixture.identity.certificate);
    H2Peer second_h2(second_tls, fixture.port());
    nonce[0] = std::byte{82U};
    check_cover(second_h2.response(
        second_h2.submit("CONNECT", second_tls.admission_path(nonce), true)));
    CHECK(pending.wait_for(0ms) == std::future_status::timeout);
    // The carrier's reservation goes with the carrier.
    carrier.reset();
    fixture.first.sync([] {});
    nonce[0] = std::byte{83U};
    CHECK(second_h2
              .response_headers(second_h2.submit(
                  "CONNECT", second_tls.admission_path(nonce), true))
              .headers.at(":status") == "200");
    take(await(pending)).take_carrier()->close();
}

// Both serving loops reach allocation after the old load-only cap check,
// before either reservation constructor runs. With one shared slot, exactly
// one peer may receive 200; the other must see the ordinary cover response.
void concurrent_served_promotions(bool fail_first_allocation) {
    H2WebFrontDoorLimits limits;
    limits.max_promoted_carriers = 1U;
    ServedFixture fixture(limits);
    auto first_accepted = fixture.accept(0U);
    auto second_accepted = fixture.accept(1U);
    fixture.target = 0;
    TlsPeer first_tls(fixture.port(), fixture.identity.certificate);
    H2Peer first_h2(first_tls, fixture.port());
    fixture.target = 1;
    TlsPeer second_tls(fixture.port(), fixture.identity.certificate);
    H2Peer second_h2(second_tls, fixture.port());
    admission::Nonce first_nonce{};
    first_nonce[0] = std::byte{84U};
    admission::Nonce second_nonce{};
    second_nonce[0] = std::byte{85U};
    const auto first_path = first_tls.admission_path(first_nonce);
    const auto second_path = second_tls.admission_path(second_nonce);
    PromotionAllocationGate gate(fixture, fail_first_allocation);
    const auto first_stream = first_h2.submit("CONNECT", first_path, true);
    CHECK(gate.await_arrivals(1U));
    const auto second_stream = second_h2.submit("CONNECT", second_path, true);
    CHECK(gate.await_arrivals(2U));
    CHECK(gate.observed_reservations());
    gate.release();
    const auto first_response = first_h2.response_headers(first_stream);
    const auto second_response = second_h2.response_headers(second_stream);
    const bool first_won = first_response.headers.at(":status") == "200";
    const bool second_won = second_response.headers.at(":status") == "200";
    CHECK(first_won != second_won);
    if (fail_first_allocation) CHECK(!first_won);
    auto& winner = first_won ? first_accepted : second_accepted;
    auto& pending = first_won ? second_accepted : first_accepted;
    auto& refused_h2 = first_won ? second_h2 : first_h2;
    auto& refused_tls = first_won ? second_tls : first_tls;
    const auto refused_stream = first_won ? second_stream : first_stream;
    const std::size_t winner_index = first_won ? 0U : 1U;
    const std::size_t refused_index = first_won ? 1U : 0U;
    check_cover(refused_h2.response(refused_stream));
    CHECK(pending.wait_for(0ms) == std::future_status::timeout);
    auto carrier = std::move(take(await(winner))).take_carrier();
    CHECK(carrier->executor_affinity() ==
          fixture.runtime(winner_index).context()->affinity());
    CHECK(carrier->secure_channel().executor_affinity() ==
          carrier->executor_affinity());
    carrier.reset();
    fixture.runtime(winner_index).sync([] {});
    admission::Nonce retry_nonce{};
    retry_nonce[0] = std::byte{86U};
    CHECK(refused_h2
              .response_headers(refused_h2.submit(
                  "CONNECT", refused_tls.admission_path(retry_nonce), true))
              .headers.at(":status") == "200");
    auto replacement = std::move(take(await(pending))).take_carrier();
    CHECK(replacement->executor_affinity() ==
          fixture.runtime(refused_index).context()->affinity());
    replacement->close();
}

void test_concurrent_served_promotions_respect_the_shared_bound() {
    concurrent_served_promotions(false);
    concurrent_served_promotions(true);
}

void test_served_replay_refusal_returns_the_promotion_slot() {
    H2WebFrontDoorLimits limits;
    limits.max_promoted_carriers = 1U;
    ServedFixture fixture(limits);
    admission::Nonce nonce{};
    nonce[0] = std::byte{87U};
    const auto ticks = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::steady_clock::now().time_since_epoch())
                           .count();
    CHECK(ticks >= 0);
    CHECK(fixture.replay->reserve(nonce, static_cast<std::uint64_t>(ticks)) ==
          admission::ReplayDecision::Accepted);
    auto refused_accept = fixture.accept(0U);
    fixture.target = 0;
    TlsPeer refused_tls(fixture.port(), fixture.identity.certificate);
    H2Peer refused_h2(refused_tls, fixture.port());
    check_cover(refused_h2.response(
        refused_h2.submit("CONNECT", refused_tls.admission_path(nonce), true)));
    CHECK(refused_accept.wait_for(0ms) == std::future_status::timeout);

    auto accepted = fixture.accept(1U);
    fixture.target = 1;
    TlsPeer tls(fixture.port(), fixture.identity.certificate);
    H2Peer h2(tls, fixture.port());
    nonce[0] = std::byte{88U};
    CHECK(h2.response_headers(
                h2.submit("CONNECT", tls.admission_path(nonce), true))
              .headers.at(":status") == "200");
    auto carrier = std::move(take(await(accepted))).take_carrier();
    CHECK(carrier->executor_affinity() == fixture.second.context()->affinity());
    carrier->close();
}

// One allocation failure in the hand-off, swept from its first allocation
// on, never keeps the connection's place: with room for one waiting
// connection, a full request still succeeds afterwards. On the listener's
// thread the failure is armed around serve(), on the serving thread from
// the adoption on, and each sweep ends where the hand-off no longer reaches
// the armed allocation. Asio's own completion of a pending accept is left
// out: a failure there loses the operation inside the library.
void test_handoff_allocation_failure_returns_the_place() {
    H2WebFrontDoorLimits limits;
    limits.max_connections = 1U;
    for (const bool on_listener : {true, false}) {
        std::size_t failures = 0U;
        bool completed = false;
        for (std::size_t nth = 1U; nth <= 64U && !completed; ++nth) {
            ServedFixture fixture(limits);
            fixture.target = 0;
            if (on_listener)
                fixture.fail_in_serve = nth;
            else
                fixture.first.sync(
                    [nth] { yume::test::arm_allocation_failure(nth); });
            boost::asio::io_context io;
            Tcp::socket waiting(io);
            waiting.connect(
                {boost::asio::ip::address_v4::loopback(), fixture.port()});
            std::this_thread::sleep_for(200ms);
            const bool fired =
                on_listener
                    ? fixture.serve_failed.load()
                    : fixture.first.sync([] {
                          return yume::test::disarm_allocation_failure();
                      });
            waiting.close();
            TlsPeer tls(fixture.port(), fixture.identity.certificate);
            H2Peer h2(tls, fixture.port());
            CHECK(h2.response(h2.submit("GET", "/")).body == kIndex);
            if (fired) {
                ++failures;
            } else {
                completed = true;
            }
        }
        CHECK(completed && failures > 0U);
    }
}

// A descriptor no served door takes is closed at once.
void test_refused_dispatch_closes_the_connection() {
    ServedFixture fixture;
    fixture.target = -1;
    boost::asio::io_context io;
    Tcp::socket refused(io);
    refused.connect({boost::asio::ip::address_v4::loopback(), fixture.port()});
    const timeval timeout{3, 0};
    CHECK(::setsockopt(refused.native_handle(), SOL_SOCKET, SO_RCVTIMEO,
                       &timeout, sizeof(timeout)) == 0);
    std::array<char, 16U> byte{};
    boost::system::error_code error;
    const auto count = refused.read_some(boost::asio::buffer(byte), error);
    CHECK(count == 0U && error == boost::asio::error::eof);
    fixture.target = 0;
    TlsPeer tls(fixture.port(), fixture.identity.certificate);
    H2Peer h2(tls, fixture.port());
    CHECK(h2.response(h2.submit("GET", "/")).body == kIndex);
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
        yume::providers::test_replay_lifetime_must_outlast_connection_deadline();
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
        yume::providers::
            test_served_doors_share_replay_and_keep_their_context();
        yume::providers::test_served_doors_share_the_connection_bound();
        yume::providers::test_served_doors_share_the_promotion_budget();
        yume::providers::
            test_concurrent_served_promotions_respect_the_shared_bound();
        yume::providers::
            test_served_replay_refusal_returns_the_promotion_slot();
        yume::providers::test_refused_dispatch_closes_the_connection();
        yume::providers::test_handoff_allocation_failure_returns_the_place();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
