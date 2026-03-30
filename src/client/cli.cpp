/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/cli.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <functional>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <charconv>
#include <string_view>
#include <utility>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <ctime>
#include <cstdlib>
#include <thread>
#if !defined(_WIN32)
#include <unistd.h>
#include <sys/select.h>
#include <sys/stat.h>
#endif
#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#endif
#include <unordered_map>
#include <limits>
#include <chrono>
#include <cstring>
#include <vector>
#include <atomic>
#include <mutex>

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/sha.h>

#include "client/forward.hpp"
#include "client/local_runtime.hpp"
#include "client/relay_runtime.hpp"
#include "client/socks.hpp"
#include "client/tunnel.hpp"
#include "core/crypto.hpp"
#include "core/identity.hpp"
#include "core/inner_crypto.hpp"
#include "core/obfs.hpp"
#include "core/protocol.hpp"
#include "core/runtime_policy.hpp"
#include "core/version.hpp"
#include "core/tls_fingerprint.hpp"
#include "core/tls_stealth.hpp"
#include "core/tls_metrics.hpp"
#include "util.hpp"
#include <nlohmann/json.hpp>

namespace yume::client {

namespace {
struct FatalError : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

constexpr std::chrono::milliseconds kConnectTimeout{10000};
constexpr std::chrono::milliseconds kHandshakeTimeout{12000};
constexpr std::chrono::milliseconds kAuthChallengeTimeout{6000};
constexpr std::chrono::milliseconds kServerInfoTimeout{6000};
constexpr std::chrono::milliseconds kServerInfoTimeoutInner{20000};
constexpr std::chrono::milliseconds kServerInfoTimeoutInnerHeavy{45000};
std::string normalize_proof_source(std::string source) {
    std::transform(source.begin(), source.end(), source.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return source;
}

void add_verified_source(std::vector<std::string>* out, std::string_view source) {
    if (!out || source.empty()) {
        return;
    }
    const std::string value(source);
    if (std::find(out->begin(), out->end(), value) == out->end()) {
        out->push_back(value);
    }
}

std::string format_verified_sources(const std::vector<std::string>& sources) {
    std::vector<std::string> labels;
    labels.reserve(sources.size());
    for (const auto& source : sources) {
        if (source == yume::policy::kAnonymProofSourceSubCa) {
            labels.emplace_back("Sub-CA");
        } else if (source == yume::policy::kAnonymProofSourceCa) {
            labels.emplace_back("CA");
        } else if (source == yume::policy::kAnonymProofSourceFixcraft) {
            labels.emplace_back("FixCraft");
        }
    }
    if (labels.empty()) {
        return "FAIL";
    }
    std::string joined;
    for (std::size_t i = 0; i < labels.size(); ++i) {
        if (i != 0) {
            joined += "+";
        }
        joined += labels[i];
    }
    return "PASS [" + joined + "]";
}

struct IoOpResult {
    boost::system::error_code ec;
    bool timed_out{false};
    std::size_t bytes{0};
};

template <typename AsyncStream, typename CancelFn>
IoOpResult read_exact_with_timeout(AsyncStream& stream,
                                  boost::asio::io_context& io,
                                  const boost::asio::mutable_buffer& buf,
                                  std::chrono::milliseconds timeout,
                                  CancelFn cancel) {
    IoOpResult res{};
    bool done = false;

    boost::asio::steady_timer timer(io);
    timer.expires_after(timeout);
    timer.async_wait([&](const boost::system::error_code& ec) {
        if (!ec && !done) {
            res.timed_out = true;
            cancel();
        }
    });

    boost::asio::async_read(stream, buf, [&](const boost::system::error_code& ec, std::size_t bytes) {
        res.ec = ec;
        res.bytes = bytes;
        done = true;
        (void)timer.cancel();
    });

    io.restart();
    io.run();
    return res;
}

IoOpResult connect_with_timeout(boost::asio::ip::tcp::socket& sock,
                                const boost::asio::ip::tcp::resolver::results_type& endpoints,
                                boost::asio::io_context& io,
                                std::chrono::milliseconds timeout) {
    IoOpResult res{};
    bool done = false;

    boost::asio::steady_timer timer(io);
    timer.expires_after(timeout);
    timer.async_wait([&](const boost::system::error_code& ec) {
        if (!ec && !done) {
            res.timed_out = true;
            boost::system::error_code ignored;
            sock.cancel(ignored);
            sock.close(ignored);
        }
    });

    boost::asio::async_connect(sock, endpoints,
                               [&](const boost::system::error_code& ec, const boost::asio::ip::tcp::endpoint&) {
                                   res.ec = ec;
                                   done = true;
                                   (void)timer.cancel();
                               });

    io.restart();
    io.run();
    return res;
}

IoOpResult handshake_with_timeout(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                                  boost::asio::io_context& io,
                                  std::chrono::milliseconds timeout) {
    IoOpResult res{};
    bool done = false;

    boost::asio::steady_timer timer(io);
    timer.expires_after(timeout);
    timer.async_wait([&](const boost::system::error_code& ec) {
        if (!ec && !done) {
            res.timed_out = true;
            boost::system::error_code ignored;
            stream.lowest_layer().cancel(ignored);
            stream.lowest_layer().close(ignored);
        }
    });

    stream.async_handshake(boost::asio::ssl::stream_base::client,
                           [&](const boost::system::error_code& ec) {
                               res.ec = ec;
                               done = true;
                               (void)timer.cancel();
                           });

    io.restart();
    io.run();
    return res;
}

std::string hex_preview(const uint8_t* data, std::size_t len, std::size_t max = 16) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    std::size_t n = std::min(len, max);
    for (std::size_t i = 0; i < n; ++i) {
        if (i) {
            oss << ' ';
        }
        oss << std::setw(2) << static_cast<unsigned int>(data[i]);
    }
    if (len > max) {
        oss << " ...";
    }
    return oss.str();
}

std::string ascii_preview(const uint8_t* data, std::size_t len, std::size_t max = 64) {
    std::string out;
    std::size_t n = std::min(len, max);
    out.reserve(n);
    for (std::size_t i = 0; i < n; ++i) {
        unsigned char c = data[i];
        if (c >= 0x20 && c < 0x7f) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('.');
        }
    }
    if (len > max) {
        out += "...";
    }
    return out;
}

std::string classify_plaintext_prefix(const uint8_t* data, std::size_t len) {
    if (!data || len == 0) {
        return {};
    }
    const auto starts_with = [&](const char* lit) {
        std::size_t n = std::strlen(lit);
        return len >= n && std::memcmp(data, lit, n) == 0;
    };
    if (starts_with("SSH-")) {
        return "SSH";
    }
    if (starts_with("HTTP/")) {
        return "HTTP";
    }
    if (starts_with("PRI * HTTP/2.0")) {
        return "HTTP/2";
    }
    if (starts_with("GET ") || starts_with("POST ") || starts_with("HEAD ") || starts_with("PUT ") || starts_with("OPTIONS ")) {
        return "HTTP";
    }
    return {};
}

std::string classify_http2_frame_prefix(const uint8_t* data, std::size_t len) {
    // HTTP/2 frame header is 9 bytes: len(3) type(1) flags(1) stream_id(4).
    // We often only have a short prefix; recognize a SETTINGS frame on stream 0.
    if (!data || len < 8) {
        return {};
    }
    uint8_t type = data[3];
    uint8_t flags = data[4];
    bool stream0_prefix = (data[5] == 0x00 && data[6] == 0x00 && data[7] == 0x00);
    if (type == 0x04 && flags == 0x00 && stream0_prefix) {
        return "HTTP/2";
    }
    return {};
}

std::string endpoint_hint_tls(bool tls_handshake_succeeded,
                              const uint8_t* prefix,
                              std::size_t prefix_len) {
    std::string plain = classify_plaintext_prefix(prefix, prefix_len);
    if (!plain.empty()) {
        if (tls_handshake_succeeded) {
            return (plain == "HTTP" || plain == "HTTP/2") ? ("HTTPS (" + plain + ")") : ("TLS (" + plain + ")");
        }
        return plain;
    }

    if (tls_handshake_succeeded) {
        std::string h2 = classify_http2_frame_prefix(prefix, prefix_len);
        if (!h2.empty()) {
            return "HTTPS (" + h2 + ")";
        }
        return "TLS (likely HTTPS)";
    }
    return "unknown";
}

bool looks_like_yume_header(const std::array<uint8_t, 8>& header) {
    uint32_t len = (static_cast<uint32_t>(header[0]) << 24) |
                   (static_cast<uint32_t>(header[1]) << 16) |
                   (static_cast<uint32_t>(header[2]) << 8) |
                   (static_cast<uint32_t>(header[3]));
    uint8_t type = header[4];
    if (len > 16U * 1024U * 1024U) {
        return false;
    }
    if (type < protocol::AUTH || type > protocol::SOPEN) {
        return false;
    }
    return true;
}

protocol::Frame read_frame_with_timeout(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                                       boost::asio::io_context& io,
                                       std::chrono::milliseconds timeout,
                                       const char* what,
                                       const std::string& host,
                                       int port,
                                       bool tls_handshake_succeeded) {
    std::array<uint8_t, 8> header_buf{};
    auto cancel = [&]() {
        boost::system::error_code ignored;
        stream.lowest_layer().cancel(ignored);
        stream.lowest_layer().close(ignored);
    };

    IoOpResult hr = read_exact_with_timeout(stream, io, boost::asio::buffer(header_buf), timeout, cancel);
    if (hr.timed_out) {
        if (what && std::strcmp(what, "server info") == 0) {
            throw FatalError(std::string("timed out waiting for server confirmation (") + host + ":" + std::to_string(port) +
                             "; inner crypto negotiation may be overloaded). try again or lower inner KDF cost");
        }
        std::string hint = endpoint_hint_tls(tls_handshake_succeeded, nullptr, 0);
        throw FatalError(std::string("this endpoint is not a yume server (") + host + ":" + std::to_string(port) +
                         "; timed out waiting for " + what +
                         "); please check the origin and try again (endpoint identified as: " + hint + ")");
    }
    if (hr.ec) {
        std::string hint = endpoint_hint_tls(tls_handshake_succeeded, header_buf.data(), header_buf.size());
        throw FatalError(std::string("this endpoint is not a yume server (") + host + ":" + std::to_string(port) +
                         "; failed to read " + what +
                         ": " + hr.ec.message() + "); please check the origin and try again (endpoint identified as: " + hint + ")");
    }
    if (!looks_like_yume_header(header_buf)) {
        std::string hint = endpoint_hint_tls(tls_handshake_succeeded, header_buf.data(), header_buf.size());
        throw FatalError(std::string("this endpoint is not a yume server (") + host + ":" + std::to_string(port) +
                         "; unexpected " + what +
                         " header; ascii=\"" + ascii_preview(header_buf.data(), header_buf.size()) +
                         "\" hex=" + hex_preview(header_buf.data(), header_buf.size()) +
                         "); please check the origin and try again (endpoint identified as: " + hint + ")");
    }

    uint32_t len = (static_cast<uint32_t>(header_buf[0]) << 24) |
                   (static_cast<uint32_t>(header_buf[1]) << 16) |
                   (static_cast<uint32_t>(header_buf[2]) << 8) |
                   (static_cast<uint32_t>(header_buf[3]));
    protocol::Frame frame{};
    frame.header.len = len;
    frame.header.type = header_buf[4];
    frame.header.stream_id = header_buf[5];
    frame.header.flags = static_cast<uint16_t>(header_buf[6] << 8) |
                         static_cast<uint16_t>(header_buf[7]);

    frame.payload.resize(len);
    if (len > 0) {
        IoOpResult pr = read_exact_with_timeout(stream, io, boost::asio::buffer(frame.payload), timeout, cancel);
        if (pr.timed_out) {
            throw FatalError(std::string("this endpoint is not a yume server (") + host + ":" + std::to_string(port) +
                             "; timed out reading " + what +
                             " payload); please check the origin and try again (endpoint identified as: " +
                             endpoint_hint_tls(tls_handshake_succeeded, nullptr, 0) + ")");
        }
        if (pr.ec) {
            throw FatalError(std::string("this endpoint is not a yume server (") + host + ":" + std::to_string(port) +
                             "; failed reading " + what +
                             " payload: " + pr.ec.message() + "); please check the origin and try again (endpoint identified as: " +
                             endpoint_hint_tls(tls_handshake_succeeded, nullptr, 0) + ")");
        }
    }
    return frame;
}

std::string get_self_path(const char* argv0) {
#if defined(_WIN32)
    char buf[MAX_PATH];
    DWORD len = GetModuleFileNameA(nullptr, buf, MAX_PATH);
    if (len > 0 && len < MAX_PATH) {
        return std::string(buf, len);
    }
#elif defined(__APPLE__)
    uint32_t size = 0;
    _NSGetExecutablePath(nullptr, &size);
    if (size > 0) {
        std::string out(size, '\0');
        if (_NSGetExecutablePath(out.data(), &size) == 0) {
            auto end = out.find('\0');
            if (end != std::string::npos) {
                out.resize(end);
            }
            std::error_code ec;
            return std::filesystem::absolute(out, ec).string();
        }
    }
#else
    char buf[4096];
    ssize_t len = ::readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (len > 0) {
        buf[len] = '\0';
        return std::string(buf);
    }
#endif
    if (argv0 && *argv0) {
        std::error_code ec;
        return std::filesystem::absolute(argv0, ec).string();
    }
    return {};
}

std::string get_system_hostname() {
#if defined(_WIN32)
    char buf[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(buf);
    if (GetComputerNameA(buf, &size) && size > 0) {
        return std::string(buf, size);
    }
#else
    char buf[256];
    if (::gethostname(buf, sizeof(buf)) == 0) {
        buf[sizeof(buf) - 1] = '\0';
        return std::string(buf);
    }
#endif
    return {};
}

constexpr const char kAnonMsgPrefix[] = "YUME-ANON-V1:";
constexpr const char kPqMsgPrefix[] = "YUME-PQ-V1:";
constexpr const char kFixcraftAnonymPubPem[] =
    "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAtupzLhANnB0VxP51vB/7yYwR+/3/jv4Str9MGLGA+is=\n"
    "-----END PUBLIC KEY-----\n";
// Default CA cert path - empty means user must provide via --anonym-ca-cert if needed
constexpr const char kDefaultAnonymCaCertPath[] = "";
struct EnvGuard {
    struct Entry {
        std::string key;
        std::string value;
        bool had;
    };
    std::vector<Entry> prev;
    ~EnvGuard() {
#if defined(_WIN32)
        for (const auto& e : prev) {
            if (e.had) {
                _putenv_s(e.key.c_str(), e.value.c_str());
            } else {
                _putenv_s(e.key.c_str(), "");
            }
        }
#else
        for (const auto& e : prev) {
            if (e.had) {
                setenv(e.key.c_str(), e.value.c_str(), 1);
            } else {
                unsetenv(e.key.c_str());
            }
        }
#endif
    }
};

void set_env(EnvGuard& guard, const std::string& key, const std::string& value) {
    const char* old = std::getenv(key.c_str());
    if (old) {
        guard.prev.push_back({key, old, true});
    } else {
        guard.prev.push_back({key, "", false});
    }
#if defined(_WIN32)
    _putenv_s(key.c_str(), value.c_str());
#else
    setenv(key.c_str(), value.c_str(), 1);
#endif
}

bool write_file_bytes(const std::string& path, const std::string& data, std::string* err) {
    try {
        std::filesystem::path p(path);
        if (p.has_parent_path()) {
            std::error_code ec;
            std::filesystem::create_directories(p.parent_path(), ec);
        }
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) {
            if (err) *err = "failed to open file: " + path;
            return false;
        }
        if (!data.empty()) {
            out.write(data.data(), static_cast<std::streamsize>(data.size()));
            if (!out) {
                if (err) *err = "failed to write file: " + path;
                return false;
            }
        }
        out.close();
        if (!out) {
            if (err) *err = "failed to flush file: " + path;
            return false;
        }
#if !defined(_WIN32)
        if (path.find(".key") != std::string::npos) {
            ::chmod(path.c_str(), 0600);
        } else {
            ::chmod(path.c_str(), 0644);
        }
#endif
        return true;
    } catch (const std::exception& ex) {
        if (err) *err = ex.what();
        return false;
    }
}

bool read_file_bytes(const std::string& path, std::string* out, std::string* err) {
    try {
        std::ifstream in(path, std::ios::binary);
        if (!in) {
            if (err) *err = "failed to open file: " + path;
            return false;
        }
        in.seekg(0, std::ios::end);
        std::streamoff size = in.tellg();
        if (size < 0) {
            if (err) *err = "failed to read file size: " + path;
            return false;
        }
        in.seekg(0, std::ios::beg);
        out->assign(static_cast<std::size_t>(size), '\0');
        if (!out->empty()) {
            in.read(out->data(), static_cast<std::streamsize>(out->size()));
            if (!in) {
                if (err) *err = "failed to read file: " + path;
                return false;
            }
        }
        return true;
    } catch (const std::exception& ex) {
        if (err) *err = ex.what();
        return false;
    }
}

int run_local_command_with_proxy(const std::string& cmd, int socks_port, bool ipv4_only) {
    std::string proxy = "socks5h://127.0.0.1:" + std::to_string(socks_port);
    EnvGuard guard;
    set_env(guard, "ALL_PROXY", proxy);
    set_env(guard, "HTTPS_PROXY", proxy);
    set_env(guard, "HTTP_PROXY", proxy);
    set_env(guard, "all_proxy", proxy);
    set_env(guard, "https_proxy", proxy);
    set_env(guard, "http_proxy", proxy);
    if (ipv4_only) {
        set_env(guard, "CURL_IPRESOLVE", "4");
    }
    return std::system(cmd.c_str());
}

std::string maybe_force_ipv4(const std::string& cmd, bool ipv4_only) {
    if (!ipv4_only) {
        return cmd;
    }
    auto starts_with_curl = [](const std::string& s) {
        return s.rfind("curl ", 0) == 0 || s.rfind("curl\t", 0) == 0 || s == "curl";
    };
    if (!starts_with_curl(cmd)) {
        return cmd;
    }
    bool has_v4 = cmd.find(" -4") != std::string::npos || cmd.find("--ipv4") != std::string::npos;
    bool has_http1 = cmd.find("--http1.1") != std::string::npos;
    std::string out = "curl ";
    if (!has_http1) {
        out += "--http1.1 ";
    }
    if (!has_v4) {
        out += "-4 ";
    }
    if (cmd == "curl") {
        return out;
    }
    return out + cmd.substr(5);
}

std::string hex_encode(const unsigned char* data, size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kHex[(data[i] >> 4) & 0xF]);
        out.push_back(kHex[data[i] & 0xF]);
    }
    return out;
}

void warn_security_disabled(const std::string& what, bool boring) {
    if (boring) {
        std::cerr << "\033[1;31mSecurity warning: " << what << " disabled\033[0m\n";
        return;
    }
    std::cerr << "\033[1;31m🔓⛓️‍💥 YOUR SECURITY IS SUFFERING BECAUSE YOU HAVE DISABLED: "
              << what << "\033[0m\n";
}

std::string get_peer_cert_fingerprint(EVP_PKEY* key, SSL* ssl) {
    (void)key;
    if (!ssl) {
        return {};
    }
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        return {};
    }
    unsigned char* der = nullptr;
    int len = i2d_X509(cert, &der);
    X509_free(cert);
    if (len <= 0 || !der) {
        if (der) OPENSSL_free(der);
        return {};
    }
    unsigned char hash[SHA256_DIGEST_LENGTH] = {0};
    SHA256(der, static_cast<size_t>(len), hash);
    OPENSSL_free(der);
    return hex_encode(hash, SHA256_DIGEST_LENGTH);
}

crypto::EVP_PKEY_ptr load_pubkey_from_cert(const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "r");
    if (!bio) {
        return {nullptr, EVP_PKEY_free};
    }
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!cert) {
        return {nullptr, EVP_PKEY_free};
    }
    EVP_PKEY* key = X509_get_pubkey(cert);
    X509_free(cert);
    return {key, EVP_PKEY_free};
}

using X509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;

X509_ptr load_cert_from_pem(const std::string& pem) {
    if (pem.empty()) {
        return {nullptr, X509_free};
    }
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) {
        return {nullptr, X509_free};
    }
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return {cert, X509_free};
}

crypto::EVP_PKEY_ptr load_pubkey_from_cert_pem(const std::string& pem) {
    auto cert = load_cert_from_pem(pem);
    if (!cert) {
        return {nullptr, EVP_PKEY_free};
    }
    EVP_PKEY* key = X509_get_pubkey(cert.get());
    return {key, EVP_PKEY_free};
}

X509_ptr load_cert_from_file(const std::string& path) {
    BIO* bio = BIO_new_file(path.c_str(), "r");
    if (!bio) {
        return {nullptr, X509_free};
    }
    X509* cert = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return {cert, X509_free};
}

bool is_cert_time_valid(X509* cert) {
    if (!cert) {
        return false;
    }
    const ASN1_TIME* not_before = X509_get0_notBefore(cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(cert);
    if (!not_before || !not_after) {
        return false;
    }
    if (X509_cmp_time(not_before, nullptr) > 0) {
        return false;
    }
    if (X509_cmp_time(not_after, nullptr) < 0) {
        return false;
    }
    return true;
}

std::string describe_verify_result(long code, const std::string& host) {
    if (code == X509_V_OK) {
        return {};
    }
    switch (code) {
        case X509_V_ERR_HOSTNAME_MISMATCH:
            return "hostname mismatch (" + host + ")";
#ifdef X509_V_ERR_IP_ADDRESS_MISMATCH
        case X509_V_ERR_IP_ADDRESS_MISMATCH:
            return "IP address mismatch (" + host + ")";
#endif
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
            return "issuer CA not found";
        case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            return "self-signed leaf certificate";
        case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
            return "self-signed certificate in chain";
        case X509_V_ERR_CERT_HAS_EXPIRED:
            return "certificate expired";
        case X509_V_ERR_CERT_NOT_YET_VALID:
            return "certificate not yet valid";
        default:
            return X509_verify_cert_error_string(code);
    }
}

std::string describe_openssl_error() {
    unsigned long err = ERR_peek_last_error();
    if (!err) {
        return {};
    }
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return buf;
}

bool file_exists(const std::string& path) {
    if (path.empty()) {
        return false;
    }
    std::error_code ec;
    auto st = std::filesystem::status(path, ec);
    if (ec) {
        return false;
    }
    return std::filesystem::is_regular_file(st);
}

bool require_file(const char* label, const std::string& path) {
    if (path.empty()) {
        return true;
    }
    if (!file_exists(path)) {
        util::log_error(std::string(label) + " not found or not a file: " + path);
        return false;
    }
    return true;
}

bool verify_cert_signed_by_ca(X509* cert, X509* ca) {
    if (!cert || !ca) {
        return false;
    }
    EVP_PKEY* ca_pub = X509_get_pubkey(ca);
    if (!ca_pub) {
        return false;
    }
    bool ok = X509_verify(cert, ca_pub) == 1;
    EVP_PKEY_free(ca_pub);
    return ok;
}

int run_proxycmd(const std::string& dest_host, int dest_port, int socks_port) {
#if defined(_WIN32)
    (void)dest_host;
    (void)dest_port;
    (void)socks_port;
    util::log_error("proxycmd is not supported on Windows yet");
    return 1;
#else
    if (dest_host.empty() || dest_port <= 0) {
        util::log_error("proxycmd missing destination");
        return 1;
    }
    boost::asio::io_context io;
    boost::asio::ip::tcp::resolver resolver(io);
    boost::asio::ip::tcp::socket sock(io);
    auto endpoints = resolver.resolve("127.0.0.1", std::to_string(socks_port));
    boost::asio::connect(sock, endpoints);

    std::array<uint8_t, 3> hello{{0x05, 0x01, 0x00}};
    boost::asio::write(sock, boost::asio::buffer(hello));
    std::array<uint8_t, 2> reply{};
    boost::asio::read(sock, boost::asio::buffer(reply));
    if (reply[0] != 0x05 || reply[1] != 0x00) {
        util::log_error("SOCKS5 auth failed");
        return 1;
    }

    if (dest_host.size() > 255) {
        util::log_error("SOCKS5 destination too long");
        return 1;
    }
    const size_t host_len = dest_host.size();
    std::vector<uint8_t> req(7 + host_len);
    size_t off = 0;
    req[off++] = 0x05;
    req[off++] = 0x01;
    req[off++] = 0x00;
    req[off++] = 0x03;
    req[off++] = static_cast<uint8_t>(host_len);
    if (host_len > 0) {
        std::memcpy(req.data() + off, dest_host.data(), host_len);
        off += host_len;
    }
    req[off++] = static_cast<uint8_t>((dest_port >> 8) & 0xFF);
    req[off++] = static_cast<uint8_t>(dest_port & 0xFF);
    boost::asio::write(sock, boost::asio::buffer(req));

    std::array<uint8_t, 4> rep{};
    boost::asio::read(sock, boost::asio::buffer(rep));
    if (rep[1] != 0x00) {
        util::log_error("SOCKS5 connect failed");
        return 1;
    }
    size_t to_read = 0;
    if (rep[3] == 0x01) to_read = 4;
    else if (rep[3] == 0x03) {
        uint8_t len = 0;
        boost::asio::read(sock, boost::asio::buffer(&len, 1));
        to_read = len;
    } else if (rep[3] == 0x04) to_read = 16;
    if (to_read > 0) {
        std::vector<uint8_t> discard(to_read);
        boost::asio::read(sock, boost::asio::buffer(discard));
    }
    std::array<uint8_t, 2> discard_port{};
    boost::asio::read(sock, boost::asio::buffer(discard_port));

    int sock_fd = sock.native_handle();
    bool stdin_open = true;
    while (true) {
        fd_set rfds;
        FD_ZERO(&rfds);
        if (stdin_open) {
            FD_SET(STDIN_FILENO, &rfds);
        }
        FD_SET(sock_fd, &rfds);
        int maxfd = sock_fd > STDIN_FILENO ? sock_fd : STDIN_FILENO;
        int rc = select(maxfd + 1, &rfds, nullptr, nullptr, nullptr);
        if (rc <= 0) {
            break;
        }
        if (stdin_open && FD_ISSET(STDIN_FILENO, &rfds)) {
            char buf[4096];
            ssize_t n = ::read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0) {
                stdin_open = false;
                boost::system::error_code ec;
                sock.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
            } else {
                boost::asio::write(sock, boost::asio::buffer(buf, static_cast<size_t>(n)));
            }
        }
        if (FD_ISSET(sock_fd, &rfds)) {
            char buf[4096];
            boost::system::error_code ec;
            size_t n = sock.read_some(boost::asio::buffer(buf), ec);
            if (ec || n == 0) {
                break;
            }
            ssize_t w = ::write(STDOUT_FILENO, buf, n);
            (void)w;
        }
    }
    return 0;
#endif
}

std::string wrap_ssh_with_proxy(const std::string& cmd, int socks_port, const std::string& self_path) {
#if defined(_WIN32)
    (void)socks_port;
    (void)self_path;
    return cmd;
#else
    auto starts_with_ssh = [](const std::string& s) {
        return s.rfind("ssh ", 0) == 0 || s.rfind("ssh\t", 0) == 0 || s == "ssh";
    };
    if (!starts_with_ssh(cmd)) {
        return cmd;
    }
    if (cmd.find("ProxyCommand") != std::string::npos) {
        return cmd;
    }
    std::string helper = self_path.empty() ? "yume" : self_path;
    std::string out = "ssh -o ProxyCommand=\"" + helper + " --proxycmd --socks " +
                      std::to_string(socks_port) + " --dest %h --dport %p\"";
    if (cmd == "ssh") {
        return out;
    }
    return out + " " + cmd.substr(4);
#endif
}
struct ParsedArgs {
    std::string config_path{"config/yume.json"};
    bool config_specified{false};
    bool completion{false};
    std::string completion_shell;
    std::string server;
    int port{0};
    std::string identity;
    int socks_port{0};
    int io_threads{0};
    int lport{0};
    std::string rhost;
    int rport{0};
    std::string run_cmd;
    bool run_ipv4{false};
    bool proxycmd{false};
    std::string dest_host;
    int dest_port{0};
    bool inner_crypto{false};
    bool inner_heavy{true};
    bool inner_hop{true};
    bool inner_hop_override{false};
    std::uint32_t hop_interval_ms{0};
    bool hop_interval_override{false};
    bool use_udp{false};
    bool udp_override{false};
    bool allow_local_ip{false};
    bool allow_local_ip_override{false};
    std::string pq_public_key;
    bool allow_embedded_master{false};
    bool allow_embedded_master_override{false};
    std::string anonym_ca_cert;
    std::string tls_ca_cert;
    std::string tls_pin_sha256;
    bool tls_stealth{true};  // ON by default
    bool tls_stealth_override{false};
    std::string tls_stealth_profile{"chrome"};
    bool tls_stealth_rotate{false};
    std::uint32_t tls_stealth_rotation_interval{100};
    bool tls_fingerprint_log{false};
    std::string tls_fingerprint_log_path{"./logs/fingerprints"};
    bool tls_fingerprint_verify{false};
    std::string tls_fingerprint_test_endpoint{"tls.peet.ws"};
    bool help{false};
    bool version{false};
    bool accept_monitoring{false};
    bool save_server{false};
    bool require_anonym{false};
    bool boring{false};
    bool boring_override{false};
    bool non_interactive{false};
    bool live_status{false};
    bool io_threads_override{false};
    bool server_in_charge{false};
    bool server_in_charge_override{false};
    int server_in_charge_port{0};
    bool server_in_charge_port_override{false};
    int server_in_charge_min_port{0};
    int server_in_charge_max_port{0};
    bool allow_exec{false};
    bool allow_exec_override{false};
    bool control_mode{false};
    bool list_controlled{false};
    std::string control_id;
    std::string preferred_name;
    std::string preferred_id;
    std::string relay_mode{"untrusted"};
    bool allow_inbound_admin{false};
    bool allow_inbound_admin_override{false};
    bool allow_outbound_admin{true};
    bool allow_outbound_admin_override{false};
    bool allow_chat{true};
    bool allow_chat_override{false};
    bool allow_file{true};
    bool allow_file_override{false};
    bool allow_bytes{true};
    bool allow_bytes_override{false};
    std::string history_dir;
    bool history_enabled{true};
    bool history_override{false};
    std::string instance_name;
    bool attach_local{false};
    std::string chat_target;
    std::string chat_password;
    std::string file_target;
    std::string file_path;
    std::string bytes_target;
    std::string bytes_path;
    bool directory_mode{false};
    std::string admin_target;
    std::string exec_cmd;
    std::string ssh_L;
    std::string ssh_R;
    std::string parse_error;
};

bool parse_int_strict(std::string_view text, int& out) {
    if (text.empty()) {
        return false;
    }
    int value = 0;
    auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc() || ptr != text.data() + text.size()) {
        return false;
    }
    out = value;
    return true;
}

bool parse_u32_strict(std::string_view text, std::uint32_t& out) {
    if (text.empty()) {
        return false;
    }
    unsigned long long value = 0;
    auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (ec != std::errc() || ptr != text.data() + text.size()) {
        return false;
    }
    if (value > std::numeric_limits<std::uint32_t>::max()) {
        return false;
    }
    out = static_cast<std::uint32_t>(value);
    return true;
}

ParsedArgs parse_args(int argc, char** argv) {
    ParsedArgs args;
    int i = 1;
    auto take_value = [&](const std::string& flag) -> const char* {
        if (i + 1 >= argc) {
            args.parse_error = "missing value for " + flag;
            return nullptr;
        }
        return argv[++i];
    };
    auto parse_int_value = [&](const std::string& flag, int& out) -> bool {
        const char* raw = take_value(flag);
        if (!raw) {
            return false;
        }
        int parsed = 0;
        if (!parse_int_strict(raw, parsed)) {
            args.parse_error = "invalid integer for " + flag + ": " + raw;
            return false;
        }
        out = parsed;
        return true;
    };
    auto parse_u32_value = [&](const std::string& flag, std::uint32_t& out) -> bool {
        const char* raw = take_value(flag);
        if (!raw) {
            return false;
        }
        std::uint32_t parsed = 0;
        if (!parse_u32_strict(raw, parsed)) {
            args.parse_error = "invalid integer for " + flag + ": " + raw;
            return false;
        }
        out = parsed;
        return true;
    };
    for (; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--") {
            // Service runners sometimes append "--" before application flags.
            // Treat it as an explicit non-interactive request and continue parsing.
            args.non_interactive = true;
        } else if (arg == "completion") {
            const char* shell = take_value("completion");
            if (!shell) {
                return args;
            }
            args.completion = true;
            args.completion_shell = shell;
        } else if (arg == "--completion") {
            const char* shell = take_value("--completion");
            if (!shell) {
                return args;
            }
            args.completion = true;
            args.completion_shell = shell;
        } else if (arg == "--config") {
            const char* cfg = take_value("--config");
            if (!cfg) {
                return args;
            }
            args.config_path = cfg;
            args.config_specified = true;
        } else if (arg == "--help" || arg == "-h") {
            args.help = true;
        } else if (arg == "--version") {
            args.version = true;
        } else if (arg == "--server") {
            const char* server = take_value("--server");
            if (!server) {
                return args;
            }
            args.server = server;
        } else if (arg == "--port") {
            if (!parse_int_value("--port", args.port)) {
                return args;
            }
        } else if (arg == "--auth" || arg == "-i") {
            const char* identity = take_value(arg);
            if (!identity) {
                return args;
            }
            args.identity = identity;
        } else if (arg == "--socks") {
            if (!parse_int_value("--socks", args.socks_port)) {
                return args;
            }
        } else if (arg == "--threads") {
            if (!parse_int_value("--threads", args.io_threads)) {
                return args;
            }
            args.io_threads_override = true;
        } else if (arg == "--lport") {
            if (!parse_int_value("--lport", args.lport)) {
                return args;
            }
        } else if (arg == "--rhost") {
            const char* rhost = take_value("--rhost");
            if (!rhost) {
                return args;
            }
            args.rhost = rhost;
        } else if (arg == "--rport") {
            if (!parse_int_value("--rport", args.rport)) {
                return args;
            }
        } else if (arg == "--run" || arg == "-c" || arg == "--cmd") {
            const char* cmd = take_value(arg);
            if (!cmd) {
                return args;
            }
            args.run_cmd = cmd;
        } else if (arg == "--run-ipv4") {
            args.run_ipv4 = true;
        } else if (arg == "--proxycmd") {
            args.proxycmd = true;
        } else if (arg == "--dest") {
            const char* dest = take_value("--dest");
            if (!dest) {
                return args;
            }
            args.dest_host = dest;
        } else if (arg == "--dport") {
            if (!parse_int_value("--dport", args.dest_port)) {
                return args;
            }
        } else if (arg == "--require-anonym") {
            args.require_anonym = true;
        } else if (arg == "--anonym-ca-cert") {
            const char* cert = take_value("--anonym-ca-cert");
            if (!cert) {
                return args;
            }
            args.anonym_ca_cert = cert;
        } else if (arg == "-L") {
            const char* value = take_value("-L");
            if (!value) {
                return args;
            }
            args.ssh_L = value;
        } else if (arg == "-R") {
            const char* value = take_value("-R");
            if (!value) {
                return args;
            }
            args.ssh_R = value;
        } else if (arg == "--inner") {
            args.inner_crypto = true;
        } else if (arg == "--inner-heavy") {
            args.inner_crypto = true;
            args.inner_heavy = true;
        } else if (arg == "--inner-light") {
            args.inner_crypto = true;
            args.inner_heavy = false;
        } else if (arg == "--hop") {
            args.inner_hop = true;
            args.inner_hop_override = true;
        } else if (arg == "--no-hop") {
            args.inner_hop = false;
            args.inner_hop_override = true;
        } else if (arg == "--hop-interval") {
            if (!parse_u32_value("--hop-interval", args.hop_interval_ms)) {
                return args;
            }
            args.hop_interval_override = true;
        } else if (arg == "--udp") {
            args.use_udp = true;
            args.udp_override = true;
        } else if (arg == "--tcp") {
            args.use_udp = false;
            args.udp_override = true;
        } else if (arg == "--allow-local-ip") {
            args.allow_local_ip = true;
            args.allow_local_ip_override = true;
        } else if (arg == "--server-in-charge") {
            args.server_in_charge = true;
            args.server_in_charge_override = true;
            if (i + 1 < argc) {
                std::string next = argv[i + 1];
                if (!next.empty() && next[0] != '-') {
                    int parsed = 0;
                    if (!parse_int_strict(next, parsed)) {
                        args.parse_error = "invalid integer for --server-in-charge: " + next;
                        return args;
                    }
                    args.server_in_charge_port = parsed;
                    args.server_in_charge_port_override = true;
                    ++i;
                }
            }
        } else if (arg == "--server-in-charge-port") {
            args.server_in_charge = true;
            args.server_in_charge_override = true;
            if (!parse_int_value("--server-in-charge-port", args.server_in_charge_port)) {
                return args;
            }
            args.server_in_charge_port_override = true;
        } else if (arg == "--server-in-charge-min-port") {
            args.server_in_charge = true;
            args.server_in_charge_override = true;
            if (!parse_int_value("--server-in-charge-min-port", args.server_in_charge_min_port)) {
                return args;
            }
        } else if (arg == "--server-in-charge-max-port") {
            args.server_in_charge = true;
            args.server_in_charge_override = true;
            if (!parse_int_value("--server-in-charge-max-port", args.server_in_charge_max_port)) {
                return args;
            }
        } else if (arg == "--allow-exec") {
            args.allow_exec = true;
            args.allow_exec_override = true;
        } else if (arg == "--exec") {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                args.exec_cmd = argv[++i];
            } else {
                args.allow_exec = true;
                args.allow_exec_override = true;
            }
        } else if (arg == "--control") {
            args.control_mode = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                args.control_id = argv[++i];
            }
        } else if (arg == "--id") {
            const char* value = take_value("--id");
            if (!value) {
                return args;
            }
            args.control_id = value;
        } else if (arg == "--list-controlled") {
            args.list_controlled = true;
        } else if (arg == "--name") {
            const char* value = take_value("--name");
            if (!value) {
                return args;
            }
            args.preferred_name = value;
        } else if (arg == "--client-id") {
            const char* value = take_value("--client-id");
            if (!value) {
                return args;
            }
            args.preferred_id = value;
        } else if (arg == "--relay-mode") {
            const char* value = take_value("--relay-mode");
            if (!value) {
                return args;
            }
            args.relay_mode = value;
        } else if (arg == "--allow-inbound-admin") {
            args.allow_inbound_admin = true;
            args.allow_inbound_admin_override = true;
        } else if (arg == "--deny-inbound-admin") {
            args.allow_inbound_admin = false;
            args.allow_inbound_admin_override = true;
        } else if (arg == "--allow-outbound-admin") {
            args.allow_outbound_admin = true;
            args.allow_outbound_admin_override = true;
        } else if (arg == "--deny-outbound-admin") {
            args.allow_outbound_admin = false;
            args.allow_outbound_admin_override = true;
        } else if (arg == "--allow-chat") {
            args.allow_chat = true;
            args.allow_chat_override = true;
        } else if (arg == "--deny-chat") {
            args.allow_chat = false;
            args.allow_chat_override = true;
        } else if (arg == "--allow-file") {
            args.allow_file = true;
            args.allow_file_override = true;
        } else if (arg == "--deny-file") {
            args.allow_file = false;
            args.allow_file_override = true;
        } else if (arg == "--allow-bytes") {
            args.allow_bytes = true;
            args.allow_bytes_override = true;
        } else if (arg == "--deny-bytes") {
            args.allow_bytes = false;
            args.allow_bytes_override = true;
        } else if (arg == "--history-dir") {
            const char* value = take_value("--history-dir");
            if (!value) {
                return args;
            }
            args.history_dir = value;
            args.history_override = true;
        } else if (arg == "--no-history") {
            args.history_enabled = false;
            args.history_override = true;
        } else if (arg == "--instance") {
            const char* value = take_value("--instance");
            if (!value) {
                return args;
            }
            args.instance_name = value;
        } else if (arg == "--attach-local") {
            args.attach_local = true;
        } else if (arg == "--chat") {
            const char* value = take_value("--chat");
            if (!value) {
                return args;
            }
            args.chat_target = value;
        } else if (arg == "--send-file") {
            const char* peer = take_value("--send-file");
            if (!peer) {
                return args;
            }
            args.file_target = peer;
            const char* path = take_value("--send-file");
            if (!path) {
                return args;
            }
            args.file_path = path;
        } else if (arg == "--send-bytes") {
            const char* peer = take_value("--send-bytes");
            if (!peer) {
                return args;
            }
            args.bytes_target = peer;
            const char* path = take_value("--send-bytes");
            if (!path) {
                return args;
            }
            args.bytes_path = path;
        } else if (arg == "--directory") {
            args.directory_mode = true;
        } else if (arg == "--admin-attach" || arg == "--server-attach") {
            const char* value = take_value(arg);
            if (!value) {
                return args;
            }
            args.admin_target = value;
        } else if (arg == "--pq-pub") {
            const char* value = take_value("--pq-pub");
            if (!value) {
                return args;
            }
            args.pq_public_key = value;
        } else if (arg == "--use-embedded-master") {
            args.allow_embedded_master = true;
            args.allow_embedded_master_override = true;
        } else if (arg == "--no-embedded-master") {
            args.allow_embedded_master = false;
            args.allow_embedded_master_override = true;
        } else if (arg == "--tls-ca") {
            const char* value = take_value("--tls-ca");
            if (!value) {
                return args;
            }
            args.tls_ca_cert = value;
        } else if (arg == "--tls-pin") {
            const char* value = take_value("--tls-pin");
            if (!value) {
                return args;
            }
            args.tls_pin_sha256 = value;
        } else if (arg == "--no-stealth") {
            args.tls_stealth = false;
            args.tls_stealth_override = true;
        } else if (arg == "--profile") {
            const char* value = take_value("--profile");
            if (!value) {
                return args;
            }
            args.tls_stealth_profile = value;
        } else if (arg == "--tls-stealth-rotate") {
            args.tls_stealth_rotate = true;
        } else if (arg == "--tls-stealth-rotation-interval") {
            if (!parse_u32_value("--tls-stealth-rotation-interval", args.tls_stealth_rotation_interval)) {
                return args;
            }
        } else if (arg == "--tls-fingerprint-log") {
            args.tls_fingerprint_log = true;
        } else if (arg == "--tls-fingerprint-log-path") {
            const char* value = take_value("--tls-fingerprint-log-path");
            if (!value) {
                return args;
            }
            args.tls_fingerprint_log_path = value;
        } else if (arg == "--tls-fingerprint-verify") {
            args.tls_fingerprint_verify = true;
        } else if (arg == "--tls-fingerprint-test-endpoint") {
            const char* value = take_value("--tls-fingerprint-test-endpoint");
            if (!value) {
                return args;
            }
            args.tls_fingerprint_test_endpoint = value;
        } else if (arg == "--accept-monitoring") {
            args.accept_monitoring = true;
        } else if (arg == "--save-server") {
            args.save_server = true;
        } else if (arg == "--boring") {
            args.boring = true;
            args.boring_override = true;
        } else if (arg == "--non-interactive") {
            args.non_interactive = true;
        } else if (arg == "--live-status") {
            args.live_status = true;
        }
    }
    return args;
}

crypto::Bytes auth_payload(EVP_PKEY* pubkey,
                           const crypto::Bytes& signature,
                           const std::optional<crypto::Bytes>& pq_ciphertext,
                           const std::optional<crypto::Bytes>& pq_salt,
                           const std::optional<std::string>& inner_mode,
                           const std::optional<bool>& inner_hop,
                           const std::optional<inner::KdfParams>& inner_kdf) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
        throw std::runtime_error("failed to allocate pubkey bio");
    }
    if (PEM_write_bio_PUBKEY(bio, pubkey) != 1) {
        BIO_free(bio);
        throw std::runtime_error("failed to write public key");
    }

    char* data = nullptr;
    long len = BIO_get_mem_data(bio, &data);
    if (len <= 0) {
        BIO_free(bio);
        throw std::runtime_error("failed to read public key");
    }

    crypto::Bytes pub_bytes(reinterpret_cast<uint8_t*>(data), reinterpret_cast<uint8_t*>(data) + len);
    BIO_free(bio);

    auto checked_add = [](size_t a, size_t b) {
        if (a > (std::numeric_limits<size_t>::max() - b)) {
            throw std::runtime_error("auth payload size overflow");
        }
        return a + b;
    };

    if (pub_bytes.size() > 0xFFFF || signature.size() > 0xFFFF) {
        throw std::runtime_error("auth payload too large");
    }
    if (pq_ciphertext && pq_ciphertext->size() > 0xFFFF) {
        throw std::runtime_error("PQ ciphertext too large");
    }
    if (pq_salt && pq_salt->size() > 0xFFFF) {
        throw std::runtime_error("PQ salt too large");
    }
    if (inner_mode && inner_mode->size() > 0xFFFF) {
        throw std::runtime_error("inner mode too large");
    }
    if (inner_hop && !pq_ciphertext.has_value()) {
        throw std::runtime_error("inner hop without PQ data");
    }
    if (inner_mode && !pq_ciphertext.has_value()) {
        throw std::runtime_error("inner mode without PQ data");
    }
    if (inner_kdf && !pq_ciphertext.has_value()) {
        throw std::runtime_error("inner kdf without PQ data");
    }
    if (inner_kdf && inner_kdf->name.size() > 0xFFFF) {
        throw std::runtime_error("inner kdf too large");
    }

    size_t total = 0;
    total = checked_add(total, 2 + pub_bytes.size());
    total = checked_add(total, 2 + signature.size());
    if (pq_ciphertext) {
        total = checked_add(total, 2 + pq_ciphertext->size());
    }
    if (pq_salt) {
        total = checked_add(total, 2 + pq_salt->size());
    }
    if (inner_mode) {
        total = checked_add(total, 2 + inner_mode->size());
    }
    if (inner_hop) {
        total = checked_add(total, 2 + 1);
    }
    if (inner_kdf) {
        total = checked_add(total, 2 + inner_kdf->name.size());
        total = checked_add(total, 2 + 16);
    }

    crypto::Bytes payload(total);
    size_t off = 0;
    auto write_len = [&](uint16_t v) {
        payload[off++] = static_cast<uint8_t>((v >> 8) & 0xFF);
        payload[off++] = static_cast<uint8_t>(v & 0xFF);
    };
    auto write_bytes = [&](const crypto::Bytes& data) {
        if (!data.empty()) {
            std::memcpy(payload.data() + off, data.data(), data.size());
            off += data.size();
        }
    };

    write_len(static_cast<uint16_t>(pub_bytes.size()));
    write_bytes(pub_bytes);
    write_len(static_cast<uint16_t>(signature.size()));
    write_bytes(signature);
    if (pq_ciphertext) {
        write_len(static_cast<uint16_t>(pq_ciphertext->size()));
        write_bytes(*pq_ciphertext);
        if (pq_salt) {
            write_len(static_cast<uint16_t>(pq_salt->size()));
            write_bytes(*pq_salt);
        }
        if (inner_mode) {
            crypto::Bytes mode_bytes(inner_mode->begin(), inner_mode->end());
            write_len(static_cast<uint16_t>(mode_bytes.size()));
            write_bytes(mode_bytes);
        }
        if (inner_hop) {
            crypto::Bytes hop_bytes(1, *inner_hop ? static_cast<uint8_t>('1') : static_cast<uint8_t>('0'));
            write_len(static_cast<uint16_t>(hop_bytes.size()));
            write_bytes(hop_bytes);
        }
        if (inner_kdf) {
            crypto::Bytes kdf_bytes(inner_kdf->name.begin(), inner_kdf->name.end());
            write_len(static_cast<uint16_t>(kdf_bytes.size()));
            write_bytes(kdf_bytes);
            crypto::Bytes param_bytes(16, 0);
            auto write_u32 = [&](size_t off, std::uint32_t val) {
                param_bytes[off] = static_cast<uint8_t>((val >> 24) & 0xFF);
                param_bytes[off + 1] = static_cast<uint8_t>((val >> 16) & 0xFF);
                param_bytes[off + 2] = static_cast<uint8_t>((val >> 8) & 0xFF);
                param_bytes[off + 3] = static_cast<uint8_t>(val & 0xFF);
            };
            write_u32(0, inner_kdf->argon2_time);
            write_u32(4, inner_kdf->argon2_memory);
            write_u32(8, inner_kdf->argon2_parallelism);
            write_u32(12, inner_kdf->pbkdf2_iters);
            write_len(static_cast<uint16_t>(param_bytes.size()));
            write_bytes(param_bytes);
        }
    }

    return payload;
}

void authenticate(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                  boost::asio::io_context& io,
                  const std::string& server_host,
                  int server_port,
                  const std::string& identity_path,
                  const std::optional<crypto::Bytes>& pq_ciphertext,
                  const std::optional<crypto::Bytes>& pq_salt,
                  const std::optional<std::string>& inner_mode,
                  const std::optional<bool>& inner_hop,
                  const std::optional<inner::KdfParams>& inner_kdf) {
    protocol::Frame challenge = read_frame_with_timeout(stream, io, kAuthChallengeTimeout, "AUTH challenge", server_host, server_port, true);
    if (challenge.header.type != protocol::AUTH) {
        throw FatalError("this endpoint is not a yume server (server did not send AUTH challenge); please check the origin and try again");
    }

    auto kp = crypto::load_keypair(identity_path, "");
    crypto::Bytes signature = crypto::sign_message(kp.private_key.get(), challenge.payload);
    crypto::Bytes payload = auth_payload(kp.public_key.get() ? kp.public_key.get() : kp.private_key.get(),
                                         signature,
                                         pq_ciphertext,
                                         pq_salt,
                                         inner_mode,
                                         inner_hop,
                                         inner_kdf);

    protocol::Frame response{{static_cast<uint32_t>(payload.size()), protocol::AUTH, 0, 0}, payload};
    protocol::send_frame(stream, response);
}

void print_bash_completion() {
    std::cout << R"(# bash completion for yume
_yume_complete() {
  local cur prev
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  local opts="--help -h --version --config --server --port --auth -i --socks --threads --lport --rhost --rport --udp --tcp --allow-local-ip --server-in-charge --server-in-charge-port --server-in-charge-min-port --server-in-charge-max-port --allow-exec --exec --control --id --list-controlled --inner --inner-heavy --inner-light --hop --no-hop --hop-interval --pq-pub --use-embedded-master --no-embedded-master --anonym-ca-cert --tls-ca --tls-pin --profile --no-stealth --tls-stealth-rotate --tls-stealth-rotation-interval --tls-fingerprint-log --tls-fingerprint-log-path --tls-fingerprint-verify --tls-fingerprint-test-endpoint --run -c --cmd --run-ipv4 --proxycmd --dest --dport --require-anonym -L -R --boring --non-interactive --live-status --accept-monitoring --save-server --completion --name --client-id --relay-mode --allow-inbound-admin --deny-inbound-admin --allow-outbound-admin --deny-outbound-admin --allow-chat --deny-chat --allow-file --deny-file --allow-bytes --deny-bytes --history-dir --no-history --instance --attach-local --directory --chat --send-file --send-bytes --admin-attach --server-attach"
  local file_opts="--config --auth -i --pq-pub --anonym-ca-cert --tls-ca --tls-fingerprint-log-path"
  case "$prev" in
    --completion)
      COMPREPLY=( $(compgen -W "bash" -- "$cur") )
      return 0
      ;;
    --profile)
      COMPREPLY=( $(compgen -W "chrome firefox safari" -- "$cur") )
      return 0
      ;;
  esac
  for opt in $file_opts; do
    if [[ "$prev" == "$opt" ]]; then
      COMPREPLY=( $(compgen -f -- "$cur") )
      return 0
    fi
  done
  if [[ "$cur" == -* ]]; then
    COMPREPLY=( $(compgen -W "$opts" -- "$cur") )
    return 0
  fi
  COMPREPLY=()
}
complete -F _yume_complete yume
)";
}

void print_version() {
    std::cout << "yume " << yume::kVersion << " (using BaseFWX " << yume::kBasefwxVersion << ")\n";
}

void print_help() {
    std::cout
        << "yume - YUME client\n\n"
        << "Usage:\n"
        << "  yume --server <host> -i <id_ed25519> [options]\n"
        << "  yume completion bash\n"
        << "  yume --help\n"
        << "  yume --version\n\n"
        << "Version:\n"
        << "  yume " << yume::kVersion << " (using BaseFWX " << yume::kBasefwxVersion << ")\n\n"
        << "Core Connection:\n"
        << "  --server <host>          Server address\n"
        << "  --config <path>          Configuration file\n"
        << "  -i, --auth <path>        Identity key file path\n\n"
        << "Traffic Modes:\n"
        << "  --socks <port>           Start SOCKS5 proxy\n"
        << "  --lport <port> --rhost <host> --rport <port>\n"
        << "                           Local TCP forward\n"
        << "  -L [bind:]lport:host:port\n"
        << "                           SSH-style local forward\n"
        << "  -R [bind:]rport:host:port\n"
        << "                           SSH-style reverse forward\n"
        << "  --run, -c, --cmd <cmd>   Run command via YUME proxy\n"
        << "  --control [id]           Control mode for a registered client\n"
        << "  --list-controlled        List controlled clients\n\n"
        << "Relay and Identity:\n"
        << "  --name <slug>            Preferred display name\n"
        << "  --client-id <32hex>      Preferred endpoint ID\n"
        << "  --relay-mode <mode>      untrusted or trusted\n"
        << "  --allow-inbound-admin    Allow trusted peers to admin-attach\n"
        << "  --deny-inbound-admin     Deny inbound admin attach\n"
        << "  --allow-outbound-admin   Allow this client to admin-attach peers\n"
        << "  --deny-outbound-admin    Deny outbound admin attach\n"
        << "  --allow-chat / --deny-chat\n"
        << "                           Allow or deny relay chat\n"
        << "  --allow-file / --deny-file\n"
        << "                           Allow or deny relay file transfer\n"
        << "  --allow-bytes / --deny-bytes\n"
        << "                           Allow or deny raw byte relay\n"
        << "  --directory              List visible relay endpoints and exit\n"
        << "  --chat <id|name>         Open a chat invite\n"
        << "  --send-file <id|name> <path>\n"
        << "                           Send a file through relay\n"
        << "  --send-bytes <id|name> <path>\n"
        << "                           Send raw bytes through relay\n"
        << "  --admin-attach <id|name> Open trusted runtime admin channel\n"
        << "  --server-attach <id>     Alias for trusted admin attach\n\n"
        << "Runtime and Local Attach:\n"
        << "  --port <n>               Server port (forced to 443)\n"
        << "  --threads <n>            IO threads (0 = auto)\n"
        << "  --instance <name>        Stable local runtime instance key\n"
        << "  --attach-local           Attach to an already running local yume\n"
        << "  --history-dir <path>     Encrypted local chat history directory\n"
        << "  --no-history             Disable local chat history\n"
        << "  --udp                    Enable UDP forwarding\n"
        << "  --tcp                    Force TCP only\n"
        << "  --allow-local-ip         Allow private/loopback destination IPs\n"
        << "  --run-ipv4               Prefer IPv4 for --run\n"
        << "  --proxycmd               Internal SSH ProxyCommand helper\n"
        << "  --accept-monitoring      Accept monitoring prompt\n"
        << "  --save-server            Save server to config\n"
        << "  --non-interactive        Disable live status line updates\n"
        << "  --live-status            Enable periodic live hop status updates\n"
        << "  --boring                 Minimal output (no emojis)\n\n"
        << "Service Launch:\n"
        << "  --                        Treat launch as non-interactive (systemd/service-safe)\n\n"
        << "Attached / Interactive Console:\n"
        << "  help                     Show commands\n"
        << "  whoami                   Show current relay identity\n"
        << "  status                   Print current runtime status\n"
        << "  directory                List visible relay endpoints\n"
        << "  invites                  List pending invites\n"
        << "  chat <peer>              Open chat invite\n"
        << "  send <text>              Send chat message on active chat\n"
        << "  send-file <peer> <path>  Send file invite and data\n"
        << "  send-bytes <peer> <path> Send raw bytes invite and data\n"
        << "  accept <invite> <pass>   Accept relay invite\n"
        << "  reject <invite> [why]    Reject relay invite\n"
        << "  history [peer]           Show local encrypted history\n"
        << "  history-delete <peer|all>\n"
        << "                           Delete local history\n"
        << "  admin attach <peer>      Open trusted runtime admin channel\n"
        << "  admin status             Query remote runtime status\n"
        << "  admin sessions           Query remote runtime sessions\n"
        << "  admin stop               Stop remote runtime\n"
        << "  exec <command>           Legacy EXEC compatibility path\n"
        << "  quit                     Stop client cleanly\n"
        << "  env YUME_COMMAND_CONSOLE=0 to disable console\n"
        << "  env YUME_LIVE_STATUS=1 to re-enable live status redraw\n\n"
        << "Security:\n"
        << "  --inner                  Enable inner PQ encryption\n"
        << "  --inner-heavy            Heavy KDF mode (default)\n"
        << "  --inner-light            Light KDF mode\n"
        << "  --hop / --no-hop         Inner key hopping on/off\n"
        << "  --hop-interval <ms>      Hop interval (250-1000 recommended)\n"
        << "  --pq-pub <path>          PQ public key path\n"
        << "  --use-embedded-master    Allow embedded BaseFWX master PQ key fallback\n"
        << "  --no-embedded-master     Disable embedded BaseFWX master fallback\n"
        << "  --require-anonym         Require at least one trusted anonym proof source\n"
        << "  --anonym-ca-cert <path>  CA certificate for anonym proof verification\n"
        << "  --tls-ca <path>          Custom CA for TLS verification\n"
        << "  --tls-pin <sha256>       Pin server TLS certificate fingerprint\n\n"
        << "TLS Stealth:\n"
        << "  --profile <name>         chrome (default), firefox, safari\n"
        << "  --no-stealth             Disable TLS stealth mode\n"
        << "  --tls-stealth-rotate     Rotate stealth profiles\n"
        << "  --tls-stealth-rotation-interval <n>\n"
        << "                           Rotation interval in connections\n"
        << "  --tls-fingerprint-log    Log TLS fingerprint metrics\n"
        << "  --tls-fingerprint-log-path <path>\n"
        << "                           Fingerprint log path\n"
        << "  --tls-fingerprint-verify Verify fingerprints against test endpoint\n"
        << "  --tls-fingerprint-test-endpoint <host>\n"
        << "                           Test endpoint for fingerprint verification\n\n"
        << "Completion:\n"
        << "  completion bash\n"
        << "  --completion bash\n\n"
        << "Compatibility:\n"
        << "  --control / --list-controlled / --exec stay available for one release cycle\n\n"
        << "Other:\n"
        << "  -h, --help               Show this help message\n"
        << "  --version                Show version information\n";
}

bool parse_ssh_forward(const std::string& spec, int& lport, std::string& host, int& rport) {
    if (spec.empty()) {
        return false;
    }
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t pos = spec.find(':', start);
        if (pos == std::string::npos) {
            parts.push_back(spec.substr(start));
            break;
        }
        parts.push_back(spec.substr(start, pos - start));
        start = pos + 1;
    }
    if (parts.size() != 3 && parts.size() != 4) {
        return false;
    }
    size_t idx = parts.size() == 4 ? 1 : 0;
    try {
        lport = std::stoi(parts[idx]);
    } catch (...) {
        return false;
    }
    host = parts[idx + 1];
    try {
        rport = std::stoi(parts[idx + 2]);
    } catch (...) {
        return false;
    }
    return lport > 0 && rport > 0 && !host.empty();
}

int resolve_io_threads(int requested) {
    if (requested > 0) {
        return requested;
    }
    unsigned int hw = std::thread::hardware_concurrency();
    return hw > 0 ? static_cast<int>(hw) : 1;
}

bool parse_env_bool(const char* name, bool fallback) {
    const char* raw = std::getenv(name);
    if (!raw || !*raw) {
        return fallback;
    }
    std::string value(raw);
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (value == "1" || value == "true" || value == "yes" || value == "on") {
        return true;
    }
    if (value == "0" || value == "false" || value == "no" || value == "off") {
        return false;
    }
    return fallback;
}

bool is_tty_stdin() {
#if defined(_WIN32)
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(fileno(stdin)) != 0;
#endif
}

bool read_stdin_line_with_timeout(std::string* out, int timeout_ms) {
    if (!out) {
        return false;
    }
#if defined(_WIN32)
    (void)timeout_ms;
    return false;
#else
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = static_cast<suseconds_t>((timeout_ms % 1000) * 1000);
    int rc = select(STDIN_FILENO + 1, &rfds, nullptr, nullptr, &tv);
    if (rc <= 0 || !FD_ISSET(STDIN_FILENO, &rfds)) {
        return false;
    }
    return static_cast<bool>(std::getline(std::cin, *out));
#endif
}

void run_io_threads(boost::asio::io_context& io, int requested) {
    // We run the io_context in small synchronous bursts earlier (connect/handshake/probes),
    // which leaves it in the "stopped" state. Restart before running the main event loop.
    io.restart();
    int threads = resolve_io_threads(requested);
    std::vector<std::thread> workers;
    if (threads > 1) {
        workers.reserve(static_cast<size_t>(threads - 1));
    }
    for (int i = 1; i < threads; ++i) {
        workers.emplace_back([&io]() { io.run(); });
    }
    io.run();
    for (auto& t : workers) {
        t.join();
    }
}

std::string trim_copy(std::string s) {
    auto is_space = [](unsigned char ch) { return std::isspace(ch) != 0; };
    while (!s.empty() && is_space(static_cast<unsigned char>(s.front()))) {
        s.erase(s.begin());
    }
    while (!s.empty() && is_space(static_cast<unsigned char>(s.back()))) {
        s.pop_back();
    }
    return s;
}

bool prompt_attach_existing(const std::string& kind) {
    if (!is_tty_stdin()) {
        return true;
    }
    util::clear_status_line();
    std::cout << kind << " is already running. Attach to the existing instance? [Y/n] " << std::flush;
    std::string answer;
    if (!std::getline(std::cin, answer)) {
        return true;
    }
    answer = trim_copy(answer);
    if (answer.empty()) {
        return true;
    }
    std::transform(answer.begin(), answer.end(), answer.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return answer == "y" || answer == "yes";
}

std::string effective_client_instance_key(const ClientConfig& cfg, const ParsedArgs& args) {
    if (!cfg.instance_name.empty()) {
        return cfg.instance_name;
    }
    return yume::identity::derive_instance_key(
        cfg.server + "|" + std::to_string(cfg.port) + "|" + cfg.identity + "|" + args.config_path);
}

void print_local_client_attach_help() {
    util::log_info("Attached console: help | whoami | status | directory | invites | chat <peer> | send <text> | send-file <peer> <path> | send-bytes <peer> <path> | accept <invite> <password> | reject <invite> [reason] | history [peer] | history-delete <peer|all> | admin attach <peer> | admin status | admin sessions | admin stop | quit");
}

nlohmann::json request_local_client_runtime(const std::string& socket_path,
                                           const std::string& op,
                                           const nlohmann::json& args,
                                           std::string* error) {
    return yume::client::LocalRuntime::request(
        socket_path,
        nlohmann::json{{"op", op}, {"args", args}},
        error,
        10000);
}

int run_local_client_attach(const std::string& socket_path, const ParsedArgs& args, const ClientConfig& cfg) {
    const char* env_pw = std::getenv("YUME_RELAY_PASSWORD");
    const std::string relay_password = env_pw ? env_pw : "";
    std::string error;

    if (args.directory_mode) {
        auto resp = request_local_client_runtime(socket_path, "directory.list", nlohmann::json::object(), &error);
        if (!error.empty() || !resp.value("ok", false)) {
            util::log_error(error.empty() ? resp.value("error", "directory request failed") : error);
            return 1;
        }
        for (const auto& entry : resp["result"]) {
            std::cout << entry.value("endpoint_id", "")
                      << " " << entry.value("display_name", "")
                      << " kind=" << entry.value("endpoint_kind", "")
                      << " relay=" << entry.value("relay_mode", "")
                      << "\n";
        }
        return 0;
    }
    if (!args.chat_target.empty()) {
        auto resp = request_local_client_runtime(socket_path, "chat.open",
                                                 {{"peer", args.chat_target}, {"password", relay_password}}, &error);
        if (!error.empty() || !resp.value("ok", false)) {
            util::log_error(error.empty() ? resp.value("error", "chat open failed") : error);
            return 1;
        }
        return 0;
    }
    if (!args.file_target.empty()) {
        auto resp = request_local_client_runtime(socket_path, "file.send",
                                                 {{"peer", args.file_target}, {"path", args.file_path}, {"password", relay_password}}, &error);
        if (!error.empty() || !resp.value("ok", false)) {
            util::log_error(error.empty() ? resp.value("error", "file send failed") : error);
            return 1;
        }
        return 0;
    }
    if (!args.bytes_target.empty()) {
        auto resp = request_local_client_runtime(socket_path, "bytes.send",
                                                 {{"peer", args.bytes_target}, {"path", args.bytes_path}, {"password", relay_password}}, &error);
        if (!error.empty() || !resp.value("ok", false)) {
            util::log_error(error.empty() ? resp.value("error", "bytes send failed") : error);
            return 1;
        }
        return 0;
    }
    if (!args.admin_target.empty()) {
        auto resp = request_local_client_runtime(socket_path, "admin.attach",
                                                 {{"peer", args.admin_target}}, &error);
        if (!error.empty() || !resp.value("ok", false)) {
            util::log_error(error.empty() ? resp.value("error", "admin attach failed") : error);
            return 1;
        }
        return 0;
    }

    if (cfg.non_interactive || !is_tty_stdin()) {
        auto resp = request_local_client_runtime(socket_path, "runtime.status", nlohmann::json::object(), &error);
        if (!error.empty() || !resp.value("ok", false)) {
            util::log_error(error.empty() ? resp.value("error", "status failed") : error);
            return 1;
        }
        std::cout << resp["result"].dump(2) << std::endl;
        return 0;
    }

    util::log_info("Attached to existing yume runtime");
    print_local_client_attach_help();
    for (;;) {
        std::string line;
        if (!std::getline(std::cin, line)) {
            return 0;
        }
        line = trim_copy(line);
        if (line.empty()) {
            continue;
        }
        if (line == "help") {
            print_local_client_attach_help();
            continue;
        }
        if (line == "quit" || line == "exit") {
            return 0;
        }
        if (line == "whoami") {
            auto resp = request_local_client_runtime(socket_path, "runtime.info", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "runtime info failed") : error);
                error.clear();
                continue;
            }
            std::cout << resp["result"].dump(2) << std::endl;
            continue;
        }
        if (line == "status") {
            auto resp = request_local_client_runtime(socket_path, "runtime.status", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "status failed") : error);
                error.clear();
                continue;
            }
            std::cout << resp["result"].dump(2) << std::endl;
            continue;
        }
        if (line == "directory") {
            auto resp = request_local_client_runtime(socket_path, "directory.list", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "directory failed") : error);
                error.clear();
                continue;
            }
            for (const auto& entry : resp["result"]) {
                std::cout << entry.value("endpoint_id", "") << " "
                          << entry.value("display_name", "")
                          << " kind=" << entry.value("endpoint_kind", "")
                          << " relay=" << entry.value("relay_mode", "")
                          << std::endl;
            }
            continue;
        }
        if (line == "invites") {
            auto resp = request_local_client_runtime(socket_path, "invite.list", nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "invite list failed") : error);
                error.clear();
                continue;
            }
            for (const auto& invite : resp["result"]) {
                std::cout << invite.value("invite_id", "") << " from="
                          << (invite.value("from_display_name", "").empty()
                                  ? invite.value("from_endpoint_id", "")
                                  : invite.value("from_display_name", ""))
                          << " kind=" << invite.value("channel_kind", "")
                          << std::endl;
            }
            continue;
        }
        if (line.rfind("chat ", 0) == 0) {
            auto resp = request_local_client_runtime(socket_path, "chat.open",
                                                     {{"peer", trim_copy(line.substr(5))}, {"password", relay_password}}, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "chat open failed") : error);
                error.clear();
            }
            continue;
        }
        if (line.rfind("send-file ", 0) == 0) {
            std::istringstream iss(line.substr(10));
            std::string peer;
            std::string path;
            iss >> peer >> path;
            auto resp = request_local_client_runtime(socket_path, "file.send",
                                                     {{"peer", peer}, {"path", path}, {"password", relay_password}}, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "file send failed") : error);
                error.clear();
            }
            continue;
        }
        if (line.rfind("send-bytes ", 0) == 0) {
            std::istringstream iss(line.substr(11));
            std::string peer;
            std::string path;
            iss >> peer >> path;
            auto resp = request_local_client_runtime(socket_path, "bytes.send",
                                                     {{"peer", peer}, {"path", path}, {"password", relay_password}}, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "bytes send failed") : error);
                error.clear();
            }
            continue;
        }
        if (line.rfind("send ", 0) == 0) {
            auto resp = request_local_client_runtime(socket_path, "chat.send",
                                                     {{"text", trim_copy(line.substr(5))}}, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "chat send failed") : error);
                error.clear();
            }
            continue;
        }
        if (line.rfind("accept ", 0) == 0) {
            std::istringstream iss(line.substr(7));
            std::string invite_id;
            std::string password;
            iss >> invite_id >> password;
            auto resp = request_local_client_runtime(socket_path, "invite.accept",
                                                     {{"invite_id", invite_id}, {"password", password}}, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "invite accept failed") : error);
                error.clear();
            }
            continue;
        }
        if (line.rfind("reject ", 0) == 0) {
            std::istringstream iss(line.substr(7));
            std::string invite_id;
            iss >> invite_id;
            std::string reason;
            std::getline(iss, reason);
            auto resp = request_local_client_runtime(socket_path, "invite.reject",
                                                     {{"invite_id", invite_id}, {"reason", trim_copy(reason)}}, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "invite reject failed") : error);
                error.clear();
            }
            continue;
        }
        if (line.rfind("history-delete ", 0) == 0) {
            std::string arg = trim_copy(line.substr(15));
            nlohmann::json req_args = nlohmann::json::object();
            if (arg != "all" && !arg.empty()) {
                req_args["peer_id"] = arg;
            }
            auto resp = request_local_client_runtime(socket_path, "history.delete", req_args, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "history delete failed") : error);
                error.clear();
            }
            continue;
        }
        if (line.rfind("history", 0) == 0) {
            std::string arg = trim_copy(line.substr(7));
            nlohmann::json req_args = nlohmann::json::object();
            if (!arg.empty()) {
                req_args["peer_id"] = arg;
            }
            auto resp = request_local_client_runtime(socket_path, "history.list", req_args, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "history failed") : error);
                error.clear();
                continue;
            }
            for (const auto& item : resp["result"]) {
                std::cout << item.value("direction", "?") << " "
                          << item.value("peer_name", item.value("peer_id", ""))
                          << " " << item.value("text", "") << std::endl;
            }
            continue;
        }
        if (line.rfind("admin attach ", 0) == 0) {
            auto resp = request_local_client_runtime(socket_path, "admin.attach",
                                                     {{"peer", trim_copy(line.substr(13))}}, &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "admin attach failed") : error);
                error.clear();
            }
            continue;
        }
        if (line == "admin status" || line == "admin sessions" || line == "admin stop") {
            const std::string op =
                (line == "admin stop") ? "admin.stop" :
                ((line == "admin sessions") ? "admin.sessions" : "admin.status");
            auto resp = request_local_client_runtime(socket_path, op, nlohmann::json::object(), &error);
            if (!error.empty() || !resp.value("ok", false)) {
                util::log_warn(error.empty() ? resp.value("error", "admin request failed") : error);
                error.clear();
                continue;
            }
            std::cout << resp["result"].dump(2) << std::endl;
            continue;
        }
        util::log_warn("unknown command: " + line);
    }
}

std::vector<std::thread> start_io_threads(boost::asio::io_context& io, int requested) {
    io.restart();
    int threads = resolve_io_threads(requested);
    std::vector<std::thread> workers;
    workers.reserve(static_cast<size_t>(threads));
    for (int i = 0; i < threads; ++i) {
        workers.emplace_back([&io]() { io.run(); });
    }
    return workers;
}

class IoThreadGroup {
public:
    IoThreadGroup(boost::asio::io_context& io, std::vector<std::thread>&& workers)
        : io_(io)
        , workers_(std::move(workers)) {}

    ~IoThreadGroup() {
        stop_and_wait();
    }

    void wait() {
        if (joined_) {
            return;
        }
        for (auto& worker : workers_) {
            if (worker.joinable()) {
                worker.join();
            }
        }
        joined_ = true;
    }

    void stop_and_wait() {
        if (joined_) {
            return;
        }
        io_.stop();
        wait();
    }

private:
    boost::asio::io_context& io_;
    std::vector<std::thread> workers_;
    bool joined_{false};
};

}  // namespace

int Cli::run(int argc, char** argv) {
    util::init_logging();

    ParsedArgs args = parse_args(argc, argv);
    if (!args.parse_error.empty()) {
        util::log_error(args.parse_error);
        return 1;
    }
    if (args.completion) {
        if (args.completion_shell == "bash") {
            print_bash_completion();
            return 0;
        }
        util::log_error("unsupported completion shell: " + args.completion_shell);
        return 1;
    }
    if (args.proxycmd) {
        int socks_port = args.socks_port > 0 ? args.socks_port : 1080;
        return run_proxycmd(args.dest_host, args.dest_port, socks_port);
    }
    if (args.help) {
        print_help();
        return 0;
    }
    if (args.version) {
        print_version();
        return 0;
    }
    std::string cli_cwd;
    {
        std::error_code ec;
        auto cwd = std::filesystem::current_path(ec);
        if (!ec) {
            cli_cwd = cwd.string();
        }
    }
    auto resolve_cli_path = [&](const std::string& value) {
        return util::resolve_path(value, cli_cwd, "");
    };
    std::string exe_dir;
    {
        std::string self_path = get_self_path(argv[0]);
        if (!self_path.empty()) {
            exe_dir = std::filesystem::path(self_path).parent_path().string();
        }
    }
    std::string config_dir;
    args.config_path = util::expand_user(args.config_path);
    if (!args.config_specified && !exe_dir.empty()) {
        std::filesystem::path cfg_path(args.config_path);
        if (!std::filesystem::exists(cfg_path)) {
            std::filesystem::path cand = std::filesystem::path(exe_dir) / cfg_path;
            if (std::filesystem::exists(cand)) {
                args.config_path = cand.string();
            }
        }
    }
    ClientConfig cfg;
    if (file_exists(kDefaultAnonymCaCertPath)) {
        cfg.anonym_ca_cert = kDefaultAnonymCaCertPath;
    }

    int reverse_listen_port = 0;
    std::string reverse_host;
    int reverse_port = 0;
    bool use_reverse = false;
    bool reverse_server_in_charge_auto = false;
    bool reverse_server_in_charge_manual = false;
    int reverse_auto_min_port = yume::policy::kReversePortMinDefault;
    int reverse_auto_max_port = yume::policy::kReversePortMaxDefault;
    if (!args.ssh_R.empty()) {
        if (!parse_ssh_forward(args.ssh_R, reverse_listen_port, reverse_host, reverse_port)) {
            util::log_error("invalid -R syntax (expected [bind:]rport:host:port)");
            return 1;
        }
        use_reverse = true;
    }
    if (!args.ssh_L.empty()) {
        int lport = 0;
        int rport = 0;
        std::string host;
        if (!parse_ssh_forward(args.ssh_L, lport, host, rport)) {
            util::log_error("invalid -L syntax (expected [bind:]lport:host:port)");
            return 1;
        }
        args.lport = lport;
        args.rhost = host;
        args.rport = rport;
    }

    if (args.config_specified || std::filesystem::exists(args.config_path)) {
        try {
            std::error_code ec;
            auto cfg_abs = std::filesystem::absolute(args.config_path, ec);
            if (!ec) {
                config_dir = cfg_abs.parent_path().string();
            } else {
                config_dir = std::filesystem::path(args.config_path).parent_path().string();
            }
            auto resolve_cfg_path = [&](const std::string& value) {
                return util::resolve_path(value, config_dir, exe_dir);
            };
            auto json = util::read_json_config(args.config_path);
            if (json.contains("server") && cfg.server.empty()) {
                cfg.server = json["server"].get<std::string>();
            }
            if (json.contains("port") && cfg.port == 443) {
                cfg.port = json["port"].get<int>();
            }
            if (json.contains("identity") && cfg.identity.empty()) {
                cfg.identity = resolve_cfg_path(json["identity"].get<std::string>());
            }
            if (json.contains("socks_port") && cfg.socks_port == 0) {
                cfg.socks_port = json["socks_port"].get<int>();
            }
            if (json.contains("threads") && cfg.io_threads == 0 && !args.io_threads_override) {
                cfg.io_threads = json["threads"].get<int>();
            }
            if (json.contains("obfuscation") && !cfg.obfuscation) {
                cfg.obfuscation = json["obfuscation"].get<bool>();
            }
            if (json.contains("inner_crypto")) {
                cfg.inner_crypto = json["inner_crypto"].get<bool>();
            }
            if (json.contains("inner_heavy")) {
                cfg.inner_heavy = json["inner_heavy"].get<bool>();
            }
            if (json.contains("inner_hop")) {
                cfg.inner_hop = json["inner_hop"].get<bool>();
            }
            if (json.contains("hop_interval_ms")) {
                cfg.hop_interval_ms = static_cast<std::uint32_t>(json["hop_interval_ms"].get<int>());
            }
            if (json.contains("udp") && !args.udp_override) {
                cfg.allow_udp = json["udp"].get<bool>();
            }
            if (json.contains("allow_local_ip") && !args.allow_local_ip_override) {
                cfg.allow_local_ip = json["allow_local_ip"].get<bool>();
            }
            if (json.contains("server_in_charge") && !args.server_in_charge_override) {
                cfg.server_in_charge = json["server_in_charge"].get<bool>();
            }
            if (json.contains("server_in_charge_port") && !args.server_in_charge_port_override) {
                cfg.server_in_charge_port = json["server_in_charge_port"].get<int>();
            }
            if (json.contains("allow_exec") && !args.allow_exec_override) {
                cfg.allow_exec = json["allow_exec"].get<bool>();
            }
            if (json.contains("pq_public_key") && cfg.pq_public_key.empty()) {
                cfg.pq_public_key = resolve_cfg_path(json["pq_public_key"].get<std::string>());
            }
            if (json.contains("use_embedded_master") && !args.allow_embedded_master_override) {
                cfg.allow_embedded_master = json["use_embedded_master"].get<bool>();
            }
            if (json.contains("anonym_pubkey") && cfg.anonym_pubkey.empty()) {
                cfg.anonym_pubkey = resolve_cfg_path(json["anonym_pubkey"].get<std::string>());
            }
            if (json.contains("anonym_ca_cert")) {
                cfg.anonym_ca_cert = resolve_cfg_path(json["anonym_ca_cert"].get<std::string>());
            }
            if (json.contains("tls_ca_cert") && cfg.tls_ca_cert.empty()) {
                cfg.tls_ca_cert = resolve_cfg_path(json["tls_ca_cert"].get<std::string>());
            }
            if (json.contains("tls_pin") && cfg.tls_pin_sha256.empty()) {
                cfg.tls_pin_sha256 = json["tls_pin"].get<std::string>();
            }
            if (json.contains("require_anonym")) {
                cfg.require_anonym = json["require_anonym"].get<bool>();
            }
            if (json.contains("boring") && !args.boring_override) {
                cfg.boring = json["boring"].get<bool>();
            }
            if (json.contains("non_interactive")) {
                cfg.non_interactive = json["non_interactive"].get<bool>();
            }
            if (json.contains("instance_name") && cfg.instance_name.empty()) {
                cfg.instance_name = json["instance_name"].get<std::string>();
            }
            if (json.contains("preferred_name") && cfg.preferred_name.empty()) {
                cfg.preferred_name = json["preferred_name"].get<std::string>();
            }
            if (json.contains("preferred_id") && cfg.preferred_id.empty()) {
                cfg.preferred_id = json["preferred_id"].get<std::string>();
            }
            if (json.contains("relay_mode")) {
                cfg.relay_mode = json["relay_mode"].get<std::string>();
            }
            if (json.contains("allow_inbound_admin") && !args.allow_inbound_admin_override) {
                cfg.allow_inbound_admin = json["allow_inbound_admin"].get<bool>();
            }
            if (json.contains("allow_outbound_admin") && !args.allow_outbound_admin_override) {
                cfg.allow_outbound_admin = json["allow_outbound_admin"].get<bool>();
            }
            if (json.contains("allow_chat") && !args.allow_chat_override) {
                cfg.allow_chat = json["allow_chat"].get<bool>();
            }
            if (json.contains("allow_file") && !args.allow_file_override) {
                cfg.allow_file = json["allow_file"].get<bool>();
            }
            if (json.contains("allow_bytes") && !args.allow_bytes_override) {
                cfg.allow_bytes = json["allow_bytes"].get<bool>();
            }
            if (json.contains("history_enabled") && !args.history_override) {
                cfg.history_enabled = json["history_enabled"].get<bool>();
            }
            if (json.contains("history_dir") && cfg.history_dir.empty()) {
                cfg.history_dir = resolve_cfg_path(json["history_dir"].get<std::string>());
            }
            if (json.contains("auto_attach_local")) {
                cfg.auto_attach_local = json["auto_attach_local"].get<bool>();
            }
        } catch (const std::exception& ex) {
            util::log_warn(std::string("config load failed: ") + ex.what());
        }
    }

    if (!args.server.empty()) {
        cfg.server = args.server;
    }
    if (args.port > 0) {
        cfg.port = args.port;
    }
    if (!args.identity.empty()) {
        cfg.identity = resolve_cli_path(args.identity);
    }
    if (args.socks_port > 0) {
        cfg.socks_port = args.socks_port;
    }
    if (args.io_threads != 0 || args.io_threads_override) {
        cfg.io_threads = args.io_threads;
    }
    if (args.inner_crypto) {
        cfg.inner_crypto = true;
    }
    if (args.inner_crypto) {
        cfg.inner_heavy = args.inner_heavy;
    }
    if (args.inner_hop_override) {
        cfg.inner_hop = args.inner_hop;
    }
    if (args.hop_interval_override) {
        cfg.hop_interval_ms = args.hop_interval_ms;
    }
    if (!args.pq_public_key.empty()) {
        cfg.pq_public_key = resolve_cli_path(args.pq_public_key);
    }
    if (args.allow_embedded_master_override) {
        cfg.allow_embedded_master = args.allow_embedded_master;
    }
    if (!args.anonym_ca_cert.empty()) {
        cfg.anonym_ca_cert = resolve_cli_path(args.anonym_ca_cert);
    }
    if (!args.tls_ca_cert.empty()) {
        cfg.tls_ca_cert = resolve_cli_path(args.tls_ca_cert);
    }
    if (!args.tls_pin_sha256.empty()) {
        cfg.tls_pin_sha256 = args.tls_pin_sha256;
    }
    if (args.require_anonym) {
        cfg.require_anonym = true;
    }
    if (args.udp_override) {
        cfg.allow_udp = args.use_udp;
    }
    if (args.allow_local_ip_override) {
        cfg.allow_local_ip = args.allow_local_ip;
    }
    if (args.server_in_charge_override) {
        cfg.server_in_charge = args.server_in_charge;
    }
    if (args.server_in_charge_port_override) {
        cfg.server_in_charge_port = args.server_in_charge_port;
    }
    if (!args.preferred_name.empty()) {
        cfg.preferred_name = args.preferred_name;
    }
    if (!args.preferred_id.empty()) {
        cfg.preferred_id = args.preferred_id;
    }
    if (!args.relay_mode.empty()) {
        cfg.relay_mode = args.relay_mode;
    }
    if (args.allow_inbound_admin_override) {
        cfg.allow_inbound_admin = args.allow_inbound_admin;
    }
    if (args.allow_outbound_admin_override) {
        cfg.allow_outbound_admin = args.allow_outbound_admin;
    }
    if (args.allow_chat_override) {
        cfg.allow_chat = args.allow_chat;
    }
    if (args.allow_file_override) {
        cfg.allow_file = args.allow_file;
    }
    if (args.allow_bytes_override) {
        cfg.allow_bytes = args.allow_bytes;
    }
    if (!args.history_dir.empty()) {
        cfg.history_dir = resolve_cli_path(args.history_dir);
    }
    if (args.history_override) {
        cfg.history_enabled = args.history_enabled;
    }
    if (!args.instance_name.empty()) {
        cfg.instance_name = args.instance_name;
    }
    if (args.allow_exec_override) {
        cfg.allow_exec = args.allow_exec;
    }
    if (args.boring_override) {
        cfg.boring = args.boring;
    }
    if (args.non_interactive) {
        cfg.non_interactive = true;
    }
    if (args.tls_stealth_override) {
        cfg.tls_stealth_enabled = args.tls_stealth;
    }
    if (!args.tls_stealth_profile.empty()) {
        cfg.tls_stealth_profile = args.tls_stealth_profile;
    }
    if (args.tls_stealth_rotate) {
        cfg.tls_stealth_rotate = true;
    }
    if (args.tls_stealth_rotation_interval > 0) {
        cfg.tls_stealth_rotation_interval = args.tls_stealth_rotation_interval;
    }
    if (args.tls_fingerprint_log) {
        cfg.tls_fingerprint_log = true;
    }
    if (!args.tls_fingerprint_log_path.empty()) {
        cfg.tls_fingerprint_log_path = args.tls_fingerprint_log_path;
    }
    if (args.tls_fingerprint_verify) {
        cfg.tls_fingerprint_verify = true;
    }
    if (!args.tls_fingerprint_test_endpoint.empty()) {
        cfg.tls_fingerprint_test_endpoint = args.tls_fingerprint_test_endpoint;
    }
#if defined(_WIN32) || defined(__APPLE__)
    if (cfg.tls_ca_cert.empty() && !cfg.anonym_ca_cert.empty()) {
        cfg.tls_ca_cert = cfg.anonym_ca_cert;
    }
#endif
    if (cfg.inner_hop && !cfg.inner_crypto) {
        cfg.inner_crypto = true;
    }
    if (!cfg.inner_crypto) {
        cfg.inner_hop = false;
    }
    if (cfg.hop_interval_ms > 0) {
        if (cfg.hop_interval_ms < 250) {
            cfg.hop_interval_ms = 250;
        } else if (cfg.hop_interval_ms > 1000) {
            cfg.hop_interval_ms = 1000;
        }
    }
    if (!use_reverse && cfg.server_in_charge) {
        reverse_server_in_charge_auto = true;
        reverse_host = "127.0.0.1";
        reverse_port = 22;
        use_reverse = true;
        if (args.server_in_charge_min_port > 0) {
            reverse_auto_min_port = args.server_in_charge_min_port;
        }
        if (args.server_in_charge_max_port > 0) {
            reverse_auto_max_port = args.server_in_charge_max_port;
        }
        reverse_auto_min_port = std::clamp(reverse_auto_min_port, 1, 65535);
        reverse_auto_max_port = std::clamp(reverse_auto_max_port, 1, 65535);
        if (reverse_auto_min_port > reverse_auto_max_port) {
            std::swap(reverse_auto_min_port, reverse_auto_max_port);
        }
        if (cfg.server_in_charge_port > 0) {
            if (cfg.server_in_charge_port < yume::policy::kServerInChargeManualMinPort ||
                cfg.server_in_charge_port > yume::policy::kServerInChargeManualMaxPort) {
                util::log_error("--server-in-charge port must be " +
                                std::to_string(yume::policy::kServerInChargeManualMinPort) + "-" +
                                std::to_string(yume::policy::kServerInChargeManualMaxPort));
                return 1;
            }
            reverse_server_in_charge_manual = true;
            reverse_listen_port = cfg.server_in_charge_port;
        } else {
            reverse_listen_port = 0;
        }
    }
    if (cfg.history_dir.empty()) {
        const char* xdg = std::getenv("XDG_CONFIG_HOME");
        const char* home = std::getenv("HOME");
        std::filesystem::path base = (xdg && *xdg)
            ? std::filesystem::path(xdg)
            : ((home && *home) ? (std::filesystem::path(home) / ".config") : std::filesystem::path("."));
        cfg.history_dir = (base / "yume" / "history").string();
    }
    if (cfg.relay_mode != "trusted") {
        cfg.relay_mode = "untrusted";
    }
    const bool live_status_enabled =
        !cfg.non_interactive &&
        (args.live_status || parse_env_bool("YUME_LIVE_STATUS", false));
    util::set_status_enabled(live_status_enabled);
    if (!require_file("identity", cfg.identity)) {
        return 1;
    }
    if (!require_file("tls_ca_cert", cfg.tls_ca_cert)) {
        return 1;
    }
    if (!require_file("anonym_ca_cert", cfg.anonym_ca_cert)) {
        return 1;
    }
    if (!require_file("anonym_pubkey", cfg.anonym_pubkey)) {
        return 1;
    }
    if (!require_file("pq_public_key", cfg.pq_public_key)) {
        return 1;
    }
    if ((args.control_mode || args.list_controlled) && args.server.empty()) {
        cfg.server = "127.0.0.1";
    }
    const bool has_active_mode =
        (!args.run_cmd.empty()) ||
        (args.lport > 0) ||
        (cfg.socks_port > 0) ||
        use_reverse ||
        args.control_mode ||
        args.list_controlled ||
        args.directory_mode ||
        !args.chat_target.empty() ||
        !args.file_target.empty() ||
        !args.bytes_target.empty() ||
        !args.admin_target.empty() ||
        args.attach_local;
    if (!has_active_mode) {
        util::log_error("no mode selected (use --socks, -R, --lport/--rhost/--rport, --run, --directory, --chat, --send-file, --send-bytes, or --server-in-charge)");
        return 1;
    }

    if (cfg.inner_crypto && cfg.pq_public_key.empty()) {
        std::error_code ec;
        std::filesystem::path runtime_dir = std::filesystem::current_path(ec);
        std::filesystem::path exe_dir;
        std::filesystem::path user_cfg_dir;
        std::string self_path = get_self_path(argv[0]);
        if (!self_path.empty()) {
            exe_dir = std::filesystem::path(self_path).parent_path();
        }
        if (const char* home = std::getenv("HOME"); home && *home) {
            user_cfg_dir = std::filesystem::path(home) / ".config" / "yume";
        }
        auto try_set = [&](const std::filesystem::path& base) {
            if (!cfg.pq_public_key.empty() || base.empty()) {
                return;
            }
            std::filesystem::path cand = base / "pq_public.key";
            if (file_exists(cand.string())) {
                cfg.pq_public_key = cand.string();
            }
        };
        try_set(user_cfg_dir);
        try_set(runtime_dir);
        try_set(exe_dir);
        if (!cfg.pq_public_key.empty()) {
            util::log_info("using discovered pq_public_key: " + cfg.pq_public_key);
        }
    }

    if (cfg.port != 443) {
        util::log_warn("forcing server port to 443 for HTTPS-only transport");
        cfg.port = 443;
    }

#if !YUME_USE_BASEFWX
    if (cfg.inner_crypto) {
        warn_security_disabled("PQ", cfg.boring);
        cfg.inner_crypto = false;
    }
#endif

    if (args.save_server && !cfg.server.empty()) {
        nlohmann::json json;
        std::ifstream in(args.config_path);
        if (in) {
            try { in >> json; } catch (...) { json = nlohmann::json::object(); }
        } else {
            json = nlohmann::json::object();
        }
        json["server"] = cfg.server;
        if (cfg.port > 0) json["port"] = cfg.port;
        if (!cfg.identity.empty()) json["identity"] = cfg.identity;
        if (cfg.socks_port > 0) json["socks_port"] = cfg.socks_port;
        if (cfg.io_threads != 0) json["threads"] = cfg.io_threads;
        json["inner_crypto"] = cfg.inner_crypto;
        json["inner_heavy"] = cfg.inner_heavy;
        json["inner_hop"] = cfg.inner_hop;
        json["hop_interval_ms"] = cfg.hop_interval_ms;
        json["udp"] = cfg.allow_udp;
        json["allow_local_ip"] = cfg.allow_local_ip;
        json["server_in_charge"] = cfg.server_in_charge;
        if (cfg.server_in_charge_port > 0) json["server_in_charge_port"] = cfg.server_in_charge_port;
        json["allow_exec"] = cfg.allow_exec;
        if (!cfg.pq_public_key.empty()) json["pq_public_key"] = cfg.pq_public_key;
        json["use_embedded_master"] = cfg.allow_embedded_master;
        if (!cfg.anonym_ca_cert.empty()) json["anonym_ca_cert"] = cfg.anonym_ca_cert;
        if (!cfg.tls_ca_cert.empty()) json["tls_ca_cert"] = cfg.tls_ca_cert;
        if (!cfg.tls_pin_sha256.empty()) json["tls_pin"] = cfg.tls_pin_sha256;
        json["require_anonym"] = cfg.require_anonym;
        json["boring"] = cfg.boring;
        json["non_interactive"] = cfg.non_interactive;
        json["instance_name"] = cfg.instance_name;
        json["preferred_name"] = cfg.preferred_name;
        json["preferred_id"] = cfg.preferred_id;
        json["relay_mode"] = cfg.relay_mode;
        json["allow_inbound_admin"] = cfg.allow_inbound_admin;
        json["allow_outbound_admin"] = cfg.allow_outbound_admin;
        json["allow_chat"] = cfg.allow_chat;
        json["allow_file"] = cfg.allow_file;
        json["allow_bytes"] = cfg.allow_bytes;
        json["history_enabled"] = cfg.history_enabled;
        if (!cfg.history_dir.empty()) json["history_dir"] = cfg.history_dir;
        json["auto_attach_local"] = cfg.auto_attach_local;
        std::ofstream out(args.config_path);
        if (out) {
            out << json.dump(2);
        }
    }

    if (args.exec_cmd.size() && !args.control_mode) {
        util::log_error("--exec requires --control");
        return 1;
    }
    if (args.control_mode && args.control_id.empty()) {
        util::log_error("--control requires --id");
        return 1;
    }
    if (cfg.server.empty() || cfg.identity.empty()) {
        util::log_error("--server and --auth (identity) are required");
        print_help();
        return 1;
    }
    const std::string local_instance_key = effective_client_instance_key(cfg, args);
    const std::string local_runtime_path = yume::client::LocalRuntime::socket_path_for(local_instance_key);
    const bool local_runtime_exists = yume::client::LocalRuntime::available(local_runtime_path);
    if (local_runtime_exists) {
        const bool interactive_attach =
            cfg.auto_attach_local && !cfg.non_interactive && is_tty_stdin() && prompt_attach_existing("yume");
        const bool should_attach = args.attach_local || interactive_attach;
        if (should_attach) {
            return run_local_client_attach(local_runtime_path, args, cfg);
        }
        util::log_error("yume is already running for this instance; use --attach-local to interact with it");
        return 1;
    } else if (args.attach_local) {
        util::log_error("no running yume instance was found for this configuration");
        return 1;
    }
    std::atomic<bool> stop_requested{false};
    std::atomic<bool> stop_announced{false};
    std::atomic<bool> force_stop_requested{false};
    std::mutex runtime_mu;
    boost::asio::io_context* active_io = nullptr;
    std::weak_ptr<Tunnel> active_tunnel;
    auto announce_stopping = [&]() {
        if (stop_announced.exchange(true)) {
            return;
        }
        util::clear_status_line();
        std::cerr << "[INFO] Stopping..." << std::endl;
    };
    auto set_active_runtime = [&](boost::asio::io_context* io_ptr, const std::shared_ptr<Tunnel>& tunnel_ptr) {
        std::lock_guard<std::mutex> lock(runtime_mu);
        active_io = io_ptr;
        active_tunnel = tunnel_ptr;
    };
    auto clear_active_runtime = [&]() {
        std::lock_guard<std::mutex> lock(runtime_mu);
        active_io = nullptr;
        active_tunnel.reset();
    };
    util::install_signal_handlers([&](int) {
        const bool already_requested = force_stop_requested.exchange(true);
        stop_requested.store(true);
        announce_stopping();
        boost::asio::io_context* io_ptr = nullptr;
        std::shared_ptr<Tunnel> tunnel_ptr;
        {
            std::lock_guard<std::mutex> lock(runtime_mu);
            io_ptr = active_io;
            tunnel_ptr = active_tunnel.lock();
        }
        if (tunnel_ptr) {
            tunnel_ptr->stop("interrupt");
        }
        if (io_ptr) {
            io_ptr->stop();
        }
        if (already_requested) {
            std::cerr << "[WARN] Force stop requested. Exiting immediately." << std::endl;
            std::_Exit(1);
        }
    });
    struct SignalHandlerResetGuard {
        ~SignalHandlerResetGuard() {
            util::install_signal_handlers({});
        }
    } signal_handler_reset_guard;
    int attempt = 0;
    bool pq_warned = false;
    bool pq_reconnect_used = false;
    bool verified_once = false;
    bool tls_fingerprint_verification_attempted = false;
    std::optional<tls_fingerprint::FingerprintData> verified_tls_fingerprint;
    for (;;) {
        if (stop_requested.load()) {
            announce_stopping();
            return 130;
        }
        bool summary_once = false;
        std::function<std::string()> status_block_builder;
        try {
            boost::asio::io_context io(resolve_io_threads(cfg.io_threads));
            set_active_runtime(&io, nullptr);
            struct ActiveRuntimeGuard {
                std::function<void()> cleanup;
                ~ActiveRuntimeGuard() {
                    if (cleanup) {
                        cleanup();
                    }
                }
            } active_runtime_guard{clear_active_runtime};
            
            // Initialize stealth mode if enabled
            std::unique_ptr<boost::asio::ssl::context> owned_ctx;
            boost::asio::ssl::context* ctx = nullptr;
            tls_fingerprint::BrowserProfile active_tls_profile = tls_fingerprint::BrowserProfile::UNKNOWN;
            if (cfg.tls_stealth_enabled) {
                // Initialize metrics manager
                if (cfg.tls_fingerprint_log) {
                    tls_metrics::MetricsManager::instance().initialize(cfg.tls_fingerprint_log_path);
                }

                // Parse browser profile
                tls_fingerprint::BrowserProfile profile = tls_fingerprint::BrowserProfile::CHROME_135;
                std::string profile_lower = cfg.tls_stealth_profile;
                std::transform(profile_lower.begin(), profile_lower.end(), profile_lower.begin(), ::tolower);

                if (profile_lower == "chrome" || profile_lower == "chrome135" || profile_lower == "chrome_135") {
                    profile = tls_fingerprint::BrowserProfile::CHROME_135;
                } else if (profile_lower == "firefox" || profile_lower == "firefox126" || profile_lower == "firefox_126") {
                    profile = tls_fingerprint::BrowserProfile::FIREFOX_126;
                } else if (profile_lower == "safari" || profile_lower == "safari17" || profile_lower == "safari_17") {
                    profile = tls_fingerprint::BrowserProfile::SAFARI_17;
                }
                active_tls_profile = profile;

                // Create stealth configuration
                tls_stealth::StealthConfig stealth_config;
                stealth_config.enabled = true;
                stealth_config.target_profile = profile;
                stealth_config.rotate_profiles = cfg.tls_stealth_rotate;
                stealth_config.rotation_interval_connections = cfg.tls_stealth_rotation_interval;
                stealth_config.log_fingerprints = cfg.tls_fingerprint_log;
                stealth_config.log_file_path = cfg.tls_fingerprint_log_path;
                stealth_config.verify_with_external_api = cfg.tls_fingerprint_verify;
                stealth_config.test_endpoint = cfg.tls_fingerprint_test_endpoint;

                // Initialize stealth manager
                tls_stealth::StealthManager::instance().initialize(stealth_config);

                ctx = &tls_stealth::StealthManager::instance().get_context().get_context();
            } else {
                owned_ctx = std::make_unique<boost::asio::ssl::context>(obfs::create_client_context());
                ctx = owned_ctx.get();
            }

            ctx->set_verify_mode(boost::asio::ssl::verify_peer);
            ctx->set_default_verify_paths();
            if (!cfg.tls_ca_cert.empty()) {
                ctx->load_verify_file(cfg.tls_ca_cert);
            }

            boost::asio::ip::tcp::resolver resolver(io);
            boost::asio::ip::tcp::resolver::results_type endpoints;
            try {
                endpoints = resolver.resolve(boost::asio::ip::tcp::v4(), cfg.server, std::to_string(cfg.port));
            } catch (const boost::system::system_error& ex) {
                throw std::runtime_error("server offline, could not reach endpoint (DNS resolution failed: " + std::string(ex.what()) + ")");
            }
            boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream(io, *ctx);
            try {
                auto cr = connect_with_timeout(stream.next_layer(), endpoints, io, kConnectTimeout);
                if (cr.timed_out) {
                    throw std::runtime_error("server offline, could not reach endpoint (connect timeout)");
                }
                if (cr.ec) {
                    throw boost::system::system_error(cr.ec);
                }
            } catch (const boost::system::system_error& ex) {
                auto code = ex.code();
                if (code == boost::asio::error::connection_refused ||
                    code == boost::asio::error::host_unreachable ||
                    code == boost::asio::error::network_unreachable ||
                    code == boost::asio::error::timed_out ||
                    code == boost::asio::error::network_down) {
                    throw std::runtime_error("server offline, could not reach endpoint");
                }
                throw std::runtime_error("server offline, could not reach endpoint (" + std::string(ex.what()) + ")");
            }
            boost::system::error_code keep_ec;
            stream.next_layer().set_option(boost::asio::socket_base::keep_alive(true), keep_ec);
            if (keep_ec) {
                util::log_warn(std::string("keepalive set failed: ") + keep_ec.message());
            }
            SSL_set_tlsext_host_name(stream.native_handle(), cfg.server.c_str());
            SSL_set1_host(stream.native_handle(), cfg.server.c_str());
            
            auto handshake_start = std::chrono::steady_clock::now();
            boost::system::error_code hs_ec;
            {
                auto hr = handshake_with_timeout(stream, io, kHandshakeTimeout);
                if (hr.timed_out) {
                    throw std::runtime_error("TLS handshake failed: timeout");
                }
                hs_ec = hr.ec;
            }
            auto handshake_end = std::chrono::steady_clock::now();
            auto handshake_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                handshake_end - handshake_start);
            
            if (hs_ec) {
                long vr = SSL_get_verify_result(stream.native_handle());
                std::string detail = describe_verify_result(vr, cfg.server);
                std::string ssl_detail = describe_openssl_error();
                std::string msg = "TLS handshake failed: " + hs_ec.message();
                if (!detail.empty()) {
                    msg += " (" + detail + ")";
                }
                if (!ssl_detail.empty()) {
                    msg += " [" + ssl_detail + "]";
                }
                throw std::runtime_error(msg);
            }
            if (!cfg.tls_pin_sha256.empty()) {
                std::string fp = get_peer_cert_fingerprint(nullptr, stream.native_handle());
                if (fp.empty() || fp != cfg.tls_pin_sha256) {
                    throw std::runtime_error("TLS pin mismatch");
                }
            }

            tls_fingerprint::FingerprintData fingerprint_for_metrics;
            if (cfg.tls_stealth_enabled) {
                if (cfg.tls_fingerprint_verify && !tls_fingerprint_verification_attempted) {
                    auto verification = tls_stealth::evaluate_tls_fingerprint(
                        cfg.tls_fingerprint_test_endpoint,
                        443,
                        active_tls_profile);
                    tls_fingerprint_verification_attempted = true;
                    if (verification.success) {
                        verified_tls_fingerprint = verification.detected_fingerprint;
                        util::log_info("TLS fingerprint verified via " + cfg.tls_fingerprint_test_endpoint
                            + ": JA3=" + verification.ja3_from_server
                            + " JA4=" + verification.ja4_from_server);
                        if (!verification.matches_target_profile) {
                            const std::string observed_profile =
                                tls_fingerprint::browser_profile_name(verification.detected_fingerprint.matched_profile);
                            util::log_warn("TLS fingerprint mismatch: expected "
                                + tls_fingerprint::browser_profile_name(active_tls_profile)
                                + ", observed " + observed_profile);
                        }
                    } else {
                        util::log_warn("TLS fingerprint verification failed: " + verification.error_message);
                    }
                }

                if (verified_tls_fingerprint.has_value()) {
                    fingerprint_for_metrics = *verified_tls_fingerprint;
                } else if (auto profile_info = tls_fingerprint::get_browser_profile_info(active_tls_profile);
                           profile_info.has_value()) {
                    fingerprint_for_metrics.ja3_hash = profile_info->ja3_hash;
                    fingerprint_for_metrics.ja4_hash = profile_info->ja4_hash;
                    fingerprint_for_metrics.alpn_protocols = profile_info->alpn_protocols;
                    fingerprint_for_metrics.ja3_components.tls_version = profile_info->tls_version;
                    fingerprint_for_metrics.ja3_components.cipher_suites = profile_info->cipher_suites;
                    fingerprint_for_metrics.ja3_components.extensions = profile_info->extensions;
                    fingerprint_for_metrics.ja3_components.supported_groups = profile_info->supported_groups;
                    fingerprint_for_metrics.ja3_components.ec_point_formats = profile_info->ec_point_formats;
                    fingerprint_for_metrics.ja4_components.protocol_version = "t13";
                    fingerprint_for_metrics.ja4_components.sni_present = "d";
                    fingerprint_for_metrics.ja4_components.cipher_count =
                        static_cast<uint8_t>(profile_info->cipher_suites.size());
                    fingerprint_for_metrics.ja4_components.extension_count =
                        static_cast<uint8_t>(profile_info->extensions.size());
                    fingerprint_for_metrics.ja4_components.first_alpn = profile_info->alpn_protocols.empty()
                        ? ""
                        : profile_info->alpn_protocols.front();
                    fingerprint_for_metrics.ja4_components.cipher_suites = profile_info->cipher_suites;
                    fingerprint_for_metrics.ja4_components.extensions = profile_info->extensions;
                    fingerprint_for_metrics.ja4_components.signature_algorithms = profile_info->signature_algorithms;
                    fingerprint_for_metrics.matched_profile = active_tls_profile;
                    fingerprint_for_metrics.matches_known_browser = true;
                    fingerprint_for_metrics.similarity_score = 100.0;
                }
            }

            if (cfg.tls_stealth_enabled && cfg.tls_fingerprint_log) {
                tls_metrics::MetricsManager::instance().record_connection_fingerprint(
                    cfg.server,
                    static_cast<uint16_t>(cfg.port),
                    fingerprint_for_metrics,
                    true,  // stealth_enabled
                    active_tls_profile,
                    true,  // handshake_succeeded
                    static_cast<uint32_t>(handshake_duration.count()),
                    ""     // error_message
                );
            }

            inner::Config inner_cfg;
            inner_cfg.enabled = cfg.inner_crypto;
            inner_cfg.pq_public_key = cfg.pq_public_key;
            inner_cfg.allow_embedded_master = cfg.allow_embedded_master;

            std::optional<crypto::Bytes> pq_ciphertext;
            std::optional<crypto::Bytes> pq_salt;
            std::optional<crypto::Bytes> inner_key;
            std::optional<std::string> inner_mode;
            std::optional<bool> inner_hop;
            std::optional<inner::KdfParams> inner_kdf;
            bool inner_disabled_for_session = false;
            bool pq_need_key = false;
            bool pq_not_supported = false;
            std::string inner_disable_reason;
            if (inner_cfg.enabled) {
                try {
                    auto hs = inner::client_prepare(inner_cfg, cfg.inner_heavy);
                    if (!hs.enabled || hs.key.empty()) {
                        throw std::runtime_error("inner crypto init failed");
                    }
                    pq_ciphertext = hs.pq_ciphertext;
                    pq_salt = hs.salt;
                    inner_key = hs.key;
                    inner_mode = cfg.inner_heavy ? std::optional<std::string>("heavy") : std::optional<std::string>("light");
                    if (!hs.kdf.empty()) {
                        inner::KdfParams params;
                        params.name = hs.kdf;
                        params.argon2_time = hs.argon2_time;
                        params.argon2_memory = hs.argon2_memory;
                        params.argon2_parallelism = hs.argon2_parallelism;
                        params.pbkdf2_iters = hs.pbkdf2_iters;
                        inner_kdf = params;
                    }
                } catch (const std::exception& ex) {
                    std::string msg = ex.what();
                    if (msg.find("PQ public key not configured") != std::string::npos) {
                        pq_need_key = true;
                        inner_disabled_for_session = true;
                        inner_disable_reason =
                            "inner crypto disabled: PQ public key not configured (use --pq-pub, provide pq_public.key, or enable --use-embedded-master)";
                    } else if (msg.find("ML-KEM-768 support is not enabled") != std::string::npos) {
                        pq_not_supported = true;
                        inner_disabled_for_session = true;
                        inner_disable_reason =
                            "inner crypto disabled: PQ not supported in this build (rebuild with liboqs/BaseFWX PQ enabled)";
                    } else {
                        throw;
                    }
                }
            }
            if (pq_ciphertext.has_value()) {
                inner_hop = cfg.inner_hop;
            }

            authenticate(stream, io, cfg.server, cfg.port, cfg.identity, pq_ciphertext, pq_salt, inner_mode, inner_hop, inner_kdf);
            util::log_info("auth response sent; waiting for server confirmation");

            protocol::Frame anon_frame;
            auto server_info_timeout = kServerInfoTimeout;
            if (pq_ciphertext.has_value() && cfg.inner_crypto) {
                server_info_timeout = cfg.inner_heavy ? kServerInfoTimeoutInnerHeavy : kServerInfoTimeoutInner;
            }
            try {
                anon_frame = read_frame_with_timeout(stream, io, server_info_timeout, "server info", cfg.server, cfg.port, true);
            } catch (const FatalError&) {
                throw;
            } catch (const std::exception&) {
                throw FatalError("this endpoint is not a yume server (failed to read server info); please check the origin and try again");
            }
            if (anon_frame.header.type != protocol::ANON) {
                throw FatalError("this endpoint is not a yume server (unexpected response type); please check the origin and try again");
            }
            bool pq_reconnect = false;
            bool have_anon = false;
            bool verity_ok = false;
            bool fixcraft_ok = false;
            crypto::EVP_PKEY_ptr sub_pub{nullptr, EVP_PKEY_free};
            crypto::EVP_PKEY_ptr ca_pub{nullptr, EVP_PKEY_free};
            bool sub_ok = false;
            bool ca_ok = false;
            std::vector<std::string> announced_proof_sources;
            std::vector<std::string> verified_proof_sources;
            bool have_inner_caps = false;
            bool server_inner_supported = false;
            bool server_inner_required = false;
            bool server_inner_dual = false;
            bool server_inner_active = false;
            std::string server_inner_mode;
            bool server_cap_pq = false;
            bool server_cap_argon2 = false;
            bool server_cap_pbkdf2 = false;
            bool server_hop_enabled = false;
            std::uint32_t server_hop_interval_ms = 0;
            std::int64_t server_time_ms = 0;
            std::string server_version;
            std::string server_error;
            std::string mode = "normal";
            std::uint32_t hop_interval_ms = 0;
            std::int64_t hop_offset_ms = 0;
            bool hop_enabled = false;
            std::string hash;
            std::string sig;
            std::string ts;
            std::string nonce;
            std::string certfp;
            std::string ca_sig;
            std::string ca_alg;
            std::string sub_sig;
            std::string sub_alg;
            std::string sub_cert_b64;
            std::string pq_pub_b64;
            std::string pq_sig;
            std::string pq_alg;
            try {
                std::string payload(anon_frame.payload.begin(), anon_frame.payload.end());
                auto json = nlohmann::json::parse(payload);
                server_version = json.value("version", "UNKNOWN");
                server_error = json.value("error", "");
                mode = json.value("mode", "normal");
                hash = json.value("hash", "");
                sig = json.value("sig", "");
                ts = json.value("ts", "");
                nonce = json.value("nonce", "");
                certfp = json.value("certfp", "");
                ca_sig = json.value("ca_sig", "");
                ca_alg = json.value("ca_alg", "");
                sub_sig = json.value("sub_sig", "");
                sub_alg = json.value("sub_alg", "");
                sub_cert_b64 = json.value("sub_cert", "");
                if (json.contains("proof_sources") && json["proof_sources"].is_array()) {
                    for (const auto& entry : json["proof_sources"]) {
                        if (entry.is_string()) {
                            announced_proof_sources.push_back(normalize_proof_source(entry.get<std::string>()));
                        }
                    }
                }
                pq_pub_b64 = json.value("pq_pub", "");
                pq_sig = json.value("pq_sig", "");
                pq_alg = json.value("pq_alg", "");
                have_inner_caps = json.contains("inner_supported") || json.contains("inner_required") ||
                                  json.contains("inner_dual") || json.contains("inner_mode");
                server_inner_supported = json.value("inner_supported", false);
                server_inner_required = json.value("inner_required", false);
                server_inner_dual = json.value("inner_dual", false);
                server_inner_active = json.value("inner_active", false);
                server_inner_mode = json.value("inner_mode", "");
                server_cap_pq = json.value("cap_pq", false);
                server_cap_argon2 = json.value("cap_argon2", false);
                server_cap_pbkdf2 = json.value("cap_pbkdf2", false);
                server_hop_enabled = json.value("hop_enabled", false);
                server_hop_interval_ms = static_cast<std::uint32_t>(json.value("hop_interval_ms", 0));
                server_time_ms = json.value("server_time_ms", 0LL);
            } catch (const nlohmann::json::parse_error&) {
                throw FatalError("this endpoint is not a yume server (invalid server response); please check the origin and try again");
            } catch (const std::exception& ex) {
                throw FatalError("this endpoint is not a yume server (" + std::string(ex.what()) + "); please check the origin and try again");
            }
            if (announced_proof_sources.empty()) {
                if (!sig.empty()) {
                    add_verified_source(&announced_proof_sources, yume::policy::kAnonymProofSourceFixcraft);
                }
                if (!ca_sig.empty()) {
                    add_verified_source(&announced_proof_sources, yume::policy::kAnonymProofSourceCa);
                }
                if (!sub_sig.empty() || !sub_cert_b64.empty()) {
                    add_verified_source(&announced_proof_sources, yume::policy::kAnonymProofSourceSubCa);
                }
            }
            if (server_version.empty() || server_version == "UNKNOWN") {
                throw FatalError("this endpoint is not a yume server (no version info); please check the origin and try again");
            }
            util::log_info("authenticated to server");

            auto sanitize_msg = [&](const std::string& msg) {
                if (!cfg.boring) {
                    return msg;
                }
                std::string out;
                out.reserve(msg.size());
                for (unsigned char c : msg) {
                    if (c >= 0x20 && c < 0x7f) {
                        out.push_back(static_cast<char>(c));
                    }
                }
                size_t start = out.find_first_not_of(' ');
                if (start == std::string::npos) {
                    return std::string{};
                }
                size_t end = out.find_last_not_of(' ');
                return out.substr(start, end - start + 1);
            };
            auto print_red = [&](const std::string& msg) {
                std::string out = sanitize_msg(msg);
                if (out.empty()) {
                    return;
                }
                std::cerr << "\033[1;31m" << out << "\033[0m" << std::endl;
            };
            auto print_green = [&](const std::string& msg) {
                std::string out = sanitize_msg(msg);
                if (out.empty()) {
                    return;
                }
                std::cout << "\033[1;32m" << out << "\033[0m" << std::endl;
            };
            auto maybe_auto_trust_pq = [&](bool allow_bootstrap) {
                if (!allow_bootstrap || pq_pub_b64.empty()) {
                    return;
                }
                if (certfp.empty()) {
                    util::log_warn("pq_pub provided but certfp missing; refusing PQ auto-trust");
                    return;
                }
                if (pq_sig.empty()) {
                    util::log_warn("pq_pub provided but pq_sig missing; refusing PQ auto-trust");
                    return;
                }
                std::string peer_fp = get_peer_cert_fingerprint(nullptr, stream.native_handle());
                if (!peer_fp.empty() && peer_fp != certfp) {
                    util::log_warn("pq_pub cert fingerprint mismatch; refusing PQ auto-trust");
                    return;
                }
                if (!sub_ok && !sub_cert_b64.empty()) {
                    if (cfg.anonym_ca_cert.empty()) {
                        util::log_warn("pq_pub provided with sub_cert but no --anonym-ca-cert set");
                    } else {
                        std::string sub_pem = util::base64_decode(sub_cert_b64);
                        auto sub_cert = load_cert_from_pem(sub_pem);
                        auto ca_cert = load_cert_from_file(cfg.anonym_ca_cert);
                        if (!sub_cert || !ca_cert) {
                            util::log_warn("pq_pub sub_cert parse failed; refusing PQ auto-trust");
                        } else if (!is_cert_time_valid(sub_cert.get())) {
                            util::log_warn("pq_pub sub_cert expired; refusing PQ auto-trust");
                        } else if (!verify_cert_signed_by_ca(sub_cert.get(), ca_cert.get())) {
                            util::log_warn("pq_pub sub_cert not signed by CA; refusing PQ auto-trust");
                        } else {
                                    sub_pub = load_pubkey_from_cert_pem(sub_pem);
                            sub_ok = static_cast<bool>(sub_pub);
                        }
                    }
                }
                if (!ca_ok && !cfg.anonym_ca_cert.empty()) {
                    ca_pub = load_pubkey_from_cert(cfg.anonym_ca_cert);
                    ca_ok = static_cast<bool>(ca_pub);
                }
                EVP_PKEY* pq_key = sub_ok ? sub_pub.get() : (ca_ok ? ca_pub.get() : nullptr);
                if (!pq_key) {
                    util::log_warn("pq_pub provided but no verified CA/sub cert available; refusing PQ auto-trust");
                    return;
                }
                std::string pq_msg = std::string(kPqMsgPrefix) + pq_pub_b64 + ":" + certfp;
                crypto::Bytes pq_msg_bytes(pq_msg.begin(), pq_msg.end());
                std::string pq_sig_raw = util::base64_decode(pq_sig);
                if (pq_sig_raw.empty()) {
                    util::log_warn("pq_sig invalid base64; refusing PQ auto-trust");
                    return;
                }
                crypto::Bytes pq_sig_bytes(pq_sig_raw.begin(), pq_sig_raw.end());
                bool ok_pq = crypto::verify_key(pq_key, pq_msg_bytes, pq_sig_bytes);
                if (!ok_pq) {
                    util::log_warn("pq_pub signature invalid; refusing PQ auto-trust");
                    return;
                }
                std::string pq_raw = util::base64_decode(pq_pub_b64);
                if (pq_raw.empty()) {
                    util::log_warn("pq_pub decode failed; refusing PQ auto-trust");
                    return;
                }
                std::string target_path = cfg.pq_public_key;
                if (target_path.empty()) {
                    const char* home = std::getenv("HOME");
                    if (home && *home) {
                        std::filesystem::path p = std::filesystem::path(home) / ".config" / "yume" / "pq_public.key";
                        target_path = p.string();
                    } else {
                        std::filesystem::path tmp;
                        try {
                            tmp = std::filesystem::temp_directory_path();
                        } catch (...) {
                            tmp = ".";
                        }
                        target_path = (tmp / "yume" / "pq_public.key").string();
                    }
                }
                if (target_path.empty()) {
                    util::log_warn("pq_pub verified but no output path available");
                    return;
                }
                bool pq_changed = true;
                std::string existing;
                std::string read_err;
                if (read_file_bytes(target_path, &existing, &read_err)) {
                    pq_changed = (existing != pq_raw);
                }
                std::string err;
                if (!pq_changed || write_file_bytes(target_path, pq_raw, &err)) {
                    if (cfg.pq_public_key.empty()) {
                        cfg.pq_public_key = target_path;
                    }
                    if (pq_changed) {
                        util::log_info("stored pq_public.key from server at " + target_path);
                    }
                    if (cfg.inner_crypto && !pq_not_supported && !pq_reconnect_used &&
                        (pq_need_key || pq_changed)) {
                        pq_reconnect = true;
                        pq_reconnect_used = true;
                    }
                } else {
                    util::log_warn("failed to store pq_public.key: " + err);
                }
            };
            bool allow_pq_bootstrap = server_error.empty() ||
                                      server_error.find("requires inner") != std::string::npos;
            maybe_auto_trust_pq(allow_pq_bootstrap);

            if (!server_error.empty()) {
                if (pq_reconnect) {
                    util::log_info("PQ public key received; reconnecting to enable inner crypto");
                    attempt++;
                    continue;
                }
                print_red(server_error);
                if (inner_disabled_for_session &&
                    server_error.find("requires inner") != std::string::npos &&
                    !inner_disable_reason.empty()) {
                    print_red(inner_disable_reason);
                }
                return 1;
            }
            if (server_version != yume::kVersion) {
                print_red("server is version " + server_version + ", you are " + std::string(yume::kVersion) +
                          ", please install a matching version to connect to this server");
                return 1;
            }
            bool want_inner = cfg.inner_crypto && !inner_disabled_for_session;
            if (have_inner_caps) {
                if (want_inner) {
                    if (!server_inner_supported) {
                        print_red("server does not support inner crypto");
                        return 1;
                    }
                    if (!server_inner_dual && !server_inner_mode.empty() && server_inner_mode != "off") {
                        if (cfg.inner_heavy && server_inner_mode == "light") {
                            print_red("server does not support inner-heavy");
                            return 1;
                        }
                        if (!cfg.inner_heavy && server_inner_mode == "heavy") {
                            print_red("server does not support inner-light");
                            return 1;
                        }
                    }
                } else if (server_inner_required) {
                    print_red("server does not support connecting without inner!");
                    return 1;
                }
            }
            if (want_inner && have_inner_caps && !server_cap_pq) {
                print_red("server does not support PQ");
                return 1;
            }
            if (want_inner && inner_kdf.has_value() && !inner_kdf->name.empty()) {
                if (inner_kdf->name == "argon2" && !server_cap_argon2) {
                    print_red("server does not support argon2");
                    return 1;
                }
                if (inner_kdf->name == "pbkdf2" && !server_cap_pbkdf2) {
                    print_red("server does not support pbkdf2");
                    return 1;
                }
            }
            if (want_inner) {
                if (server_hop_enabled && !cfg.inner_hop) {
                    print_red("server requires hopping");
                    return 1;
                }
                if (!server_hop_enabled && cfg.inner_hop) {
                    print_red("server does not support hopping");
                    return 1;
                }
            }
            hop_interval_ms = cfg.hop_interval_ms;
            if (server_hop_interval_ms > 0) {
                hop_interval_ms = server_hop_interval_ms;
            }
            if (hop_interval_ms > 0) {
                if (hop_interval_ms < 250) {
                    hop_interval_ms = 250;
                } else if (hop_interval_ms > 1000) {
                    hop_interval_ms = 1000;
                }
            }
            hop_offset_ms = 0;
            if (server_time_ms > 0) {
                hop_offset_ms = server_time_ms - util::now_ms();
            }
            hop_enabled = (want_inner && cfg.inner_hop && server_hop_enabled && inner_key.has_value());
            if (hop_interval_ms == 0) {
                hop_enabled = false;
            }

            if (mode == "anonym") {
                const bool fixcraft_present =
                    std::find(announced_proof_sources.begin(), announced_proof_sources.end(),
                              std::string(yume::policy::kAnonymProofSourceFixcraft)) != announced_proof_sources.end() ||
                    !sig.empty();
                const bool ca_present =
                    std::find(announced_proof_sources.begin(), announced_proof_sources.end(),
                              std::string(yume::policy::kAnonymProofSourceCa)) != announced_proof_sources.end() ||
                    !ca_sig.empty();
                const bool sub_present =
                    std::find(announced_proof_sources.begin(), announced_proof_sources.end(),
                              std::string(yume::policy::kAnonymProofSourceSubCa)) != announced_proof_sources.end() ||
                    !sub_sig.empty() || !sub_cert_b64.empty();

                if (hash.empty() || ts.empty() || nonce.empty()) {
                    print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                    print_red("ANONYM PROOF IS INCOMPLETE");
                    return 1;
                }
                if (certfp.empty()) {
                    print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                    print_red("ANONYM PROOF MISSING CERTIFICATE FINGERPRINT");
                    return 1;
                }
                long long ts_val = 0;
                try {
                    ts_val = std::stoll(ts);
                } catch (...) {
                    print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                    print_red("INVALID TIMESTAMP IN ANONYM PROOF");
                    return 1;
                }
                const long long now = static_cast<long long>(std::time(nullptr));
                if (std::llabs(now - ts_val) > yume::policy::kAnonymProofWindowSeconds) {
                    print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                    print_red("ANONYM PROOF EXPIRED OR NOT YET VALID");
                    return 1;
                }
                const std::string peer_fp = get_peer_cert_fingerprint(nullptr, stream.native_handle());
                if (!peer_fp.empty() && certfp != peer_fp) {
                    print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                    print_red("ANONYM CERTIFICATE FINGERPRINT MISMATCH");
                    return 1;
                }

                std::string message = std::string(kAnonMsgPrefix) + hash + ":" + ts + ":" + nonce + ":" + certfp;
                crypto::Bytes msg_bytes(message.begin(), message.end());

                if (fixcraft_present) {
                    if (sig.empty()) {
                        print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                        print_red("FIXCRAFT SIGNATURE MISSING");
                        return 1;
                    }
                    crypto::EVP_PKEY_ptr pubkey{nullptr, EVP_PKEY_free};
                    if (!cfg.anonym_pubkey.empty()) {
                        auto kp = crypto::load_keypair("", cfg.anonym_pubkey);
                        pubkey.reset(kp.public_key.release());
                    } else {
                        BIO* bio = BIO_new_mem_buf(kFixcraftAnonymPubPem, -1);
                        if (!bio) {
                            print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                            print_red("FAILED TO LOAD EMBEDDED ANONYM PUBLIC KEY");
                            return 1;
                        }
                        EVP_PKEY* key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
                        BIO_free(bio);
                        if (!key) {
                            print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                            print_red("FAILED TO LOAD EMBEDDED ANONYM PUBLIC KEY");
                            return 1;
                        }
                        pubkey.reset(key);
                    }
                    std::string sig_raw = util::base64_decode(sig);
                    if (sig_raw.empty()) {
                        print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                        print_red("INVALID SIGNATURE FORMAT FROM SERVER");
                        return 1;
                    }
                    crypto::Bytes sig_bytes(sig_raw.begin(), sig_raw.end());
                    if (!crypto::verify_key(pubkey.get(), msg_bytes, sig_bytes)) {
                        print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                        print_red("THIS SERVER IS FORGING SIGNATURES, REPORT IT TO FIXCRAFT, INC. ASAP, ALSO FILE A COMPLAINT TO AN INTERNET AUTHORITY");
                        return 1;
                    }
                    fixcraft_ok = true;
                    add_verified_source(&verified_proof_sources, yume::policy::kAnonymProofSourceFixcraft);
                }

                if (sub_present) {
                    if (cfg.anonym_ca_cert.empty()) {
                        print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                        print_red("ANONYM SUB CERT PROVIDED BUT NO --anonym-ca-cert SET");
                        return 1;
                    }
                    if (sub_cert_b64.empty()) {
                        print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                        print_red("ANONYM SUB CERT MISSING");
                        return 1;
                    }
                    if (sub_sig.empty()) {
                        print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                        print_red("ANONYM SUB SIGNATURE MISSING");
                        return 1;
                    }
                    std::string sub_pem = util::base64_decode(sub_cert_b64);
                    auto sub_cert = load_cert_from_pem(sub_pem);
                    if (!sub_cert) {
                        print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                        print_red("FAILED TO PARSE ANONYM SUB CERT");
                        return 1;
                    }
                    auto ca_cert = load_cert_from_file(cfg.anonym_ca_cert);
                    if (!ca_cert) {
                        print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                        print_red("FAILED TO LOAD ANONYM CA CERT");
                        return 1;
                    }
                    if (!is_cert_time_valid(sub_cert.get())) {
                        print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                        print_red("ANONYM SUB CERT IS EXPIRED OR NOT YET VALID");
                        return 1;
                    }
                    if (!verify_cert_signed_by_ca(sub_cert.get(), ca_cert.get())) {
                        print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                        print_red("ANONYM SUB CERT IS NOT SIGNED BY THE TRUSTED CA");
                        return 1;
                    }
                    crypto::EVP_PKEY_ptr sub_key{X509_get_pubkey(sub_cert.get()), EVP_PKEY_free};
                    if (!sub_key) {
                        print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                        print_red("FAILED TO LOAD SUB CERT PUBLIC KEY");
                        return 1;
                    }
                    std::string sub_sig_raw = util::base64_decode(sub_sig);
                    if (sub_sig_raw.empty()) {
                        print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                        print_red("INVALID ANONYM SUB SIGNATURE FORMAT");
                        return 1;
                    }
                    crypto::Bytes sub_sig_bytes(sub_sig_raw.begin(), sub_sig_raw.end());
                    if (!crypto::verify_key(sub_key.get(), msg_bytes, sub_sig_bytes)) {
                        print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                        print_red("ANONYM SUB SIGNATURE INVALID");
                        return 1;
                    }
                    sub_pub = std::move(sub_key);
                    sub_ok = true;
                    add_verified_source(&verified_proof_sources, yume::policy::kAnonymProofSourceSubCa);
                }

                if (ca_present) {
                    if (ca_sig.empty()) {
                        print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                        print_red("ANONYM CA SIGNATURE MISSING");
                        return 1;
                    }
                    if (cfg.anonym_ca_cert.empty()) {
                        util::log_warn("anonym CA signature provided but no --anonym-ca-cert set; skipping CA verification");
                    } else {
                        auto ca_key = load_pubkey_from_cert(cfg.anonym_ca_cert);
                        if (!ca_key) {
                            print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                            print_red("FAILED TO LOAD ANONYM CA CERT");
                            return 1;
                        }
                        std::string ca_sig_raw = util::base64_decode(ca_sig);
                        if (ca_sig_raw.empty()) {
                            print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                            print_red("INVALID ANONYM CA SIGNATURE FORMAT");
                            return 1;
                        }
                        crypto::Bytes ca_sig_bytes(ca_sig_raw.begin(), ca_sig_raw.end());
                        if (!crypto::verify_key(ca_key.get(), msg_bytes, ca_sig_bytes)) {
                            print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                            print_red("ANONYM CA SIGNATURE INVALID");
                            return 1;
                        }
                        ca_pub = std::move(ca_key);
                        ca_ok = true;
                        add_verified_source(&verified_proof_sources, yume::policy::kAnonymProofSourceCa);
                    }
                }

                verity_ok = fixcraft_ok || ca_ok || sub_ok;
                if (!verity_ok) {
                    print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                    print_red("NO TRUSTED ANONYM PROOF SOURCE COULD BE VERIFIED");
                    return 1;
                }
                if (!verified_once) {
                    if (cfg.boring) {
                        print_green("Verified");
                    } else {
                        print_green("✅✒️ Verified");
                    }
                    verified_once = true;
                } else {
                    print_green("Server Verified");
                }
            } else {
                if (cfg.require_anonym) {
                    print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                    print_red("SERVER IS NOT IN ANONYM MODE");
                    return 1;
                }
                if (!args.accept_monitoring) {
                    print_red("🛑 🔓 CRITICAL WARNING:");
                    print_red("YOUR DATA WILL BE MONITORED BY THE SERVER OPERATOR YOU ARE CONNECTING TO!! ARE YOU ULTIMATELY SURE YOU TRUST THAT PERSON??");
                    print_red("TYPE: \"THIS MAY COMPROMISE MY PRIVACY\" to continue");
                    std::string line;
                    std::getline(std::cin, line);
                    auto normalize = [](std::string s) {
                        auto is_space = [](unsigned char ch) { return std::isspace(ch) != 0; };
                        while (!s.empty() && is_space(static_cast<unsigned char>(s.front()))) {
                            s.erase(s.begin());
                        }
                        while (!s.empty() && is_space(static_cast<unsigned char>(s.back()))) {
                            s.pop_back();
                        }
                        std::transform(s.begin(), s.end(), s.begin(),
                                       [](unsigned char ch) { return static_cast<char>(std::toupper(ch)); });
                        return s;
                    };
                    if (normalize(line) != "THIS MAY COMPROMISE MY PRIVACY") {
                        return 1;
                    }
                }
            }
            have_anon = true;
            verity_ok = (mode == "anonym") && (fixcraft_ok || ca_ok || sub_ok);
            if (pq_reconnect) {
                util::log_info("PQ public key received; reconnecting to enable inner crypto");
                attempt++;
                continue;
            }
            if (inner_disabled_for_session && !pq_warned) {
                warn_security_disabled("PQ", cfg.boring);
                if (pq_not_supported) {
                    util::log_warn("PQ not supported in this build; inner crypto disabled for this session");
                } else if (pq_need_key) {
                    util::log_warn("PQ public key not configured; inner crypto disabled for this session");
                }
                pq_warned = true;
            }
            auto build_hop_status_line = [hop_enabled, hop_interval_ms, hop_offset_ms]() {
                auto color_wrap = [](const std::string& text, const char* code) {
                    return std::string("\033[") + code + "m" + text + "\033[0m";
                };
                std::string hop_state = hop_enabled ? "ON" : "OFF";
                std::string hop_line = color_wrap(hop_state, hop_enabled ? "1;32" : "1;31");
                std::ostringstream hop_freq_stream;
                hop_freq_stream.setf(std::ios::fixed);
                hop_freq_stream << std::setprecision(2)
                                << (hop_enabled && hop_interval_ms > 0
                                        ? (1000.0 / static_cast<double>(hop_interval_ms))
                                        : 0.0);
                std::string hop_freq = color_wrap(hop_freq_stream.str() + "Hz", "1;33");
                std::int64_t adjusted = util::now_ms() + hop_offset_ms;
                if (adjusted < 0) {
                    adjusted = 0;
                }
                std::int64_t last_change = (hop_enabled && hop_interval_ms > 0)
                                               ? (adjusted % static_cast<std::int64_t>(hop_interval_ms))
                                               : 0;
                std::string hop_last = color_wrap(std::to_string(last_change) + "ms", "1;34");
                return color_wrap("Hopping", "1;36") + ": " + hop_line + " - " + hop_freq + " | " + hop_last;
            };

            if (have_anon && !summary_once) {
                auto color_wrap = [&](const std::string& text, const char* code) {
                    return std::string("\033[") + code + "m" + text + "\033[0m";
                };
                auto to_upper = [](std::string v) {
                    for (char& c : v) {
                        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
                    }
                    return v;
                };
                std::string protection_line = "TLS";
                if (inner_key.has_value()) {
                    std::vector<std::string> protections;
                    protections.push_back("PQ");
                    std::string kdf_name;
                    if (inner_kdf.has_value()) {
                        kdf_name = inner_kdf->name;
                    }
                    if (kdf_name.empty()) {
                        kdf_name = cfg.inner_heavy ? "argon2" : "hkdf";
                    }
                    protections.push_back(to_upper(kdf_name));
                    protection_line.clear();
                    for (size_t i = 0; i < protections.size(); ++i) {
                        if (i) protection_line += "/";
                        protection_line += protections[i];
                    }
                }
                std::string inner_state = (inner_key.has_value() || server_inner_active) ? "ON" : "OFF";
                std::string inner_line = color_wrap(inner_state, (inner_state == "ON") ? "1;32" : "1;31");
                if (inner_key.has_value()) {
                    inner_line += color_wrap(cfg.inner_heavy ? " (heavy)" : " (light)", "1;35");
                    if (have_inner_caps && server_inner_dual) {
                        inner_line += color_wrap(", dual", "1;35");
                    }
                }
                std::string server_display = color_wrap(cfg.server, "1;33");
                std::string version_value = color_wrap(server_version.empty() ? "UNKNOWN" : server_version, "1;35");
                std::string connection_value = color_wrap("🔒 TLS", "1;32");
                std::string protection_value = color_wrap(protection_line, "1;35");
                std::string verity_state = format_verified_sources(verified_proof_sources);
                std::string verity_line = color_wrap(verity_state, verity_ok ? "1;32" : "1;31");
                std::string header =
                    color_wrap("Connected to", "1;36") + " " + server_display + ":\n" +
                    color_wrap("VERSION", "1;36") + ": " + version_value + "\n" +
                    color_wrap("Connection", "1;36") + ": " + connection_value + "\n" +
                    color_wrap("Protection", "1;36") + ": " + protection_value + "\n" +
                    color_wrap("Inner", "1;36") + ": " + inner_line + "\n";
                std::string footer = color_wrap("Verity", "1;36") + ": " + verity_line + "\n";
                const std::string border = color_wrap("------------------------------------------", "1;34");
                status_block_builder = [header, footer, border, build_hop_status_line]() {
                    return border + "\n" + header + build_hop_status_line() + "\n" + footer + border + "\n";
                };
                if (!live_status_enabled) {
                    std::cout
                        << border << "\n"
                        << color_wrap("Connected to", "1;36") << " " << server_display << ":\n"
                        << color_wrap("VERSION", "1;36") << ": " << version_value << "\n"
                        << color_wrap("Connection", "1;36") << ": " << connection_value << "\n"
                        << color_wrap("Protection", "1;36") << ": " << protection_value << "\n"
                        << color_wrap("Inner", "1;36") << ": " << inner_line << "\n"
                        << build_hop_status_line() << "\n"
                        << color_wrap("Verity", "1;36") << ": " << verity_line << "\n"
                        << border << "\n";
                    if (hop_enabled) {
                        util::log_info("live hop updates are disabled; use --live-status (or YUME_LIVE_STATUS=1) to update periodically");
                    }
                } else {
                    util::set_status_line(status_block_builder());
                }
                summary_once = true;
            }

            auto derive_hop_key = [&](const crypto::Bytes& key) -> crypto::Bytes {
                if (!hop_enabled || hop_interval_ms == 0) {
                    return key;
                }
                std::uint64_t hop_id = inner::hop_id_from_time_ms(util::now_ms(), hop_interval_ms, hop_offset_ms);
                return inner::derive_hop_key(key, hop_id);
            };
            auto decrypt_control_payload = [&](const crypto::Bytes& key,
                                               uint8_t frame_type,
                                               uint8_t stream_id,
                                               const crypto::Bytes& blob) -> crypto::Bytes {
                if (!hop_enabled || hop_interval_ms == 0) {
                    return inner::decrypt_payload(key, frame_type, stream_id, blob);
                }
                std::uint64_t hop_id = inner::hop_id_from_time_ms(util::now_ms(), hop_interval_ms, hop_offset_ms);
                std::uint64_t candidates[3] = {hop_id, hop_id > 0 ? hop_id - 1 : hop_id, hop_id + 1};
                for (std::size_t i = 0; i < 3; ++i) {
                    std::uint64_t id = candidates[i];
                    if (i == 1 && hop_id == 0) {
                        continue;
                    }
                    crypto::Bytes hop_key = inner::derive_hop_key(key, id);
                    try {
                        return inner::decrypt_payload(hop_key, frame_type, stream_id, blob);
                    } catch (...) {
                    }
                }
                throw std::runtime_error("control decrypt failed");
            };

            auto send_control_frame = [&](const nlohmann::json& req) {
                std::string payload_str = req.dump();
                crypto::Bytes payload(payload_str.begin(), payload_str.end());
                uint16_t flags = 0;
                if (inner_key.has_value()) {
                    crypto::Bytes key = derive_hop_key(*inner_key);
                    payload = inner::encrypt_payload(key, protocol::CONTROL, 0, payload);
                    flags |= protocol::kFlagInnerEncrypted;
                }
                protocol::Frame frame{{static_cast<uint32_t>(payload.size()), protocol::CONTROL, 0, flags}, payload};
                protocol::send_frame(stream, frame);
            };

            auto send_control_request = [&](const nlohmann::json& req) -> nlohmann::json {
                send_control_frame(req);
                auto resp_frame = protocol::read_frame(stream);
                if (resp_frame.header.type != protocol::CONTROL) {
                    throw std::runtime_error("unexpected control response");
                }
                crypto::Bytes payload = resp_frame.payload;
                if (inner_key.has_value()) {
                    if ((resp_frame.header.flags & protocol::kFlagInnerEncrypted) == 0) {
                        throw std::runtime_error("control response missing inner encryption");
                    }
                    payload = decrypt_control_payload(*inner_key, protocol::CONTROL, resp_frame.header.stream_id, resp_frame.payload);
                }
                nlohmann::json out;
                out = nlohmann::json::parse(std::string(payload.begin(), payload.end()));
                return out;
            };

            if (cfg.server_in_charge || cfg.allow_exec) {
                nlohmann::json reg;
                reg["cmd"] = "register";
                reg["hostname"] = get_system_hostname();
                reg["wan_ip"] = "";
                reg["server_in_charge"] = cfg.server_in_charge;
                reg["allow_exec"] = cfg.allow_exec;
                send_control_frame(reg);
            }

            if (args.list_controlled) {
                nlohmann::json req;
                req["cmd"] = "list";
                auto resp = send_control_request(req);
                if (resp.contains("error")) {
                    util::log_error(resp["error"].get<std::string>());
                    return 1;
                }
                if (!resp.contains("clients")) {
                    util::log_error("control list missing clients");
                    return 1;
                }
                const auto& clients = resp["clients"];
                if (!clients.is_array() || clients.empty()) {
                    std::cout << "no controlled clients\n";
                    return 0;
                }
                for (const auto& item : clients) {
                    std::string perms;
                    const bool allow_exec = item.value("allow_exec", false);
                    const bool server_in_charge = item.value("server_in_charge", false);
                    if (server_in_charge) {
                        perms += "server-in-charge";
                    }
                    if (allow_exec) {
                        if (!perms.empty()) perms += ",";
                        perms += "exec";
                    }
                    if (perms.empty()) {
                        perms = "none";
                    }
                    std::cout << "id=" << item.value("id", "")
                              << " host=" << item.value("hostname", "")
                              << " wan=" << item.value("wan_ip", "")
                              << " perms=" << perms << "\n";
                }
                return 0;
            }

            if (args.control_mode) {
                nlohmann::json req;
                req["cmd"] = "attach";
                req["id"] = args.control_id;
                auto resp = send_control_request(req);
                if (!resp.value("ok", false)) {
                    util::log_error(resp.value("error", "control attach failed"));
                    return 1;
                }
                std::string perms;
                if (resp.value("server_in_charge", false)) {
                    perms += "server-in-charge";
                }
                if (resp.value("allow_exec", false)) {
                    if (!perms.empty()) perms += ",";
                    perms += "exec";
                }
                if (perms.empty()) {
                    perms = "none";
                }
                util::log_info("attached to id=" + resp.value("id", "") +
                               " host=" + resp.value("hostname", "") +
                               " wan=" + resp.value("wan_ip", "") +
                               " perms=" + perms);
            }

            auto tunnel = std::make_shared<Tunnel>(std::move(stream));
            set_active_runtime(&io, tunnel);
            if (inner_key.has_value()) {
                tunnel->set_inner_key(*inner_key);
            }
            tunnel->set_hop(hop_enabled, hop_interval_ms, hop_offset_ms);
            tunnel->set_server_in_charge(cfg.server_in_charge);
            tunnel->set_allow_exec(cfg.allow_exec);
            std::string close_reason;
            auto hop_status_stop = std::make_shared<std::atomic<bool>>(false);
            tunnel->set_close_handler([&close_reason, &io, hop_status_stop](const std::string& reason) {
                close_reason = reason;
                hop_status_stop->store(true);
                io.stop();
            });
            RelayRuntime::Options relay_opts;
            relay_opts.identity_path = cfg.identity;
            relay_opts.hostname = get_system_hostname();
            relay_opts.preferred_name = cfg.preferred_name;
            relay_opts.preferred_id = cfg.preferred_id;
            relay_opts.instance_name = cfg.instance_name.empty()
                ? yume::identity::derive_instance_key(cfg.server + ":" + cfg.identity)
                : cfg.instance_name;
            relay_opts.relay_mode = control::relay_mode_from_string(cfg.relay_mode);
            relay_opts.allow_inbound_admin = cfg.allow_inbound_admin;
            relay_opts.allow_outbound_admin = cfg.allow_outbound_admin;
            relay_opts.allow_chat = cfg.allow_chat;
            relay_opts.allow_file = cfg.allow_file;
            relay_opts.allow_bytes = cfg.allow_bytes;
            relay_opts.history_enabled = cfg.history_enabled;
            relay_opts.history_dir = util::expand_user(cfg.history_dir);
            auto relay_runtime = std::make_shared<RelayRuntime>(tunnel, cfg, relay_opts);
            relay_runtime->set_stop_callback([&]() {
                stop_requested.store(true);
                announce_stopping();
                tunnel->stop("runtime stop");
                io.stop();
            });
            std::string relay_error;
            auto local_runtime = std::make_shared<yume::client::LocalRuntime>(local_runtime_path, relay_runtime);
            if (!local_runtime->start(&relay_error)) {
                util::log_warn("local attach disabled: " + relay_error);
                relay_error.clear();
            }
            tunnel->set_control_handler([relay_runtime](const nlohmann::json& json) {
                relay_runtime->on_control_message(json);
            });
            tunnel->set_inbound_open_handler([relay_runtime](uint8_t stream_id, const nlohmann::json& json) {
                relay_runtime->on_inbound_open(stream_id, json);
            });
            tunnel->start();
            IoThreadGroup io_threads(io, start_io_threads(io, cfg.io_threads));
            if (!relay_runtime->announce_presence(&relay_error)) {
                util::log_warn("relay presence unavailable: " + relay_error);
            }
            if (args.directory_mode) {
                auto endpoints = relay_runtime->request_directory(&relay_error);
                if (!relay_error.empty()) {
                    util::log_error(relay_error);
                    return 1;
                }
                for (const auto& endpoint : endpoints) {
                    std::cout << endpoint.endpoint_id
                              << " " << endpoint.display_name
                              << " kind=" << control::to_string(endpoint.endpoint_kind)
                              << " relay=" << control::to_string(endpoint.relay_mode)
                              << "\n";
                }
                return 0;
            }
            const char* relay_password_env = std::getenv("YUME_RELAY_PASSWORD");
            const std::string relay_password = relay_password_env ? relay_password_env : "";
            if (!args.chat_target.empty()) {
                if (!relay_runtime->open_chat(args.chat_target, relay_password, &relay_error)) {
                    util::log_error("chat open failed: " + relay_error);
                    return 1;
                }
            }
            if (!args.file_target.empty()) {
                if (!relay_runtime->send_file(args.file_target, args.file_path, relay_password, &relay_error)) {
                    util::log_error("file send failed: " + relay_error);
                    return 1;
                }
            }
            if (!args.bytes_target.empty()) {
                if (!relay_runtime->send_bytes_path(args.bytes_target, args.bytes_path, relay_password, &relay_error)) {
                    util::log_error("bytes send failed: " + relay_error);
                    return 1;
                }
            }
            if (!args.admin_target.empty()) {
                if (!relay_runtime->admin_attach(args.admin_target, &relay_error)) {
                    util::log_error("admin attach failed: " + relay_error);
                    return 1;
                }
            }
            std::thread hop_status_thread;
            if (live_status_enabled) {
                if (status_block_builder && hop_enabled) {
                    // Avoid aliasing with hop interval (e.g. 500ms hop + 500ms refresh looks frozen).
                    // Keep cadence human-readable to reduce terminal churn.
                    const int refresh_raw = static_cast<int>(hop_interval_ms / 2) + 137;
                    const auto refresh_ms = std::chrono::milliseconds(
                        std::clamp<int>(refresh_raw, 300, 1200));
                    hop_status_thread = std::thread([hop_status_stop, status_block_builder, refresh_ms]() {
                        while (!hop_status_stop->load()) {
                            util::set_status_line(status_block_builder());
                            std::this_thread::sleep_for(refresh_ms);
                        }
                        util::clear_status_line();
                    });
                } else if (status_block_builder) {
                    util::set_status_line(status_block_builder());
                }
            }
            struct HopStatusGuard {
                std::shared_ptr<std::atomic<bool>> stop;
                std::thread* thread{nullptr};
                ~HopStatusGuard() {
                    if (stop) {
                        stop->store(true);
                    }
                    if (thread && thread->joinable()) {
                        thread->join();
                    }
                    util::clear_status_line();
                }
            } hop_guard{hop_status_stop, &hop_status_thread};

            auto console_stop = std::make_shared<std::atomic<bool>>(false);
            std::thread console_thread;
            const bool console_enabled =
                !cfg.non_interactive &&
                is_tty_stdin() &&
                parse_env_bool("YUME_COMMAND_CONSOLE", true) &&
                args.run_cmd.empty() &&
                args.exec_cmd.empty() &&
                !args.list_controlled &&
                (cfg.socks_port > 0 || use_reverse || args.lport > 0 ||
                 args.directory_mode || !args.chat_target.empty() ||
                 !args.file_target.empty() || !args.bytes_target.empty() ||
                 !args.admin_target.empty());
            if (console_enabled) {
                util::log_info("Console: help | whoami | status | directory | invites | chat <peer> | send <text> | send-file <peer> <path> | send-bytes <peer> <path> | accept <invite> <password> | reject <invite> [reason] | history [peer] | history-delete <peer|all> | admin attach <peer> | exec <cmd> | quit");
                console_thread = std::thread([console_stop,
                                              &stop_requested,
                                              &announce_stopping,
                                              &io,
                                              tunnel,
                                              local_runtime,
                                              status_block_builder,
                                              relay_runtime]() {
                    while (!console_stop->load()) {
                        std::string line;
                        if (!read_stdin_line_with_timeout(&line, 250)) {
                            continue;
                        }
                        line = trim_copy(line);
                        if (line.empty()) {
                            continue;
                        }
                        if (line == "help") {
                            util::log_info("Commands: help | whoami | status | directory | invites | chat <peer> | send <text> | send-file <peer> <path> | send-bytes <peer> <path> | accept <invite> <password> | reject <invite> [reason] | history [peer] | history-delete <peer|all> | admin attach <peer> | admin status | admin sessions | admin stop | exec <cmd> | quit");
                            continue;
                        }
                        if (line == "whoami") {
                            auto self = relay_runtime->self_info();
                            util::log_info("id=" + self.endpoint_id + " name=" + self.display_name + " relay=" + control::to_string(self.relay_mode));
                            continue;
                        }
                        if (line == "status") {
                            if (status_block_builder) {
                                util::clear_status_line();
                                std::cout << status_block_builder() << std::flush;
                            } else {
                                util::log_info("status is not available yet");
                            }
                            std::cout << "\n" << relay_runtime->status_json().dump(2) << std::endl;
                            continue;
                        }
                        if (line == "directory") {
                            std::string error;
                            auto entries = relay_runtime->request_directory(&error);
                            if (!error.empty()) {
                                util::log_warn(error);
                                continue;
                            }
                            for (const auto& entry : entries) {
                                std::cout << entry.endpoint_id << " " << entry.display_name
                                          << " kind=" << control::to_string(entry.endpoint_kind)
                                          << " relay=" << control::to_string(entry.relay_mode)
                                          << std::endl;
                            }
                            continue;
                        }
                        if (line == "invites") {
                            auto invites = relay_runtime->pending_invites();
                            if (invites.empty()) {
                                util::log_info("no pending invites");
                                continue;
                            }
                            for (const auto& invite : invites) {
                                std::cout << invite.invite_id << " from="
                                          << (invite.from_display_name.empty() ? invite.from_endpoint_id : invite.from_display_name)
                                          << " kind=" << control::to_string(invite.channel_kind) << std::endl;
                            }
                            continue;
                        }
                        if (line.rfind("chat ", 0) == 0) {
                            auto rest = trim_copy(line.substr(5));
                            const char* env_pw = std::getenv("YUME_RELAY_PASSWORD");
                            std::string password = env_pw ? env_pw : "";
                            if (password.empty()) {
                                util::log_warn("set YUME_RELAY_PASSWORD before opening a chat");
                                continue;
                            }
                            std::string error;
                            if (!relay_runtime->open_chat(rest, password, &error)) {
                                util::log_warn(error);
                            } else {
                                util::log_info("chat invite sent to " + rest);
                            }
                            continue;
                        }
                        if (line.rfind("send-file ", 0) == 0) {
                            std::istringstream iss(line.substr(10));
                            std::string peer;
                            std::string path;
                            iss >> peer >> path;
                            const char* env_pw = std::getenv("YUME_RELAY_PASSWORD");
                            std::string password = env_pw ? env_pw : "";
                            if (peer.empty() || path.empty() || password.empty()) {
                                util::log_warn("usage: send-file <peer> <path> with YUME_RELAY_PASSWORD set");
                                continue;
                            }
                            std::string error;
                            if (!relay_runtime->send_file(peer, path, password, &error)) {
                                util::log_warn(error);
                            }
                            continue;
                        }
                        if (line.rfind("send-bytes ", 0) == 0) {
                            std::istringstream iss(line.substr(11));
                            std::string peer;
                            std::string path;
                            iss >> peer >> path;
                            const char* env_pw = std::getenv("YUME_RELAY_PASSWORD");
                            std::string password = env_pw ? env_pw : "";
                            if (peer.empty() || path.empty() || password.empty()) {
                                util::log_warn("usage: send-bytes <peer> <path> with YUME_RELAY_PASSWORD set");
                                continue;
                            }
                            std::string error;
                            if (!relay_runtime->send_bytes_path(peer, path, password, &error)) {
                                util::log_warn(error);
                            }
                            continue;
                        }
                        if (line.rfind("send ", 0) == 0) {
                            std::string error;
                            if (!relay_runtime->send_chat(trim_copy(line.substr(5)), &error)) {
                                util::log_warn(error);
                            }
                            continue;
                        }
                        if (line.rfind("accept ", 0) == 0) {
                            std::istringstream iss(line.substr(7));
                            std::string invite_id;
                            std::string password;
                            iss >> invite_id >> password;
                            if (invite_id.empty() || password.empty()) {
                                util::log_warn("usage: accept <invite> <password>");
                                continue;
                            }
                            std::string error;
                            if (!relay_runtime->accept_invite(invite_id, password, &error)) {
                                util::log_warn(error);
                            }
                            continue;
                        }
                        if (line.rfind("reject ", 0) == 0) {
                            std::istringstream iss(line.substr(7));
                            std::string invite_id;
                            iss >> invite_id;
                            std::string reason;
                            std::getline(iss, reason);
                            std::string error;
                            if (!relay_runtime->reject_invite(invite_id, trim_copy(reason), &error)) {
                                util::log_warn(error);
                            }
                            continue;
                        }
                        if (line.rfind("history-delete ", 0) == 0) {
                            std::string arg = trim_copy(line.substr(15));
                            nlohmann::json req{{"op", "history.delete"}, {"args", nlohmann::json::object()}};
                            if (arg != "all" && !arg.empty()) {
                                req["args"]["peer_id"] = arg;
                            }
                            relay_runtime->handle_local_request(req);
                            util::log_info("history deleted");
                            continue;
                        }
                        if (line.rfind("history", 0) == 0) {
                            std::string arg = trim_copy(line.substr(7));
                            nlohmann::json req{{"op", "history.list"}, {"args", nlohmann::json::object()}};
                            if (!arg.empty()) {
                                req["args"]["peer_id"] = arg;
                            }
                            auto resp = relay_runtime->handle_local_request(req);
                            if (!resp.value("ok", false)) {
                                util::log_warn(resp.value("error", "history failed"));
                                continue;
                            }
                            for (const auto& item : resp["result"]) {
                                std::cout << item.value("direction", "?") << " "
                                          << item.value("peer_name", item.value("peer_id", "")) << " "
                                          << item.value("text", "") << std::endl;
                            }
                            continue;
                        }
                        if (line.rfind("admin attach ", 0) == 0) {
                            std::string peer = trim_copy(line.substr(13));
                            std::string error;
                            if (!relay_runtime->admin_attach(peer, &error)) {
                                util::log_warn(error);
                            }
                            continue;
                        }
                        if (line == "admin status" || line == "admin sessions" || line == "admin stop") {
                            const std::string local_op =
                                (line == "admin stop") ? "admin.stop" :
                                ((line == "admin sessions") ? "admin.sessions" : "admin.status");
                            auto resp = relay_runtime->handle_local_request({{"op", local_op}, {"args", nlohmann::json::object()}});
                            if (!resp.value("ok", false)) {
                                util::log_warn(resp.value("error", "admin request failed"));
                            } else {
                                std::cout << resp["result"].dump(2) << std::endl;
                            }
                            continue;
                        }
                        if (line == "quit" || line == "exit" || line == "stop") {
                            stop_requested.store(true);
                            announce_stopping();
                            tunnel->stop("console stop");
                            io.stop();
                            break;
                        }
                        if (line.rfind("exec ", 0) == 0) {
                            std::string cmd = trim_copy(line.substr(5));
                            if (cmd.empty()) {
                                util::log_warn("usage: exec <command>");
                                continue;
                            }
                            uint8_t stream_id = tunnel->reserve_stream_id();
                            if (stream_id == 0) {
                                util::log_warn("no stream id available for exec");
                                continue;
                            }
                            tunnel->register_stream(
                                stream_id,
                                [stream_id](const Tunnel::Bytes& data) {
                                    std::cout.write(reinterpret_cast<const char*>(data.data()), data.size());
                                    std::cout.flush();
                                },
                                [stream_id]() {
                                    util::log_info("exec stream " + std::to_string(static_cast<int>(stream_id)) + " closed");
                                });
                            tunnel->send_exec(stream_id, cmd);
                            util::log_info("exec sent on stream " + std::to_string(static_cast<int>(stream_id)));
                            continue;
                        }
                        util::log_warn("unknown command: " + line);
                    }
                });
            }
            struct ConsoleGuard {
                std::shared_ptr<std::atomic<bool>> stop;
                std::thread* thread{nullptr};
                ~ConsoleGuard() {
                    if (stop) {
                        stop->store(true);
                    }
                    if (thread && thread->joinable()) {
                        thread->join();
                    }
                }
            } console_guard{console_stop, &console_thread};

            struct ReverseTarget {
                std::string host;
                int port;
            };
            auto reverse_targets = std::make_shared<std::unordered_map<uint8_t, ReverseTarget>>();
            auto reverse_sessions = std::make_shared<std::unordered_map<uint8_t, std::shared_ptr<ReverseForwardSession>>>();
            tunnel->set_reverse_handler([reverse_targets, reverse_sessions, tunnel](uint8_t listen_id, uint8_t stream_id) {
                auto it = reverse_targets->find(listen_id);
                if (it == reverse_targets->end()) {
                    tunnel->send_open_ack(stream_id, false, "unknown reverse listener");
                    return;
                }
                auto session = std::make_shared<ReverseForwardSession>(tunnel, stream_id, it->second.host, it->second.port);
                (*reverse_sessions)[stream_id] = session;
                session->start();
            });

            if (use_reverse) {
                uint8_t listen_id = tunnel->reserve_stream_id();
                if (listen_id == 0) {
                    util::log_error("no stream ids available for remote forward");
                    return 1;
                }
                (*reverse_targets)[listen_id] = ReverseTarget{reverse_host, reverse_port};
                const bool auto_random = reverse_server_in_charge_auto && !reverse_server_in_charge_manual;
                const bool reclaim = !reverse_server_in_charge_auto;
                const int min_port = auto_random ? reverse_auto_min_port : 0;
                const int max_port = auto_random ? reverse_auto_max_port : 0;
                if (auto_random) {
                    util::log_info("requesting server-in-charge reverse SSH on random port " +
                                   std::to_string(min_port) + "-" + std::to_string(max_port));
                } else {
                    util::log_info("requesting remote listener on port " + std::to_string(reverse_listen_port));
                }
                tunnel->request_remote_listen(
                    listen_id, reverse_listen_port,
                    [listen_port = reverse_listen_port,
                     auto_mode = reverse_server_in_charge_auto](bool ok, const std::string& reason) {
                        if (ok) {
                            int active_port = listen_port;
                            if (!reason.empty()) {
                                try {
                                    auto json = nlohmann::json::parse(reason);
                                    active_port = json.value("port", active_port);
                                } catch (...) {
                                    try {
                                        active_port = std::stoi(reason);
                                    } catch (...) {
                                    }
                                }
                            }
                            util::log_info("remote listener active on port " + std::to_string(active_port));
                            if (auto_mode) {
                                util::log_info("server-in-charge ready: server can reach client SSH via 127.0.0.1:" +
                                               std::to_string(active_port) + " -> 127.0.0.1:22");
                            }
                        } else {
                            util::log_error("remote listener failed: " + reason);
                        }
                    },
                    reclaim, min_port, max_port);
            }

            if (!args.exec_cmd.empty()) {
                uint8_t stream_id = tunnel->reserve_stream_id();
                if (stream_id == 0) {
                    util::log_error("no stream ids available for exec");
                    return 1;
                }
                auto done = std::make_shared<std::atomic<bool>>(false);
                tunnel->register_stream(stream_id,
                                        [stream_id](const Tunnel::Bytes& data) {
                                            std::cout.write(reinterpret_cast<const char*>(data.data()), data.size());
                                            std::cout.flush();
                                        },
                                        [done, &io]() {
                                            done->store(true);
                                            io.stop();
                                        });
                tunnel->send_exec(stream_id, args.exec_cmd);
                io_threads.wait();
                if (!close_reason.empty()) {
                    throw std::runtime_error("tunnel closed: " + close_reason);
                }
                return 0;
            }

            if (!args.run_cmd.empty()) {
                int port = cfg.socks_port > 0 ? cfg.socks_port : 0;
                auto socks = std::make_shared<SocksServer>(io, port, tunnel, cfg.allow_udp);
                socks->start();
                int actual_port = socks->port();
                if (actual_port <= 0) {
                    util::log_error("failed to start local SOCKS5 proxy for --run");
                    return 1;
                }
                util::log_info("running local command via SOCKS5 127.0.0.1:" + std::to_string(actual_port));
                auto work = boost::asio::make_work_guard(io);
                std::string cmd = maybe_force_ipv4(args.run_cmd, true);
                if (cmd == args.run_cmd) {
                    util::log_warn("IPv4-only enforced; if your command supports IPv4 forcing, add it explicitly.");
                }
                std::string self_path;
                try {
                    self_path = std::filesystem::absolute(argv[0]).string();
                } catch (...) {
                    self_path.clear();
                }
                cmd = wrap_ssh_with_proxy(cmd, actual_port, self_path);
                int code = run_local_command_with_proxy(cmd, actual_port, true);
                work.reset();
                io.stop();
                io_threads.wait();
                return code == 0 ? 0 : 1;
            }

            if (args.lport > 0 || !args.rhost.empty() || args.rport > 0) {
                if (args.lport <= 0 || args.rhost.empty() || args.rport <= 0) {
                    util::log_error("--lport, --rhost, and --rport must be set together");
                    return 1;
                }

                if (cfg.allow_udp) {
                    auto forward = std::make_shared<UdpForwardServer>(io, args.lport, args.rhost, args.rport, tunnel,
                                                                      cfg.allow_local_ip);
                    forward->start();
                    util::log_info("udp forwarding localhost:" + std::to_string(args.lport) + " -> " +
                                   args.rhost + ":" + std::to_string(args.rport));
                } else {
                    auto forward = std::make_shared<ForwardServer>(io, args.lport, args.rhost, args.rport, tunnel,
                                                                   cfg.allow_local_ip);
                    forward->start();
                    util::log_info("forwarding localhost:" + std::to_string(args.lport) + " -> " +
                                   args.rhost + ":" + std::to_string(args.rport));
                }
                io_threads.wait();
                if (stop_requested.load()) {
                    announce_stopping();
                    return 130;
                }
                if (!close_reason.empty()) {
                    throw std::runtime_error("tunnel closed: " + close_reason);
                }
                return 0;
            }

            if (cfg.socks_port > 0) {
                auto socks = std::make_shared<SocksServer>(io, cfg.socks_port, tunnel, cfg.allow_udp);
                socks->start();
                util::log_info("SOCKS5 listening on 127.0.0.1:" + std::to_string(cfg.socks_port));
                io_threads.wait();
                if (stop_requested.load()) {
                    announce_stopping();
                    return 130;
                }
                if (!close_reason.empty()) {
                    throw std::runtime_error("tunnel closed: " + close_reason);
                }
                return 0;
            }

            if (use_reverse) {
                io_threads.wait();
                if (stop_requested.load()) {
                    announce_stopping();
                    return 130;
                }
                if (!close_reason.empty()) {
                    throw std::runtime_error("tunnel closed: " + close_reason);
                }
                return 0;
            }

            if (!args.chat_target.empty() || !args.file_target.empty() ||
                !args.bytes_target.empty() || !args.admin_target.empty()) {
                io_threads.wait();
                if (stop_requested.load()) {
                    announce_stopping();
                    return 130;
                }
                if (!close_reason.empty()) {
                    throw std::runtime_error("tunnel closed: " + close_reason);
                }
                return 0;
            }

            util::log_warn("no mode selected");
            return 1;
        } catch (const FatalError& ex) {
            if (stop_requested.load()) {
                announce_stopping();
                return 130;
            }
            util::log_error(ex.what());
            return 1;
        } catch (const std::exception& ex) {
            if (stop_requested.load()) {
                announce_stopping();
                return 130;
            }
            attempt++;
            int backoff = std::min(30, 1 << std::min(attempt, 5));
            util::log_warn(std::string("connection failed: ") + ex.what());
            util::log_warn("retrying in " + std::to_string(backoff) + "s");
            for (int i = 0; i < backoff * 10; ++i) {
                if (stop_requested.load()) {
                    announce_stopping();
                    return 130;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }
}

}  // namespace yume::client
