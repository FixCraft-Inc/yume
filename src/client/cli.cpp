/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/cli.hpp"

#include <iomanip>
#include <iostream>
#include <functional>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
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

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509.h>
#include <openssl/sha.h>

#include "client/forward.hpp"
#include "client/socks.hpp"
#include "client/tunnel.hpp"
#include "core/crypto.hpp"
#include "core/inner_crypto.hpp"
#include "core/obfs.hpp"
#include "core/protocol.hpp"
#include "core/version.hpp"
#include "core/tls_fingerprint.hpp"
#include "core/tls_stealth.hpp"
#include "core/tls_metrics.hpp"
#include "util.hpp"
#include <nlohmann/json.hpp>

namespace yume::client {

namespace {
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
    bool accept_monitoring{false};
    bool save_server{false};
    bool require_anonym{false};
    bool boring{false};
    bool boring_override{false};
    bool non_interactive{false};
    bool io_threads_override{false};
    bool server_in_charge{false};
    bool server_in_charge_override{false};
    bool allow_exec{false};
    bool allow_exec_override{false};
    bool control_mode{false};
    bool list_controlled{false};
    std::string control_id;
    std::string exec_cmd;
    std::string ssh_L;
    std::string ssh_R;
};

ParsedArgs parse_args(int argc, char** argv) {
    ParsedArgs args;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--config" && i + 1 < argc) {
            args.config_path = argv[++i];
            args.config_specified = true;
        } else if (arg == "--help" || arg == "-h") {
            args.help = true;
        } else if (arg == "--server" && i + 1 < argc) {
            args.server = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            args.port = std::stoi(argv[++i]);
        } else if ((arg == "--auth" || arg == "-i") && i + 1 < argc) {
            args.identity = argv[++i];
        } else if (arg == "--socks" && i + 1 < argc) {
            args.socks_port = std::stoi(argv[++i]);
        } else if (arg == "--threads" && i + 1 < argc) {
            args.io_threads = std::stoi(argv[++i]);
            args.io_threads_override = true;
        } else if (arg == "--lport" && i + 1 < argc) {
            args.lport = std::stoi(argv[++i]);
        } else if (arg == "--rhost" && i + 1 < argc) {
            args.rhost = argv[++i];
        } else if (arg == "--rport" && i + 1 < argc) {
            args.rport = std::stoi(argv[++i]);
        } else if ((arg == "--run" || arg == "-c" || arg == "--cmd") && i + 1 < argc) {
            args.run_cmd = argv[++i];
        } else if (arg == "--run-ipv4") {
            args.run_ipv4 = true;
        } else if (arg == "--proxycmd") {
            args.proxycmd = true;
        } else if (arg == "--dest" && i + 1 < argc) {
            args.dest_host = argv[++i];
        } else if (arg == "--dport" && i + 1 < argc) {
            args.dest_port = std::stoi(argv[++i]);
        } else if (arg == "--require-anonym") {
            args.require_anonym = true;
        } else if (arg == "--anonym-ca-cert" && i + 1 < argc) {
            args.anonym_ca_cert = argv[++i];
        } else if (arg == "-L" && i + 1 < argc) {
            args.ssh_L = argv[++i];
        } else if (arg == "-R" && i + 1 < argc) {
            args.ssh_R = argv[++i];
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
        } else if (arg == "--hop-interval" && i + 1 < argc) {
            args.hop_interval_ms = static_cast<std::uint32_t>(std::stoul(argv[++i]));
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
        } else if (arg == "--id" && i + 1 < argc) {
            args.control_id = argv[++i];
        } else if (arg == "--list-controlled") {
            args.list_controlled = true;
        } else if (arg == "--pq-pub" && i + 1 < argc) {
            args.pq_public_key = argv[++i];
        } else if (arg == "--tls-ca" && i + 1 < argc) {
            args.tls_ca_cert = argv[++i];
        } else if (arg == "--tls-pin" && i + 1 < argc) {
            args.tls_pin_sha256 = argv[++i];
        } else if (arg == "--no-stealth") {
            args.tls_stealth = false;
            args.tls_stealth_override = true;
        } else if (arg == "--profile" && i + 1 < argc) {
            args.tls_stealth_profile = argv[++i];
        } else if (arg == "--tls-stealth-rotate") {
            args.tls_stealth_rotate = true;
        } else if (arg == "--tls-stealth-rotation-interval" && i + 1 < argc) {
            args.tls_stealth_rotation_interval = std::stoul(argv[++i]);
        } else if (arg == "--tls-fingerprint-log") {
            args.tls_fingerprint_log = true;
        } else if (arg == "--tls-fingerprint-log-path" && i + 1 < argc) {
            args.tls_fingerprint_log_path = argv[++i];
        } else if (arg == "--tls-fingerprint-verify") {
            args.tls_fingerprint_verify = true;
        } else if (arg == "--tls-fingerprint-test-endpoint" && i + 1 < argc) {
            args.tls_fingerprint_test_endpoint = argv[++i];
        } else if (arg == "--accept-monitoring") {
            args.accept_monitoring = true;
        } else if (arg == "--save-server") {
            args.save_server = true;
        } else if (arg == "--boring") {
            args.boring = true;
            args.boring_override = true;
        } else if (arg == "--non-interactive") {
            args.non_interactive = true;
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
                  const std::string& identity_path,
                  const std::optional<crypto::Bytes>& pq_ciphertext,
                  const std::optional<crypto::Bytes>& pq_salt,
                  const std::optional<std::string>& inner_mode,
                  const std::optional<bool>& inner_hop,
                  const std::optional<inner::KdfParams>& inner_kdf) {
    protocol::Frame challenge = protocol::read_frame(stream);
    if (challenge.header.type != protocol::AUTH) {
        throw std::runtime_error("server did not send AUTH challenge");
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

void print_help() {
    std::cout
        << "yume - YUME client\n\n"
        << "Usage:\n"
        << "  yume --server <host> -i <id_ed25519> [--socks 1080]\n"
        << "  yume --server <host> -i <id_ed25519> --lport <local> --rhost <host> --rport <port>\n"
        << "  yume --server <host> -i <id_ed25519> --run \"<command>\"\n"
        << "  yume --help\n\n"
        << "Required:\n"
        << "  --server <host>       Server address\n"
        << "  -i, --auth <path>     Identity key file path\n\n"
        << "Optional:\n"
        << "  --socks <port>       Start SOCKS5 proxy on specified port\n"
        << "  --threads <n>        IO thread count (0 = auto-detect)\n"
        << "  --lport <port>       Local port to forward\n"
        << "  --rhost <host>       Forward destination host\n"
        << "  --rport <port>       Forward destination port\n"
        << "  --udp                Enable UDP for forwards/SOCKS5\n"
        << "  --tcp                Force TCP only (default)\n"
        << "  --allow-local-ip     Allow forwarding to private/loopback IPs\n"
        << "  --server-in-charge   Allow server to control this client\n"
        << "  --allow-exec         Allow server to execute commands\n"
        << "  --exec <cmd>         Execute command (with --control) or enable exec\n"
        << "  --control [id]       Control mode for registered client\n"
        << "  --id <id>            Target client ID for control mode\n"
        << "  --list-controlled    List all controlled clients\n"
        << "  --inner              Enable inner encryption\n"
        << "  --inner-heavy        Use heavy KDF (default with --inner)\n"
        << "  --inner-light        Use lighter KDF\n"
        << "  --hop                Enable inner key hopping\n"
        << "  --no-hop             Disable inner key hopping\n"
        << "  --hop-interval <ms>  Hop interval in ms (250-1000 recommended)\n"
        << "  --pq-pub <path>      Override post-quantum public key\n"
        << "  --anonym-ca-cert <path> CA certificate for anonymity verification\n"
        << "  --tls-ca <path>      Custom CA for TLS verification\n"
        << "  --tls-pin <sha256>   Pin server TLS certificate fingerprint\n"
        << "  --profile <name>     TLS stealth profile: chrome (default), firefox, safari\n"
        << "  --no-stealth         Disable TLS stealth mode (ON by default)\n"
        << "  --tls-stealth-rotate Rotate between stealth profiles\n"
        << "  --tls-stealth-rotation-interval <n>  Profile rotation interval (connections)\n"
        << "  --tls-fingerprint-log  Log TLS fingerprint metrics\n"
        << "  --tls-fingerprint-log-path <path>  Path for fingerprint logs\n"
        << "  --tls-fingerprint-verify  Verify fingerprint with test endpoint\n"
        << "  --tls-fingerprint-test-endpoint <host>  Test endpoint for verification\n"
        << "  --run, -c, --cmd <cmd>  Run command locally with YUME proxy\n"
        << "                          (SSH auto-wraps ProxyCommand via SOCKS)\n"
        << "  --run-ipv4           Prefer IPv4 for --run commands\n"
        << "  --proxycmd           Internal SSH ProxyCommand helper\n"
        << "  --require-anonym     Abort if server not in anonymous mode\n"
        << "  -L [bind:]lport:host:port  SSH-style local port forward\n"
        << "  -R [bind:]rport:host:port  SSH-style remote port forward\n"
        << "  --boring             Minimal output without emojis\n"
        << "  --non-interactive    Disable live status line updates\n"
        << "  --config <path>      Configuration file path\n"
        << "  --accept-monitoring  Accept monitoring without warning\n"
        << "  --save-server        Save server to configuration\n"
        << "  -h, --help           Show this help message\n";
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

void run_io_threads(boost::asio::io_context& io, int requested) {
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

std::vector<std::thread> start_io_threads(boost::asio::io_context& io, int requested) {
    int threads = resolve_io_threads(requested);
    std::vector<std::thread> workers;
    workers.reserve(static_cast<size_t>(threads));
    for (int i = 0; i < threads; ++i) {
        workers.emplace_back([&io]() { io.run(); });
    }
    return workers;
}

}  // namespace

int Cli::run(int argc, char** argv) {
    util::init_logging();

    ParsedArgs args = parse_args(argc, argv);
    if (args.proxycmd) {
        int socks_port = args.socks_port > 0 ? args.socks_port : 1080;
        return run_proxycmd(args.dest_host, args.dest_port, socks_port);
    }
    if (args.help) {
        print_help();
        return 0;
    }
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
            if (json.contains("allow_exec") && !args.allow_exec_override) {
                cfg.allow_exec = json["allow_exec"].get<bool>();
            }
            if (json.contains("pq_public_key") && cfg.pq_public_key.empty()) {
                cfg.pq_public_key = resolve_cfg_path(json["pq_public_key"].get<std::string>());
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
        cfg.identity = util::resolve_path(args.identity, config_dir, exe_dir);
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
        cfg.pq_public_key = util::resolve_path(args.pq_public_key, config_dir, exe_dir);
    }
    if (!args.anonym_ca_cert.empty()) {
        cfg.anonym_ca_cert = util::resolve_path(args.anonym_ca_cert, config_dir, exe_dir);
    }
    if (!args.tls_ca_cert.empty()) {
        cfg.tls_ca_cert = util::resolve_path(args.tls_ca_cert, config_dir, exe_dir);
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
    util::set_status_enabled(!cfg.non_interactive);
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

    if (cfg.inner_crypto && cfg.pq_public_key.empty()) {
        std::error_code ec;
        std::filesystem::path runtime_dir = std::filesystem::current_path(ec);
        std::filesystem::path exe_dir;
        std::string self_path = get_self_path(argv[0]);
        if (!self_path.empty()) {
            exe_dir = std::filesystem::path(self_path).parent_path();
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
        try_set(runtime_dir);
        try_set(exe_dir);
        if (!cfg.pq_public_key.empty()) {
            util::log_info("using pq_public_key from runtime directory");
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
        json["allow_exec"] = cfg.allow_exec;
        if (!cfg.pq_public_key.empty()) json["pq_public_key"] = cfg.pq_public_key;
        if (!cfg.anonym_ca_cert.empty()) json["anonym_ca_cert"] = cfg.anonym_ca_cert;
        if (!cfg.tls_ca_cert.empty()) json["tls_ca_cert"] = cfg.tls_ca_cert;
        if (!cfg.tls_pin_sha256.empty()) json["tls_pin"] = cfg.tls_pin_sha256;
        json["require_anonym"] = cfg.require_anonym;
        json["boring"] = cfg.boring;
        json["non_interactive"] = cfg.non_interactive;
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
    int attempt = 0;
    bool pq_warned = false;
    bool pq_reconnect_used = false;
    bool verified_once = false;
    for (;;) {
        bool summary_once = false;
        std::function<std::string()> status_block_builder;
        try {
            boost::asio::io_context io(resolve_io_threads(cfg.io_threads));
            
            // Initialize stealth mode if enabled
            std::unique_ptr<boost::asio::ssl::context> owned_ctx;
            boost::asio::ssl::context* ctx = nullptr;
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
                throw std::runtime_error("server offline, unable to establish connection (DNS resolution failed: " + std::string(ex.what()) + ")");
            }
            boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream(io, *ctx);
            try {
                boost::asio::connect(stream.next_layer(), endpoints);
            } catch (const boost::system::system_error& ex) {
                auto code = ex.code();
                if (code == boost::asio::error::connection_refused ||
                    code == boost::asio::error::host_unreachable ||
                    code == boost::asio::error::network_unreachable ||
                    code == boost::asio::error::timed_out ||
                    code == boost::asio::error::network_down) {
                    throw std::runtime_error("server offline, unable to establish connection");
                }
                throw std::runtime_error("server offline, unable to establish connection (" + std::string(ex.what()) + ")");
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
            stream.handshake(boost::asio::ssl::stream_base::client, hs_ec);
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

            // Log TLS fingerprint metrics if stealth mode is enabled
            if (cfg.tls_stealth_enabled && cfg.tls_fingerprint_log) {
                // Create fingerprint data (simplified - full implementation would parse ClientHello)
                tls_fingerprint::FingerprintData fingerprint;
                // In production, you'd capture and parse the actual ClientHello here
                
                // Get the current profile being used
                tls_fingerprint::BrowserProfile profile = 
                    tls_stealth::StealthManager::instance().get_context().current_profile();
                
                // Record the connection
                tls_metrics::MetricsManager::instance().record_connection_fingerprint(
                    cfg.server,
                    static_cast<uint16_t>(cfg.port),
                    fingerprint,
                    true,  // stealth_enabled
                    profile,
                    true,  // handshake_succeeded
                    static_cast<uint32_t>(handshake_duration.count()),
                    ""     // error_message
                );
            }

            inner::Config inner_cfg;
            inner_cfg.enabled = cfg.inner_crypto;
            inner_cfg.pq_public_key = cfg.pq_public_key;

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
                            "inner crypto disabled: PQ public key not configured (use --pq-pub or place pq_public.key next to the executable)";
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

            authenticate(stream, cfg.identity, pq_ciphertext, pq_salt, inner_mode, inner_hop, inner_kdf);
            util::log_info("authenticated to server");

            protocol::Frame anon_frame;
            try {
                anon_frame = protocol::read_frame(stream);
            } catch (const std::exception& ex) {
                throw std::runtime_error("this does not appear to be a yume server (failed to read server info)");
            }
            if (anon_frame.header.type != protocol::ANON) {
                throw std::runtime_error("this does not appear to be a yume server (unexpected response type)");
            }
            bool pq_reconnect = false;
            bool have_anon = false;
            bool verity_ok = false;
            crypto::EVP_PKEY_ptr sub_pub{nullptr, EVP_PKEY_free};
            crypto::EVP_PKEY_ptr ca_pub{nullptr, EVP_PKEY_free};
            bool sub_ok = false;
            bool ca_ok = false;
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
                throw std::runtime_error("this does not appear to be a yume server (invalid server response)");
            } catch (const std::exception& ex) {
                throw std::runtime_error("this does not appear to be a yume server (" + std::string(ex.what()) + ")");
            }
            if (server_version.empty() || server_version == "UNKNOWN") {
                throw std::runtime_error("this does not appear to be a yume server (no version info)");
            }

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
                if (hash.empty() || sig.empty() || ts.empty() || nonce.empty()) {
                    print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                    print_red("ANONYM PROOF IS INCOMPLETE");
                    return 1;
                }
                if (cfg.require_anonym && certfp.empty()) {
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
                if (std::llabs(now - ts_val) > 600) {
                    print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                    print_red("ANONYM PROOF EXPIRED OR NOT YET VALID");
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
                std::string peer_fp = get_peer_cert_fingerprint(pubkey.get(), stream.native_handle());
                if (!certfp.empty() && !peer_fp.empty() && certfp != peer_fp) {
                    print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                    print_red("ANONYM CERTIFICATE FINGERPRINT MISMATCH");
                    return 1;
                }
                std::string message = std::string(kAnonMsgPrefix) + hash + ":" + ts + ":" + nonce;
                if (!certfp.empty()) {
                    message += ":" + certfp;
                }
                crypto::Bytes msg_bytes(message.begin(), message.end());
                std::string sig_raw = util::base64_decode(sig);
                if (sig_raw.empty()) {
                    print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                    print_red("INVALID SIGNATURE FORMAT FROM SERVER");
                    return 1;
                }
                crypto::Bytes sig_bytes(sig_raw.begin(), sig_raw.end());
                bool ok_sig = crypto::verify_key(pubkey.get(), msg_bytes, sig_bytes);
                if (!ok_sig) {
                    print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                    print_red("THIS SERVER IS FORGING SIGNATURES, REPORT IT TO FIXCRAFT, INC. ASAP, ALSO FILE A COMPLAINT TO AN INTERNET AUTHORITY");
                    return 1;
                }
                if (!sub_cert_b64.empty()) {
                    if (cfg.anonym_ca_cert.empty()) {
                        print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                        print_red("ANONYM SUB CERT PROVIDED BUT NO --anonym-ca-cert SET");
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
                    bool ok_sub = crypto::verify_key(sub_key.get(), msg_bytes, sub_sig_bytes);
                    if (!ok_sub) {
                        print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                        print_red("ANONYM SUB SIGNATURE INVALID");
                        return 1;
                    }
                    sub_pub = std::move(sub_key);
                    sub_ok = true;
                }
                if (!cfg.anonym_ca_cert.empty() && sub_cert_b64.empty()) {
                    if (ca_sig.empty()) {
                        print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                        print_red("ANONYM CA SIGNATURE MISSING");
                        return 1;
                    }
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
                    bool ok_ca = crypto::verify_key(ca_key.get(), msg_bytes, ca_sig_bytes);
                    if (!ok_ca) {
                        print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                        print_red("ANONYM CA SIGNATURE INVALID");
                        return 1;
                    }
                    ca_pub = std::move(ca_key);
                    ca_ok = true;
                } else if (!cfg.anonym_ca_cert.empty() && !ca_sig.empty()) {
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
                    bool ok_ca = crypto::verify_key(ca_key.get(), msg_bytes, ca_sig_bytes);
                    if (!ok_ca) {
                        print_red("🛑🔺🔓 CRITICAL ERROR 🔓🔺🛑");
                        print_red("ANONYM CA SIGNATURE INVALID");
                        return 1;
                    }
                    ca_pub = std::move(ca_key);
                    ca_ok = true;
                } else if (!ca_sig.empty()) {
                    util::log_warn("anonym CA signature provided but no --anonym-ca-cert set; skipping CA verification");
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
                    print_red("TYPE: \"THIS MAY COMPROMISE MY PRIVACY\" to contine");
                    std::string line;
                    std::getline(std::cin, line);
                    if (line != "THIS MAY COMPROMISE MY PRIVACY") {
                        return 1;
                    }
                }
            }
            have_anon = true;
            verity_ok = (mode == "anonym");
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
                return std::string("Hopping: ") + hop_line + " - " + hop_freq + " | " + hop_last;
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
                    inner_line += cfg.inner_heavy ? " (heavy)" : " (light)";
                    if (have_inner_caps && server_inner_dual) {
                        inner_line += ", dual";
                    }
                }
                std::string server_display = color_wrap(cfg.server, "1;33");
                std::string verity_state = verity_ok ? "PASS" : "FAIL";
                std::string verity_line = color_wrap(verity_state, verity_ok ? "1;32" : "1;31");
                std::string header =
                    "Connected to " + server_display + ":\n" +
                    "VERSION: " + (server_version.empty() ? "UNKNOWN" : server_version) + "\n" +
                    "Connection: TLS\n" +
                    "Protection: " + protection_line + "\n" +
                    "Inner: " + inner_line + "\n";
                std::string footer = "FixCraft Verity: " + verity_line + "\n";
                const std::string border = "------------------------------------------";
                status_block_builder = [header, footer, border, build_hop_status_line]() {
                    return border + "\n" + header + build_hop_status_line() + "\n" + footer + border;
                };
                if (cfg.non_interactive) {
                    std::cout
                        << "Connected to " << server_display << ":\n"
                        << "VERSION: " << (server_version.empty() ? "UNKNOWN" : server_version) << "\n"
                        << "Connection: TLS\n"
                        << "Protection: " << protection_line << "\n"
                        << "Inner: " << inner_line << "\n"
                        << build_hop_status_line() << "\n"
                        << "FixCraft Verity: " << verity_line << "\n";
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
            if (inner_key.has_value()) {
                tunnel->set_inner_key(*inner_key);
            }
            tunnel->set_hop(hop_enabled, hop_interval_ms, hop_offset_ms);
            tunnel->set_server_in_charge(cfg.server_in_charge);
            tunnel->set_allow_exec(cfg.allow_exec);
            std::string close_reason;
            auto hop_status_stop = std::make_shared<std::atomic<bool>>(false);
            tunnel->set_close_handler([&close_reason, hop_status_stop](const std::string& reason) {
                close_reason = reason;
                hop_status_stop->store(true);
            });
            tunnel->start();
            std::thread hop_status_thread;
            if (!cfg.non_interactive) {
                if (status_block_builder && hop_enabled) {
                    hop_status_thread = std::thread([hop_status_stop, status_block_builder]() {
                        while (!hop_status_stop->load()) {
                            util::set_status_line(status_block_builder());
                            std::this_thread::sleep_for(std::chrono::milliseconds(250));
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
                util::log_info("requesting remote listener on port " + std::to_string(reverse_listen_port));
                tunnel->request_remote_listen(listen_id, reverse_listen_port,
                                              [listen_port = reverse_listen_port](bool ok, const std::string& reason) {
                                                  if (ok) {
                                                      util::log_info("remote listener active on port " + std::to_string(listen_port));
                                                  } else {
                                                      util::log_error("remote listener failed: " + reason);
                                                  }
                                              });
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
            run_io_threads(io, cfg.io_threads);
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
            auto workers = start_io_threads(io, cfg.io_threads);
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
            for (auto& t : workers) {
                if (t.joinable()) {
                    t.join();
                }
            }
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
                run_io_threads(io, cfg.io_threads);
                if (!close_reason.empty()) {
                    throw std::runtime_error("tunnel closed: " + close_reason);
                }
                return 0;
            }

            if (cfg.socks_port > 0) {
                auto socks = std::make_shared<SocksServer>(io, cfg.socks_port, tunnel, cfg.allow_udp);
                socks->start();
                util::log_info("SOCKS5 listening on 127.0.0.1:" + std::to_string(cfg.socks_port));
                run_io_threads(io, cfg.io_threads);
                if (!close_reason.empty()) {
                    throw std::runtime_error("tunnel closed: " + close_reason);
                }
                return 0;
            }

            if (use_reverse) {
                run_io_threads(io, cfg.io_threads);
                if (!close_reason.empty()) {
                    throw std::runtime_error("tunnel closed: " + close_reason);
                }
                return 0;
            }

            util::log_warn("no mode selected");
            return 1;
        } catch (const std::exception& ex) {
            attempt++;
            int backoff = std::min(30, 1 << std::min(attempt, 5));
            util::log_warn(std::string("connection failed: ") + ex.what());
            util::log_warn("retrying in " + std::to_string(backoff) + "s");
            std::this_thread::sleep_for(std::chrono::seconds(backoff));
        }
    }
}

}  // namespace yume::client
