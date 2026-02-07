/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "client/cli.hpp"

#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <utility>
#include <filesystem>
#include <fstream>
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
    bool use_udp{false};
    bool udp_override{false};
    bool allow_local_ip{false};
    bool allow_local_ip_override{false};
    std::string pq_public_key;
    std::string anonym_ca_cert;
    std::string tls_ca_cert;
    std::string tls_pin_sha256;
    bool help{false};
    bool accept_monitoring{false};
    bool save_server{false};
    bool require_anonym{false};
    bool boring{false};
    bool boring_override{false};
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
        } else if (arg == "--accept-monitoring") {
            args.accept_monitoring = true;
        } else if (arg == "--save-server") {
            args.save_server = true;
        } else if (arg == "--boring") {
            args.boring = true;
            args.boring_override = true;
        }
    }
    return args;
}

crypto::Bytes auth_payload(EVP_PKEY* pubkey,
                           const crypto::Bytes& signature,
                           const std::optional<crypto::Bytes>& pq_ciphertext,
                           const std::optional<crypto::Bytes>& pq_salt) {
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

    size_t total = 0;
    total = checked_add(total, 2 + pub_bytes.size());
    total = checked_add(total, 2 + signature.size());
    if (pq_ciphertext) {
        total = checked_add(total, 2 + pq_ciphertext->size());
    }
    if (pq_salt) {
        total = checked_add(total, 2 + pq_salt->size());
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
    }

    return payload;
}

void authenticate(boost::asio::ssl::stream<boost::asio::ip::tcp::socket>& stream,
                  const std::string& identity_path,
                  const std::optional<crypto::Bytes>& pq_ciphertext,
                  const std::optional<crypto::Bytes>& pq_salt) {
    protocol::Frame challenge = protocol::read_frame(stream);
    if (challenge.header.type != protocol::AUTH) {
        throw std::runtime_error("server did not send AUTH challenge");
    }

    auto kp = crypto::load_keypair(identity_path, "");
    crypto::Bytes signature = crypto::sign_message(kp.private_key.get(), challenge.payload);
    crypto::Bytes payload = auth_payload(kp.public_key.get() ? kp.public_key.get() : kp.private_key.get(),
                                         signature,
                                         pq_ciphertext,
                                         pq_salt);

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
        << "  --pq-pub <path>      Override post-quantum public key\n"
        << "  --anonym-ca-cert <path> CA certificate for anonymity verification\n"
        << "  --tls-ca <path>      Custom CA for TLS verification\n"
        << "  --tls-pin <sha256>   Pin server TLS certificate fingerprint\n"
        << "  --run, -c, --cmd <cmd>  Run command locally with YUME proxy\n"
        << "                          (SSH auto-wraps ProxyCommand via SOCKS)\n"
        << "  --run-ipv4           Prefer IPv4 for --run commands\n"
        << "  --proxycmd           Internal SSH ProxyCommand helper\n"
        << "  --require-anonym     Abort if server not in anonymous mode\n"
        << "  -L [bind:]lport:host:port  SSH-style local port forward\n"
        << "  -R [bind:]rport:host:port  SSH-style remote port forward\n"
        << "  --boring             Minimal output without emojis\n"
        << "  --config <path>      Configuration file path\n"
        << "  --accept-monitoring  Accept monitoring without warning\n"
        << "  --save-server        Save server to configuration\n"
        << "  -h, --help           Show this help message\n";
}

bool file_exists(const std::string& path) {
    if (path.empty()) {
        return false;
    }
    std::error_code ec;
    return std::filesystem::exists(path, ec);
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
            auto json = util::read_json_config(args.config_path);
            if (json.contains("server") && cfg.server.empty()) {
                cfg.server = json["server"].get<std::string>();
            }
            if (json.contains("port") && cfg.port == 443) {
                cfg.port = json["port"].get<int>();
            }
            if (json.contains("identity") && cfg.identity.empty()) {
                cfg.identity = util::expand_user(json["identity"].get<std::string>());
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
                cfg.pq_public_key = util::expand_user(json["pq_public_key"].get<std::string>());
            }
            if (json.contains("anonym_pubkey") && cfg.anonym_pubkey.empty()) {
                cfg.anonym_pubkey = util::expand_user(json["anonym_pubkey"].get<std::string>());
            }
            if (json.contains("anonym_ca_cert")) {
                cfg.anonym_ca_cert = util::expand_user(json["anonym_ca_cert"].get<std::string>());
            }
            if (json.contains("tls_ca_cert") && cfg.tls_ca_cert.empty()) {
                cfg.tls_ca_cert = util::expand_user(json["tls_ca_cert"].get<std::string>());
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
        cfg.identity = util::expand_user(args.identity);
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
    if (!args.pq_public_key.empty()) {
        cfg.pq_public_key = util::expand_user(args.pq_public_key);
    }
    if (!args.anonym_ca_cert.empty()) {
        cfg.anonym_ca_cert = util::expand_user(args.anonym_ca_cert);
    }
    if (!args.tls_ca_cert.empty()) {
        cfg.tls_ca_cert = util::expand_user(args.tls_ca_cert);
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
    if (!file_exists(cfg.identity)) {
        util::log_error("identity key not found: " + cfg.identity);
        return 1;
    }

    int attempt = 0;
    bool pq_warned = false;
    bool pq_reconnect_used = false;
    bool verified_once = false;
    for (;;) {
        try {
            boost::asio::io_context io;
            auto ctx = obfs::create_client_context();
            ctx.set_verify_mode(boost::asio::ssl::verify_peer);
            ctx.set_default_verify_paths();
            if (!cfg.tls_ca_cert.empty()) {
                ctx.load_verify_file(cfg.tls_ca_cert);
            }

            boost::asio::ip::tcp::resolver resolver(io);
            auto endpoints = resolver.resolve(boost::asio::ip::tcp::v4(), cfg.server, std::to_string(cfg.port));
            boost::asio::ssl::stream<boost::asio::ip::tcp::socket> stream(io, ctx);
            boost::asio::connect(stream.next_layer(), endpoints);
            boost::system::error_code keep_ec;
            stream.next_layer().set_option(boost::asio::socket_base::keep_alive(true), keep_ec);
            if (keep_ec) {
                util::log_warn(std::string("keepalive set failed: ") + keep_ec.message());
            }
            SSL_set_tlsext_host_name(stream.native_handle(), cfg.server.c_str());
            SSL_set1_host(stream.native_handle(), cfg.server.c_str());
            stream.handshake(boost::asio::ssl::stream_base::client);
            if (!cfg.tls_pin_sha256.empty()) {
                std::string fp = get_peer_cert_fingerprint(nullptr, stream.native_handle());
                if (fp.empty() || fp != cfg.tls_pin_sha256) {
                    throw std::runtime_error("TLS pin mismatch");
                }
            }

            inner::Config inner_cfg;
            inner_cfg.enabled = cfg.inner_crypto;
            inner_cfg.pq_public_key = cfg.pq_public_key;

            std::optional<crypto::Bytes> pq_ciphertext;
            std::optional<crypto::Bytes> pq_salt;
            std::optional<crypto::Bytes> inner_key;
            bool inner_disabled_for_session = false;
            bool pq_need_key = false;
            bool pq_not_supported = false;
            if (inner_cfg.enabled) {
                try {
                    auto hs = inner::client_prepare(inner_cfg, cfg.inner_heavy);
                    if (!hs.enabled || hs.key.empty()) {
                        throw std::runtime_error("inner crypto init failed");
                    }
                    pq_ciphertext = hs.pq_ciphertext;
                    pq_salt = hs.salt;
                    inner_key = hs.key;
                } catch (const std::exception& ex) {
                    std::string msg = ex.what();
                    if (msg.find("PQ public key not configured") != std::string::npos) {
                        pq_need_key = true;
                        inner_disabled_for_session = true;
                    } else if (msg.find("ML-KEM-768 support is not enabled") != std::string::npos) {
                        pq_not_supported = true;
                        inner_disabled_for_session = true;
                    } else {
                        throw;
                    }
                }
            }

            authenticate(stream, cfg.identity, pq_ciphertext, pq_salt);
            util::log_info("authenticated to server");

            protocol::Frame anon_frame = protocol::read_frame(stream);
        bool pq_reconnect = false;
        if (anon_frame.header.type == protocol::ANON) {
            std::string payload(anon_frame.payload.begin(), anon_frame.payload.end());
            auto json = nlohmann::json::parse(payload);
            std::string mode = json.value("mode", "normal");
            std::string hash = json.value("hash", "");
            std::string sig = json.value("sig", "");
            std::string ts = json.value("ts", "");
            std::string nonce = json.value("nonce", "");
            std::string certfp = json.value("certfp", "");
            std::string ca_sig = json.value("ca_sig", "");
            std::string ca_alg = json.value("ca_alg", "");
            std::string sub_sig = json.value("sub_sig", "");
            std::string sub_alg = json.value("sub_alg", "");
            std::string sub_cert_b64 = json.value("sub_cert", "");
            std::string pq_pub_b64 = json.value("pq_pub", "");
            std::string pq_sig = json.value("pq_sig", "");
            std::string pq_alg = json.value("pq_alg", "");

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

            if (mode == "anonym") {
                crypto::EVP_PKEY_ptr sub_pub{nullptr, EVP_PKEY_free};
                crypto::EVP_PKEY_ptr ca_pub{nullptr, EVP_PKEY_free};
                bool sub_ok = false;
                bool ca_ok = false;
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
                if (!pq_pub_b64.empty()) {
                    if (certfp.empty()) {
                        util::log_warn("pq_pub provided but certfp missing; refusing PQ auto-trust");
                    } else if (pq_sig.empty()) {
                        util::log_warn("pq_pub provided but pq_sig missing; refusing PQ auto-trust");
                    } else {
                        EVP_PKEY* pq_key = sub_ok ? sub_pub.get() : (ca_ok ? ca_pub.get() : nullptr);
                        if (!pq_key) {
                            util::log_warn("pq_pub provided but no verified CA/sub cert available; refusing PQ auto-trust");
                        } else {
                            std::string pq_msg = std::string(kPqMsgPrefix) + pq_pub_b64 + ":" + certfp;
                            crypto::Bytes pq_msg_bytes(pq_msg.begin(), pq_msg.end());
                            std::string pq_sig_raw = util::base64_decode(pq_sig);
                            if (pq_sig_raw.empty()) {
                                util::log_warn("pq_sig invalid base64; refusing PQ auto-trust");
                            } else {
                                crypto::Bytes pq_sig_bytes(pq_sig_raw.begin(), pq_sig_raw.end());
                                bool ok_pq = crypto::verify_key(pq_key, pq_msg_bytes, pq_sig_bytes);
                                if (!ok_pq) {
                                    util::log_warn("pq_pub signature invalid; refusing PQ auto-trust");
                                } else {
                                    std::string pq_raw = util::base64_decode(pq_pub_b64);
                                    if (pq_raw.empty()) {
                                        util::log_warn("pq_pub decode failed; refusing PQ auto-trust");
                                    } else {
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
                                        if (!target_path.empty()) {
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
                                        } else {
                                            util::log_warn("pq_pub verified but no output path available");
                                        }
                                    }
                                }
                            }
                        }
                    }
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
        }
            if (cfg.require_anonym && anon_frame.header.type != protocol::ANON) {
                util::log_error("server did not provide anonym proof");
                return 1;
            }
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

            auto send_control_frame = [&](const nlohmann::json& req) {
                std::string payload_str = req.dump();
                crypto::Bytes payload(payload_str.begin(), payload_str.end());
                uint16_t flags = 0;
                if (inner_key.has_value()) {
                    payload = inner::encrypt_payload(*inner_key, protocol::CONTROL, 0, payload);
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
                    payload = inner::decrypt_payload(*inner_key, protocol::CONTROL, resp_frame.header.stream_id, resp_frame.payload);
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
            tunnel->set_server_in_charge(cfg.server_in_charge);
            tunnel->set_allow_exec(cfg.allow_exec);
            std::string close_reason;
            tunnel->set_close_handler([&close_reason](const std::string& reason) { close_reason = reason; });
            tunnel->start();

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
                util::log_info("remote forward active; waiting for connections");
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
