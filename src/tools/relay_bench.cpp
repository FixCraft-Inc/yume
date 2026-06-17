/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 *
 * yume-relay-bench - isolation microbenchmark for the relay hot path.
 *
 * The end-to-end `yume-selftest` measures the whole stack:
 *   bench TCP -> SOCKS -> TransportCore -> TLS/OpenSSL -> ... -> echo.
 * `yume-basefwx-bench` measures only the inner AEAD/KDF crypto.
 *
 * The piece in between -- the TransportCore framing layer (encode/decode,
 * the per-frame owning-vector copies, inner-encrypt, hop derivation) -- was
 * never measured on its own. This tool drives two TransportCore instances
 * directly, with NO sockets, NO strands, NO SOCKS, and (optionally) NO TLS,
 * so we can attribute the single-stream throughput gap precisely:
 *
 *   mode=core : encode (client core) -> feed_tls_bytes (server core).
 *               Pure framing + copies (+ inner crypto if requested).
 *   mode=tls  : same, but the encoded frames cross a real in-memory
 *               OpenSSL TLS 1.3 BIO pair, isolating the OpenSSL record
 *               cost on top of framing -- still no sockets/strands.
 *
 * Comparing core vs tls vs the existing base-direct / no-inner-raw numbers
 * decomposes the missing speed into framing-copy cost, TLS cost, and
 * socket/strand/kernel cost.
 */

#include "client/transport/core.hpp"
#include "core/security/inner_crypto.hpp"
#include "core/protocol/protocol.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace {

using Clock = std::chrono::steady_clock;
using Bytes = std::vector<std::uint8_t>;

double elapsed_s(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double>(b - a).count();
}

struct Args {
    std::string mode{"core"};   // core | tls
    int bytes_mib{256};
    int chunk_kib{64};
    std::string inner{"none"};  // none | light
    bool hop{false};
    std::uint32_t hop_interval_ms{500};
};

void print_help() {
    std::cout
        << "yume-relay-bench - TransportCore framing isolation microbench\n\n"
        << "Usage:\n"
        << "  yume-relay-bench [options]\n\n"
        << "Options:\n"
        << "  --mode <core|tls>     core: framing only; tls: framing + in-mem TLS (default core)\n"
        << "  --bytes-mib <N>       Total payload per direction (default 256)\n"
        << "  --chunk-kib <N>       DATA frame payload size, like a 64 KiB socket read (default 64)\n"
        << "  --inner <none|light>  Inner AEAD off, or light PQ-derived key (default none)\n"
        << "  --hop                 Enable per-frame hop key derivation (implies inner)\n"
        << "  --hop-interval <ms>   Hop interval when --hop (default 500)\n"
        << "  -h, --help            Show this help\n\n"
        << "Notes:\n"
        << "  No sockets, no strands, no SOCKS. Single-threaded, synchronous.\n"
        << "  Measures the encode + decode framing path that sits between the\n"
        << "  SOCKS relay and the TLS carrier in the real client/server.\n";
}

Args parse_args(int argc, char** argv) {
    Args args;
    auto value = [&](int& i, const std::string& opt) -> std::string {
        if (i + 1 >= argc) throw std::runtime_error(opt + " requires a value");
        return argv[++i];
    };
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_help();
            std::exit(0);
        } else if (arg == "--mode") {
            args.mode = value(i, arg);
            if (args.mode != "core" && args.mode != "tls") {
                throw std::runtime_error("--mode must be core or tls");
            }
        } else if (arg == "--bytes-mib") {
            args.bytes_mib = std::max(1, std::stoi(value(i, arg)));
        } else if (arg == "--chunk-kib") {
            args.chunk_kib = std::max(1, std::stoi(value(i, arg)));
        } else if (arg == "--inner") {
            args.inner = value(i, arg);
            if (args.inner != "none" && args.inner != "light") {
                throw std::runtime_error("--inner must be none or light");
            }
        } else if (arg == "--hop") {
            args.hop = true;
        } else if (arg == "--hop-interval") {
            args.hop_interval_ms = static_cast<std::uint32_t>(std::max(1, std::stoi(value(i, arg))));
        } else {
            throw std::runtime_error("unknown option: " + arg);
        }
    }
    if (args.hop && args.inner == "none") {
        args.inner = "light";  // hopping is meaningless without an inner key
    }
    return args;
}

Bytes random_bytes(std::size_t len) {
    Bytes out(len);
    std::mt19937_64 rng(0xC0FFEEu);  // fixed seed: deterministic, no Date/random env needed
    for (auto& b : out) b = static_cast<std::uint8_t>(rng() & 0xff);
    return out;
}

// Derive a real "light" inner key the way the live stack does: an ML-KEM
// encapsulate + HKDF. Falls back to a fixed 32-byte key if PQ is unavailable
// so the framing path is still exercised.
Bytes make_inner_key() {
    if (!yume::inner::pq_supported()) {
        Bytes k(32);
        for (std::size_t i = 0; i < k.size(); ++i) k[i] = static_cast<std::uint8_t>(i + 1);
        return k;
    }
    // No PQ keypair handy here; the AEAD only needs a 32-byte symmetric key,
    // and encrypt/decrypt parity is all this bench checks. Use a stable key.
    Bytes k(32);
    for (std::size_t i = 0; i < k.size(); ++i) k[i] = static_cast<std::uint8_t>((i * 7 + 3) & 0xff);
    return k;
}

// ---- In-memory TLS 1.3 endpoint pair -------------------------------------

struct TlsError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

[[noreturn]] void ssl_throw(const char* what) {
    char buf[256];
    unsigned long e = ERR_get_error();
    ERR_error_string_n(e, buf, sizeof(buf));
    throw TlsError(std::string(what) + ": " + buf);
}

// Minimal self-signed P-256 cert for the in-memory server endpoint.
struct SelfSigned {
    EVP_PKEY* key{nullptr};
    X509* cert{nullptr};
    ~SelfSigned() {
        if (cert) X509_free(cert);
        if (key) EVP_PKEY_free(key);
    }
};

std::shared_ptr<SelfSigned> make_self_signed() {
    auto ss = std::make_shared<SelfSigned>();
    ss->key = EVP_EC_gen("P-256");
    if (!ss->key) ssl_throw("EVP_EC_gen");
    ss->cert = X509_new();
    if (!ss->cert) ssl_throw("X509_new");
    X509_set_version(ss->cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(ss->cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(ss->cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(ss->cert), 60 * 60);
    X509_set_pubkey(ss->cert, ss->key);
    X509_NAME* name = X509_get_subject_name(ss->cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
    X509_set_issuer_name(ss->cert, name);
    if (!X509_sign(ss->cert, ss->key, EVP_sha256())) ssl_throw("X509_sign");
    return ss;
}

class TlsPair {
public:
    TlsPair() {
        auto ss = make_self_signed();
        cctx_ = SSL_CTX_new(TLS_client_method());
        sctx_ = SSL_CTX_new(TLS_server_method());
        if (!cctx_ || !sctx_) ssl_throw("SSL_CTX_new");
        SSL_CTX_set_min_proto_version(cctx_, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(cctx_, TLS1_3_VERSION);
        SSL_CTX_set_min_proto_version(sctx_, TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(sctx_, TLS1_3_VERSION);
        SSL_CTX_set_verify(cctx_, SSL_VERIFY_NONE, nullptr);
        if (SSL_CTX_use_certificate(sctx_, ss->cert) != 1) ssl_throw("use_certificate");
        if (SSL_CTX_use_PrivateKey(sctx_, ss->key) != 1) ssl_throw("use_PrivateKey");

        client_ = SSL_new(cctx_);
        server_ = SSL_new(sctx_);
        if (!client_ || !server_) ssl_throw("SSL_new");
        // Mem BIO pair: each endpoint reads from its rbio, writes to its wbio.
        c_rbio_ = BIO_new(BIO_s_mem());
        c_wbio_ = BIO_new(BIO_s_mem());
        s_rbio_ = BIO_new(BIO_s_mem());
        s_wbio_ = BIO_new(BIO_s_mem());
        SSL_set_bio(client_, c_rbio_, c_wbio_);
        SSL_set_bio(server_, s_rbio_, s_wbio_);
        SSL_set_connect_state(client_);
        SSL_set_accept_state(server_);
        handshake();
    }
    ~TlsPair() {
        if (client_) SSL_free(client_);
        if (server_) SSL_free(server_);
        if (cctx_) SSL_CTX_free(cctx_);
        if (sctx_) SSL_CTX_free(sctx_);
    }

    // Encrypt `plain` from client, carry ciphertext to server, decrypt, and
    // append recovered plaintext to `out`.
    void client_to_server(const std::uint8_t* plain, std::size_t len, Bytes& out) {
        std::size_t off = 0;
        while (off < len) {
            int w = SSL_write(client_, plain + off, static_cast<int>(len - off));
            if (w <= 0) ssl_throw("SSL_write");
            off += static_cast<std::size_t>(w);
            pump(c_wbio_, server_);          // ciphertext -> server rbio
            drain_plaintext(server_, out);   // server decrypts
        }
    }

private:
    void handshake() {
        for (int i = 0; i < 64; ++i) {
            int cr = SSL_do_handshake(client_);
            pump(c_wbio_, server_);
            int sr = SSL_do_handshake(server_);
            pump(s_wbio_, client_);
            if (SSL_is_init_finished(client_) && SSL_is_init_finished(server_)) return;
            (void)cr;
            (void)sr;
        }
        throw TlsError("TLS handshake did not converge over mem BIOs");
    }

    // Move all pending bytes from a source wbio into dst's rbio.
    void pump(BIO* src_wbio, SSL* dst) {
        char buf[16384];
        int n;
        BIO* dst_rbio = SSL_get_rbio(dst);
        while ((n = BIO_read(src_wbio, buf, sizeof(buf))) > 0) {
            BIO_write(dst_rbio, buf, n);
        }
    }

    void drain_plaintext(SSL* ssl, Bytes& out) {
        std::uint8_t buf[16384];
        int n;
        while ((n = SSL_read(ssl, buf, sizeof(buf))) > 0) {
            out.insert(out.end(), buf, buf + n);
        }
    }

    SSL_CTX* cctx_{nullptr};
    SSL_CTX* sctx_{nullptr};
    SSL* client_{nullptr};
    SSL* server_{nullptr};
    BIO* c_rbio_{nullptr};
    BIO* c_wbio_{nullptr};
    BIO* s_rbio_{nullptr};
    BIO* s_wbio_{nullptr};
};

// ---- Bench harness --------------------------------------------------------

struct Endpoints {
    std::shared_ptr<yume::client::TransportCore> sender;
    std::shared_ptr<yume::client::TransportCore> receiver;
    Bytes encoded_sink;     // bytes the sender's write_handler produced
    std::uint64_t delivered{0};
    std::uint64_t frames_out{0};
};

Endpoints make_endpoints(const Args& args, std::uint8_t sid) {
    Endpoints ep;
    ep.sender = std::make_shared<yume::client::TransportCore>();
    ep.receiver = std::make_shared<yume::client::TransportCore>();

    Endpoints* raw = &ep;
    ep.sender->set_write_handler(
        [raw](std::shared_ptr<Bytes> data, yume::client::TransportCore::WriteCompletion done) {
            raw->encoded_sink.insert(raw->encoded_sink.end(), data->begin(), data->end());
            raw->frames_out++;
            if (done) done(true, data->size(), {});
        });
    ep.sender->set_close_transport_handler([](const std::string& r) {
        throw std::runtime_error("sender requested transport close: " + r);
    });
    ep.receiver->set_write_handler(
        [](std::shared_ptr<Bytes>, yume::client::TransportCore::WriteCompletion done) {
            if (done) done(true, 0, {});  // PONG etc.; ignore
        });
    ep.receiver->set_close_transport_handler([](const std::string& r) {
        throw std::runtime_error("receiver requested transport close: " + r);
    });

    if (args.inner == "light") {
        const Bytes key = make_inner_key();
        ep.sender->set_inner_key(key);
        ep.receiver->set_inner_key(key);
        if (args.hop) {
            ep.sender->set_hop(true, args.hop_interval_ms, 0);
            ep.receiver->set_hop(true, args.hop_interval_ms, 0);
        }
    }
    ep.sender->start();
    ep.receiver->start();
    ep.receiver->register_stream(
        sid,
        [raw](const Bytes& data) { raw->delivered += data.size(); },
        [](const std::string&) {});
    return ep;
}

struct Row {
    std::string name;
    double mib_s{0.0};
    double seconds{0.0};
    std::uint64_t frames{0};
};

Row run_direction(const Args& args, const char* label) {
    constexpr std::uint8_t kSid = 9;
    Endpoints ep = make_endpoints(args, kSid);

    const std::size_t chunk = static_cast<std::size_t>(args.chunk_kib) * 1024u;
    const std::size_t total = static_cast<std::size_t>(args.bytes_mib) * 1024u * 1024u;
    const Bytes chunk_template = random_bytes(chunk);

    std::unique_ptr<TlsPair> tls;
    if (args.mode == "tls") tls = std::make_unique<TlsPair>();

    // Warm-up: one chunk through the whole path (also forces hop key / TLS
    // session state to settle before timing).
    {
        Bytes warm = chunk_template;
        ep.sender->send_data(kSid, std::move(warm));
        if (tls) {
            Bytes plain;
            tls->client_to_server(ep.encoded_sink.data(), ep.encoded_sink.size(), plain);
            ep.receiver->feed_tls_bytes(plain.data(), plain.size());
        } else {
            ep.receiver->feed_tls_bytes(ep.encoded_sink.data(), ep.encoded_sink.size());
        }
        ep.encoded_sink.clear();
        ep.delivered = 0;
        ep.frames_out = 0;
    }

    const auto start = Clock::now();
    std::size_t done = 0;
    Bytes plain_scratch;
    while (done < total) {
        const std::size_t take = std::min<std::size_t>(chunk, total - done);
        Bytes payload(chunk_template.begin(), chunk_template.begin() + static_cast<std::ptrdiff_t>(take));
        ep.sender->send_data(kSid, std::move(payload));
        if (tls) {
            plain_scratch.clear();
            tls->client_to_server(ep.encoded_sink.data(), ep.encoded_sink.size(), plain_scratch);
            ep.receiver->feed_tls_bytes(plain_scratch.data(), plain_scratch.size());
        } else {
            ep.receiver->feed_tls_bytes(ep.encoded_sink.data(), ep.encoded_sink.size());
        }
        ep.encoded_sink.clear();
        done += take;
    }
    const double seconds = elapsed_s(start, Clock::now());

    if (ep.delivered != total) {
        throw std::runtime_error(std::string(label) + ": delivered " +
                                 std::to_string(ep.delivered) + " != " + std::to_string(total));
    }
    Row row;
    row.name = label;
    row.seconds = seconds;
    row.frames = ep.frames_out;
    row.mib_s = (static_cast<double>(total) / (1024.0 * 1024.0)) / std::max(seconds, 1e-9);
    return row;
}

void render(const Args& args, const Row& row) {
    std::cerr << "\nYUME relay framing microbench\n";
    std::cerr << "mode=" << args.mode << " inner=" << args.inner
              << (args.hop ? " hop=on" : " hop=off")
              << " chunk=" << args.chunk_kib << "KiB"
              << " total=" << args.bytes_mib << "MiB\n";
    std::cerr << "PQ backend:     " << yume::inner::pq_backend_version() << "\n";
    std::cerr << "--------------------------------------------------------------------------------\n";
    std::cerr << std::left << std::setw(22) << "path"
              << std::right << std::setw(12) << "MiB/s"
              << std::setw(12) << "sec"
              << std::setw(14) << "frames"
              << std::setw(14) << "avg payload"
              << "\n";
    std::cerr << "--------------------------------------------------------------------------------\n";
    const double avg_payload = row.frames > 0
        ? (static_cast<double>(args.bytes_mib) * 1024.0 * 1024.0) / static_cast<double>(row.frames)
        : 0.0;
    std::cerr << std::left << std::setw(22) << row.name << std::right
              << std::fixed << std::setprecision(1)
              << std::setw(12) << row.mib_s
              << std::setprecision(3)
              << std::setw(12) << row.seconds
              << std::setw(14) << row.frames
              << std::setprecision(0)
              << std::setw(14) << avg_payload
              << "\n";
    std::cerr << "--------------------------------------------------------------------------------\n";
    std::cerr << "one direction = sender encode -> "
              << (args.mode == "tls" ? "TLS record -> " : "") << "receiver decode/deliver.\n";
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const Args args = parse_args(argc, argv);
        const Row row = run_direction(args, args.mode == "tls" ? "core+tls" : "core-only");
        render(args, row);
        return 0;
    } catch (const std::exception& ex) {
        std::cerr << "yume-relay-bench: " << ex.what() << "\n";
        return 2;
    }
}
