# YUME (Yume Universal Multiprotocol Engine)

Cross-platform encrypted transport (client + server) over TLS 1.3 with TCP/UDP multiplexing.

## Build

```bash
cmake -B build
cmake --build build -j$(nproc)
```

### Minimal / Embedded (OpenWRT, BusyBox, Android)

Use a minimal build to reduce dependencies:

```bash
cmake -B build -DYUME_MINIMAL=ON -DYUME_USE_BASEFWX=ON
cmake --build build -j$(nproc)
```

Cross-compile by providing a toolchain file:

```bash
cmake -B build -DCMAKE_TOOLCHAIN_FILE=/path/to/toolchain.cmake -DYUME_MINIMAL=ON
```

Notes:
- Requires OpenSSL and Boost.System (or Boost from your SDK).
- BaseFWX is still used in minimal mode.
- Release and CI builds are expected to fail if mandatory BaseFWX crypto support is missing.
- Full releases require Argon2, PQ/OQS, and LZMA support in the bundled BaseFWX dependency path.
- For privileged port 443 on Linux, run with `sudo` or set `cap_net_bind_service`.
- For Cloudflare, use a TCP passthrough product (e.g., Spectrum) or disable HTTP proxying. HTTP-mode proxies terminate TLS and will break YUME.

## Run

```bash
sudo ./build/bin/yumed --config config/yumed.json
./build/bin/yume --config config/yume.json --socks 1080
```

### Real HTTP facade

Serve a real HTML page on `/` and redirect everything else to `/`:

```bash
sudo ./build/bin/yumed --listen 443 --cert certs/server.crt --key certs/server.key --auth-keys /etc/yume/authorized_keys --real --real-index certs/index.html --real-secret "change-me"
```

Auto-generate and store the HTML secret:

```bash
sudo ./build/bin/yumed --listen 443 --cert certs/server.crt --key certs/server.key --auth-keys /etc/yume/authorized_keys --real --real-index certs/index.html --real-secret-file ./.secrets/html_secret
```

### Anonym mode (no server logging)

```bash
sudo ./build/bin/yumed --listen 443 --cert certs/server.crt --key certs/server.key --auth-keys /etc/yume/authorized_keys --anonym
```

YUME supports three anonym proof policies:

- `auto`: use every available proof source; startup fails only if none are usable
- `local`: use CA/Sub-CA local proof only; never call a remote API
- `fixcraft`: require remote FixCraft proof; local proofs may also be attached

Set it with `--anonym-proof-mode <auto|local|fixcraft>` or `anonym_proof_mode` in config.

If you want FixCraft-backed proof explicitly, configure it directly:

```bash
sudo ./build/bin/yumed --listen 443 --cert certs/server.crt --key certs/server.key --auth-keys /etc/yume/authorized_keys --anonym --anonym-proof-mode fixcraft --anonym-api https://api.fixcraft.jp/verity
```

Client trust options:

```json
{
  "anonym_pubkey": "/etc/yume/fixcraft_anonym_pub.pem",
  "require_anonym": true
}
```

`require_anonym` now means: require at least one trusted anonym proof source. It is not FixCraft-only anymore.

#### Optional: CA-backed sub-signature for anonym proof

You can add a CA-signed sub-certificate so clients can verify a local proof chain without any remote API dependency.

Generate a sub key + cert signed by your CA:

```bash
./scripts/gen_anonym_sub.sh --ca-cert /path/to/ca.cert.pem --ca-key /path/to/ca.key.pem --out-prefix /etc/yume/anonym_sub
```

Start yumed with the sub key + cert:

```bash
sudo ./build/bin/yumed --anonym --anonym-proof-mode local --anonym-sub-key /etc/yume/anonym_sub.key --anonym-sub-cert /etc/yume/anonym_sub.pem
```

Clients must trust the CA cert to accept the sub signature:

```json
{
  "anonym_ca_cert": "/path/to/ca.cert.pem",
  "require_anonym": true
}
```

Client verity now passes if any trusted proof source verifies:

- `Verity: PASS [FixCraft]`
- `Verity: PASS [CA]`
- `Verity: PASS [Sub-CA]`
- `Verity: PASS [Sub-CA+FixCraft]`

If the server provides a valid local CA/Sub-CA proof and the client has the matching CA cert, `api.fixcraft.jp` is unnecessary.

## Modes

SOCKS proxy (default):

```bash
yume --server fixcraft.net --auth id_ed25519 --socks 1080
```

Port forward (SSH-style):

```bash
yume --lport 2222 --rhost fw-main.fixcraft.jp --rport 22
```

Remote forward (server listens, tunnels back to client local):

```bash
yume -R 7437:127.0.0.1:22
```

Local run (executes locally; all network traffic goes through YUME):

```bash
yume --server fixcraft.net --auth id_ed25519 --run "curl https://1.1.1.1"
```

Force IPv4 for local run (curl gets `-4 --http1.1`):

```bash
yume --server fixcraft.net --auth id_ed25519 --run-ipv4 --run "curl https://ifconfig.me"
```

SSH (auto-wrapped to route via local SOCKS if `nc`, `ncat`, or `connect-proxy` is available):

```bash
yume --server fixcraft.net --auth id_ed25519 --run "ssh user@host"
```

Note: server-side command execution is disabled for safety. Use SOCKS or port forwarding.

## Key Management

```bash
./build/bin/yumed --auth-keys /etc/yume/authorized_keys --keys-list
./build/bin/yumed --auth-keys /etc/yume/authorized_keys --keys-add /path/to/user.pub --keys-alias <fingerprint> alice
./build/bin/yumed --auth-keys /etc/yume/authorized_keys --keys-remove alice
./build/bin/yumed --auth-keys /etc/yume/authorized_keys --keys-gen ./keys/user1 --keys-gen-add
```

## Inner Crypto (BaseFWX + PQ)

Optional inner encryption uses BaseFWX AES-GCM with ML-KEM-768 key exchange and a salted heavy KDF by default. Enable with:

```json
{
  "inner_crypto": true,
  "inner_heavy": true,
  "pq_public_key": "/etc/yume/master_pq.pk"
}
```

Server config:

```json
{
  "inner_crypto": true,
  "inner_heavy": true,
  "pq_private_key": "/etc/yume/master_pq.sk",
  "allow_exec": false
}
```

Requires liboqs for PQ support.

## Release Guarantees

- Release workflows run preflight validation against the pinned BaseFWX commit.
- Release artifacts are inspected after build for linkage/runtime expectations.
- Missing mandatory BaseFWX crypto support is treated as a release failure, not a degraded release.

## Scalability Notes

- Server sessions are fully async on a shared io_context thread pool (no per-connection threads).
- Authorized keys are loaded once at startup.
- Frames are capped at 16 MiB per message to limit memory pressure.

## License

GNU GPL v3. See `LICENSE`.
