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
cmake -B build -DYUME_MINIMAL=ON -DYUME_USE_BASEFWX=OFF
cmake --build build -j$(nproc)
```

Cross-compile by providing a toolchain file:

```bash
cmake -B build -DCMAKE_TOOLCHAIN_FILE=/path/to/toolchain.cmake -DYUME_MINIMAL=ON
```

Notes:
- Requires OpenSSL and Boost.System (or Boost from your SDK).
- PQ inner crypto (BaseFWX + liboqs) is disabled in minimal mode.
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
sudo ./build/bin/yumed --listen 443 --cert certs/server.crt --key certs/server.key --auth-keys /etc/yume/authorized_keys --anonym --anonym-api https://api.fixcraft.jp/verity
```

Client should set the FixCraft anonym public key:

```json
{
  "anonym_pubkey": "/etc/yume/fixcraft_anonym_pub.pem"
}
```

## Modes

SOCKS proxy (default):

```bash
yume --server fixcraft.net --auth id_ed25519 --socks 1080
```

Port forward (SSH-style):

```bash
yume --lport 2222 --rhost fw-main.fixcraft.jp --rport 22
```

One-shot command (must enable on server):

```bash
yume -c "curl 1.1.1.1:7761"
yume --run "ssh admin@fwx-jp"
```

## Key Management

```bash
./build/bin/yumed --auth-keys /etc/yume/authorized_keys --keys-list
./build/bin/yumed --auth-keys /etc/yume/authorized_keys --keys-add /path/to/user.pub --keys-alias <fingerprint> alice
./build/bin/yumed --auth-keys /etc/yume/authorized_keys --keys-remove alice
./build/bin/yumed --auth-keys /etc/yume/authorized_keys --keys-gen ./keys/user1 --keys-gen-add
```

## Inner Crypto (BaseFWX + PQ)

Optional inner encryption uses BaseFWX AES-GCM with ML-KEM-768 key exchange. Enable with:

```json
{
  "inner_crypto": true,
  "pq_public_key": "/etc/yume/master_pq.pk"
}
```

Server config:

```json
{
  "inner_crypto": true,
  "pq_private_key": "/etc/yume/master_pq.sk",
  "allow_exec": false
}
```

Requires liboqs for PQ support.

## Scalability Notes

- Server sessions are fully async on a shared io_context thread pool (no per-connection threads).
- Authorized keys are loaded once at startup.
- Frames are capped at 16 MiB per message to limit memory pressure.

## License

GNU GPL v3. See `LICENSE`.
