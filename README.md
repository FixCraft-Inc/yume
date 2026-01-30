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

## Run

```bash
sudo ./build/yumed --config config/yumed.json
./build/yume --config config/yume.json --socks 1080
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
