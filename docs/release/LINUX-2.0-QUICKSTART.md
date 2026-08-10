# YUME 2.0 Linux x86-64 quick start

The first YUME 2.0 release lane supports only glibc Linux on x86-64. The client
archive and server executable are separate artifacts:

- `yume-amd64-linux.tar.xz` contains `yume`, the adjacent
  `yume-chrome-tls-helper`, licensing documents, and `manifest.json`.
- `yumed-amd64-linux` is the server.

Android, GUI, Windows, macOS, ARM, OpenWRT, static binaries, and a Debian
archive are not supported by this release lane.

## Verify and unpack

Verify the release SHA-256 files and signatures before installation. Then:

```sh
tar -xJf yume-amd64-linux.tar.xz
cd yume-amd64-linux
./yume --version
./yume-chrome-tls-helper --version
```

Keep the helper next to `yume`, owned by root or the account running YUME, and
not writable by group or other users. The client rejects symlinked,
non-executable, or unsafe helper files.

Install the server separately if this machine hosts a YUME endpoint:

```sh
sudo install -m 0755 yumed-amd64-linux /usr/local/bin/yumed
```

## Configure and connect

Provision certificates, independent admission and inner PSKs, and an Ed25519
client identity by following the full `docs/QUICKSTART.md` from the matching
source release. The opt-in Chrome 151 backend is selected explicitly:

```sh
./yume \
  --server server.example \
  --port 443 \
  --tls-name server.example \
  --tls-ca /path/to/server-ca.pem \
  --auth /path/to/client.key \
  --obfs-secret-file /path/to/admission.hex \
  --inner-psk-file /path/to/inner.hex \
  --transport-profile chrome151-node24-v1 \
  --tls-backend chrome151 \
  --socks 127.0.0.1:1080
```

There is no silent fallback. `openssl-diagnostic` remains the default until
the lifecycle, scale, soak, WAN, and same-session cover gates are complete.
Do not describe the opt-in backend as invisible to DPI or independently
audited.
