# YUME Linux x86-64 release quick start

The first stable release lane targets glibc Linux on x86-64. The client archive
and server executable are separate artifacts:

- `yume-amd64-linux.tar.xz` contains `yume`, any retained comparison helper,
  licensing documents, and `manifest.json`.
- `yumed-amd64-linux` is the server executable.

The release manifest is authoritative for published targets and included
files. Android, GUI, Windows, macOS, ARM, OpenWrt, static binaries, and Debian
packages are unsupported unless that release's manifest and notes include
them.

## Verify and unpack

Verify the published checksum and detached signature before installation. Then:

```sh
tar -xJf yume-amd64-linux.tar.xz
cd yume-amd64-linux
./yume --version
```

The release build embeds the checksum-pinned cryptographic dependencies needed
by the native transport. Packaging checks reject unexpected runtime OpenSSL or
liboqs dependencies and embedded build-directory search paths. Compare the
unpacked files with `manifest.json` before running them.

Install the server only if this machine hosts a YUME endpoint:

```sh
sudo install -m 0755 yumed-amd64-linux /usr/local/bin/yumed
```

A bare server executable is not a complete deployment. Use only a release that
also provides the matching cover backend, service contract, configuration
guidance, and required licensing files. Until that package exists, build and
install the exact source release instead of assembling pieces from different
revisions.

## Configure and connect

Provision certificates, independent admission and inner pre-shared keys, and a
composite Ed25519 and ML-DSA-87 client identity with the quick start from the
matching source release. A minimal client invocation is:

```sh
./yume \
  --server server.example \
  --port 443 \
  --tls-name server.example \
  --tls-ca /path/to/server-ca.pem \
  --auth /path/to/client.key \
  --obfs-secret-file /path/to/admission.hex \
  --inner-psk-file /path/to/inner.hex \
  --socks 127.0.0.1:1080
```

Use the transport profile and native backend selected by that release. There is
no silent downgrade to a diagnostic backend or an unauthenticated transport.
Read the matching implementation status and release notes before treating the
build as qualified for a platform, classifier, network, or long-running use.
