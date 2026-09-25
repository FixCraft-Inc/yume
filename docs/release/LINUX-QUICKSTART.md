<!-- Generated from docs/src/en_US/pages/linux_quickstart.doc by scripts/yume_docs.py. Edit that file, not this one. -->
# YUME Linux x86-64 release quick start

The release lane targets glibc Linux on x86-64. It builds on Ubuntu 24.04,
and its binaries need glibc 2.38 or newer, so Ubuntu 22.04 and Debian 12
cannot run them. The native client archive and server executable are separate
artifacts:

- `yume-amd64-linux.tar.xz` contains `yume`, `yume-setup`, `yume-doctor`,
  licensing documents, this quick start and `manifest.json`.
- `yumed-amd64-linux` is the native server executable.

The release manifest identifies the exact files and source. Android,
Windows, macOS, ARM,
OpenWrt, fully static binaries and Debian packages require their own
qualification. A generated archive alone is not a qualified release.

## Verify and unpack

Verify the published checksum and detached signature before installation.
Keep both downloaded artifacts from the same release, then unpack the client:

```sh
tar -xJf yume-amd64-linux.tar.xz
cd yume-amd64-linux
./yume --version
```

The native release binaries embed the pinned patched OpenSSL needed by their
transport. Packaging checks reject runtime OpenSSL/liboqs dependencies and
embedded build-directory search paths. Setup and doctor are Python tools;
they separately require Python 3 and an OpenSSL 3.5 or newer command-line
executable on `PATH`. Compare unpacked files with `manifest.json` before
running them.

## Provision and connect

Use the bundled tools to create a new schema-1 server kit and first client.
The output directory must not already exist:

```sh
./yume-setup init --host server.example --port 8443 --output "$PWD/server-kit"
./yume-doctor --config server-kit/client/yume.json
./yume --config server-kit/client/yume.json --validate
```

The kit contains TLS material, composite identities, independent admission
and client access keys, server authorization and a cover site. Transfer only
`server-kit/server/` to the endpoint. Keep the client directory on the client
machine and preserve private-file permissions. Review the server's endpoint
and direct TCP/UDP destination policy before startup.

On the server, install the matching daemon and validate the transferred
configuration as the account that will run it:

```sh
sudo install -m 0755 /path/to/yumed-amd64-linux /usr/local/bin/yumed
yumed --config /path/to/server/yumed.json --validate
yumed --config /path/to/server/yumed.json
```

The example uses unprivileged port 8443. For port 443, provision with
`--port 443` and arrange `CAP_NET_BIND_SERVICE` through an appropriate service
configuration. The archive does not install a service or change the host
network. The daemon serves the generated cover site in-process.

Once the server is running, connect from the client:

```sh
./yume --config server-kit/client/yume.json
```

The generated client exposes SOCKS5 on `127.0.0.1:1080`. The native CLI uses
schema-1 configuration.
Read the matching implementation status and release notes before treating a
build as qualified for a platform, classifier, network or long-running use.
