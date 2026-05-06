---
layout: doc
title: YUME operations
permalink: /docs/OPERATIONS/
---

# YUME operations

This page covers the release, deployment, and service workflows that operators need after the first successful connection.

## Release verification

Each release is expected to publish:

- client and daemon artifacts for supported targets
- per-artifact `.sha256` files
- per-artifact `.md5` files
- aggregate `SHA256SUMS.txt` and `MD5SUMS.txt`
- `release-manifest.json`
- optional `.sig` detached signatures when GPG secrets are configured

Recommended verification:

```bash
sha256sum -c SHA256SUMS.txt
md5sum -c MD5SUMS.txt
gpg --verify yumed-amd64-linux.sig yumed-amd64-linux
```

The manifest records file size, OS, architecture, component, linkage, hashes, and signature sidecars. Treat missing mandatory hashes as a release problem.

## BaseFWX pinning

YUME depends on BaseFWX for post-quantum and AEAD primitives. The release and CI workflows read `.basefwx-ref`, fetch that exact ref, and fail preflight if it is not reachable. Keep this file pinned to a commit or immutable release ref for production releases.

## Service deployment

A minimal systemd service can run the daemon with a dedicated user:

```ini
[Unit]
Description=YUME daemon
After=network-online.target
Wants=network-online.target

[Service]
User=yume
Group=yume
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/yumed --listen 443 --cert /etc/yume/server.crt --key /etc/yume/server.key --auth-keys /etc/yume/authorized_keys --real --real-index /var/www/yume/index.html
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

For a hardened service, keep `auth_keys.meta`, TLS private keys, and PQ private keys readable only by the daemon user.

## Key and permission operations

List keys and aliases:

```bash
yumed --auth-keys /etc/yume/authorized_keys --keys-list
```

Add a generated key:

```bash
yumed --auth-keys /etc/yume/authorized_keys --keys-gen ./keys/user1 --keys-gen-add
```

Remove a key or alias:

```bash
yumed --auth-keys /etc/yume/authorized_keys --keys-remove alice
```

`authorized_keys` controls connection admission. `auth_keys.meta` controls post-auth permissions. The daemon reads both at startup, so restart after editing.

## Public endpoint policy

Public endpoints should publish:

- hostname and port
- daemon release tag
- TLS certificate identity
- YUME public key or expected key fingerprint
- allowed modes and fair-use limits
- whether anonym proof is enabled
- whether the endpoint accepts only SOCKS/forwarding or also admin/file/chat channels

Do not advertise a public endpoint until users can pin enough metadata to detect replacement or downgrade.

## Troubleshooting

If the client cannot connect:

- confirm direct TCP reachability to the daemon port
- confirm no HTTP proxy is terminating TLS in front of `yumed`
- run the client with `--no-obfs` only as a diagnostic comparison
- ensure client and server agree on `--obfs-secret` when strict pinning is enabled
- check that the client's public key is present in `authorized_keys`
- verify that the server certificate chain matches what the client expects

If forwarding connects but cannot reach a target:

- check `auth_keys.meta` for LAN/private-IP permission if the target is RFC1918 or loopback
- confirm the release was built with the required feature switch
- confirm the daemon was started with the matching runtime flag
- inspect daemon logs for an auth-policy denial
