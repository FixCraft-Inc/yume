# Preventing SOCKS bypass

YUME's SOCKS listener carries only the connections that an application sends
to it. It is not a system VPN or a kill switch. A browser can still use direct
DNS, QUIC, WebRTC, connectivity checks, or another process for traffic outside
the configured proxy path.

Treat browser settings as one layer. Browser flags and preferences change, so
verify them against the browser version you deploy. If traffic must fail closed
for the whole machine, enforce that in the operating system and review the
policy independently.

## Browser setup

For Chromium-family browsers, start with a separate profile and route names
through the SOCKS proxy:

```bash
chromium \
  --user-data-dir=/tmp/chromium-yume-profile \
  --proxy-server="socks5://127.0.0.1:1088" \
  --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1" \
  --disable-quic \
  --webrtc-ip-handling-policy=disable_non_proxied_udp \
  --enable-features=WebRtcHideLocalIpsWithMdns \
  --no-pings
```

This configuration sends HTTP and HTTPS through SOCKS, prevents ordinary
local name resolution, disables QUIC's direct UDP path, and limits non-proxied
WebRTC candidates. WebRTC applications may stop working unless they can use a
proxied TCP relay. Chromium can remove or rename flags, so an accepted command
line is not evidence that every request followed it.

For Firefox, set the SOCKS host and port, then enable remote DNS. Disable HTTP/3
and either disable WebRTC or restrict it to the proxy policy required by your
deployment. The relevant preferences include:

```text
network.proxy.type = 1
network.proxy.socks = 127.0.0.1
network.proxy.socks_port = 1088
network.proxy.socks_version = 5
network.proxy.socks_remote_dns = true
network.http.http3.enabled = false
media.peerconnection.enabled = false
network.dns.disablePrefetch = true
network.dns.disablePrefetchFromHTTPS = true
network.prefetch-next = false
```

Disabling WebRTC is the simpler fail-closed choice when calls and peer-to-peer
browser features are not needed. Managed-browser policies are preferable to
per-user flags for a maintained deployment.

## Verify the route

First confirm that a request explicitly sent through SOCKS exits from the YUME
server's address:

```bash
curl --socks5-hostname 127.0.0.1:1088 https://ipinfo.io/ip
```

Then observe the client host while loading pages. Replace the example server
address with the actual YUME endpoint:

```bash
sudo tcpdump -n -i any \
  'not host 127.0.0.1 and not host 203.0.113.10'
```

Unexpected DNS, UDP/443, STUN, or direct destination traffic is a bypass. Also
test browser startup, shutdown, extension updates, captive-portal checks,
WebRTC, IPv4, IPv6, DNS failure, YUME disconnect, and process restart. A single
IP-check page does not qualify a route policy.

## System-wide enforcement

A system-wide policy should allow the YUME process to reach only its configured
server path, allow the required loopback listeners, and reject other outbound
traffic. It must cover TCP, UDP, DNS, and IPv6. Network namespaces, a dedicated
service account, and nftables or the platform firewall can provide that
boundary.

Do not paste a generic firewall recipe into a remote system. Interface names,
resolver behavior, service accounts, local networks, management access, and
recovery paths differ. Resolve those inputs first, apply the rules through a
recoverable console, and test that stopping YUME blocks the protected workload
without locking out administration.

YUME does not currently publish a qualified full-system routing or kill-switch
configuration. The packet and TUN paths are separate features with their own
platform and release gates.

## Android boundary

The separate Android client uses `android.net.VpnService` and a TUN device, but
its current native synchronization, connected routing, DNS, IPv6, bypass,
revocation, reconnect, and kill-switch gates remain open. Do not rely on the
present Android build as a YUME kill switch until those paths pass direct
device tests against the same native candidate.
