# Source of truth for the "Routing through Tor" diagram in README.md.
# Render with: scripts/draw_pipeline.py docs/diagrams/tor_pipeline.spec
width: 72
--
title: HUMAN APP
sub:   browser / curl on machine A
--
title: YUME CLIENT
sub:   --proxy or --tor
arrow: local SOCKS / --run / forward
--
title: LOCAL TOR
sub:   SOCKS5 on 127.0.0.1:9050
arrow: SOCKS5 CONNECT to <onion>:443
--
title: TOR CIRCUIT
sub:   3 hops, hidden-service rendezvous
arrow: encrypted Tor cells
--
title: SERVER TOR
sub:   HiddenServicePort 443 -> 127.0.0.1:443
arrow: rendezvous on machine B
--
title: YUMED SERVER
sub:   sees a 127.0.0.1 connection
arrow: TLS 1.3 + YUME frames
--
title: TARGET SITE
sub:   sees yumed egress IP
arrow: outbound TCP/UDP
