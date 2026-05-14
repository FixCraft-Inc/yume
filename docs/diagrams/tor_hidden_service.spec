# Companion to yume.1's ROUTING MODEL section — describes
# `yume --tor --server <onion>` routing.
# Render with: scripts/draw_pipeline.py docs/diagrams/tor_hidden_service.spec
width: 34
--
title: HUMAN APP
sub:   browser / curl
--
title: YUME CLIENT
sub:   --tor / --proxy socks5://...
arrow: SOCKS, --run, or forward
--
title: LOCAL TOR
sub:   127.0.0.1:9050
arrow: SOCKS5 to <onion>:443
--
title: TOR CIRCUIT
sub:   hidden-service rendezvous
arrow: encrypted cells
--
title: SERVER TOR
sub:   hidden service publisher
arrow: rendezvous on server
--
title: YUMED SERVER
sub:   binds 127.0.0.1 only
arrow: TLS 1.3 + YUME frames
--
title: TARGET SITE
sub:   sees yumed egress IP
arrow: outbound socket
