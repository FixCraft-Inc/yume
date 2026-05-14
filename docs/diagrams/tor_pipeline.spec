# Source of truth for the "Routing through Tor" diagram in README.md.
# Render with: scripts/draw_pipeline.py docs/diagrams/tor_pipeline.spec
--
title: HUMAN APP
sub:   browser / curl
--
title: YUME CLIENT
sub:   --tor or --proxy
arrow: local SOCKS / --run
--
title: LOCAL TOR
sub:   127.0.0.1:9050
arrow: SOCKS5 to <onion>:443
--
title: TOR CIRCUIT
sub:   hidden-service rendezvous
arrow: encrypted Tor cells
--
title: SERVER TOR
sub:   publishes .onion
arrow: rendezvous on server
--
title: YUMED SERVER
sub:   binds 127.0.0.1 only
arrow: TLS 1.3 + YUME frames
--
title: TARGET SITE
sub:   sees yumed egress IP
arrow: outbound socket
