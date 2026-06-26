# Source of truth for the "Typical Direct Route" diagram in EXPLAINED.md.
# Render with: scripts/draw_pipeline.py docs/diagrams/direct_route.spec
--
title: HUMAN APP
sub:   browser / curl
--
title: YUME CLIENT
sub:   TLS / H2 / YUME frames
arrow: ==YUME==>
--
title: YUMED SERVER
sub:   direct egress
arrow: outbound TCP/UDP
--
title: TARGET SITE
sub:   sees server IP
