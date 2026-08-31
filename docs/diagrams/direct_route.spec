# Source of truth for the direct-route diagram in docs/man/yume.1 (ROUTING MODEL).
# Render with: scripts/draw_pipeline.py docs/diagrams/direct_route.spec
--
title: HUMAN APP
sub:   browser / curl
--
title: YUME CLIENT
sub:   TLS / H2 / YUME frames
--
title: YUMED SERVER
sub:   direct egress
arrow: ==YUME==>
--
title: TARGET SITE
sub:   sees server IP
