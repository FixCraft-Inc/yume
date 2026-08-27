# Current federation: one direct peer link joins two local relay endpoints.
# There is no third-node transit and no federated exit/proxy path.
# Render with: scripts/draw_pipeline.py docs/diagrams/federation.spec
--
title: YUME CLIENT A
sub:   local relay endpoint
--
title: YUMED A
sub:   direct federation peer
arrow: TLS / H2 / AUTH v2
--
title: YUMED B
sub:   one hop; no transit
arrow: direct authenticated link
--
title: YUME CLIENT B
sub:   local relay endpoint
arrow: relay invite / data / close
