# Federated cluster: client enters any peer, traffic may cross peer links.
# Render with: scripts/draw_pipeline.py docs/diagrams/federation.spec
--
title: YUME CLIENT
sub:   any authorized key
--
title: ENTRY YUMED
sub:   bootstrap or public node
arrow: ==YUME==> mutual TLS peer link
--
title: REMOTE YUMED
sub:   cluster peer
arrow: local target open
--
title: TARGET SITE
sub:   sees remote peer egress
