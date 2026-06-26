# Relay path: client in one region, exit yumed in another (PERFORMANCE.md).
# Render with: scripts/draw_pipeline.py docs/diagrams/relay_route.spec
--
title: HUMAN APP
sub:   browser / curl
--
title: YUME CLIENT
sub:   US or home network
arrow: ==YUME==>
--
title: RELAY YUMED
sub:   entry / mid-hop server
arrow: ==YUME==> federation or relay
--
title: EXIT YUMED
sub:   Japan or egress region
arrow: outbound socket
--
title: TARGET SITE
sub:   sees exit server IP
