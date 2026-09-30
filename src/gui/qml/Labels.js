// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

.pragma library

// Wording the pages share. How a state is classed and named is
// AppState::state_kind and state_label, which the tray uses too.

function nodes(list) {
    return list ? list.join("  ›  ") : ""
}

function hops(count) {
    return count === 1 ? qsTr("1 hop") : qsTr("%1 hops").arg(count)
}

// A route's length before a noun: "a 3-hop route".
function hopRoute(count) {
    return qsTr("%1-hop route").arg(count)
}
