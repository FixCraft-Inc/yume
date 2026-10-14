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
    return count === 1 ? qsTrId("desktop.1.hop") : qsTrId("desktop.1.hops").arg(count)
}

// A route's length before a noun: "a 3-hop route".
function hopRoute(count) {
    return qsTrId("desktop.1.hop.route").arg(count)
}

// config/tuning_presets.json is English. Each text it shows maps to the
// catalog message with that exact source, as Android resolves it, so an
// edited text falls back to its new English instead of a stale translation.
// tests/test_yume_translations.py keeps this table and the file in step.
const presetMessages = {
    "Data per key epoch": "data.per.key.epoch",
    "Flow budget": "flow.budget",
    "Credit returns per window": "credit.returns.per.window",
    "Rotate keys while idle": "rotate.keys.while.idle",
    "tunnel / direct throughput": "tuning.metric.tunnel.direct.throughput",
    "tunnel throughput": "tuning.metric.tunnel.throughput",
    "One host, one session, one download, loss-free emulated RTTs of 40, 100 and 200 ms, 6 MiB host TCP ceilings. Six 12-second samples per condition, tail-rate medians. Both peers use the selected limits.": "one.host.one.session.one.download.loss.free.emulated.rt",
    "One host, one session, one download, loss-free emulated RTTs of 40, 100 and 200 ms, host TCP ceilings raised to 64 MiB. Both peers use the selected limits.": "one.host.one.session.one.download.loss.free.emulated.rt.2",
    "Emulated paths only. Not a real-path speed or stealth claim.": "emulated.paths.only.not.a.real.path.speed.or.stealth.cl",
    "A separate run from epoch-comparison. Host ceilings and the software emulator limit results. Not a real-path speed or stealth claim.": "a.separate.run.from.epoch.comparison.host.ceilings.and",
    "Five measured throughput positions: stealth, stealth-16, balanced, fast, max. Conditions differ: fast and max improve on balanced only with raised host TCP ceilings. These are choices, not a universal speed score.": "tuning.level.speed",
    "Data per directional key epoch: 4 for 1 MiB, 3 for 4 MiB, 2 for 16 MiB, 1 for 64 MiB. Algorithms and mandatory rotation do not change.": "tuning.level.security",
    "Window, credit-return and idle-rotation settings only: 4 keeps the default 4 MiB budget, two credit returns and idle rotation off. Lower levels enlarge windows or add credit records, and fast and max add idle rekey exchanges. No classifier result is implied; changing the epoch also changes rekey frequency.": "tuning.level.stealth"
}

function presetText(english) {
    const id = presetMessages[english || ""]
    return id ? qsTrId(id) : (english || "")
}
