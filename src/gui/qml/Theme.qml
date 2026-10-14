// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

pragma Singleton
import QtQuick
import YumeBackend 1.0

// The GUI's design tokens. The colours are Material's TonalSpot scheme
// seeded with the mark's colour as it shows over white (#e59fd1), the same
// values the Android app uses, so buttons, selection, cards and text keep
// the relationships of a phone's own dynamic colours. website/DESIGN.md
// says how they were derived. The default theme follows the system.
QtObject {
    readonly property bool dark: App.dark

    readonly property color paper: dark ? "#181216" : "#fff7f9"
    readonly property color paperSoft: dark ? "#241e22" : "#f8eaf0"
    readonly property color paperDeep: dark ? "#2f282c" : "#f2e5ea"
    readonly property color cloud: dark ? "#201a1e" : "#ffffff"
    readonly property color ink: dark ? "#ecdfe5" : "#201a1e"
    readonly property color inkSoft: dark ? "#d2c2ca" : "#4f444a"
    readonly property color muted: dark ? "#9b8d94" : "#7e7178"
    readonly property color rule: dark ? "#4f444a" : "#d2c2ca"
    readonly property color ruleSoft: dark ? "#2f282c" : "#f2e5ea"
    readonly property color accent: dark ? "#f5b2e1" : "#834c75"
    readonly property color accentStrong: dark ? "#f5b2e1" : "#834c75"
    readonly property color accentSoft: dark ? "#56404f" : "#f9daed"
    readonly property color button: dark ? "#f5b2e1" : "#834c75"
    readonly property color buttonHover: dark ? "#e8a6d5" : "#8d5a80"
    readonly property color buttonInk: dark ? "#4e1e45" : "#ffffff"
    readonly property color focus: accentStrong

    // Figure and state roles: the desktop's hues harmonized toward the seed,
    // a mid tone, a strong ink and a soft container in each theme.
    readonly property color server: dark ? "#c39dd9" : "#c39dd9"
    readonly property color serverStrong: dark ? "#e0b8f6" : "#725187"
    readonly property color serverSoft: dark ? "#59396e" : "#f4daff"
    readonly property color data: dark ? "#90abe3" : "#90abe3"
    readonly property color dataStrong: dark ? "#abc7ff" : "#425e91"
    readonly property color dataSoft: dark ? "#294677" : "#d7e2ff"
    readonly property color disguise: dark ? "#e99679" : "#e99679"
    readonly property color disguiseStrong: dark ? "#ffb59b" : "#8f4c34"
    readonly property color disguiseSoft: dark ? "#72351f" : "#ffdbcf"
    readonly property color keys: dark ? "#d8a158" : "#d8a158"
    readonly property color keysStrong: dark ? "#f7bc70" : "#815512"
    readonly property color keysSoft: dark ? "#643f00" : "#ffddb6"
    readonly property color outside: dark ? "#6eb9aa" : "#6eb9aa"
    readonly property color outsideStrong: dark ? "#89d4c5" : "#156a5e"
    readonly property color outsideSoft: dark ? "#005046" : "#a5f1e1"
    readonly property color refused: dark ? "#e794a3" : "#e794a3"
    readonly property color refusedStrong: dark ? "#ffb2bf" : "#8e4958"
    readonly property color refusedSoft: dark ? "#713341" : "#ffd9de"

    readonly property string displayFont: "Jost"
    readonly property string monoFont: "monospace"

    readonly property int radius: 16
    readonly property int radiusSmall: 10
    readonly property int gap: 16
    readonly property int gapSmall: 8
    readonly property int pad: 20

    readonly property int textSmall: 12
    readonly property int textBody: 14
    readonly property int textLabel: 13
    readonly property int textHeading: 17
    readonly property int textTitle: 28
    readonly property int textHero: 36

    // The colour a connection state is shown in: mint while connected, amber
    // while it works towards one, coral after a failure, and grey at rest.
    function stateColor(kind) {
        switch (kind) {
        case "good": return outsideStrong
        case "busy": return disguiseStrong
        case "bad": return refusedStrong
        default: return muted
        }
    }
    function stateSoft(kind) {
        switch (kind) {
        case "good": return outsideSoft
        case "busy": return disguiseSoft
        case "bad": return refusedSoft
        default: return ruleSoft
        }
    }
}
