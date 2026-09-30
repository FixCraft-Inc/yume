// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

pragma Singleton
import QtQuick
import YumeBackend 1.0

// The GUI's design tokens. Colours are the website's OKLCH tokens
// (website/assets/tokens.css) converted to sRGB: neutrals on the plum axis,
// hue 337, and the figure roles at matched lightness. Light is the default.
QtObject {
    readonly property bool dark: App.dark

    readonly property color paper: dark ? "#10080e" : "#fff9fd"
    readonly property color paperSoft: dark ? "#2a1d26" : "#ffedfa"
    readonly property color paperDeep: dark ? "#1b0b17" : "#fce0f3"
    readonly property color cloud: dark ? "#21171e" : "#fffcfe"
    readonly property color ink: dark ? "#f0e4ec" : "#392c35"
    readonly property color inkSoft: dark ? "#c3b6bf" : "#503f4b"
    readonly property color muted: dark ? "#958891" : "#6c5a67"
    readonly property color rule: dark ? "#40343c" : "#e3d2dd"
    readonly property color ruleSoft: dark ? "#2a2127" : "#f4e7f0"
    readonly property color accent: dark ? "#e596d0" : "#e899d3"
    readonly property color accentStrong: dark ? "#ffb2ee" : "#9c4088"
    readonly property color accentSoft: dark ? "#3e1935" : "#fad4ef"
    readonly property color button: dark ? "#e8a5d5" : "#f8bbe7"
    readonly property color buttonHover: dark ? "#ffb5eb" : "#f4a7df"
    readonly property color buttonInk: dark ? "#1f111b" : "#392c35"
    readonly property color focus: accentStrong

    // Roles: the server in iris, data in blue, the disguise in amber, keys
    // in yellow, the outside world in mint and refusals in coral.
    readonly property color server: dark ? "#a392d6" : "#b5a4ea"
    readonly property color serverStrong: dark ? "#d1c4fd" : "#674ea1"
    readonly property color serverSoft: dark ? "#2b243f" : "#ebe5ff"
    readonly property color data: dark ? "#6da4d3" : "#7cb8ea"
    readonly property color dataStrong: dark ? "#a8d3f9" : "#1b659a"
    readonly property color dataSoft: dark ? "#12283b" : "#dbeefe"
    readonly property color disguise: dark ? "#dd9b5f" : "#f1ad71"
    readonly property color disguiseStrong: dark ? "#f8c696" : "#985521"
    readonly property color disguiseSoft: dark ? "#3c220f" : "#ffe8d2"
    readonly property color keys: dark ? "#e0c262" : "#f0ce65"
    readonly property color keysStrong: dark ? "#f3de90" : "#7d5e07"
    readonly property color keysSoft: dark ? "#352a09" : "#fcf2cd"
    readonly property color outside: dark ? "#73b598" : "#82c9aa"
    readonly property color outsideStrong: dark ? "#aadfc6" : "#25694f"
    readonly property color outsideSoft: dark ? "#112d21" : "#dbf4e8"
    readonly property color refused: dark ? "#da827b" : "#ec928b"
    readonly property color refusedStrong: dark ? "#febab4" : "#a73e3b"
    readonly property color refusedSoft: dark ? "#401d1b" : "#ffe3df"

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
