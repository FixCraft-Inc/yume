// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

pragma Singleton
import QtQuick
import YumeBackend 1.0
import "Palette.js" as Palette

// The GUI's design tokens. The colours are YUME's shared palette,
// config/palette.json, generated into Palette.js: the values the Android app
// and the website use, with light and dark designed as separate themes.
// website/DESIGN.md describes the palette. The default theme follows the
// system.
QtObject {
    readonly property bool dark: App.dark
    readonly property var p: dark ? Palette.dark : Palette.light

    // The page, the cards and sidebar on it, the wash under a hovered
    // control, and rows or selections raised inside a card.
    readonly property color paper: p.page
    readonly property color cloud: p.surface
    readonly property color paperSoft: p.hover
    readonly property color paperDeep: p.raised
    readonly property color ink: p.ink
    readonly property color inkSoft: p.inkSoft
    readonly property color muted: p.muted
    // A field's outline, a button's border, and the hairline of a card or a
    // divider.
    readonly property color lineStrong: p.lineStrong
    readonly property color rule: p.line
    readonly property color ruleSoft: p.hairline
    // The accent marks controls, links and the current item, on its soft
    // container where something is selected.
    readonly property color accent: p.accent
    readonly property color accentOn: p.accentOn
    readonly property color accentSoft: p.accentSoft
    readonly property color accentInk: p.accentInk
    // The main action: blossom with plum text in light, pink with wine in dark.
    readonly property color button: p.button
    readonly property color buttonHover: p.buttonHover
    readonly property color buttonPressed: p.buttonPressed
    readonly property color buttonInk: p.buttonInk
    readonly property color focus: p.focus
    readonly property color inverse: p.inverse
    readonly property color inverseInk: p.inverseInk
    readonly property color logoFrom: p.logoFrom
    readonly property color logoTo: p.logoTo

    // Figure and state roles: natural hues at low strength, each with a mid
    // tone, a strong ink, a soft container and the ink on that container.
    readonly property color server: p.serverMid
    readonly property color serverStrong: p.serverStrong
    readonly property color serverSoft: p.serverSoft
    readonly property color serverInk: p.serverOnSoft
    readonly property color data: p.dataMid
    readonly property color dataStrong: p.dataStrong
    readonly property color dataSoft: p.dataSoft
    readonly property color dataInk: p.dataOnSoft
    readonly property color disguise: p.disguiseMid
    readonly property color disguiseStrong: p.disguiseStrong
    readonly property color disguiseSoft: p.disguiseSoft
    readonly property color disguiseInk: p.disguiseOnSoft
    readonly property color keys: p.keysMid
    readonly property color keysStrong: p.keysStrong
    readonly property color keysSoft: p.keysSoft
    readonly property color keysInk: p.keysOnSoft
    readonly property color outside: p.outsideMid
    readonly property color outsideStrong: p.outsideStrong
    readonly property color outsideSoft: p.outsideSoft
    readonly property color outsideInk: p.outsideOnSoft
    readonly property color refused: p.refusedMid
    readonly property color refusedStrong: p.refusedStrong
    readonly property color refusedSoft: p.refusedSoft
    readonly property color refusedInk: p.refusedOnSoft

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

    // The colour a connection state is shown in: sage while connected,
    // apricot while it works towards one, rose after a failure, and grey at
    // rest. The strong tone is the text on the soft one.
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
        default: return paperDeep
        }
    }
}
