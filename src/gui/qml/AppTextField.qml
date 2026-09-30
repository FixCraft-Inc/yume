// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Controls

// A text field in the GUI's theme, with a focus ring.
TextField {
    id: control
    implicitHeight: 38
    leftPadding: 12
    rightPadding: 12
    color: Theme.ink
    placeholderTextColor: Qt.rgba(Theme.muted.r, Theme.muted.g, Theme.muted.b, 0.6)
    selectionColor: Theme.accent
    selectedTextColor: Theme.buttonInk
    font.pixelSize: Theme.textBody
    background: Rectangle {
        radius: Theme.radiusSmall
        color: Theme.paper
        border.width: control.activeFocus ? 2 : 1
        border.color: control.activeFocus ? Theme.focus : Theme.rule
    }
}
