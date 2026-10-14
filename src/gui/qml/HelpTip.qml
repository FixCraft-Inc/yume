// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Controls

// A small "?" that holds an explanation the page does not spell out. The
// text shows on hover, on keyboard focus and while pressed, and screen
// readers hear it as the button's description.
AbstractButton {
    id: tip
    property string help
    // What the explanation is about, which screen readers announce first.
    property string name

    focusPolicy: Qt.StrongFocus
    hoverEnabled: true
    implicitWidth: 22
    implicitHeight: 22
    Accessible.role: Accessible.Button
    Accessible.name: name
    Accessible.description: help

    AppToolTip {
        visible: tip.hovered || tip.visualFocus || tip.pressed
        delay: tip.hovered ? 300 : 0
        text: tip.help
    }

    contentItem: Icon {
        name: "help"
        size: 16
        stroke: 1.6
        color: tip.hovered || tip.visualFocus ? Theme.accentStrong : Theme.muted
    }
    background: Rectangle {
        radius: width / 2
        color: tip.hovered ? Theme.ruleSoft : "transparent"
        border.width: tip.visualFocus ? 2 : 0
        border.color: Theme.focus
    }
}
