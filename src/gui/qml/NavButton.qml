// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Controls

// One entry of the sidebar's page list.
ItemDelegate {
    id: control
    property string iconName
    property string shortcutText
    property bool current: false

    focusPolicy: Qt.StrongFocus
    hoverEnabled: true
    implicitHeight: 40
    leftPadding: 12
    rightPadding: 12
    Accessible.role: Accessible.PageTab
    Accessible.name: text
    Accessible.selected: current
    Keys.onReturnPressed: clicked()
    Keys.onEnterPressed: clicked()

    contentItem: Item {
        implicitHeight: 24
        Icon {
            id: glyph
            name: control.iconName
            width: 18; height: 18
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            color: control.current ? Theme.accentStrong : Theme.inkSoft
        }
        Text {
            textFormat: Text.PlainText
            text: control.text
            anchors.left: glyph.right
            anchors.leftMargin: 12
            anchors.right: hint.left
            anchors.verticalCenter: parent.verticalCenter
            color: control.current ? Theme.ink : Theme.inkSoft
            font.pixelSize: Theme.textBody
            font.weight: control.current ? Font.DemiBold : Font.Normal
            elide: Text.ElideRight
        }
        Text {
            textFormat: Text.PlainText
            id: hint
            text: control.shortcutText
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            color: Theme.muted
            font.pixelSize: 11
            opacity: control.hovered || control.visualFocus ? 1 : 0
        }
    }

    background: Rectangle {
        radius: Theme.radiusSmall
        color: control.current ? Theme.accentSoft
             : control.hovered ? Theme.paperDeep : "transparent"
        border.width: control.visualFocus ? 2 : 0
        border.color: Theme.focus
    }
}
