// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Layouts

// A fixed fact of the posture: what it is and what it means, never a switch.
RowLayout {
    id: fact
    property string label
    property string value
    property string note
    property string iconName
    property color tint: Theme.accentStrong
    spacing: 12
    Accessible.role: Accessible.StaticText
    Accessible.name: label + ": " + value

    Rectangle {
        Layout.alignment: Qt.AlignTop
        width: 30; height: 30; radius: 9
        color: Qt.rgba(fact.tint.r, fact.tint.g, fact.tint.b, 0.12)
        Icon {
            anchors.centerIn: parent
            name: fact.iconName
            width: 16; height: 16
            color: fact.tint
        }
    }
    ColumnLayout {
        spacing: 1
        Layout.fillWidth: true
        Text {
            textFormat: Text.PlainText
            horizontalAlignment: Text.AlignLeft
            text: fact.label
            color: Theme.muted
            font.pixelSize: Theme.textSmall
            font.weight: Font.DemiBold
            Layout.fillWidth: true
        }
        Text {
            textFormat: Text.PlainText
            horizontalAlignment: Text.AlignLeft
            text: fact.value
            color: Theme.ink
            font.pixelSize: Theme.textBody
            font.weight: Font.DemiBold
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
        }
        Text {
            textFormat: Text.PlainText
            horizontalAlignment: Text.AlignLeft
            visible: fact.note.length > 0
            text: fact.note
            color: Theme.inkSoft
            font.pixelSize: Theme.textSmall
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
        }
    }
}
