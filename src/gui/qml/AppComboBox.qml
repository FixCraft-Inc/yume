// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.
import QtQuick
import QtQuick.Controls

ComboBox {
    id: control
    implicitHeight: 38
    leftPadding: mirrored ? 32 : 12
    rightPadding: mirrored ? 12 : 32
    contentItem: Text {
        textFormat: Text.PlainText
        text: control.displayText
        color: control.enabled ? Theme.ink : Theme.muted
        font.pixelSize: Theme.textBody
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
    }
    background: Rectangle {
        radius: Theme.radiusSmall
        color: Theme.paper
        border.width: control.activeFocus ? 2 : 1
        border.color: control.activeFocus ? Theme.focus : Theme.rule
    }
    indicator: Text {
        textFormat: Text.PlainText
        text: "⌄"
        color: Theme.inkSoft
        x: control.mirrored ? 12 : control.width - width - 12
        y: (control.height - height) / 2
        font.pixelSize: 20
    }
    delegate: ItemDelegate {
        required property var modelData
        required property int index
        width: control.width
        highlighted: control.highlightedIndex === index
        contentItem: Text {
            textFormat: Text.PlainText
            text: modelData[control.textRole]
            color: Theme.ink
            font.pixelSize: Theme.textBody
            elide: Text.ElideRight
        }
        background: Rectangle { color: parent.highlighted ? Theme.accentSoft : Theme.paper }
    }
    popup.background: Rectangle { color: Theme.paper; border.color: Theme.rule; radius: Theme.radiusSmall }
}
