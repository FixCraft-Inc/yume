// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.
import QtQuick
import QtQuick.Controls

// A drop-down list in the field's style. Its list opens as a card below it,
// with the highlighted choice on the soft accent.
ComboBox {
    id: control
    implicitHeight: 38
    hoverEnabled: true
    leftPadding: mirrored ? 34 : 12
    rightPadding: mirrored ? 12 : 34
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
        border.color: control.activeFocus ? Theme.focus
                    : control.hovered ? Theme.lineStrong : Theme.rule
    }
    indicator: Icon {
        name: "chevron-down"
        size: 16
        stroke: 2
        color: Theme.inkSoft
        x: control.mirrored ? 12 : control.width - width - 12
        y: (control.height - height) / 2
        rotation: control.popup.visible ? 180 : 0
    }
    delegate: ItemDelegate {
        id: choice
        required property var modelData
        required property int index
        width: ListView.view ? ListView.view.width : control.width
        implicitHeight: 34
        hoverEnabled: true
        highlighted: control.highlightedIndex === index
        contentItem: Text {
            textFormat: Text.PlainText
            text: choice.modelData[control.textRole]
            color: control.currentIndex === choice.index ? Theme.accentInk : Theme.ink
            font.pixelSize: Theme.textBody
            font.weight: control.currentIndex === choice.index ? Font.DemiBold : Font.Normal
            verticalAlignment: Text.AlignVCenter
            elide: Text.ElideRight
        }
        background: Rectangle {
            radius: Theme.radiusSmall - 2
            color: control.currentIndex === choice.index ? Theme.accentSoft
                 : choice.highlighted || choice.hovered ? Theme.paperSoft : "transparent"
        }
    }
    popup.y: control.height + 4
    popup.padding: 4
    popup.background: Rectangle {
        color: Theme.cloud
        border.color: Theme.ruleSoft
        radius: Theme.radiusSmall
    }
}
