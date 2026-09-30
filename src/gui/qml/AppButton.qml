// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Controls

// A button in one of three weights: primary for a page's main action,
// secondary (outlined) and quiet (text only). Keyboard focus draws a ring.
Button {
    id: control
    property string kind: "secondary"
    property string iconName
    property bool compact: false

    focusPolicy: Qt.StrongFocus
    hoverEnabled: true
    Accessible.name: text
    // Space activates a focused button, and so do Return and Enter.
    Keys.onReturnPressed: if (enabled) clicked()
    Keys.onEnterPressed: if (enabled) clicked()
    implicitHeight: compact ? 30 : 38
    leftPadding: compact ? 10 : 16
    rightPadding: compact ? 10 : 16
    font.pixelSize: compact ? Theme.textSmall : Theme.textBody
    font.weight: Font.DemiBold

    contentItem: Row {
        spacing: 7
        Icon {
            visible: control.iconName.length > 0
            name: control.iconName
            width: control.compact ? 14 : 16
            height: width
            anchors.verticalCenter: parent.verticalCenter
            color: label.color
        }
        Text {
            textFormat: Text.PlainText
            id: label
            text: control.text
            font: control.font
            anchors.verticalCenter: parent.verticalCenter
            color: !control.enabled ? Theme.muted
                 : control.kind === "primary" ? Theme.buttonInk
                 : control.kind === "danger" ? Theme.refusedStrong
                 : Theme.ink
        }
    }

    background: Rectangle {
        radius: height / 2
        color: {
            if (control.kind === "primary")
                return !control.enabled ? Theme.ruleSoft
                     : control.down || control.hovered ? Theme.buttonHover : Theme.button
            if (control.kind === "quiet")
                return control.down || control.hovered ? Theme.ruleSoft : "transparent"
            return control.down || control.hovered ? Theme.paperSoft : Theme.cloud
        }
        border.width: control.visualFocus ? 2 : (control.kind === "secondary" || control.kind === "danger" ? 1 : 0)
        border.color: control.visualFocus ? Theme.focus
                    : control.kind === "danger" ? Theme.refused : Theme.rule
    }
}
