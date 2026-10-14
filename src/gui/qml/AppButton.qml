// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Controls

// A button in one of four weights: primary for a page's main action (the
// palette's soft button colour), secondary (outlined), quiet (text only) and
// danger. Hover and press each step the fill. Keyboard focus draws a ring.
// An iconOnly button draws just its icon and shows its text as a tooltip,
// which also names it to screen readers.
Button {
    id: control
    property string kind: "secondary"
    property string iconName
    property bool compact: false
    property bool iconOnly: false

    focusPolicy: Qt.StrongFocus
    hoverEnabled: true
    Accessible.name: text
    // Space activates a focused button, and so do Return and Enter.
    Keys.onReturnPressed: if (enabled) clicked()
    Keys.onEnterPressed: if (enabled) clicked()
    implicitHeight: compact ? 30 : 38
    implicitWidth: iconOnly ? implicitHeight : implicitContentWidth + leftPadding + rightPadding
    leftPadding: iconOnly ? 0 : compact ? 10 : 16
    rightPadding: iconOnly ? 0 : compact ? 10 : 16
    font.pixelSize: compact ? Theme.textSmall : Theme.textBody
    font.weight: Font.DemiBold

    contentItem: Row {
        spacing: 7
        // An icon alone sits in the middle of the button.
        leftPadding: control.iconOnly ? (control.availableWidth - buttonIcon.size) / 2 : 0
        Icon {
            id: buttonIcon
            visible: control.iconName.length > 0
            name: control.iconName
            size: control.compact ? 14 : 16
            anchors.verticalCenter: parent.verticalCenter
            color: label.color
        }
        Text {
            textFormat: Text.PlainText
            id: label
            visible: !control.iconOnly
            text: control.text
            font: control.font
            anchors.verticalCenter: parent.verticalCenter
            color: !control.enabled ? Theme.muted
                 : control.kind === "primary" ? Theme.buttonInk
                 : control.kind === "danger" ? Theme.refusedStrong
                 : Theme.ink
        }
    }

    AppToolTip {
        visible: control.iconOnly && (control.hovered || control.visualFocus)
        text: control.text
    }

    background: Rectangle {
        radius: height / 2
        color: {
            if (control.kind === "primary")
                return !control.enabled ? Theme.paperDeep
                     : control.down ? Theme.buttonPressed
                     : control.hovered ? Theme.buttonHover : Theme.button
            if (!control.enabled)
                return "transparent"
            if (control.kind === "quiet")
                return control.down ? Theme.paperDeep : control.hovered ? Theme.paperSoft : "transparent"
            return control.down ? Theme.paperDeep : control.hovered ? Theme.paperSoft : Theme.cloud
        }
        border.width: control.visualFocus ? 2 : (control.kind === "secondary" || control.kind === "danger" ? 1 : 0)
        border.color: control.visualFocus ? Theme.focus
                    : control.kind === "danger" ? Theme.refused : Theme.rule
        Behavior on color { ColorAnimation { duration: 120 } }
    }
}
