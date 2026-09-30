// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Layouts

// One figure with its label, for the overview's tiles.
Rectangle {
    id: metric
    property string label
    property string value
    property string detail
    property string iconName
    property color tint: Theme.ink

    color: Theme.cloud
    radius: Theme.radius
    border.color: Theme.rule
    implicitHeight: content.implicitHeight + 32
    implicitWidth: 180
    Accessible.role: Accessible.StaticText
    Accessible.name: label + ": " + value

    ColumnLayout {
        id: content
        anchors.fill: parent
        anchors.margins: 16
        spacing: 4
        RowLayout {
            spacing: 6
            Icon {
                visible: metric.iconName.length > 0
                name: metric.iconName
                size: 14
                color: Theme.muted
            }
            Text {
                textFormat: Text.PlainText
                horizontalAlignment: Text.AlignLeft
                text: metric.label
                color: Theme.muted
                font.pixelSize: Theme.textSmall
                font.weight: Font.DemiBold
                Layout.fillWidth: true
                elide: Text.ElideRight
            }
        }
        Text {
            textFormat: Text.PlainText
            horizontalAlignment: Text.AlignLeft
            text: metric.value
            color: metric.tint
            font.family: Theme.displayFont
            font.pixelSize: 26
            Layout.fillWidth: true
            elide: Text.ElideRight
        }
        Text {
            textFormat: Text.PlainText
            horizontalAlignment: Text.AlignLeft
            visible: metric.detail.length > 0
            text: metric.detail
            color: Theme.muted
            font.pixelSize: Theme.textSmall
            Layout.fillWidth: true
            elide: Text.ElideRight
        }
    }
}
