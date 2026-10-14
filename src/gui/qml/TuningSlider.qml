// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ColumnLayout {
    id: row
    property string label
    property string axis
    property int level: 1
    property int maximum: 4
    property color tint: Theme.accentStrong
    property string explanation
    signal selected(int level)
    spacing: 2
    RowLayout {
        Layout.fillWidth: true
        Text {
            textFormat: Text.PlainText
            text: row.label
            color: row.tint
            font.pixelSize: Theme.textBody
            font.weight: Font.DemiBold
            Layout.fillWidth: true
        }
        Text {
            textFormat: Text.PlainText
            text: row.level + " / " + row.maximum
            color: Theme.inkSoft
            font.pixelSize: Theme.textLabel
        }
    }
    Slider {
        id: slider
        objectName: row.axis + "Slider"
        Layout.fillWidth: true
        from: 1
        to: row.maximum
        stepSize: 1
        snapMode: Slider.SnapAlways
        value: row.level
        Accessible.name: row.label
        Accessible.description: row.explanation
        onMoved: row.selected(Math.round(value))
        AppToolTip {
            visible: slider.hovered && row.explanation.length > 0
            text: row.explanation
        }
        background: Item {
            x: slider.leftPadding
            y: slider.topPadding + slider.availableHeight / 2 - height / 2
            implicitHeight: 12
            width: slider.availableWidth
            height: implicitHeight
            Rectangle { anchors.verticalCenter: parent.verticalCenter; width: parent.width; height: 4; radius: 2; color: Theme.rule }
            Repeater {
                model: row.maximum
                Rectangle {
                    required property int index
                    width: 8; height: 8; radius: 4
                    x: index * (parent.width - width) / (row.maximum - 1)
                    anchors.verticalCenter: parent.verticalCenter
                    color: row.tint
                }
            }
        }
        handle: Rectangle {
            x: slider.leftPadding + slider.visualPosition * (slider.availableWidth - width)
            y: slider.topPadding + slider.availableHeight / 2 - height / 2
            implicitWidth: 22; implicitHeight: 22
            radius: 11
            color: row.tint
            border.width: slider.activeFocus ? 3 : 2
            border.color: slider.activeFocus ? Theme.focus : Theme.paper
        }
    }
}
