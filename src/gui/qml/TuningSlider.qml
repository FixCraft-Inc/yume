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
    property color tint: Theme.accent
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
            // The track fills up to the handle, and each level's stop takes
            // the tint once the level reaches it.
            Rectangle { anchors.verticalCenter: parent.verticalCenter; width: parent.width; height: 4; radius: 2; color: Theme.rule }
            Rectangle {
                anchors.verticalCenter: parent.verticalCenter
                x: slider.mirrored ? parent.width - width : 0
                width: slider.visualPosition * parent.width
                height: 4; radius: 2
                color: row.tint
            }
            Repeater {
                model: row.maximum
                Rectangle {
                    required property int index
                    width: 6; height: 6; radius: 3
                    x: (slider.mirrored ? row.maximum - 1 - index : index) * (parent.width - width) / (row.maximum - 1)
                    anchors.verticalCenter: parent.verticalCenter
                    color: index + 1 <= slider.value ? row.tint : Theme.lineStrong
                }
            }
        }
        handle: Rectangle {
            x: slider.leftPadding + slider.visualPosition * (slider.availableWidth - width)
            y: slider.topPadding + slider.availableHeight / 2 - height / 2
            implicitWidth: 20; implicitHeight: 20
            radius: 10
            color: row.tint
            border.width: 3
            border.color: slider.activeFocus ? Theme.focus : Theme.cloud
        }
    }
}
