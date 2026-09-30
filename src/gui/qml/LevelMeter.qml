// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Layouts

// A preset's level, 1 to 4, as four segments. It shows a level and takes no
// input: presets change in the kit's configuration.
RowLayout {
    id: meter
    property string label
    property int level: 0
    property color tint: Theme.accentStrong
    spacing: 10
    Accessible.role: Accessible.Indicator
    Accessible.name: qsTr("%1 level %2 of 4").arg(label).arg(level)

    Text {
        textFormat: Text.PlainText
        text: meter.label
        color: Theme.inkSoft
        font.pixelSize: Theme.textLabel
        Layout.preferredWidth: 72
    }
    Row {
        spacing: 4
        Repeater {
            model: 4
            Rectangle {
                width: 30; height: 8; radius: 4
                color: index < meter.level ? meter.tint : Theme.ruleSoft
            }
        }
    }
    Text {
        textFormat: Text.PlainText
        text: qsTr("%1/4").arg(meter.level)
        color: Theme.muted
        font.pixelSize: Theme.textSmall
    }
    Item { Layout.fillWidth: true }
}
