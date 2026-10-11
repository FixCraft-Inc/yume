// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Layouts

// A preset's level as segments. It shows a level and takes no
// input: presets change in the kit's configuration.
RowLayout {
    id: meter
    property string label
    property int level: 0
    property int maximum: 4
    property color tint: Theme.accentStrong
    spacing: 10
    Accessible.role: Accessible.Indicator
    Accessible.name: qsTrId("desktop.level.of").arg(label).arg(level).arg(maximum)

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
            model: meter.maximum
            Rectangle {
                width: (136 - (meter.maximum - 1) * 4) / meter.maximum
                height: 8; radius: 4
                color: index < meter.level ? meter.tint : Theme.ruleSoft
            }
        }
    }
    Text {
        textFormat: Text.PlainText
        text: qsTrId("desktop.message").arg(meter.level).arg(meter.maximum)
        color: Theme.muted
        font.pixelSize: Theme.textSmall
    }
    Item { Layout.fillWidth: true }
}
