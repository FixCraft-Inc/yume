// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import YumeBackend 1.0

Flickable {
    id: page
    objectName: "creditsPage"
    contentHeight: column.implicitHeight + 48
    clip: true
    boundsBehavior: Flickable.StopAtBounds
    ScrollBar.vertical: ScrollBar {}

    ColumnLayout {
        id: column
        x: 32
        width: page.width - 64
        spacing: Theme.gap

        Repeater {
            model: App.credits.contributors || []
            Card {
                required property var modelData
                Layout.fillWidth: true
                title: modelData.name
                subtitle: qsTrId(modelData.role) + "\n" + qsTrId(modelData.contribution)
            }
        }
        Repeater {
            model: [
                {title: qsTrId("credits.desktop.components"), entries: App.credits.components.desktop},
                {title: qsTrId("credits.native.components"), entries: App.credits.components.native.concat(App.credits.components.linux)}
            ]
            ColumnLayout {
                required property var modelData
                Layout.fillWidth: true
                Text {
                    text: modelData.title
                    textFormat: Text.PlainText
                    color: Theme.ink
                    font.pixelSize: Theme.textLabel
                    wrapMode: Text.WordWrap
                    Layout.fillWidth: true
                    Accessible.role: Accessible.Heading
                }
                Repeater {
                    model: modelData.entries
                    Card {
                        required property var modelData
                        Layout.fillWidth: true
                        title: modelData.name + " · " + modelData.license
                        subtitle: qsTrId(modelData.use)
                    }
                }
            }
        }
    }
}
