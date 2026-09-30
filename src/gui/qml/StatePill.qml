// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import YumeBackend 1.0

// The connection state as a dot and a word, coloured by what it means.
Rectangle {
    id: pill
    property string phase
    // The state the status reply names. Item's own state is a final property.
    property string reported
    readonly property string kind: App.stateKind(phase, reported)

    implicitHeight: 28
    implicitWidth: row.implicitWidth + 24
    radius: height / 2
    color: Theme.stateSoft(kind)
    Accessible.role: Accessible.StaticText
    Accessible.name: App.stateLabel(phase, reported)

    Row {
        id: row
        anchors.centerIn: parent
        spacing: 8
        Rectangle {
            width: 8; height: 8; radius: 4
            anchors.verticalCenter: parent.verticalCenter
            color: Theme.stateColor(pill.kind)
        }
        Text {
            textFormat: Text.PlainText
            text: App.stateLabel(pill.phase, pill.reported)
            color: Theme.stateColor(pill.kind)
            font.pixelSize: Theme.textLabel
            font.weight: Font.DemiBold
            anchors.verticalCenter: parent.verticalCenter
        }
    }
}
