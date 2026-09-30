// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import YumeBackend 1.0

// A labelled value in the monospace face with a button that copies it.
RowLayout {
    id: row
    property string label
    property string value
    property bool copyable: true
    spacing: Theme.gapSmall

    Text {
        textFormat: Text.PlainText
        text: row.label
        color: Theme.muted
        font.pixelSize: Theme.textLabel
        Layout.preferredWidth: 120
        elide: Text.ElideRight
    }
    Text {
        textFormat: Text.PlainText
        horizontalAlignment: Text.AlignLeft
        text: row.value
        color: Theme.ink
        font.family: Theme.monoFont
        font.pixelSize: Theme.textLabel
        Layout.fillWidth: true
        elide: Text.ElideMiddle
        Accessible.role: Accessible.StaticText
        Accessible.name: row.label + ": " + row.value
    }
    AppButton {
        visible: row.copyable && row.value.length > 0
        kind: "quiet"
        compact: true
        iconName: "copy"
        text: qsTr("Copy")
        Accessible.name: qsTr("Copy %1").arg(row.label)
        onClicked: App.copyText(row.value)
    }
}
