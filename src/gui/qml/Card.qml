// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Layouts

// A rounded surface with an optional heading. Content goes in its column.
Rectangle {
    id: card
    property string title
    property string subtitle
    property alias trailing: trailingSlot.data
    default property alias content: column.data
    property int padding: Theme.pad

    color: Theme.cloud
    radius: Theme.radius
    border.color: Theme.rule
    border.width: 1
    // The space between the heading and the content, counted only when the
    // card holds visible content, so a heading-only card is no taller than it.
    readonly property int headingGap: Theme.gapSmall + 4
    readonly property bool hasContent: column.visibleChildren.length > 0
    implicitHeight: (hasContent ? column.implicitHeight : 0)
                    + (heading.visible ? heading.implicitHeight + (hasContent ? headingGap : 0) : 0)
                    + 2 * padding
    implicitWidth: 320

    RowLayout {
        id: heading
        visible: card.title.length > 0
        anchors { left: parent.left; right: parent.right; top: parent.top; margins: card.padding }
        spacing: Theme.gapSmall
        ColumnLayout {
            spacing: 2
            Layout.fillWidth: true
            Text {
                textFormat: Text.PlainText
                horizontalAlignment: Text.AlignLeft
                text: card.title
                color: Theme.ink
                font.pixelSize: Theme.textHeading
                font.weight: Font.DemiBold
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
                maximumLineCount: 2
                elide: Text.ElideRight
            }
            Text {
                textFormat: Text.PlainText
                horizontalAlignment: Text.AlignLeft
                visible: card.subtitle.length > 0
                text: card.subtitle
                color: Theme.muted
                font.pixelSize: Theme.textSmall
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
            }
        }
        Row { id: trailingSlot; spacing: Theme.gapSmall; Layout.alignment: Qt.AlignTop }
    }

    ColumnLayout {
        id: column
        spacing: Theme.gapSmall
        anchors {
            left: parent.left
            right: parent.right
            top: heading.visible ? heading.bottom : parent.top
            topMargin: heading.visible ? card.headingGap : card.padding
            leftMargin: card.padding
            rightMargin: card.padding
        }
    }
}
