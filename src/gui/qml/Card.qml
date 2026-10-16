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
    border.color: Theme.ruleSoft
    border.width: 1
    // The space between the heading and the content, counted only when the
    // card holds visible content, so a heading-only card is no taller than it.
    readonly property int headingGap: Theme.gapSmall + 4
    readonly property bool hasContent: column.visibleChildren.length > 0
    implicitHeight: (hasContent ? column.implicitHeight : 0)
                    + (heading.visible ? heading.implicitHeight + (hasContent ? headingGap : 0) : 0)
                    + 2 * padding
    implicitWidth: 320

    Item {
        id: heading
        objectName: "cardHeading"
        visible: card.title.length > 0
        anchors { left: parent.left; right: parent.right; top: parent.top; margins: card.padding }
        implicitHeight: Math.max(titles.implicitHeight, trailingSlot.implicitHeight)
        // Width flows from the card to the text, and wrapped height flows
        // back through positioners. A layout solver can loop or retain a
        // zero-width text column when a hidden card receives new text.
        Column {
            id: titles
            anchors.left: parent.left
            width: Math.max(0, heading.width - trailingSlot.implicitWidth
                            - (trailingSlot.implicitWidth > 0 ? Theme.gapSmall : 0))
            spacing: 2
            Text {
                textFormat: Text.PlainText
                horizontalAlignment: Text.AlignLeft
                objectName: "cardTitle"
                text: card.title
                color: Theme.ink
                font.pixelSize: Theme.textHeading
                font.family: Theme.displayFont
                font.weight: Font.Bold
                Accessible.role: Accessible.Heading
                width: parent.width
                wrapMode: Text.WordWrap
                maximumLineCount: 2
                elide: Text.ElideRight
            }
            Text {
                textFormat: Text.PlainText
                horizontalAlignment: Text.AlignLeft
                visible: card.subtitle.length > 0
                objectName: "cardSubtitle"
                text: card.subtitle
                color: Theme.muted
                font.pixelSize: Theme.textSmall
                width: parent.width
                wrapMode: Text.WordWrap
            }
        }
        Row {
            id: trailingSlot
            anchors.right: parent.right
            spacing: Theme.gapSmall
        }
    }

    ColumnLayout {
        id: column
        objectName: "cardContent"
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
