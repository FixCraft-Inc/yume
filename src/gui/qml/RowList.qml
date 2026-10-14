// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Layouts

// Rows a Repeater builds from a model, inside a card or another layout. Each
// row sets `width: parent.width`. Hidden while the model is empty.
//
// A plain Column, not a layout: Qt 6.4's layouts can keep a destroyed row
// while a page is hidden and crash when it is shown (QTBUG-111792). The
// width also comes from the parent, not only from fillWidth. While a row of
// cards is hidden, a card keeps its preferred width (1 in the Overview), so
// this column is 0 wide. When the row shows, Qt 6.4 widens the card but does
// not lay this column out again, and a positioner skips zero-width rows, so
// the rows that arrived meanwhile never draw.
Column {
    id: list
    property alias model: rows.model
    property alias delegate: rows.delegate
    readonly property alias count: rows.count

    Layout.fillWidth: true
    Layout.preferredWidth: parent ? parent.width : 0
    visible: rows.count > 0
    spacing: Theme.gapSmall

    Repeater { id: rows }
}
