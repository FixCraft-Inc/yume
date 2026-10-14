// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Controls

// A tooltip in plain text, wrapped to a readable width, in the inverse
// colours of the theme so it stands out from the page in both themes.
ToolTip {
    id: tip
    delay: 400
    padding: 10
    width: Math.min(implicitWidth, 380)
    contentItem: Text {
        textFormat: Text.PlainText
        text: tip.text
        color: Theme.inverseInk
        font.pixelSize: Theme.textSmall
        lineHeight: 1.15
        wrapMode: Text.WordWrap
    }
    background: Rectangle {
        radius: Theme.radiusSmall
        color: Theme.inverse
    }
}
