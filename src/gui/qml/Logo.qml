// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Shapes
import YumeBackend 1.0

// The YUME mark, the path of assets/icon.svg, which App.markPath reads, in
// its 256-unit box. The dark
// theme keeps the icon's own pale gradient; the light theme deepens it so
// the mark holds its contrast on the light paper.
Item {
    id: logo
    implicitWidth: 32
    implicitHeight: 32

    Shape {
        anchors.centerIn: parent
        width: 256
        height: 256
        scale: Math.min(logo.width, logo.height) / 256
        ShapePath {
            strokeWidth: -1
            fillRule: ShapePath.OddEvenFill
            fillGradient: LinearGradient {
                x1: 145.1; y1: 251.9
                x2: 125.8; y2: 22.0
                GradientStop { position: 0; color: Theme.dark ? "#dcffc3f1" : "#ec9ed6" }
                GradientStop { position: 1; color: Theme.dark ? "#dbe18fca" : "#b0569c" }
            }
            PathSvg { path: App.markPath }
        }
    }
}
