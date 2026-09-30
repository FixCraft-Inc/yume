// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Shapes

// A line icon drawn from a 24-unit path, so it needs no image plugin and
// takes any colour.
Item {
    id: icon
    property string name
    property color color: "black"
    property real stroke: 1.8
    // The icon's side. Layouts size their children by implicit size, so
    // callers set this rather than width and height.
    property real size: 20
    implicitWidth: size
    implicitHeight: size

    readonly property var paths: ({
        "overview": "M3 12h4l3-7 4 14 3-7h4",
        "connect": "M9 3v5 M15 3v5 M6 8h12v3a6 6 0 0 1-12 0z M12 17v4",
        "logs": "M5 6h14 M5 10h14 M5 14h10 M5 18h7",
        "posture": "M12 3l7 3v5c0 4.6-3 8-7 10-4-2-7-5.4-7-10V6z M9 12l2 2 4-4",
        "copy": "M9 9h10v11H9z M5 15V4h10",
        "folder": "M3 7h6l2 2h10v10H3z",
        "trash": "M4 7h16 M10 11v6 M14 11v6 M6 7l1 13h10l1-13 M9 7V4h6v3",
        "import": "M12 3v12 M7 10l5 5 5-5 M4 19h16",
        "route": "M6 18a2 2 0 1 0 0.01 0 M18 6a2 2 0 1 0 0.01 0 M8 18h5a3 3 0 0 0 0-6h-2a3 3 0 0 1 0-6h5",
        "warning": "M12 4l9 16H3z M12 10v4 M12 17v0.5",
        "check": "M5 12l4 4 10-10",
        "up": "M12 19V5 M6 11l6-6 6 6",
        "down": "M12 5v14 M6 13l6 6 6-6",
        "key": "M8 15a4 4 0 1 0 0.01 0 M11 12l8-8 M16 7l3 3",
        "server": "M4 5h16v6H4z M4 13h16v6H4z M8 8h0.5 M8 16h0.5"
    })

    Shape {
        anchors.centerIn: parent
        width: 24
        height: 24
        scale: Math.min(icon.width, icon.height) / 24
        ShapePath {
            strokeColor: icon.color
            strokeWidth: icon.stroke
            fillColor: "transparent"
            capStyle: ShapePath.RoundCap
            joinStyle: ShapePath.RoundJoin
            PathSvg { path: icon.paths[icon.name] || "" }
        }
    }
}
