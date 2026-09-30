// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick

// Recent send and receive rates as two lines on a shared scale, newest on the
// inline end. samples holds [sent, received] pairs in bytes per second.
Canvas {
    id: spark
    property var samples: []
    property int capacity: 90
    property color sentColor: Theme.accentStrong
    property color receivedColor: Theme.dataStrong

    onSamplesChanged: requestPaint()
    onWidthChanged: requestPaint()
    Connections {
        target: Theme
        function onDarkChanged() { spark.requestPaint() }
    }
    Accessible.role: Accessible.Graphic
    Accessible.name: qsTr("Recent throughput")

    onPaint: {
        const ctx = getContext("2d")
        ctx.reset()
        const count = samples.length
        let peak = 1
        for (let i = 0; i < count; ++i)
            peak = Math.max(peak, samples[i][0], samples[i][1])
        const step = width / Math.max(1, capacity - 1)
        const mirrored = spark.LayoutMirroring.enabled
        const xAt = (i) => {
            const x = width - (count - 1 - i) * step
            return mirrored ? width - x : x
        }
        const yAt = (v) => height - 2 - (height - 4) * v / peak
        ctx.strokeStyle = Theme.ruleSoft
        ctx.lineWidth = 1
        ctx.beginPath()
        ctx.moveTo(0, height - 1.5)
        ctx.lineTo(width, height - 1.5)
        ctx.stroke()
        const line = (index, color) => {
            if (count < 2) return
            ctx.strokeStyle = color
            ctx.lineWidth = 2
            ctx.lineJoin = "round"
            ctx.beginPath()
            for (let i = 0; i < count; ++i) {
                const x = xAt(i), y = yAt(samples[i][index])
                if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y)
            }
            ctx.stroke()
        }
        line(1, receivedColor)
        line(0, sentColor)
    }
}
