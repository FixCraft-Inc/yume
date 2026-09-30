// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import YumeBackend 1.0
import "Labels.js" as Labels

// The selected kit's tunnel as its control socket reports it.
Flickable {
    id: page
    signal reviewRoute()

    readonly property var status: App.status
    readonly property bool running: App.phase === "running"
    readonly property var circuits: status.circuits || null
    readonly property var proposal: circuits ? circuits.proposal : null
    readonly property var traffic: status.traffic || ({})

    contentHeight: column.implicitHeight + 48
    clip: true
    boundsBehavior: Flickable.StopAtBounds
    ScrollBar.vertical: ScrollBar {}

    ColumnLayout {
        id: column
        x: 32
        width: page.width - 64
        spacing: Theme.gap

        // No kit: say where to get one.
        Card {
            visible: App.phase === "none"
            Layout.fillWidth: true
            title: qsTr("No kit yet")
            subtitle: qsTr("A kit holds one client's settings and credentials. Import a sealed kit you received, with its code.")
            AppButton {
                kind: "primary"
                iconName: "import"
                text: qsTr("Import a kit")
                onClicked: App.page = "connect"
            }
        }

        // A shorter route needs the user's explicit acceptance.
        Rectangle {
            visible: page.proposal !== null && page.proposal !== undefined
            Layout.fillWidth: true
            implicitHeight: proposalRow.implicitHeight + 28
            radius: Theme.radius
            color: Theme.disguiseSoft
            border.color: Theme.disguise
            Accessible.role: Accessible.AlertMessage
            Accessible.name: proposalText.text
            RowLayout {
                id: proposalRow
                anchors.fill: parent
                anchors.margins: 14
                spacing: 12
                Icon { name: "route"; width: 22; height: 22; color: Theme.disguiseStrong }
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 2
                    Text {
                        textFormat: Text.PlainText
                        horizontalAlignment: Text.AlignLeft
                        id: proposalText
                        text: page.proposal
                              ? qsTr("No %1 can be built. A %2 is proposed.")
                                    .arg(Labels.hopRoute(page.circuits.hops)).arg(Labels.hopRoute(page.proposal.hops))
                              : ""
                        color: Theme.ink
                        font.pixelSize: Theme.textBody
                        font.weight: Font.DemiBold
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                    }
                    Text {
                        textFormat: Text.PlainText
                        horizontalAlignment: Text.AlignLeft
                        text: qsTr("New connections wait until you accept it or a %1 works again.")
                              .arg(page.circuits ? Labels.hopRoute(page.circuits.hops) : "")
                        color: Theme.inkSoft
                        font.pixelSize: Theme.textSmall
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                    }
                }
                AppButton {
                    objectName: "reviewRoute"
                    kind: "primary"
                    text: qsTr("Review")
                    onClicked: page.reviewRoute()
                }
            }
        }

        // The state, where it goes and how fast.
        Card {
            visible: App.phase !== "none"
            Layout.fillWidth: true
            padding: 24
            RowLayout {
                Layout.fillWidth: true
                spacing: 24
                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 6
                    Text {
                        textFormat: Text.PlainText
                        text: App.stateLabel(App.phase, page.status.state || "")
                        color: Theme.stateColor(App.stateKind(App.phase, page.status.state || ""))
                        font.family: Theme.displayFont
                        font.pixelSize: Theme.textHero
                        Accessible.role: Accessible.Heading
                    }
                    Text {
                        textFormat: Text.PlainText
                        horizontalAlignment: Text.AlignLeft
                        text: {
                            if (!page.running) return App.phase === "stopped"
                                ? qsTr("The tunnel is not running. Connect starts it, and it keeps running if you close this window.")
                                : ""
                            const target = page.status.server ? page.status.server.host + ":" + page.status.server.port : ""
                            if (page.status.state === "connected")
                                return qsTr("to %1 for %2").arg(target).arg(App.formatDuration(page.status.connected_ms || 0))
                            if (page.status.state === "waiting")
                                return qsTr("to %1, next attempt in %2").arg(target).arg(App.formatDuration(page.status.retry_ms || 0))
                            return qsTr("to %1").arg(target)
                        }
                        color: Theme.inkSoft
                        font.pixelSize: Theme.textBody
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                    }
                    Text {
                        textFormat: Text.PlainText
                        horizontalAlignment: Text.AlignLeft
                        visible: App.error.length > 0
                        text: App.error
                        color: Theme.refusedStrong
                        font.pixelSize: Theme.textLabel
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                    }
                    Text {
                        textFormat: Text.PlainText
                        horizontalAlignment: Text.AlignLeft
                        visible: page.running && page.status.last_failure !== null && page.status.last_failure !== undefined
                        text: page.status.last_failure
                              ? qsTr("Last failure: %1, %2").arg(page.status.last_failure.code).arg(page.status.last_failure.message)
                              : ""
                        color: Theme.refusedStrong
                        font.pixelSize: Theme.textSmall
                        Layout.fillWidth: true
                        elide: Text.ElideRight
                    }
                }
                ColumnLayout {
                    visible: page.running
                    spacing: 6
                    Layout.alignment: Qt.AlignTop
                    RowLayout {
                        spacing: 8
                        Icon { name: "up"; width: 16; height: 16; color: Theme.accentStrong }
                        Text {
                            textFormat: Text.PlainText
                            text: App.formatRate(App.sendRate)
                            color: Theme.ink
                            font.family: Theme.displayFont
                            font.pixelSize: 22
                            Accessible.name: qsTr("Sending %1").arg(text)
                        }
                    }
                    RowLayout {
                        spacing: 8
                        Icon { name: "down"; width: 16; height: 16; color: Theme.dataStrong }
                        Text {
                            textFormat: Text.PlainText
                            text: App.formatRate(App.receiveRate)
                            color: Theme.ink
                            font.family: Theme.displayFont
                            font.pixelSize: 22
                            Accessible.name: qsTr("Receiving %1").arg(text)
                        }
                    }
                }
            }
            Sparkline {
                visible: page.running
                Layout.fillWidth: true
                Layout.preferredHeight: 64
                Layout.topMargin: 8
                samples: App.rateHistory
            }
            CopyRow {
                visible: page.running && (page.status.server_identity || "").length > 0
                Layout.fillWidth: true
                Layout.topMargin: 4
                label: qsTr("Server identity")
                value: page.status.server_identity || ""
            }
        }

        // Totals since yume started.
        GridLayout {
            visible: page.running
            Layout.fillWidth: true
            columns: page.width > 1000 ? 4 : 2
            columnSpacing: Theme.gap
            rowSpacing: Theme.gap
            Metric {
                Layout.fillWidth: true
                iconName: "up"
                label: qsTr("Sent")
                value: App.formatBytes(page.traffic.payload_bytes_sent || 0)
                detail: qsTr("%1 on the wire").arg(App.formatBytes(page.traffic.record_bytes_sent || 0))
            }
            Metric {
                Layout.fillWidth: true
                iconName: "down"
                label: qsTr("Received")
                value: App.formatBytes(page.traffic.payload_bytes_received || 0)
                detail: qsTr("%1 on the wire").arg(App.formatBytes(page.traffic.record_bytes_received || 0))
            }
            Metric {
                Layout.fillWidth: true
                iconName: "key"
                label: qsTr("Sessions")
                value: String(page.status.sessions || 0)
                detail: qsTr("authenticated since start")
            }
            Metric {
                Layout.fillWidth: true
                iconName: "warning"
                label: qsTr("Failed attempts")
                value: String(page.status.failed_attempts || 0)
                detail: qsTr("since the last session")
                tint: (page.status.failed_attempts || 0) > 0 ? Theme.refusedStrong : Theme.ink
            }
        }

        RowLayout {
            visible: page.running
            Layout.fillWidth: true
            spacing: Theme.gap

            Card {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignTop
                Layout.preferredWidth: 1
                title: qsTr("Local access")
                subtitle: qsTr("Point applications here. Only this computer can reach them.")
                Repeater {
                    model: page.status.socks5 || []
                    CopyRow {
                        required property var modelData
                        Layout.fillWidth: true
                        label: qsTr("SOCKS5")
                        value: modelData
                    }
                }
                Repeater {
                    model: page.status.forwards || []
                    CopyRow {
                        required property var modelData
                        Layout.fillWidth: true
                        label: qsTr("Forward")
                        value: modelData
                    }
                }
                Text {
                    textFormat: Text.PlainText
                    visible: (page.status.socks5 || []).length + (page.status.forwards || []).length === 0
                    text: qsTr("This kit opens no local listener.")
                    color: Theme.muted
                    font.pixelSize: Theme.textLabel
                }
            }

            Card {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignTop
                Layout.preferredWidth: 1
                title: page.circuits ? qsTr("Route through the cluster") : qsTr("Route")
                subtitle: page.circuits
                          ? qsTr("Each hop knows only its neighbours.")
                          : qsTr("One server carries your streams and sees their destinations.")
                RowLayout {
                    visible: !page.circuits
                    spacing: 10
                    Icon { name: "server"; width: 18; height: 18; color: Theme.serverStrong }
                    Text {
                        textFormat: Text.PlainText
                        text: page.status.server ? page.status.server.host + ":" + page.status.server.port : ""
                        color: Theme.ink
                        font.pixelSize: Theme.textBody
                    }
                }
                GridLayout {
                    visible: page.circuits !== null
                    columns: 2
                    columnSpacing: 16
                    rowSpacing: 4
                    Text { textFormat: Text.PlainText; text: qsTr("In use"); color: Theme.muted; font.pixelSize: Theme.textLabel }
                    Text {
                        textFormat: Text.PlainText
                        text: page.circuits
                              ? (page.circuits.current_hops === 0
                                 ? qsTr("no route, %1 configured").arg(Labels.hops(page.circuits.hops))
                                 : qsTr("%1 of %2 configured").arg(Labels.hops(page.circuits.current_hops)).arg(page.circuits.hops))
                              : ""
                        color: Theme.ink
                        font.pixelSize: Theme.textLabel
                        font.weight: Font.DemiBold
                    }
                    Text { textFormat: Text.PlainText; text: qsTr("Shorter routes"); color: Theme.muted; font.pixelSize: Theme.textLabel }
                    Text {
                        textFormat: Text.PlainText
                        text: page.circuits
                              ? (page.circuits.accepted_hops > 0
                                 ? qsTr("you accepted %1").arg(Labels.hops(page.circuits.accepted_hops))
                                 : page.circuits.min_hops < page.circuits.hops
                                   ? qsTr("down to %1 approved in the kit").arg(Labels.hops(page.circuits.min_hops))
                                   : qsTr("only with your acceptance"))
                              : ""
                        color: Theme.ink
                        font.pixelSize: Theme.textLabel
                    }
                    Text { textFormat: Text.PlainText; text: qsTr("Plain HTTP"); color: Theme.muted; font.pixelSize: Theme.textLabel }
                    Text {
                        textFormat: Text.PlainText
                        text: page.circuits && page.circuits.plain_http === "allow" ? qsTr("allowed") : qsTr("refused")
                        color: Theme.ink
                        font.pixelSize: Theme.textLabel
                    }
                }
                Text {
                    textFormat: Text.PlainText
                    horizontalAlignment: Text.AlignLeft
                    visible: page.circuits !== null && page.circuits.stopped !== null && page.circuits.stopped !== undefined
                    text: page.circuits && page.circuits.stopped ? qsTr("Circuits stopped: %1").arg(page.circuits.stopped) : ""
                    color: Theme.refusedStrong
                    font.pixelSize: Theme.textLabel
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
                Repeater {
                    model: page.circuits ? page.circuits.routes : []
                    RowLayout {
                        required property var modelData
                        Layout.fillWidth: true
                        spacing: 10
                        Icon { name: "route"; width: 16; height: 16; color: Theme.serverStrong }
                        Text {
                            textFormat: Text.PlainText
                            horizontalAlignment: Text.AlignLeft
                            text: Labels.nodes(modelData.nodes)
                            color: Theme.ink
                            font.pixelSize: Theme.textLabel
                            font.weight: Font.DemiBold
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }
                        Text {
                            textFormat: Text.PlainText
                            text: qsTr("%1 · %2 streams").arg(App.formatDuration(modelData.age_ms)).arg(modelData.streams)
                            color: Theme.muted
                            font.pixelSize: Theme.textSmall
                        }
                    }
                }
            }
        }

        // The last start's own words when it did not come up.
        Card {
            visible: App.phase === "stopped" && App.error.length > 0 && App.outputTail.length > 0
            Layout.fillWidth: true
            title: qsTr("Output of the latest start")
            Text {
                textFormat: Text.PlainText
                text: App.outputTail
                color: Theme.inkSoft
                font.family: Theme.monoFont
                font.pixelSize: Theme.textSmall
                Layout.fillWidth: true
                wrapMode: Text.WrapAnywhere
                maximumLineCount: 14
            }
        }
    }
}
