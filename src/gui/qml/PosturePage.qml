// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import YumeBackend 1.0

// What protects the tunnel, as the running yume reports it. Security is
// fixed by the protocol and the kit, so this page states it and offers no
// switch. Only the GUI's own appearance can be changed here.
Flickable {
    id: page
    contentHeight: column.implicitHeight + 48
    clip: true
    boundsBehavior: Flickable.StopAtBounds
    ScrollBar.vertical: ScrollBar {}

    readonly property var posture: App.status.posture || null
    readonly property var limits: posture ? posture.limits : null
    // The composition this page can describe. Another transport is shown only
    // as the program names it.
    readonly property bool known: posture !== null && posture.transport === "YTP/1"
                                  && posture.suite === "ytp1-tls13-h2"
    readonly property var preset: App.preset
    readonly property bool hasPreset: preset && preset.id !== undefined

    ColumnLayout {
        id: column
        x: 32
        width: page.width - 64
        spacing: Theme.gap

        Card {
            visible: page.posture === null
            Layout.fillWidth: true
            title: qsTr("Connect to see the posture")
            subtitle: qsTr("This page shows what the running yume reports about its protection, never what a file says it might use.")
        }

        RowLayout {
            visible: page.posture !== null
            Layout.fillWidth: true
            spacing: Theme.gap

            Card {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignTop
                Layout.preferredWidth: 3
                title: qsTr("Protection")
                subtitle: page.known
                          ? qsTr("Fixed by YTP/1. Every YUME session uses all of it, and none of it can be switched off.")
                          : qsTr("This GUI does not describe transport %1. It lists what the program reports.")
                                .arg(page.posture ? page.posture.transport : "")

                FactRow {
                    Layout.fillWidth: true
                    iconName: "posture"
                    label: qsTr("Transport")
                    value: page.posture ? page.posture.transport + "  ·  " + page.posture.suite : ""
                }
                FactRow {
                    visible: page.known
                    Layout.fillWidth: true
                    iconName: "key"
                    tint: Theme.keysStrong
                    label: qsTr("Key exchange")
                    value: qsTr("X25519 and ML-KEM-1024 together")
                    note: qsTr("A hybrid of a classical and a post-quantum method: the session key stays secret while either one holds.")
                }
                FactRow {
                    visible: page.known
                    Layout.fillWidth: true
                    iconName: "server"
                    tint: Theme.serverStrong
                    label: qsTr("Server identity")
                    value: qsTr("Ed25519 and ML-DSA-87 signatures")
                    note: qsTr("Both signatures must verify against the identity your kit trusts.")
                }
                FactRow {
                    visible: page.known
                    Layout.fillWidth: true
                    iconName: "check"
                    tint: Theme.dataStrong
                    label: qsTr("Records")
                    value: qsTr("AES-256-GCM with one-use message keys")
                }
                FactRow {
                    Layout.fillWidth: true
                    iconName: "route"
                    tint: Theme.disguiseStrong
                    label: qsTr("Outer layer")
                    value: page.known
                           ? qsTr("TLS 1.3 and HTTP/2, shaped after %1").arg(page.posture.evidence_profile)
                           : (page.posture ? page.posture.evidence_profile : "")
                    note: qsTr("It follows a captured browser session. That is not proof the traffic cannot be told apart.")
                }
                FactRow {
                    Layout.fillWidth: true
                    iconName: "key"
                    tint: Theme.keysStrong
                    label: qsTr("Key rotation")
                    value: page.posture && page.posture.epoch_bytes
                           ? qsTr("At most %1 per key in each direction").arg(App.formatBytes(page.posture.epoch_bytes))
                           : page.limits ? qsTr("At most %1 per key, less if the server sets less").arg(App.formatBytes(page.limits.max_epoch_bytes)) : ""
                    note: page.limits
                          ? (page.limits.idle_epoch_rotation
                             ? qsTr("Also after a pause in traffic. That saves a round trip later, but a browser sends no such exchange.")
                             : qsTr("Not after a pause in traffic, which a browser would not do either."))
                          : ""
                }
                FactRow {
                    Layout.fillWidth: true
                    iconName: "check"
                    tint: Theme.inkSoft
                    label: qsTr("Cryptography")
                    value: page.posture ? page.posture.security + "  ·  " + page.posture.crypto_backend : ""
                }
            }

            Card {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignTop
                Layout.preferredWidth: 2
                title: qsTr("Tuning preset")
                subtitle: qsTr("Set when a kit is made, with yume-setup init --preset. It shows here and changes nothing.")

                Rectangle {
                    implicitWidth: presetName.implicitWidth + 28
                    implicitHeight: 34
                    radius: 17
                    color: page.hasPreset ? Theme.accentSoft : Theme.ruleSoft
                    Text {
                        textFormat: Text.PlainText
                        id: presetName
                        anchors.centerIn: parent
                        text: page.hasPreset ? page.preset.id : qsTr("custom")
                        color: page.hasPreset ? Theme.accentStrong : Theme.inkSoft
                        font.family: Theme.displayFont
                        font.pixelSize: 18
                    }
                }
                Text {
                    textFormat: Text.PlainText
                    horizontalAlignment: Text.AlignLeft
                    visible: !page.hasPreset
                    text: qsTr("These limits match no preset. They were set by hand.")
                    color: Theme.muted
                    font.pixelSize: Theme.textSmall
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
                LevelMeter {
                    visible: page.hasPreset
                    Layout.fillWidth: true
                    label: qsTr("Speed")
                    level: page.hasPreset ? page.preset.levels.speed : 0
                    tint: Theme.dataStrong
                }
                LevelMeter {
                    visible: page.hasPreset
                    Layout.fillWidth: true
                    label: qsTr("Security")
                    level: page.hasPreset ? page.preset.levels.security : 0
                    tint: Theme.keysStrong
                }
                LevelMeter {
                    visible: page.hasPreset
                    Layout.fillWidth: true
                    label: qsTr("Stealth")
                    level: page.hasPreset ? page.preset.levels.stealth : 0
                    tint: Theme.accentStrong
                }
                GridLayout {
                    Layout.fillWidth: true
                    Layout.topMargin: 8
                    columns: 2
                    columnSpacing: 16
                    rowSpacing: 4
                    Text { textFormat: Text.PlainText; text: qsTr("Queue and window"); color: Theme.muted; font.pixelSize: Theme.textLabel }
                    Text {
                        textFormat: Text.PlainText
                        text: page.limits ? App.formatBytes(page.limits.max_queued_bytes) : ""
                        color: Theme.ink; font.pixelSize: Theme.textLabel; font.family: Theme.monoFont
                    }
                    Text { textFormat: Text.PlainText; text: qsTr("Data per key, at most"); color: Theme.muted; font.pixelSize: Theme.textLabel }
                    Text {
                        textFormat: Text.PlainText
                        text: page.limits ? App.formatBytes(page.limits.max_epoch_bytes) : ""
                        color: Theme.ink; font.pixelSize: Theme.textLabel; font.family: Theme.monoFont
                    }
                    Text { textFormat: Text.PlainText; text: qsTr("Credit returns per window"); color: Theme.muted; font.pixelSize: Theme.textLabel }
                    Text {
                        textFormat: Text.PlainText
                        text: page.limits ? String(page.limits.credit_returns_per_window) : ""
                        color: Theme.ink; font.pixelSize: Theme.textLabel; font.family: Theme.monoFont
                    }
                    Text { textFormat: Text.PlainText; text: qsTr("Rotation after a pause"); color: Theme.muted; font.pixelSize: Theme.textLabel }
                    Text {
                        textFormat: Text.PlainText
                        text: page.limits ? (page.limits.idle_epoch_rotation ? qsTr("on") : qsTr("off")) : ""
                        color: Theme.ink; font.pixelSize: Theme.textLabel; font.family: Theme.monoFont
                    }
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.gap

            Card {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignTop
                Layout.preferredWidth: 3
                title: qsTr("Presets")
                subtitle: qsTr("Levels run from 1 to 4. Higher speed costs data per key or closeness to the captured browser.")
                Repeater {
                    model: App.presets
                    RowLayout {
                        required property var modelData
                        Layout.fillWidth: true
                        spacing: 12
                        Text {
                            textFormat: Text.PlainText
                            text: modelData.id
                            color: page.hasPreset && page.preset.id === modelData.id ? Theme.accentStrong : Theme.ink
                            font.pixelSize: Theme.textLabel
                            font.weight: Font.DemiBold
                            Layout.preferredWidth: 80
                        }
                        Text {
                            textFormat: Text.PlainText
                            horizontalAlignment: Text.AlignLeft
                            text: qsTr("speed %1 · security %2 · stealth %3")
                                  .arg(modelData.levels.speed).arg(modelData.levels.security).arg(modelData.levels.stealth)
                            color: Theme.inkSoft
                            font.pixelSize: Theme.textLabel
                            Layout.fillWidth: true
                        }
                        Text {
                            textFormat: Text.PlainText
                            text: qsTr("%1 per key").arg(App.formatBytes(modelData.limits.max_epoch_bytes))
                            color: Theme.muted
                            font.pixelSize: Theme.textSmall
                        }
                    }
                }
            }

            Card {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignTop
                Layout.preferredWidth: 2
                title: qsTr("Appearance")
                RowLayout {
                    spacing: 6
                    Repeater {
                        model: [{ id: "light", label: qsTr("Light") },
                                { id: "dark", label: qsTr("Dark") },
                                { id: "system", label: qsTr("System") }]
                        AppButton {
                            required property var modelData
                            compact: true
                            kind: App.themeMode === modelData.id ? "primary" : "secondary"
                            text: modelData.label
                            Accessible.name: qsTr("%1 theme").arg(modelData.label)
                            Accessible.checked: App.themeMode === modelData.id
                            onClicked: App.themeMode = modelData.id
                        }
                    }
                }
                Text {
                    textFormat: Text.PlainText
                    horizontalAlignment: Text.AlignLeft
                    text: qsTr("yume-gui %1  ·  yume %2  ·  control protocol 1")
                          .arg(App.version).arg(App.status.version || qsTr("not running"))
                    color: Theme.muted
                    font.pixelSize: Theme.textSmall
                    Layout.topMargin: 10
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
                Text {
                    textFormat: Text.PlainText
                    horizontalAlignment: Text.AlignLeft
                    text: qsTr("Free software under the GNU AGPL 3.0 or later. Jost font under the SIL Open Font License 1.1.")
                    color: Theme.muted
                    font.pixelSize: Theme.textSmall
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
            }
        }
    }
}
