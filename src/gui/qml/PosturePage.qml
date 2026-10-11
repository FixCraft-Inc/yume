// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import YumeBackend 1.0

// What protects the tunnel, as the running yume reports it. Security is
// fixed by the protocol. Tuning edits are a separate draft applied by the core.
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

        TuningPanel { Layout.fillWidth: true }

        Card {
            visible: page.posture === null
            Layout.fillWidth: true
            title: qsTrId("desktop.connect.to.see.the.posture")
            subtitle: qsTrId("desktop.this.page.shows.what.the.running.yume.reports.about.its")
        }

        RowLayout {
            visible: page.posture !== null
            Layout.fillWidth: true
            spacing: Theme.gap

            Card {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignTop
                Layout.preferredWidth: 3
                title: qsTrId("protection")
                subtitle: page.known
                          ? qsTrId("desktop.fixed.by.ytp.1.every.yume.session.uses.all.of.it.and.no")
                          : qsTrId("desktop.this.gui.does.not.describe.transport.it.lists.what.the")
                                .arg(page.posture ? page.posture.transport : "")

                FactRow {
                    Layout.fillWidth: true
                    iconName: "posture"
                    label: qsTrId("desktop.transport")
                    value: page.posture ? page.posture.transport + "  ·  " + page.posture.suite : ""
                }
                FactRow {
                    visible: page.known
                    Layout.fillWidth: true
                    iconName: "key"
                    tint: Theme.keysStrong
                    label: qsTrId("desktop.key.exchange")
                    value: qsTrId("desktop.x25519.and.ml.kem.1024.together")
                    note: qsTrId("desktop.a.hybrid.of.a.classical.and.a.post.quantum.method.the.s")
                }
                FactRow {
                    visible: page.known
                    Layout.fillWidth: true
                    iconName: "server"
                    tint: Theme.serverStrong
                    label: qsTrId("desktop.server.identity")
                    value: qsTrId("desktop.ed25519.and.ml.dsa.87.signatures")
                    note: qsTrId("desktop.both.signatures.must.verify.against.the.identity.your.k")
                }
                FactRow {
                    visible: page.known
                    Layout.fillWidth: true
                    iconName: "check"
                    tint: Theme.dataStrong
                    label: qsTrId("desktop.records")
                    value: qsTrId("desktop.aes.256.gcm.with.one.use.message.keys")
                }
                FactRow {
                    Layout.fillWidth: true
                    iconName: "route"
                    tint: Theme.disguiseStrong
                    label: qsTrId("desktop.outer.layer")
                    value: page.known
                           ? qsTrId("desktop.tls.1.3.and.http.2.shaped.after").arg(page.posture.evidence_profile)
                           : (page.posture ? page.posture.evidence_profile : "")
                    note: qsTrId("desktop.it.follows.a.captured.browser.session.that.is.not.proof")
                }
                FactRow {
                    Layout.fillWidth: true
                    iconName: "key"
                    tint: Theme.keysStrong
                    label: qsTrId("desktop.key.rotation")
                    value: page.posture && page.posture.epoch_bytes
                           ? qsTrId("desktop.at.most.per.key.in.each.direction").arg(App.formatBytes(page.posture.epoch_bytes))
                           : page.limits ? qsTrId("desktop.at.most.per.key.less.if.the.server.sets.less").arg(App.formatBytes(page.limits.max_epoch_bytes)) : ""
                    note: page.limits
                          ? (page.limits.idle_epoch_rotation
                             ? qsTrId("desktop.also.after.a.pause.in.traffic.that.saves.a.round.trip.l")
                             : qsTrId("desktop.not.after.a.pause.in.traffic.which.a.browser.would.not"))
                          : ""
                }
                FactRow {
                    Layout.fillWidth: true
                    iconName: "posture"
                    label: qsTrId("desktop.live.client.settings")
                    value: page.hasPreset ? page.preset.id : qsTrId("desktop.custom")
                    note: page.limits ? qsTrId("desktop.flow.budget.credit.returns.per.window")
                          .arg(App.formatBytes(page.limits.max_queued_bytes))
                          .arg(page.limits.credit_returns_per_window) : ""
                }
                FactRow {
                    Layout.fillWidth: true
                    iconName: "check"
                    tint: Theme.inkSoft
                    label: qsTrId("cryptography")
                    value: page.posture ? page.posture.security + "  ·  " + page.posture.crypto_backend : ""
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.gap

            Card {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignTop
                Layout.preferredWidth: 2
                title: qsTrId("desktop.appearance")
                RowLayout {
                    spacing: 6
                    Repeater {
                        model: [{ id: "light", label: qsTrId("desktop.light") },
                                { id: "dark", label: qsTrId("desktop.dark") },
                                { id: "system", label: qsTrId("system") }]
                        AppButton {
                            required property var modelData
                            compact: true
                            kind: App.themeMode === modelData.id ? "primary" : "secondary"
                            text: modelData.label
                            Accessible.name: qsTrId("desktop.theme").arg(modelData.label)
                            Accessible.checked: App.themeMode === modelData.id
                            onClicked: App.themeMode = modelData.id
                        }
                    }
                }
                Text {
                    textFormat: Text.PlainText
                    horizontalAlignment: Text.AlignLeft
                    text: qsTrId("desktop.yume.gui.yume.control.protocol.1")
                          .arg(App.version).arg(App.status.version || qsTrId("desktop.not.running.2"))
                    color: Theme.muted
                    font.pixelSize: Theme.textSmall
                    Layout.topMargin: 10
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
                Text {
                    textFormat: Text.PlainText
                    horizontalAlignment: Text.AlignLeft
                    text: qsTrId("desktop.free.software.under.the.gnu.agpl.3.0.or.later.jost.font")
                    color: Theme.muted
                    font.pixelSize: Theme.textSmall
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
            }
        }
    }
}
