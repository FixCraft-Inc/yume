// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.
import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import YumeBackend 1.0
import "Labels.js" as Labels

Card {
    id: panel
    title: qsTrId("desktop.connection.settings")
    subtitle: qsTrId("desktop.for.changes.take.effect.on.the.next.connection.applying").arg(App.kitName || qsTrId("desktop.no.kit.2"))
    readonly property var editor: App.tuning
    readonly property var chosen: editor.selection
    readonly property bool hasChoice: chosen.id !== undefined
    readonly property var posture: App.status.posture || null
    readonly property var liveLimits: posture ? posture.limits : null
    readonly property real epoch: posture && posture.epoch_bytes ? posture.epoch_bytes : 0
    readonly property bool capped: epoch > 0 && liveLimits && epoch < liveLimits.max_epoch_bytes
    readonly property var measurement: hasChoice ? chosen.measurement : null
    readonly property var conditions: measurement ? editor.measurements[measurement.reference] : null

    function measurementText() {
        if (!conditions) return qsTrId("desktop.custom.limits.have.no.measured.speed.position")
        var parts = []
        for (var i = 0; i < measurement.values.length; ++i) {
            const value = measurement.values[i]
            parts.push(conditions.rtt_ms[i] + " ms: " + (conditions.unit === "percent" ? value + "%"
                       : conditions.unit === "Mbit/s" ? App.formatRate(value * 1e6 / 8)
                       : value + " " + conditions.unit))
        }
        return Labels.presetText(conditions.metric) + " · " + parts.join(" · ")
    }
    // How the numbers were measured, and what the axes describe, behind "?".
    function measurementHelp() {
        const axes = qsTrId("desktop.stealth.describes.windows.credits.and.idle.rotation.not")
        return conditions ? Labels.presetText(conditions.conditions) + "\n\n" + axes : axes
    }

    RowLayout {
        Layout.fillWidth: true
        enabled: panel.editor.ready && !panel.editor.busy && !App.renaming && !App.removing && !App.importing
        spacing: 8
        AppComboBox {
            id: combinations
            objectName: "tuningCombination"
            Layout.fillWidth: true
            model: App.presets
            textRole: "id"
            currentIndex: {
                for (var i = 0; i < App.presets.length; ++i)
                    if (App.presets[i].id === panel.chosen.id) return i
                return -1
            }
            displayText: panel.hasChoice ? panel.chosen.id : qsTrId("desktop.custom.choose.a.combination.to.use.sliders")
            Accessible.name: qsTrId("desktop.tuning.combination")
            onActivated: panel.editor.choose(App.presets[index].id)
        }
        AppButton {
            text: qsTrId("desktop.reload")
            compact: true
            onClicked: panel.editor.reload()
        }
        AppButton {
            objectName: "applyTuning"
            text: App.phase === "running" ? qsTrId("desktop.apply.and.restart") : qsTrId("desktop.save.settings")
            kind: "primary"
            enabled: panel.hasChoice && (App.phase === "running" || App.phase === "stopped")
            onClicked: panel.editor.apply_preset()
        }
    }

    GridLayout {
        Layout.fillWidth: true
        columns: panel.width > 720 ? 2 : 1
        columnSpacing: 32
        rowSpacing: 12
        ColumnLayout {
            Layout.fillWidth: true
            Layout.preferredWidth: 1
            enabled: panel.hasChoice && panel.editor.ready && !panel.editor.busy
            Repeater {
                model: [{axis: "stealth", label: qsTrId("stealth"), tint: Theme.accent},
                        {axis: "speed", label: qsTrId("speed"), tint: Theme.dataStrong},
                        {axis: "security", label: qsTrId("security"), tint: Theme.keysStrong}]
                TuningSlider {
                    required property var modelData
                    Layout.fillWidth: true
                    axis: modelData.axis
                    label: modelData.label
                    tint: modelData.tint
                    level: panel.hasChoice ? panel.chosen.levels[axis] : 1
                    maximum: App.presets.reduce(function(m, p) { return Math.max(m, p.levels[axis]) }, 1)
                    explanation: Labels.presetText(App.presetNotes[axis])
                    onSelected: function(level) { panel.editor.move_slider(axis, level) }
                }
            }
        }
        ColumnLayout {
            Layout.fillWidth: true
            Layout.preferredWidth: 1
            Layout.alignment: Qt.AlignTop
            spacing: 8
            Repeater {
                model: panel.editor.fields
                RowLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    Text {
                        textFormat: Text.PlainText
                        text: Labels.presetText(modelData.label)
                        color: Theme.inkSoft
                        font.pixelSize: Theme.textLabel
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                    }
                    Text {
                        textFormat: Text.PlainText
                        text: !panel.editor.ready ? "—" : modelData.unit === "boolean"
                              ? (panel.editor.limits[modelData.key] ? qsTrId("on") : qsTrId("off"))
                              : (panel.editor.limits[modelData.key] / modelData.divisor) + (modelData.unit === "MiB" ? " MiB" : "")
                        color: Theme.ink
                        font.pixelSize: Theme.textLabel
                    }
                }
            }
            Text {
                objectName: "serverEpoch"
                textFormat: Text.PlainText
                text: panel.epoch > 0
                      ? (panel.capped ? qsTrId("desktop.server.cap.mib.per.key.in.this.session")
                                      : qsTrId("desktop.live.session.mib.per.key.the.server.s.higher.allowance"))
                        .arg(panel.epoch / 1048576)
                      : qsTrId("desktop.connect.to.learn.the.effective.key.epoch.the.server.can")
                color: panel.capped ? Theme.accent : Theme.muted
                font.pixelSize: Theme.textSmall
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
            }
        }
    }
    // The measured position stays on the page with its limit; the method
    // and what each axis describes are one hover or focus away. The "?"
    // follows the text by anchors, which mirror for right-to-left, rather
    // than by layout stretch, which Qt 6.4 shares out differently.
    Item {
        Layout.fillWidth: true
        implicitHeight: Math.max(measurementText.implicitHeight, measurementHelp.implicitHeight)
        Text {
            id: measurementText
            objectName: "measurementText"
            textFormat: Text.PlainText
            horizontalAlignment: Text.AlignLeft
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            width: Math.min(implicitWidth, parent.width - measurementHelp.width - 6)
            text: panel.measurementText()
            color: Theme.ink
            font.pixelSize: Theme.textLabel
            wrapMode: Text.WordWrap
        }
        HelpTip {
            id: measurementHelp
            objectName: "measurementHelp"
            anchors.left: measurementText.right
            anchors.leftMargin: 6
            anchors.verticalCenter: parent.verticalCenter
            name: qsTrId("measured.speed.conditions")
            help: panel.measurementHelp()
        }
    }
    Text {
        textFormat: Text.PlainText
        text: panel.conditions ? Labels.presetText(panel.conditions.limitation) : ""
        visible: panel.conditions !== null
        color: Theme.muted
        font.pixelSize: Theme.textSmall
        Layout.fillWidth: true
        Layout.topMargin: -4
        wrapMode: Text.WordWrap
    }
    AppButton {
        objectName: "openExpert"
        visible: !panel.editor.expertUnlocked
        enabled: panel.editor.ready && !panel.editor.busy
        text: qsTrId("desktop.expert.settings.2")
        compact: true
        onClicked: warning.open()
    }
    ColumnLayout {
        visible: panel.editor.expertUnlocked
        enabled: !panel.editor.busy
        Layout.fillWidth: true
        Text {
            textFormat: Text.PlainText
            text: qsTrId("desktop.apply.one.field.at.a.time.byte.fields.use.exact.bytes.i")
            color: Theme.inkSoft
            font.pixelSize: Theme.textSmall
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
        }
        RowLayout {
            Layout.fillWidth: true
            AppComboBox {
                id: expertField
                objectName: "expertField"
                Layout.fillWidth: true
                model: panel.editor.fields.map(function(field) { return Labels.presetText(field.label) })
                Accessible.name: qsTrId("desktop.expert.setting")
                onActivated: expertValue.text = String(panel.editor.limits[panel.editor.fields[currentIndex].key])
            }
            AppTextField {
                id: expertValue
                objectName: "expertValue"
                Layout.preferredWidth: 150
                maximumLength: 32
                text: panel.editor.fields.length ? String(panel.editor.limits[panel.editor.fields[expertField.currentIndex].key]) : ""
                Accessible.name: qsTrId("desktop.exact.value.in.bytes.count.or.true.false")
            }
            AppButton {
                objectName: "applyExpert"
                text: App.phase === "running" ? qsTrId("desktop.apply.and.restart") : qsTrId("desktop.save.value")
                enabled: expertValue.text.length > 0 && (App.phase === "running" || App.phase === "stopped")
                onClicked: panel.editor.apply_expert(panel.editor.fields[expertField.currentIndex].key, expertValue.text)
            }
        }
    }
    Text {
        objectName: "tuningMessage"
        textFormat: Text.PlainText
        visible: text.length > 0
        text: panel.editor.message
        color: Theme.ink
        font.pixelSize: Theme.textBody
        Layout.fillWidth: true
        wrapMode: Text.WordWrap
        Accessible.name: text
    }
    Dialog {
        id: warning
        objectName: "expertWarning"
        modal: true
        focus: true
        anchors.centerIn: Overlay.overlay
        width: Math.min(560, panel.Window.window.width - 48)
        padding: 24
        closePolicy: Popup.CloseOnEscape
        onOpened: cancel.forceActiveFocus()
        background: Rectangle { color: Theme.cloud; radius: Theme.radius; border.color: Theme.rule }
        contentItem: ColumnLayout {
            spacing: 16
            Text {
                textFormat: Text.PlainText
                text: qsTrId("desktop.expert.settings")
                color: Theme.ink
                font.pixelSize: 24
                font.family: Theme.displayFont
            }
            Text {
                textFormat: Text.PlainText
                text: qsTrId("desktop.larger.epochs.expose.more.data.if.an.epoch.key.is.compr")
                color: Theme.inkSoft
                font.pixelSize: Theme.textBody
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
            }
            RowLayout {
                AppButton { id: cancel; text: qsTrId("cancel"); onClicked: warning.close() }
                AppButton {
                    objectName: "confirmExpert"
                    text: qsTrId("i.know.what.i.m.doing")
                    kind: "primary"
                    onClicked: { panel.editor.unlock_expert(); warning.close() }
                }
            }
        }
    }
}
