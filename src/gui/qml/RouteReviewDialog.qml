// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import YumeBackend 1.0
import "Labels.js" as Labels

// Consent to one exact shorter route. The dialog keeps the proposal it
// opened with, accepts only that id, and refuses to accept once the running
// yume proposes something else. Closing it, or no answer, accepts nothing.
Dialog {
    id: dialog
    property var reviewed: null
    readonly property var current: App.status.circuits ? App.status.circuits.proposal : null
    readonly property bool changed: reviewed !== null &&
                                    (current === null || current === undefined || current.id !== reviewed.id)

    function openFor(proposal) {
        if (!proposal) return
        reviewed = proposal
        open()
    }

    modal: true
    focus: true
    anchors.centerIn: Overlay.overlay
    width: Math.min(560, (parent ? parent.width : 560) - 64)
    padding: 24
    closePolicy: Popup.CloseOnEscape
    onClosed: reviewed = null

    background: Rectangle {
        radius: Theme.radius
        color: Theme.cloud
        border.color: Theme.rule
    }
    Overlay.modal: Rectangle { color: Qt.rgba(0.1, 0.03, 0.08, 0.45) }

    contentItem: ColumnLayout {
        LayoutMirroring.enabled: App.rightToLeft
        LayoutMirroring.childrenInherit: true
        spacing: 12

        Text {
            textFormat: Text.PlainText
            text: qsTr("Use a shorter route?")
            color: Theme.ink
            font.family: Theme.displayFont
            font.pixelSize: 24
            Accessible.role: Accessible.Heading
        }
        Text {
            textFormat: Text.PlainText
            horizontalAlignment: Text.AlignLeft
            text: dialog.reviewed && App.status.circuits
                  ? qsTr("No route of %1 can be built right now. yume proposes a route of %2 through:")
                        .arg(Labels.hops(App.status.circuits.hops)).arg(Labels.hops(dialog.reviewed.hops))
                  : ""
            color: Theme.inkSoft
            font.pixelSize: Theme.textBody
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
        }
        Rectangle {
            Layout.fillWidth: true
            implicitHeight: route.implicitHeight + 20
            radius: Theme.radiusSmall
            color: Theme.serverSoft
            RowLayout {
                id: route
                anchors.fill: parent
                anchors.margins: 10
                spacing: 10
                Icon { name: "route"; width: 18; height: 18; color: Theme.serverStrong }
                Text {
                    textFormat: Text.PlainText
                    horizontalAlignment: Text.AlignLeft
                    text: dialog.reviewed ? Labels.nodes(dialog.reviewed.nodes) : ""
                    color: Theme.ink
                    font.pixelSize: Theme.textBody
                    font.weight: Font.DemiBold
                    Layout.fillWidth: true
                    wrapMode: Text.WordWrap
                }
                Text {
                    textFormat: Text.PlainText
                    visible: dialog.reviewed !== null && dialog.reviewed.latency_ms !== undefined
                    text: dialog.reviewed && dialog.reviewed.latency_ms !== undefined
                          ? qsTr("%1 ms").arg(dialog.reviewed.latency_ms) : ""
                    color: Theme.muted
                    font.pixelSize: Theme.textLabel
                }
            }
        }
        Text {
            textFormat: Text.PlainText
            text: qsTr("What you give up")
            color: Theme.muted
            font.pixelSize: Theme.textSmall
            font.weight: Font.DemiBold
        }
        Text {
            textFormat: Text.PlainText
            horizontalAlignment: Text.AlignLeft
            text: dialog.reviewed ? dialog.reviewed.gives_up : ""
            color: Theme.ink
            font.pixelSize: Theme.textBody
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
        }
        Text {
            textFormat: Text.PlainText
            horizontalAlignment: Text.AlignLeft
            text: qsTr("Accepting lasts until a route of the configured length works again or yume stops. Until you accept, new connections wait.")
            color: Theme.muted
            font.pixelSize: Theme.textSmall
            Layout.fillWidth: true
            wrapMode: Text.WordWrap
        }
        Rectangle {
            visible: dialog.changed
            Layout.fillWidth: true
            implicitHeight: changedText.implicitHeight + 16
            radius: Theme.radiusSmall
            color: Theme.refusedSoft
            Text {
                textFormat: Text.PlainText
                horizontalAlignment: Text.AlignLeft
                id: changedText
                anchors.fill: parent
                anchors.margins: 8
                text: qsTr("yume no longer proposes this route. Close and review the current proposal.")
                color: Theme.refusedStrong
                font.pixelSize: Theme.textLabel
                wrapMode: Text.WordWrap
            }
        }
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: 8
            spacing: 8
            Item { Layout.fillWidth: true }
            AppButton {
                id: keepWaiting
                objectName: "keepWaiting"
                text: qsTr("Keep waiting")
                focus: true
                onClicked: dialog.close()
            }
            AppButton {
                objectName: "acceptRoute"
                kind: "primary"
                text: qsTr("Accept this route")
                enabled: dialog.reviewed !== null && !dialog.changed
                onClicked: {
                    App.acceptRoute(dialog.reviewed.id)
                    dialog.close()
                }
            }
        }
    }
    onOpened: keepWaiting.forceActiveFocus()
}
