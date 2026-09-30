// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import YumeBackend 1.0

ApplicationWindow {
    id: window
    width: 1180
    height: 760
    minimumWidth: 900
    minimumHeight: 600
    visible: true
    color: Theme.paper
    title: App.kitName.length > 0 ? qsTr("YUME – %1").arg(App.kitName) : "YUME"

    readonly property var pageNames: ["overview", "connect", "logs", "posture"]
    readonly property var pageTitles: [qsTr("Overview"), qsTr("Connect"), qsTr("Logs"), qsTr("Posture")]
    readonly property var proposal: App.status.circuits ? App.status.circuits.proposal : null

    // Called by the capture mode and the proposal banner.
    function openRouteReview() { routeReview.openFor(window.proposal) }
    function closeDialogs() { routeReview.close() }

    // With a tray icon, closing hides the window and the GUI stays in the
    // tray. Either way the tunnel keeps running.
    onClosing: function(close) {
        if (App.trayActive) {
            close.accepted = false
            window.hide()
        }
    }

    Shortcut { sequence: "Ctrl+1"; onActivated: App.page = "overview" }
    Shortcut { sequence: "Ctrl+2"; onActivated: App.page = "connect" }
    Shortcut { sequence: "Ctrl+3"; onActivated: App.page = "logs" }
    Shortcut { sequence: "Ctrl+4"; onActivated: App.page = "posture" }

    // Controls and layouts mirror for right-to-left only through this
    // attached property, which a Window cannot carry itself.
    Item {
        id: root
        anchors.fill: parent
        LayoutMirroring.enabled: App.rightToLeft
        LayoutMirroring.childrenInherit: true

        RowLayout {
            anchors.fill: parent
            spacing: 0

            Sidebar {
                Layout.fillHeight: true
                Layout.preferredWidth: 236
                pageNames: window.pageNames
                pageTitles: window.pageTitles
            }
            Rectangle { Layout.fillHeight: true; width: 1; color: Theme.rule }

            ColumnLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                spacing: 0

                // The page title, the state and the primary action, on every page.
                RowLayout {
                    Layout.fillWidth: true
                    Layout.leftMargin: 32
                    Layout.rightMargin: 32
                    Layout.topMargin: 22
                    Layout.bottomMargin: 14
                    spacing: 14
                    ColumnLayout {
                        spacing: 0
                        Layout.fillWidth: true
                        Text {
                            textFormat: Text.PlainText
                            text: window.pageTitles[window.pageNames.indexOf(App.page)]
                            color: Theme.ink
                            font.family: Theme.displayFont
                            font.pixelSize: Theme.textTitle
                            Accessible.role: Accessible.Heading
                        }
                        Text {
                            textFormat: Text.PlainText
                            horizontalAlignment: Text.AlignLeft
                            // The running client names its server. A stopped
                            // kit shows the one its file names.
                            text: App.kitName.length === 0 ? qsTr("No kit selected")
                                  : App.status.server
                                    ? App.kitName + "  ·  " + App.status.server.host + ":" + App.status.server.port
                                    : App.kitServer.length > 0 ? App.kitName + "  ·  " + App.kitServer : App.kitName
                            color: Theme.muted
                            font.pixelSize: Theme.textLabel
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }
                    }
                    StatePill {
                        visible: App.kitName.length > 0
                        phase: App.phase
                        reported: App.status.state || ""
                    }
                    AppButton {
                        id: primary
                        objectName: "primaryAction"
                        visible: App.kitName.length > 0 && App.setupError.length === 0
                        kind: App.actionStops ? "secondary" : "primary"
                        text: App.actionText
                        enabled: App.actionEnabled
                        onClicked: App.runAction()
                    }
                }

                Rectangle {
                    visible: App.setupError.length > 0
                    Layout.fillWidth: true
                    Layout.leftMargin: 32
                    Layout.rightMargin: 32
                    Layout.bottomMargin: 12
                    implicitHeight: setupText.implicitHeight + 24
                    radius: Theme.radiusSmall
                    color: Theme.refusedSoft
                    Text {
                        textFormat: Text.PlainText
                        horizontalAlignment: Text.AlignLeft
                        id: setupText
                        anchors.fill: parent
                        anchors.margins: 12
                        text: qsTr("This GUI cannot start tunnels: %1").arg(App.setupError)
                        color: Theme.refusedStrong
                        font.pixelSize: Theme.textLabel
                        wrapMode: Text.WordWrap
                    }
                }

                StackLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    currentIndex: window.pageNames.indexOf(App.page)
                    OverviewPage { onReviewRoute: window.openRouteReview() }
                    ConnectPage {}
                    LogsPage {}
                    PosturePage {}
                }
            }
        }

        // A short notice, such as a copy or a refused action.
        Rectangle {
            visible: App.notice.length > 0
            anchors.horizontalCenter: parent.horizontalCenter
            anchors.bottom: parent.bottom
            anchors.bottomMargin: 24
            radius: height / 2
            color: Theme.ink
            implicitWidth: noticeText.implicitWidth + 36
            implicitHeight: 40
            Accessible.role: Accessible.AlertMessage
            Accessible.name: App.notice
            Text {
                textFormat: Text.PlainText
                id: noticeText
                anchors.centerIn: parent
                text: App.notice
                color: Theme.paper
                font.pixelSize: Theme.textLabel
            }
            MouseArea { anchors.fill: parent; onClicked: App.clearNotice() }
        }
    }

    RouteReviewDialog { id: routeReview }
}
