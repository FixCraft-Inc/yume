// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import YumeBackend 1.0

// The brand, the pages and the kits. Choosing a kit shows its tunnel.
Rectangle {
    id: sidebar
    property var pageNames: []
    property var pageTitles: []
    readonly property var icons: ["overview", "connect", "logs", "posture"]
    color: Theme.paperSoft

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 14
        spacing: 4

        RowLayout {
            Layout.leftMargin: 6
            Layout.topMargin: 8
            Layout.bottomMargin: 18
            spacing: 10
            Logo { implicitWidth: 34; implicitHeight: 34 }
            ColumnLayout {
                spacing: -2
                Text {
                    textFormat: Text.PlainText
                    text: "YUME"
                    color: Theme.ink
                    font.family: Theme.displayFont
                    font.pixelSize: 24
                    font.letterSpacing: 3
                }
                Text {
                    textFormat: Text.PlainText
                    text: qsTr("Desktop")
                    color: Theme.muted
                    font.pixelSize: Theme.textSmall
                }
            }
        }

        Repeater {
            model: sidebar.pageNames.length
            NavButton {
                Layout.fillWidth: true
                text: sidebar.pageTitles[index]
                iconName: sidebar.icons[index]
                shortcutText: "Ctrl+" + (index + 1)
                current: App.page === sidebar.pageNames[index]
                onClicked: App.page = sidebar.pageNames[index]
            }
        }

        Item { Layout.fillHeight: true }

        Text {
            textFormat: Text.PlainText
            text: qsTr("KITS")
            color: Theme.muted
            font.pixelSize: 11
            font.weight: Font.DemiBold
            font.letterSpacing: 1.2
            Layout.leftMargin: 8
            Layout.bottomMargin: 2
        }
        Text {
            textFormat: Text.PlainText
            horizontalAlignment: Text.AlignLeft
            visible: App.kits.length === 0
            text: qsTr("None yet. Import one on the Connect page.")
            color: Theme.muted
            font.pixelSize: Theme.textSmall
            wrapMode: Text.WordWrap
            Layout.fillWidth: true
            Layout.leftMargin: 8
            Layout.bottomMargin: 8
        }
        ListView {
            id: kitList
            Layout.fillWidth: true
            Layout.preferredHeight: Math.min(contentHeight, 5 * 48)
            clip: true
            spacing: 2
            model: App.kits
            boundsBehavior: Flickable.StopAtBounds
            delegate: ItemDelegate {
                required property var modelData
                readonly property bool selected: modelData.name === App.kitName
                width: kitList.width
                height: 46
                focusPolicy: Qt.StrongFocus
                hoverEnabled: true
                leftPadding: 10
                rightPadding: 10
                Accessible.name: qsTr("Kit %1, %2").arg(modelData.name)
                                 .arg(App.stateLabel(modelData.phase, modelData.state))
                onClicked: App.kitName = modelData.name
                contentItem: RowLayout {
                    spacing: 10
                    Rectangle {
                        implicitWidth: 8; implicitHeight: 8; radius: 4
                        color: Theme.stateColor(App.stateKind(modelData.phase, modelData.state))
                    }
                    ColumnLayout {
                        spacing: 0
                        Layout.fillWidth: true
                        Text {
                            textFormat: Text.PlainText
                            horizontalAlignment: Text.AlignLeft
                            text: modelData.name
                            color: Theme.ink
                            font.pixelSize: Theme.textLabel
                            font.weight: selected ? Font.DemiBold : Font.Normal
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }
                        Text {
                            textFormat: Text.PlainText
                            horizontalAlignment: Text.AlignLeft
                            text: modelData.server || qsTr("server not readable")
                            color: Theme.muted
                            font.pixelSize: 11
                            Layout.fillWidth: true
                            elide: Text.ElideRight
                        }
                    }
                }
                background: Rectangle {
                    radius: Theme.radiusSmall
                    color: selected ? Theme.cloud : hovered ? Theme.paperDeep : "transparent"
                    border.width: visualFocus ? 2 : selected ? 1 : 0
                    border.color: visualFocus ? Theme.focus : Theme.rule
                }
            }
        }
    }
}
