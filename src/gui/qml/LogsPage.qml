// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import YumeBackend 1.0

// The lines the running yume printed, from its messages request, with the
// latest start's output when it did not come up.
Item {
    id: page
    readonly property string filter: filterField.text.toLowerCase()
    readonly property bool running: App.phase === "running" || App.phase === "stopping"

    ColumnLayout {
        anchors.fill: parent
        anchors.leftMargin: 32
        anchors.rightMargin: 32
        anchors.bottomMargin: 24
        spacing: Theme.gap

        RowLayout {
            Layout.fillWidth: true
            spacing: 10
            AppTextField {
                id: filterField
                Layout.preferredWidth: 320
                placeholderText: qsTr("Filter lines")
                Accessible.name: qsTr("Filter lines")
            }
            CheckBox {
                id: follow
                checked: true
                text: qsTr("Follow")
                focusPolicy: Qt.StrongFocus
                indicator: Rectangle {
                    x: follow.leftPadding
                    y: (follow.height - height) / 2
                    width: 20; height: 20; radius: 6
                    color: follow.checked ? Theme.button : Theme.paper
                    border.width: follow.visualFocus ? 2 : 1
                    border.color: follow.visualFocus ? Theme.focus : follow.checked ? Theme.accent : Theme.rule
                    Icon {
                        visible: follow.checked
                        anchors.centerIn: parent
                        name: "check"
                        width: 14; height: 14
                        stroke: 2.2
                        color: Theme.buttonInk
                    }
                }
                contentItem: Text {
                    textFormat: Text.PlainText
                    leftPadding: follow.indicator.width + 6
                    text: follow.text
                    color: Theme.ink
                    font.pixelSize: Theme.textLabel
                    verticalAlignment: Text.AlignVCenter
                }
            }
            Item { Layout.fillWidth: true }
            Text {
                textFormat: Text.PlainText
                text: App.messagesMissed > 0
                      ? qsTr("%1 lines, %2 earlier ones no longer kept").arg(App.messages.count).arg(App.messagesMissed)
                      : qsTr("%1 lines").arg(App.messages.count)
                color: Theme.muted
                font.pixelSize: Theme.textSmall
            }
            AppButton {
                compact: true
                iconName: "copy"
                text: qsTr("Copy all")
                enabled: App.messages.count > 0
                onClicked: App.copyText(App.messages.text())
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            radius: Theme.radius
            color: Theme.cloud
            border.color: Theme.rule
            clip: true

            ListView {
                id: lines
                anchors.fill: parent
                anchors.margins: 12
                model: App.messages
                clip: true
                boundsBehavior: Flickable.StopAtBounds
                ScrollBar.vertical: ScrollBar {}
                onCountChanged: if (follow.checked) positionViewAtEnd()
                Accessible.role: Accessible.List
                Accessible.name: qsTr("Printed lines")
                delegate: Item {
                    id: line
                    required property string time
                    required property string text
                    required property bool warning
                    readonly property bool shown: page.filter.length === 0 || text.toLowerCase().indexOf(page.filter) >= 0
                    width: lines.width
                    height: shown ? lineRow.implicitHeight + 6 : 0
                    visible: shown
                    RowLayout {
                        id: lineRow
                        width: parent.width
                        spacing: 14
                        Text {
                            textFormat: Text.PlainText
                            text: line.time
                            color: Theme.muted
                            font.family: Theme.monoFont
                            font.pixelSize: Theme.textSmall
                            Layout.alignment: Qt.AlignTop
                        }
                        Text {
                            text: line.text
                            color: line.warning ? Theme.disguiseStrong : Theme.ink
                            font.family: Theme.monoFont
                            font.pixelSize: Theme.textSmall
                            Layout.fillWidth: true
                            wrapMode: Text.WrapAnywhere
                            textFormat: Text.PlainText
                        }
                    }
                }
            }

            Column {
                visible: App.messages.count === 0
                anchors.centerIn: parent
                width: Math.min(parent.width - 48, 520)
                spacing: 8
                Text {
                    textFormat: Text.PlainText
                    width: parent.width
                    horizontalAlignment: Text.AlignHCenter
                    text: page.running ? qsTr("No lines yet")
                          : App.phase === "none" ? qsTr("No kit selected")
                          : qsTr("The tunnel is not running")
                    color: Theme.ink
                    font.pixelSize: Theme.textHeading
                }
                Text {
                    textFormat: Text.PlainText
                    width: parent.width
                    horizontalAlignment: Text.AlignHCenter
                    text: page.running ? "" : qsTr("Lines appear here while yume runs.")
                    color: Theme.muted
                    font.pixelSize: Theme.textLabel
                    wrapMode: Text.WordWrap
                }
            }
        }

        Card {
            visible: !page.running && App.outputTail.length > 0
            Layout.fillWidth: true
            Layout.maximumHeight: 220
            title: qsTr("Output of the latest start")
            Text {
                text: App.outputTail
                color: Theme.inkSoft
                font.family: Theme.monoFont
                font.pixelSize: Theme.textSmall
                Layout.fillWidth: true
                wrapMode: Text.WrapAnywhere
                maximumLineCount: 8
                textFormat: Text.PlainText
            }
        }
    }
}
