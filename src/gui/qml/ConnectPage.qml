// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Controls
import QtQuick.Dialogs
import QtQuick.Layouts
import YumeBackend 1.0

// Kits: which one to run, and importing a sealed kit with its code.
Flickable {
    id: page
    contentHeight: column.implicitHeight + 48
    clip: true
    boundsBehavior: Flickable.StopAtBounds
    ScrollBar.vertical: ScrollBar {}

    property string pendingRemoval

    ColumnLayout {
        id: column
        x: 32
        width: page.width - 64
        spacing: Theme.gap

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.gap

            Card {
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignTop
                Layout.preferredWidth: 3
                title: qsTr("Kits")
                subtitle: App.kitsDirectory.length > 0 ? qsTr("Kept in %1").arg(App.kitsDirectory) : ""
                trailing: AppButton {
                    compact: true
                    kind: "quiet"
                    text: qsTr("Refresh")
                    enabled: !App.renaming
                    onClicked: App.refreshKits()
                }

                Text {
                    textFormat: Text.PlainText
                    visible: App.kits.length === 0
                    text: qsTr("No kits yet. Import the sealed kit you received.")
                    color: Theme.muted
                    font.pixelSize: Theme.textLabel
                }

                Repeater {
                    model: App.kits
                    Rectangle {
                        id: kitRow
                        required property var modelData
                        readonly property bool selected: modelData.name === App.kitName
                        readonly property bool removing: page.pendingRemoval === modelData.name
                        Layout.fillWidth: true
                        implicitHeight: rowLayout.implicitHeight + 20
                        radius: Theme.radiusSmall
                        color: selected ? Theme.accentSoft : "transparent"
                        border.color: selected ? Theme.accent : Theme.ruleSoft
                        RowLayout {
                            id: rowLayout
                            anchors.fill: parent
                            anchors.margins: 10
                            spacing: 10
                            Rectangle {
                                implicitWidth: 10; implicitHeight: 10; radius: 5
                                color: Theme.stateColor(App.stateKind(kitRow.modelData.phase, kitRow.modelData.state))
                            }
                            ColumnLayout {
                                spacing: 0
                                Layout.fillWidth: true
                                Text {
                                    textFormat: Text.PlainText
                                    horizontalAlignment: Text.AlignLeft
                                    text: kitRow.modelData.name
                                    color: Theme.ink
                                    font.pixelSize: Theme.textBody
                                    font.weight: Font.DemiBold
                                    Layout.fillWidth: true
                                    elide: Text.ElideRight
                                }
                                Text {
                                    textFormat: Text.PlainText
                                    horizontalAlignment: Text.AlignLeft
                                    text: (kitRow.modelData.server || qsTr("server not readable")) + "  ·  "
                                          + App.stateLabel(kitRow.modelData.phase, kitRow.modelData.state)
                                    color: Theme.muted
                                    font.pixelSize: Theme.textSmall
                                    Layout.fillWidth: true
                                    elide: Text.ElideRight
                                }
                            }
                            AppButton {
                                visible: !kitRow.selected && !kitRow.removing
                                compact: true
                                text: qsTr("Show")
                                Accessible.name: qsTr("Show %1").arg(kitRow.modelData.name)
                                onClicked: App.kitName = kitRow.modelData.name
                            }
                            AppButton {
                                visible: !kitRow.removing
                                compact: true
                                kind: "quiet"
                                iconName: "folder"
                                text: qsTr("Folder")
                                Accessible.name: qsTr("Open the folder of %1").arg(kitRow.modelData.name)
                                onClicked: App.openKitFolder(kitRow.modelData.name)
                            }
                            AppButton {
                                visible: !kitRow.removing && kitRow.modelData.phase === "stopped"
                                enabled: !App.renaming && !App.importing
                                compact: true
                                kind: "quiet"
                                text: qsTr("Rename")
                                Accessible.name: qsTr("Rename %1").arg(kitRow.modelData.name)
                                onClicked: renameDialog.openFor(kitRow.modelData.name)
                            }
                            AppButton {
                                visible: !kitRow.removing && kitRow.modelData.phase === "stopped"
                                enabled: !App.renaming
                                compact: true
                                kind: "quiet"
                                iconName: "trash"
                                text: qsTr("Remove")
                                Accessible.name: qsTr("Remove %1").arg(kitRow.modelData.name)
                                onClicked: page.pendingRemoval = kitRow.modelData.name
                            }
                            // Removal deletes the kit's credentials, so it asks once more in place.
                            Text {
                                textFormat: Text.PlainText
                                visible: kitRow.removing
                                text: qsTr("Delete this kit and its keys?")
                                color: Theme.refusedStrong
                                font.pixelSize: Theme.textSmall
                            }
                            AppButton {
                                visible: kitRow.removing
                                compact: true
                                kind: "danger"
                                text: qsTr("Delete")
                                enabled: !App.renaming
                                onClicked: {
                                    page.pendingRemoval = ""
                                    App.removeKit(kitRow.modelData.name)
                                }
                            }
                            AppButton {
                                visible: kitRow.removing
                                compact: true
                                text: qsTr("Keep")
                                onClicked: page.pendingRemoval = ""
                            }
                        }
                    }
                }
            }

            Card {
                id: importCard
                Layout.fillWidth: true
                Layout.alignment: Qt.AlignTop
                Layout.preferredWidth: 2
                title: qsTr("Import a sealed kit")
                subtitle: qsTr("A sealed kit is one file. Its code, given to you separately, opens it on this device.")

                property url file

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 8
                    AppButton {
                        iconName: "import"
                        text: qsTr("Choose file…")
                        onClicked: fileDialog.open()
                    }
                    Text {
                        textFormat: Text.PlainText
                        horizontalAlignment: Text.AlignLeft
                        text: importCard.file.toString().length > 0
                              ? decodeURIComponent(importCard.file.toString().replace(/^file:\/\//, ""))
                              : qsTr("No file chosen")
                        color: importCard.file.toString().length > 0 ? Theme.ink : Theme.muted
                        font.pixelSize: Theme.textSmall
                        Layout.fillWidth: true
                        elide: Text.ElideMiddle
                    }
                }
                Text { textFormat: Text.PlainText; text: qsTr("Name"); color: Theme.muted; font.pixelSize: Theme.textSmall; Layout.topMargin: 6 }
                AppTextField {
                    id: nameField
                    Layout.fillWidth: true
                    placeholderText: qsTr("for example: work")
                    maximumLength: 48
                    Accessible.name: qsTr("Kit name")
                }
                Text { textFormat: Text.PlainText; text: qsTr("Code"); color: Theme.muted; font.pixelSize: Theme.textSmall; Layout.topMargin: 6 }
                AppTextField {
                    id: codeField
                    Layout.fillWidth: true
                    placeholderText: "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
                    font.family: Theme.monoFont
                    echoMode: TextInput.Password
                    maximumLength: 64
                    inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText
                    Accessible.name: qsTr("Kit code")
                    onAccepted: importButton.clicked()
                }
                RowLayout {
                    Layout.fillWidth: true
                    Layout.topMargin: 6
                    AppButton {
                        id: importButton
                        kind: "primary"
                        text: App.importing ? qsTr("Importing…") : qsTr("Import")
                        enabled: !App.importing && !App.renaming && importCard.file.toString().length > 0
                                 && nameField.text.length > 0 && codeField.text.length > 0
                        onClicked: {
                            App.importKit(importCard.file, nameField.text, codeField.text)
                            // The code is not kept once yume has it.
                            codeField.clear()
                        }
                    }
                    Text {
                        textFormat: Text.PlainText
                        horizontalAlignment: Text.AlignLeft
                        visible: App.importMessage.length > 0
                        text: App.importMessage
                        color: App.importFailed ? Theme.refusedStrong : Theme.outsideStrong
                        font.pixelSize: Theme.textSmall
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                    }
                }
                Text {
                    textFormat: Text.PlainText
                    horizontalAlignment: Text.AlignLeft
                    text: qsTr("yume opens the kit and reads the code on its standard input. This window does not keep the code.")
                    color: Theme.muted
                    font.pixelSize: Theme.textSmall
                    Layout.fillWidth: true
                    Layout.topMargin: 4
                    wrapMode: Text.WordWrap
                }
            }
        }

        Rectangle {
            Layout.fillWidth: true
            implicitHeight: note.implicitHeight + 24
            radius: Theme.radiusSmall
            color: Theme.paperSoft
            Text {
                textFormat: Text.PlainText
                horizontalAlignment: Text.AlignLeft
                id: note
                anchors.fill: parent
                anchors.margins: 12
                text: qsTr("A connected tunnel keeps running when you close this window or it quits. Open YUME again to see it or disconnect it.")
                color: Theme.inkSoft
                font.pixelSize: Theme.textSmall
                wrapMode: Text.WordWrap
            }
        }
    }

    Dialog {
        id: renameDialog
        objectName: "renameKitDialog"
        property string originalName
        readonly property bool validName: App.validKitName(renameField.text)

        function openFor(name) {
            originalName = name
            renameField.text = name
            open()
        }
        function submit() {
            if (!renameAccept.enabled) return
            App.renameKit(originalName, renameField.text)
            close()
        }

        modal: true
        focus: true
        anchors.centerIn: Overlay.overlay
        width: Math.min(460, (parent ? parent.width : 460) - 64)
        padding: 24
        closePolicy: Popup.CloseOnEscape
        onOpened: {
            renameField.forceActiveFocus(Qt.TabFocusReason)
            renameField.selectAll()
        }
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
                text: qsTr("Rename %1").arg(renameDialog.originalName)
                color: Theme.ink
                font.family: Theme.displayFont
                font.pixelSize: 24
                Accessible.role: Accessible.Heading
            }
            AppTextField {
                id: renameField
                objectName: "renameKitName"
                Layout.fillWidth: true
                maximumLength: 48
                Accessible.name: qsTr("New kit name")
                onAccepted: renameDialog.submit()
            }
            Text {
                textFormat: Text.PlainText
                Layout.fillWidth: true
                text: qsTr("Use 1 to 48 letters, digits, dots, dashes or underscores. Start with a letter, digit or underscore.")
                color: renameDialog.validName ? Theme.muted : Theme.refusedStrong
                font.pixelSize: Theme.textSmall
                wrapMode: Text.WordWrap
            }
            RowLayout {
                Layout.fillWidth: true
                Item { Layout.fillWidth: true }
                AppButton {
                    text: qsTr("Cancel")
                    onClicked: renameDialog.close()
                }
                AppButton {
                    id: renameAccept
                    objectName: "renameKitAccept"
                    kind: "primary"
                    text: qsTr("Rename")
                    enabled: renameDialog.validName && renameField.text !== renameDialog.originalName
                             && !App.renaming && !App.importing
                    onClicked: renameDialog.submit()
                }
            }
        }
    }

    FileDialog {
        id: fileDialog
        title: qsTr("Choose a sealed kit")
        fileMode: FileDialog.OpenFile
        onAccepted: {
            importCard.file = selectedFile
            if (nameField.text.length === 0) nameField.text = App.suggestKitName(selectedFile)
        }
    }
}
