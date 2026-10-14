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
                title: qsTrId("kits")
                subtitle: App.kitsDirectory.length > 0 ? qsTrId("desktop.kept.in").arg(App.kitsDirectory) : ""
                trailing: AppButton {
                    compact: true
                    kind: "quiet"
                    text: qsTrId("desktop.refresh")
                    enabled: !App.renaming && !App.removing
                    onClicked: App.refreshKits()
                }

                Text {
                    textFormat: Text.PlainText
                    visible: App.kits.length === 0
                    text: qsTrId("desktop.no.kits.yet.import.the.sealed.kit.you.received")
                    color: Theme.muted
                    font.pixelSize: Theme.textLabel
                }

                // Rows a Repeater rebuilds sit in a plain Column, not the card's
                // layout: Qt 6.4's layouts can keep a destroyed row while a page
                // is hidden and crash when it is shown (QTBUG-111792).
                Column {
                    id: kitList
                    Layout.fillWidth: true
                    spacing: Theme.gapSmall
                    visible: kitRows.count > 0
                    Repeater {
                        id: kitRows
                        model: App.kits
                        Rectangle {
                            id: kitRow
                            required property var modelData
                            readonly property bool selected: modelData.name === App.kitName
                            readonly property bool removing: page.pendingRemoval === modelData.name
                            width: kitList.width
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
                                        text: (kitRow.modelData.server || qsTrId("desktop.server.not.readable")) + "  ·  "
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
                                    text: qsTrId("desktop.show")
                                    Accessible.name: qsTrId("desktop.show.2").arg(kitRow.modelData.name)
                                    onClicked: App.kitName = kitRow.modelData.name
                                }
                                AppButton {
                                    visible: !kitRow.removing
                                    compact: true
                                    iconOnly: true
                                    kind: "quiet"
                                    iconName: "folder"
                                    text: qsTrId("desktop.folder")
                                    Accessible.name: qsTrId("desktop.open.the.folder.of").arg(kitRow.modelData.name)
                                    onClicked: App.openKitFolder(kitRow.modelData.name)
                                }
                                AppButton {
                                    visible: !kitRow.removing && kitRow.modelData.phase === "stopped"
                                    enabled: !App.renaming && !App.removing && !App.importing
                                    compact: true
                                    iconOnly: true
                                    kind: "quiet"
                                    iconName: "edit"
                                    text: qsTrId("rename")
                                    Accessible.name: qsTrId("desktop.rename").arg(kitRow.modelData.name)
                                    onClicked: renameDialog.openFor(kitRow.modelData.name)
                                }
                                AppButton {
                                    visible: !kitRow.removing && kitRow.modelData.phase === "stopped"
                                    enabled: !App.renaming && !App.removing
                                    compact: true
                                    iconOnly: true
                                    kind: "quiet"
                                    iconName: "trash"
                                    text: qsTrId("desktop.remove")
                                    Accessible.name: qsTrId("desktop.remove.2").arg(kitRow.modelData.name)
                                    onClicked: page.pendingRemoval = kitRow.modelData.name
                                }
                                // Removal deletes the kit's credentials, so it asks once more in place.
                                Text {
                                    textFormat: Text.PlainText
                                    visible: kitRow.removing
                                    text: qsTrId("desktop.delete.this.kit.and.its.keys")
                                    color: Theme.refusedStrong
                                    font.pixelSize: Theme.textSmall
                                }
                                AppButton {
                                    visible: kitRow.removing
                                    compact: true
                                    kind: "danger"
                                    text: qsTrId("delete")
                                    enabled: !App.renaming && !App.removing
                                    onClicked: {
                                        page.pendingRemoval = ""
                                        App.removeKit(kitRow.modelData.name)
                                    }
                                }
                                AppButton {
                                    visible: kitRow.removing
                                    compact: true
                                    text: qsTrId("desktop.keep")
                                    onClicked: page.pendingRemoval = ""
                                }
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
                title: qsTrId("desktop.import.a.sealed.kit")
                subtitle: qsTrId("desktop.a.sealed.kit.is.one.file.its.code.given.to.you.separate")

                property url file

                // The chosen file sits beside the button, or under it when
                // the card is too narrow for both.
                Flow {
                    id: fileRow
                    Layout.fillWidth: true
                    spacing: 8
                    AppButton {
                        id: chooseFile
                        iconName: "import"
                        text: qsTrId("desktop.choose.file")
                        onClicked: fileDialog.open()
                    }
                    Text {
                        textFormat: Text.PlainText
                        horizontalAlignment: Text.AlignLeft
                        verticalAlignment: Text.AlignVCenter
                        width: Math.min(implicitWidth, fileRow.width)
                        height: chooseFile.height
                        text: importCard.file.toString().length > 0
                              ? decodeURIComponent(importCard.file.toString().replace(/^file:\/\//, ""))
                              : qsTrId("no.file.chosen")
                        color: importCard.file.toString().length > 0 ? Theme.ink : Theme.muted
                        font.pixelSize: Theme.textSmall
                        elide: Text.ElideMiddle
                    }
                }
                Text { textFormat: Text.PlainText; text: qsTrId("name"); color: Theme.muted; font.pixelSize: Theme.textSmall; Layout.topMargin: 6 }
                AppTextField {
                    id: nameField
                    Layout.fillWidth: true
                    placeholderText: qsTrId("desktop.for.example.work")
                    maximumLength: 48
                    Accessible.name: qsTrId("desktop.kit.name")
                }
                RowLayout {
                    Layout.topMargin: 6
                    spacing: 4
                    Text { textFormat: Text.PlainText; text: qsTrId("code"); color: Theme.muted; font.pixelSize: Theme.textSmall }
                    HelpTip {
                        name: qsTrId("desktop.more.about").arg(qsTrId("code"))
                        help: qsTrId("desktop.yume.opens.the.kit.and.reads.the.code.on.its.standard.i")
                    }
                }
                AppTextField {
                    id: codeField
                    Layout.fillWidth: true
                    placeholderText: "XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
                    font.family: Theme.monoFont
                    echoMode: TextInput.Password
                    maximumLength: 64
                    inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText
                    Accessible.name: qsTrId("desktop.kit.code")
                    onAccepted: importButton.clicked()
                }
                RowLayout {
                    Layout.fillWidth: true
                    Layout.topMargin: 6
                    AppButton {
                        id: importButton
                        kind: "primary"
                        text: App.importing ? qsTrId("desktop.importing") : qsTrId("desktop.import")
                        enabled: !App.importing && !App.renaming && !App.removing && importCard.file.toString().length > 0
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
                text: qsTrId("desktop.a.connected.tunnel.keeps.running.when.you.close.this.wi")
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
                text: qsTrId("desktop.rename").arg(renameDialog.originalName)
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
                Accessible.name: qsTrId("desktop.new.kit.name")
                onAccepted: renameDialog.submit()
            }
            Text {
                textFormat: Text.PlainText
                Layout.fillWidth: true
                text: qsTrId("desktop.use.1.to.48.letters.digits.dots.dashes.or.underscores.s")
                color: renameDialog.validName ? Theme.muted : Theme.refusedStrong
                font.pixelSize: Theme.textSmall
                wrapMode: Text.WordWrap
            }
            RowLayout {
                Layout.fillWidth: true
                Item { Layout.fillWidth: true }
                AppButton {
                    text: qsTrId("cancel")
                    onClicked: renameDialog.close()
                }
                AppButton {
                    id: renameAccept
                    objectName: "renameKitAccept"
                    kind: "primary"
                    text: qsTrId("rename")
                    enabled: renameDialog.validName && renameField.text !== renameDialog.originalName
                             && !App.renaming && !App.removing && !App.importing
                    onClicked: renameDialog.submit()
                }
            }
        }
    }

    FileDialog {
        id: fileDialog
        title: qsTrId("desktop.choose.a.sealed.kit")
        fileMode: FileDialog.OpenFile
        onAccepted: {
            importCard.file = selectedFile
            if (nameField.text.length === 0) nameField.text = App.suggestKitName(selectedFile)
        }
    }
}
