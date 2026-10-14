// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import YumeBackend 1.0

// Who made YUME, what it is built on and who translated it, as lists rather
// than a card for every entry.
Flickable {
    id: page
    objectName: "creditsPage"
    contentHeight: column.implicitHeight + 48
    clip: true
    boundsBehavior: Flickable.StopAtBounds
    ScrollBar.vertical: ScrollBar {}

    readonly property var translations: App.credits.translations || []
    readonly property var languageGroups: [
        {title: qsTrId("maintained"), entries: translations.filter(language => language.group === "maintained")},
        {title: qsTrId("community.translations"), entries: translations.filter(language => language.group !== "maintained")}
    ].filter(group => group.entries.length > 0)

    // Two columns, a name with its detail beneath and a description beside
    // it, for components and languages alike.
    component ListRow: RowLayout {
        id: listRow
        property string name
        property string detail
        property string description
        property bool strong: true
        spacing: Theme.gap
        Accessible.role: Accessible.StaticText
        Accessible.name: [name, detail, description].filter(part => part.length > 0).join(", ")
        ColumnLayout {
            spacing: 1
            Layout.preferredWidth: Math.min(240, listRow.width * 0.4)
            Layout.minimumWidth: Layout.preferredWidth
            Layout.maximumWidth: Layout.preferredWidth
            Layout.alignment: Qt.AlignTop | Qt.AlignLeft
            Text {
                textFormat: Text.PlainText
                horizontalAlignment: Text.AlignLeft
                text: listRow.name
                color: Theme.ink
                font.pixelSize: Theme.textBody
                // Language names stay at the regular weight: a script the
                // font lacks is drawn by a fallback font that may have no
                // bold, and mixed weights read as a fault.
                font.weight: listRow.strong ? Font.DemiBold : Font.Normal
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
            }
            Text {
                textFormat: Text.PlainText
                horizontalAlignment: Text.AlignLeft
                visible: listRow.detail.length > 0
                text: listRow.detail
                color: Theme.muted
                font.pixelSize: Theme.textSmall
                Layout.fillWidth: true
                wrapMode: Text.WordWrap
            }
        }
        Text {
            textFormat: Text.PlainText
            horizontalAlignment: Text.AlignLeft
            text: listRow.description
            color: Theme.inkSoft
            font.pixelSize: Theme.textLabel
            Layout.fillWidth: true
            Layout.alignment: Qt.AlignTop | Qt.AlignLeft
            wrapMode: Text.WordWrap
        }
    }

    ColumnLayout {
        id: column
        x: 32
        width: page.width - 64
        spacing: Theme.gap

        GridLayout {
            Layout.fillWidth: true
            columns: page.width > 760 ? Math.max(1, (App.credits.contributors || []).length) : 1
            columnSpacing: Theme.gap
            rowSpacing: Theme.gap
            Repeater {
                model: App.credits.contributors || []
                Card {
                    required property var modelData
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    Layout.preferredWidth: 1
                    title: modelData.name
                    subtitle: qsTrId(modelData.role)
                    Text {
                        textFormat: Text.PlainText
                        horizontalAlignment: Text.AlignLeft
                        text: qsTrId(modelData.contribution)
                        color: Theme.inkSoft
                        font.pixelSize: Theme.textLabel
                        Layout.fillWidth: true
                        wrapMode: Text.WordWrap
                    }
                }
            }
        }

        Repeater {
            model: [
                {title: qsTrId("credits.desktop.components"), entries: App.credits.components.desktop},
                {title: qsTrId("credits.native.components"), entries: App.credits.components.native.concat(App.credits.components.linux)}
            ]
            Card {
                required property var modelData
                Layout.fillWidth: true
                title: modelData.title
                RowList {
                    id: components
                    spacing: 10
                    model: modelData.entries
                    delegate: ListRow {
                        required property var modelData
                        width: components.width
                        name: modelData.name
                        detail: modelData.license
                        description: qsTrId(modelData.use)
                    }
                }
            }
        }

        // Every translation, native then community, with who translated it.
        Card {
            visible: page.languageGroups.length > 0
            Layout.fillWidth: true
            title: qsTrId("credits.translations")
            RowList {
                id: languages
                spacing: 14
                model: page.languageGroups
                delegate: Column {
                    id: group
                    required property var modelData
                    width: languages.width
                    spacing: 8
                    Text {
                        textFormat: Text.PlainText
                        text: group.modelData.title
                        color: Theme.muted
                        font.pixelSize: Theme.textSmall
                        font.weight: Font.DemiBold
                        font.capitalization: Font.AllUppercase
                        font.letterSpacing: 0.6
                        Accessible.role: Accessible.Heading
                    }
                    Repeater {
                        model: group.modelData.entries
                        ListRow {
                            required property var modelData
                            width: group.width
                            strong: false
                            name: modelData.name
                            detail: modelData.coverage < 100 ? qsTrId("some.text.appears.in.english") : ""
                            description: modelData.credits.map(credit => credit.name).join(", ")
                        }
                    }
                }
            }
        }
    }
}
