// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

#include "gui/fonts.hpp"

#include <QFont>
#include <QFontDatabase>
#include <QStringList>

namespace yume::gui {

bool register_fonts() {
    const int jost = QFontDatabase::addApplicationFont(
        QStringLiteral(":/yume/fonts/Jost-Regular.ttf"));
    const int quicksand = QFontDatabase::addApplicationFont(
        QStringLiteral(":/yume/fonts/Quicksand-Bold.ttf"));
    if (jost == -1 || quicksand == -1) return false;
    // Quicksand has no Cyrillic. The bundled Jost face calls itself Jost*,
    // including the asterisk. Qt's glyph fallback uses this substitution
    // on Qt 6.4 too, where QML has no font.families property.
    QFont::insertSubstitutions(QStringLiteral("Quicksand"),
                              QFontDatabase::applicationFontFamilies(jost));
    return true;
}

}  // namespace yume::gui
