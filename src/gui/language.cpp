/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "gui/language.hpp"

namespace yume::gui {

QString catalog_language(const QLocale& locale) {
    const QLocale::Language language = locale.language();
    if (language == QLocale::C || language == QLocale::AnyLanguage) return {};
    if (language == QLocale::Chinese) {
        // Qt fills in the likely script, so zh_CN reads Simplified and
        // zh_TW Traditional without a table of regions here.
        switch (locale.script()) {
            case QLocale::SimplifiedHanScript:
                return QStringLiteral("zh-Hans");
            case QLocale::TraditionalHanScript:
                return QStringLiteral("zh-Hant");
            default:
                return {};
        }
    }
    return QLocale::languageToCode(language).toLower();
}

}  // namespace yume::gui
