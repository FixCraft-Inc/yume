/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <QLocale>
#include <QString>

namespace yume::gui {

// The catalog language a locale reads (translations/catalog.json): its
// ISO 639 code, and for Chinese also its script, since Simplified and
// Traditional are separate catalog languages. zh_CN, zh_SG and zh_Hans give
// zh-Hans, and zh_TW, zh_HK and zh_MO give zh-Hant. Empty for the C locale
// and for Chinese in any other script. The compiled catalog of a language is
// :/i18n/yume_<tag>.qm.
QString catalog_language(const QLocale& locale);

}  // namespace yume::gui
