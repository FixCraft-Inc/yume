/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <QColor>
#include <QIcon>
#include <QPainterPath>
#include <QString>

namespace yume::gui {

// The YUME mark. assets/icon.svg owns its outline, and everything the GUI
// draws of it reads that file, so the window icon, the tray and the pages
// show one shape without an SVG plugin.

// The outline's path data, in the icon's 256-unit box, as SVG path text.
// Empty when the embedded icon cannot be read.
QString mark_path_data();

// The outline as a painter path, for the commands the icon uses: moveto,
// lineto, cubic curve and close, absolute or relative. Empty for text it
// cannot read.
QPainterPath parse_svg_path(const QString& data);

// The mark in the light theme's plum gradient, with a dot in the lower
// trailing corner when dot is valid, at the usual icon sizes.
QIcon mark_icon(const QColor& dot = QColor());

}  // namespace yume::gui
