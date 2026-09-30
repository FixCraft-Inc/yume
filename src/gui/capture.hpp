/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <QString>

class QQuickWindow;

namespace yume::gui {

class AppState;

// Renders every page to DIR/<page>-<theme>-<direction>.png for review, the
// route review dialog when a proposal is shown and the tray icon in each
// state as DIR/tray-<kind>.png, then quits the
// application with 0, or 1 when an image could not be written. It waits for
// the selected kit's first status so pages show what the socket reports.
void start_capture(QQuickWindow* window, AppState* state,
                   const QString& directory);

}  // namespace yume::gui
