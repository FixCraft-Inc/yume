/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

class QQmlEngine;

namespace yume::gui {

// Gives the engine a network access manager that refuses every request. The
// pages load only embedded files, and text from a server or peer must never
// make the GUI fetch a URL outside the tunnel, even if a page renders it as
// rich text by mistake. Every page also sets plain text. This is the second
// guard.
void make_engine_offline(QQmlEngine& engine);

}  // namespace yume::gui
