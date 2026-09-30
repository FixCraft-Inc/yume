/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <QString>

#include "gui/kit_store.hpp"

namespace yume::gui {

// Exit statuses of the headless actions. Nothing exercised is distinct from
// a failed leg, so a run that tested nothing never reads as a pass.
inline constexpr int kHeadlessPassed = 0;
inline constexpr int kHeadlessLegFailed = 1;
inline constexpr int kHeadlessNothingExercised = 2;

// Runs a lifecycle action on a kit through the same Tunnel the window uses,
// with no display: status, connect (until yume reports connected), stop
// (until its socket and process are gone) or cycle (connect, stop, connect,
// stop). Each leg prints one JSON line on standard output with what the
// control socket reported. connect leaves the tunnel running when this
// process exits.
int run_headless_action(const Places& places, const QString& action,
                        const QString& kit);

// Imports a sealed kit with the code read from standard input, as the
// window's import does, and prints one JSON line.
int run_headless_import(const Places& places, const QString& file,
                        const QString& name);

}  // namespace yume::gui
