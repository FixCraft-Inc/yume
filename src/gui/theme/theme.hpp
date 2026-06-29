/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <imgui.h>

namespace yume::gui::theme {

enum class Mode { Dark, Light };

// Material 3 colour tokens. Only the slots we actually reference are
// pulled in; full M3 has more (e.g. inverse-surface) which we don't use.
struct Palette {
    ImVec4 primary;
    ImVec4 on_primary;
    ImVec4 primary_container;
    ImVec4 on_primary_container;
    ImVec4 secondary;
    ImVec4 on_secondary;
    ImVec4 tertiary;
    ImVec4 surface;
    ImVec4 surface_dim;
    ImVec4 surface_bright;
    ImVec4 surface_container_lowest;
    ImVec4 surface_container_low;
    ImVec4 surface_container;
    ImVec4 surface_container_high;
    ImVec4 surface_container_highest;
    ImVec4 on_surface;
    ImVec4 on_surface_variant;
    ImVec4 outline;
    ImVec4 outline_variant;
    ImVec4 error;
    ImVec4 on_error;
    ImVec4 success;
    ImVec4 warning;
};

Palette material3_dark();
Palette material3_light();

// Push the Material 3 style + colours onto the active ImGuiStyle.
// Intended to be called once at startup; switching mode is a re-apply.
void apply_material3(Mode m);

// Returns the currently active palette (read-only).
Palette const& current_palette();

// Convenience colour fetchers for code that doesn't want to grab the
// palette directly.
ImVec4 color_for(const char* token);

}  // namespace yume::gui::theme
