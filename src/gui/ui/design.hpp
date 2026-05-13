/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <string_view>

#include <imgui.h>

namespace yume::gui::ui {

struct Fonts {
    ImFont* body{nullptr};
    ImFont* strong{nullptr};
    ImFont* small{nullptr};
    ImFont* section{nullptr};
    ImFont* title{nullptr};
    ImFont* mono{nullptr};
};

struct Colors {
    ImVec4 background;
    ImVec4 surface;
    ImVec4 surface_high;
    ImVec4 outline;
    ImVec4 text;
    ImVec4 muted;
    ImVec4 accent;
    ImVec4 accent_hover;
    // Text/glyph colour to use when painting on top of an accent surface
    // (primary_button, active segment of segmented_control, checkbox
    // fill, etc.). Mirrors Android's on_primary: dark wine on light pink
    // in dark mode; white on dark plum in light mode. Without this the
    // default text colour blends into the accent.
    ImVec4 on_accent;
    ImVec4 success;
    ImVec4 warning;
    ImVec4 error;
};

void install_fonts(float content_scale);
void apply_style(float content_scale, bool dark_mode);

Fonts const& fonts();
Colors const& colors();
float scale();

void page_header(char const* title, char const* subtitle = nullptr);
void section_label(char const* label);
void field_label(char const* label);
void muted_text(char const* fmt, ...);
void message_text(ImVec4 color, char const* fmt, ...);
float form_width(float max_width = 0.0f);

bool nav_item(char const* id, char const* label, bool selected, ImVec2 size);
float button_width(char const* label, float min_width = 0.0f);
bool primary_button(char const* label, ImVec2 size = ImVec2(0, 0));
bool secondary_button(char const* label, ImVec2 size = ImVec2(0, 0));
bool quiet_button(char const* label, ImVec2 size = ImVec2(0, 0));
bool disclosure_header(char const* label, bool open);

// Modern check control: rounded accent-filled box on the left, label on the
// right. Whole row clickable. Returns true on the frame the value flipped.
bool checkbox(char const* label, bool* value);

// Pill / segmented-button tab control. Returns the (possibly-changed) active
// index. Renders as a single rounded container with one segment highlighted.
int segmented_control(char const* id,
                      char const* const* labels,
                      int count,
                      int current);

// Modern dropdown select. Renders as a pill-style filled control with
// the current value and a chevron; opens a styled popup on click. Returns
// true on the frame *current changed. Pass min_width = 0 to size to the
// widest label.
bool combo(char const* id,
           int* current,
           char const* const* items,
           int count,
           float min_width = 0.0f);

// Cleaner replacement for ImGui::BeginTable for data tables. Pushes the
// design-system colours and spacing; pair with end_data_table().
bool begin_data_table(char const* id,
                      int columns,
                      ImGuiTableFlags extra_flags = 0);

// Convenience: setup N columns with the given labels and emit a styled
// header row. Call inside begin_data_table() / end_data_table().
void data_table_headers(std::initializer_list<char const*> headers);
// Emit only the styled header row. Use when the caller wants to set up
// columns manually (e.g. with fixed widths) before headers.
void data_table_header_row();
void end_data_table();

bool begin_card(char const* id, ImVec2 size = ImVec2(0, 0));
bool begin_auto_card(char const* id, float width = 0.0f);
void end_card();

ImVec2 status_pill(char const* text, ImVec4 color);
void unavailable_panel(char const* title, char const* message);

}  // namespace yume::gui::ui
