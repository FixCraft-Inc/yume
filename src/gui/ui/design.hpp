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

bool begin_card(char const* id, ImVec2 size = ImVec2(0, 0));
bool begin_auto_card(char const* id, float width = 0.0f);
void end_card();

ImVec2 status_pill(char const* text, ImVec4 color);
void unavailable_panel(char const* title, char const* message);

}  // namespace yume::gui::ui
