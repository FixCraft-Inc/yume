/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * Material 3 theme adaptation for Dear ImGui. Colours and shape tokens
 * are taken from the M3 reference palette; ImGui can't express full
 * elevation or shadows so we fake hierarchy with surface tints and
 * outlineVariant strokes.
 */

#include "theme/theme.hpp"

#include <cstring>

namespace yume::gui::theme {

namespace {

constexpr ImVec4 rgb(int hex) {
    return ImVec4(((hex >> 16) & 0xFF) / 255.0f,
                  ((hex >> 8)  & 0xFF) / 255.0f,
                   (hex        & 0xFF) / 255.0f,
                   1.0f);
}

constexpr ImVec4 rgba(int hex, float a) {
    return ImVec4(((hex >> 16) & 0xFF) / 255.0f,
                  ((hex >> 8)  & 0xFF) / 255.0f,
                   (hex        & 0xFF) / 255.0f,
                   a);
}

Palette g_palette = material3_dark();

}  // namespace

// Palette mirrors the Android YUME Material 3 theme (Color.kt + Theme.kt):
// dusty plum, rose-pink, lavender tonal palette on a near-black night surface.
Palette material3_dark() {
    Palette p{};
    p.primary                   = rgb(0xE8BECC);   // soft rose-pink
    p.on_primary                = rgb(0x3A1F2E);
    p.primary_container         = rgb(0x563E53);   // YumePlumDeep
    p.on_primary_container      = rgb(0xF4DDEA);
    p.secondary                 = rgb(0xD9BFD4);   // lavender
    p.on_secondary              = rgb(0x281A28);
    p.tertiary                  = rgb(0xE0BCCF);   // rose
    p.surface                   = rgb(0x101014);   // YumeNight
    p.surface_dim               = rgb(0x0B0B0F);
    p.surface_bright            = rgb(0x2A252D);
    p.surface_container_lowest  = rgb(0x07070A);
    p.surface_container_low     = rgb(0x141318);
    p.surface_container         = rgb(0x17171C);   // YumeNightSurface
    p.surface_container_high    = rgb(0x222129);   // YumeNightRaised
    p.surface_container_highest = rgb(0x2A2A33);
    p.on_surface                = rgb(0xEAE3EA);
    p.on_surface_variant        = rgb(0xB5ABB3);
    p.outline                   = rgb(0x605466);
    p.outline_variant           = rgb(0x3A3340);
    p.error                     = rgb(0xFFB1BD);
    p.on_error                  = rgb(0x4B1F27);   // YumeErrorContainer
    p.success                   = rgb(0x86E0A8);
    p.warning                   = rgb(0xFFE7A6);   // YumeVerifyContent
    return p;
}

Palette material3_light() {
    Palette p{};
    p.primary                   = rgb(0x70536B);   // YumePlum
    p.on_primary                = rgb(0xFFFBFF);
    p.primary_container         = rgb(0xEDE3EF);   // YumeLilac
    p.on_primary_container      = rgb(0x281A28);
    p.secondary                 = rgb(0x7D5867);   // YumeBerry
    p.on_secondary              = rgb(0xFFFBFF);
    p.tertiary                  = rgb(0x5F607B);   // YumeIris
    p.surface                   = rgb(0xFFFBFE);   // YumePaper
    p.surface_dim               = rgb(0xE8E1E8);   // YumeMist
    p.surface_bright            = rgb(0xFFFFFF);
    p.surface_container_lowest  = rgb(0xFFFFFF);
    p.surface_container_low     = rgb(0xF5F1F6);   // YumeFog
    p.surface_container         = rgb(0xEDE3EF);   // YumeLilac
    p.surface_container_high    = rgb(0xE6E0EB);   // YumeCloud
    p.surface_container_highest = rgb(0xDED5DF);
    p.on_surface                = rgb(0x201A21);   // YumeInk
    p.on_surface_variant        = rgb(0x6D6570);   // YumeSlate
    p.outline                   = rgb(0x9A8E97);
    p.outline_variant           = rgb(0xD9CFDA);
    p.error                     = rgb(0xB72E5C);
    p.on_error                  = rgb(0xFFFFFF);
    p.success                   = rgb(0x2E7D32);
    p.warning                   = rgb(0xB26A00);
    return p;
}

Palette const& current_palette() { return g_palette; }

ImVec4 color_for(const char* token) {
    if (!token) return g_palette.on_surface;
    if (std::strcmp(token, "primary") == 0) return g_palette.primary;
    if (std::strcmp(token, "error") == 0) return g_palette.error;
    if (std::strcmp(token, "success") == 0) return g_palette.success;
    if (std::strcmp(token, "warning") == 0) return g_palette.warning;
    if (std::strcmp(token, "surface") == 0) return g_palette.surface;
    return g_palette.on_surface;
}

void apply_material3(Mode m) {
    g_palette = (m == Mode::Dark) ? material3_dark() : material3_light();
    Palette const& p = g_palette;

    ImGuiStyle& s = ImGui::GetStyle();

    // Shape tokens (M3 small/medium/large radii).
    s.WindowRounding        = 16.0f;
    s.ChildRounding         = 12.0f;
    s.FrameRounding         = 10.0f;
    s.PopupRounding         = 12.0f;
    s.GrabRounding          = 10.0f;
    s.ScrollbarRounding     = 8.0f;
    s.TabRounding           = 10.0f;

    s.WindowPadding         = ImVec2(20.0f, 20.0f);
    s.FramePadding          = ImVec2(12.0f, 8.0f);
    s.ItemSpacing           = ImVec2(12.0f, 8.0f);
    s.ItemInnerSpacing      = ImVec2(8.0f,  6.0f);
    s.IndentSpacing         = 18.0f;
    s.ScrollbarSize         = 14.0f;
    s.GrabMinSize           = 14.0f;
    s.SeparatorTextBorderSize = 1.0f;
    s.SeparatorTextPadding  = ImVec2(20.0f, 4.0f);
    s.WindowBorderSize      = 0.0f;
    s.ChildBorderSize       = 1.0f;
    s.FrameBorderSize       = 0.0f;
    s.PopupBorderSize       = 1.0f;
    s.TabBorderSize         = 0.0f;

    ImVec4* c = s.Colors;
    c[ImGuiCol_Text]                  = p.on_surface;
    c[ImGuiCol_TextDisabled]          = ImVec4(p.on_surface_variant.x,
                                              p.on_surface_variant.y,
                                              p.on_surface_variant.z, 0.6f);
    c[ImGuiCol_WindowBg]              = p.surface;
    c[ImGuiCol_ChildBg]               = p.surface_container_low;
    c[ImGuiCol_PopupBg]               = p.surface_container_high;
    c[ImGuiCol_Border]                = p.outline_variant;
    c[ImGuiCol_BorderShadow]          = ImVec4(0.0f, 0.0f, 0.0f, 0.0f);
    c[ImGuiCol_FrameBg]               = p.surface_container_high;
    c[ImGuiCol_FrameBgHovered]        = p.surface_container_highest;
    c[ImGuiCol_FrameBgActive]         = p.surface_bright;
    c[ImGuiCol_TitleBg]               = p.surface_container_low;
    c[ImGuiCol_TitleBgActive]         = p.surface_container;
    c[ImGuiCol_TitleBgCollapsed]      = p.surface_container_lowest;
    c[ImGuiCol_MenuBarBg]             = p.surface_container_low;
    c[ImGuiCol_ScrollbarBg]           = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_ScrollbarGrab]         = p.outline_variant;
    c[ImGuiCol_ScrollbarGrabHovered]  = p.outline;
    c[ImGuiCol_ScrollbarGrabActive]   = p.primary;
    c[ImGuiCol_CheckMark]             = p.primary;
    c[ImGuiCol_SliderGrab]            = p.primary;
    c[ImGuiCol_SliderGrabActive]      = p.primary_container;
    // Default ImGui::Button uses neutral surface tones so any raw button
    // (e.g. "Clear" in Logs, "Send" in Chat) keeps its label readable
    // with the global on_surface text colour in BOTH dark and light
    // themes. Premium accented buttons go through ui::primary_button,
    // which pushes its own ImGuiCol_Button + ImGuiCol_Text stack and
    // doesn't depend on these defaults.
    c[ImGuiCol_Button]                = p.surface_container_high;
    c[ImGuiCol_ButtonHovered]         = p.surface_container_highest;
    c[ImGuiCol_ButtonActive]          = p.primary_container;
    c[ImGuiCol_Header]                = p.surface_container_high;
    c[ImGuiCol_HeaderHovered]         = p.surface_container_highest;
    c[ImGuiCol_HeaderActive]          = p.primary_container;
    c[ImGuiCol_Separator]             = p.outline_variant;
    c[ImGuiCol_SeparatorHovered]      = p.outline;
    c[ImGuiCol_SeparatorActive]       = p.primary;
    // Resize grip + zebra rows: derive alpha overlays from on_surface so
    // they actually show up on a light background. Hardcoded white worked
    // on dark mode only.
    c[ImGuiCol_ResizeGrip]            = ImVec4(p.on_surface.x, p.on_surface.y,
                                               p.on_surface.z, 0.08f);
    c[ImGuiCol_ResizeGripHovered]     = ImVec4(p.on_surface.x, p.on_surface.y,
                                               p.on_surface.z, 0.18f);
    c[ImGuiCol_ResizeGripActive]      = p.primary;
    c[ImGuiCol_Tab]                   = p.surface_container;
    c[ImGuiCol_TabHovered]            = p.surface_container_high;
    c[ImGuiCol_TabActive]             = p.primary_container;
    c[ImGuiCol_TabUnfocused]          = p.surface_container_low;
    c[ImGuiCol_TabUnfocusedActive]    = p.surface_container;
    c[ImGuiCol_PlotLines]             = p.primary;
    c[ImGuiCol_PlotLinesHovered]      = p.primary_container;
    c[ImGuiCol_PlotHistogram]         = p.tertiary;
    c[ImGuiCol_PlotHistogramHovered]  = p.secondary;
    c[ImGuiCol_TableHeaderBg]         = p.surface_container_high;
    c[ImGuiCol_TableBorderStrong]     = p.outline_variant;
    c[ImGuiCol_TableBorderLight]      = p.outline_variant;
    c[ImGuiCol_TableRowBg]            = ImVec4(0, 0, 0, 0);
    // Zebra-stripe tint derived from on_surface so it's a subtle dark
    // overlay on light tables and a subtle light overlay on dark ones.
    c[ImGuiCol_TableRowBgAlt]         = ImVec4(p.on_surface.x, p.on_surface.y,
                                               p.on_surface.z, 0.04f);
    c[ImGuiCol_TextSelectedBg]        = ImVec4(p.primary.x, p.primary.y, p.primary.z, 0.35f);
    c[ImGuiCol_DragDropTarget]        = p.tertiary;
    c[ImGuiCol_NavHighlight]          = p.primary;
    c[ImGuiCol_NavWindowingHighlight] = p.primary;
    c[ImGuiCol_NavWindowingDimBg]     = rgba(0x000000, 0.5f);
    c[ImGuiCol_ModalWindowDimBg]      = rgba(0x000000, 0.5f);
}

}  // namespace yume::gui::theme
