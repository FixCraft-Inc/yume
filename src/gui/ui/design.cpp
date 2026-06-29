/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "ui/design.hpp"
#include "ui/embedded_fonts.hpp"
#include "theme/theme.hpp"

#include <algorithm>
#include <cfloat>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <initializer_list>
#include <optional>
#include <string>

#if YUME_GUI_FONTCONFIG
#include <fontconfig/fontconfig.h>
#endif

#if YUME_GUI_FREETYPE
#include <misc/freetype/imgui_freetype.h>
#endif

namespace yume::gui::ui {

namespace {

Fonts g_fonts;
Colors g_colors;
float g_scale = 1.0f;

constexpr ImVec4 rgb(int hex) {
    return ImVec4(((hex >> 16) & 0xFF) / 255.0f,
                  ((hex >> 8) & 0xFF) / 255.0f,
                  (hex & 0xFF) / 255.0f,
                  1.0f);
}

ImVec4 alpha(ImVec4 c, float a) {
    c.w = a;
    return c;
}

float px(float v) {
    return v * g_scale;
}

// Jost has a noticeably smaller x-height than URW Gothic / Segoe UI, so
// it reads as visually smaller at the same pixel size. Bump every Jost
// dimension by this factor so the layout depth and balance stays the
// same regardless of which path we take. Tuned to roughly match URW
// Gothic's optical size.
constexpr float kJostSizeBoost   = 1.12f;
// Slightly heavier strokes on Jost so the bundled font reads with the
// same visual weight as a hinted system font. Pure aesthetic knob —
// FreeType applies it during atlas baking.
constexpr float kJostRasterBoost = 1.18f;

#if YUME_GUI_FONTCONFIG
std::optional<std::string> fontconfig_match(std::string const& family) {
    if (!FcInit()) return std::nullopt;
    FcPattern* pattern = FcNameParse(reinterpret_cast<FcChar8 const*>(family.c_str()));
    if (!pattern) return std::nullopt;
    FcConfigSubstitute(nullptr, pattern, FcMatchPattern);
    FcDefaultSubstitute(pattern);

    FcResult result = FcResultNoMatch;
    FcPattern* match = FcFontMatch(nullptr, pattern, &result);
    FcPatternDestroy(pattern);
    if (!match) return std::nullopt;

    FcChar8* file = nullptr;
    std::optional<std::string> path;
    if (FcPatternGetString(match, FC_FILE, 0, &file) == FcResultMatch && file) {
        path = reinterpret_cast<char const*>(file);
    }
    FcPatternDestroy(match);
    return path;
}
#endif

std::optional<std::string> existing_path(std::initializer_list<char const*> paths) {
    for (char const* p : paths) {
        if (p && std::filesystem::exists(p)) return std::string(p);
    }
    return std::nullopt;
}

std::optional<std::string> find_ui_font() {
#if YUME_GUI_FONTCONFIG
    for (char const* family : {
             "URW Gothic:style=Book",
             "URW Gothic",
             "Inter",
             "Noto Sans",
             "Roboto",
             "DejaVu Sans"}) {
        if (auto p = fontconfig_match(family)) return p;
    }
#endif
    return existing_path({
        "/usr/share/fonts/opentype/urw-base35/URWGothic-Book.otf",
        "/usr/share/fonts/opentype/inter/Inter-Regular.otf",
        "/usr/share/fonts/truetype/noto/NotoSans-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    });
}

std::optional<std::string> find_strong_font() {
#if YUME_GUI_FONTCONFIG
    for (char const* family : {
             "URW Gothic:style=Demi",
             "Inter:style=Medium",
             "Noto Sans:style=SemiBold",
             "Roboto:style=Medium",
             "DejaVu Sans:style=Bold"}) {
        if (auto p = fontconfig_match(family)) return p;
    }
#endif
    return existing_path({
        "/usr/share/fonts/opentype/urw-base35/URWGothic-Demi.otf",
        "/usr/share/fonts/opentype/inter/Inter-Medium.otf",
        "/usr/share/fonts/truetype/noto/NotoSans-SemiBold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    });
}

std::optional<std::string> find_mono_font() {
#if YUME_GUI_FONTCONFIG
    for (char const* family : {"JetBrains Mono", "Noto Sans Mono", "Roboto Mono", "DejaVu Sans Mono"}) {
        if (auto p = fontconfig_match(family)) return p;
    }
#endif
    return existing_path({
        "/usr/share/fonts/truetype/noto/NotoSansMono-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
    });
}

ImFont* add_embedded_jost(float size,
                          float rasterizer_multiply,
                          bool synthetic_bold,
                          bool synthetic_oblique = false) {
    ImGuiIO& io = ImGui::GetIO();
    ImFontConfig cfg;
    cfg.OversampleH = 4;
    cfg.OversampleV = 2;
    cfg.PixelSnapH = false;
    cfg.RasterizerMultiply = rasterizer_multiply;
    cfg.RasterizerDensity = 1.0f;
    // AddFontFromMemoryTTF defaults to taking ownership and free()ing
    // the buffer on atlas destroy. Our buffer lives in .rodata, so
    // explicitly opt out — otherwise ImGui calls free() on a static
    // address and the process aborts at shutdown.
    cfg.FontDataOwnedByAtlas = false;
#if YUME_GUI_FREETYPE
    // Jost's built-in TrueType hinting is weaker than a foundry font
    // like URW Gothic, so LightHinting tends to pixel-snap stems and
    // gives the font a "rigid / pixely" look. NoHinting lets FreeType
    // produce continuous subpixel positioning, which reads cleaner at
    // our 15-30 px sizes — closer to URW Gothic's smooth vector look.
    cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_NoHinting;
    if (synthetic_bold)    cfg.FontBuilderFlags |= ImGuiFreeTypeBuilderFlags_Bold;
    if (synthetic_oblique) cfg.FontBuilderFlags |= ImGuiFreeTypeBuilderFlags_Oblique;
#else
    (void)synthetic_bold;
    (void)synthetic_oblique;
#endif
    std::snprintf(cfg.Name, sizeof(cfg.Name), "Jost-Regular %.0f", size);
    return io.Fonts->AddFontFromMemoryTTF(
        const_cast<unsigned char*>(jost_regular_ttf),
        static_cast<int>(jost_regular_ttf_len), size, &cfg);
}

// Try the supplied system font path first. If it loads we honour the
// caller's original size — system fonts (URW Gothic / Segoe UI) are
// what the layout was tuned against. If the load fails or no path was
// found, fall back to the embedded Jost at size * kJostSizeBoost so
// the optical size matches.
//
// synthetic_bold is intentionally NOT applied on the system path: the
// caller selects the heavy weight via find_strong_font (URWGothic-Demi,
// seguisb.ttf, etc.), so layering FreeType synthetic bold on top would
// double-up the strokes and make the font read as "pixely / rigid".
// synthetic_oblique still applies on the system path because we don't
// have a find_italic_font helper — body_italic slants the Book weight
// instead of loading a dedicated *Oblique file.
ImFont* add_system_or_jost(std::optional<std::string> const& path,
                           float size,
                           float rasterizer_multiply,
                           bool synthetic_bold,
                           bool synthetic_oblique = false) {
    ImGuiIO& io = ImGui::GetIO();
    if (path && std::filesystem::exists(*path)) {
        ImFontConfig cfg;
        cfg.OversampleH = 4;
        cfg.OversampleV = 2;
        cfg.PixelSnapH = false;
        cfg.RasterizerMultiply = rasterizer_multiply;
        cfg.RasterizerDensity = 1.0f;
#if YUME_GUI_FREETYPE
        cfg.FontBuilderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;
        if (synthetic_oblique) cfg.FontBuilderFlags |= ImGuiFreeTypeBuilderFlags_Oblique;
#else
        (void)synthetic_oblique;
#endif
        std::snprintf(cfg.Name, sizeof(cfg.Name), "%s %.0f", path->c_str(), size);
        if (ImFont* font = io.Fonts->AddFontFromFileTTF(path->c_str(), size, &cfg)) {
            return font;
        }
    }
    return add_embedded_jost(size * kJostSizeBoost,
                             rasterizer_multiply * kJostRasterBoost,
                             synthetic_bold,
                             synthetic_oblique);
}

ImU32 color_u32(ImVec4 c) {
    return ImGui::ColorConvertFloat4ToU32(c);
}

}  // namespace

void install_fonts(float content_scale) {
    g_scale = std::clamp(content_scale, 1.0f, 2.0f);
    ImGuiIO& io = ImGui::GetIO();
    io.Fonts->Clear();
#if YUME_GUI_FREETYPE
    io.Fonts->FontBuilderIO = ImGuiFreeType::GetBuilderForFreeType();
    io.Fonts->FontBuilderFlags = ImGuiFreeTypeBuilderFlags_LightHinting;
#endif

    // Prefer the user's system font (URW Gothic via fontconfig on Linux,
    // Segoe UI etc. on Windows). The layout was tuned against URW Gothic
    // metrics, so we pass the original sizes when a system font is found.
    // add_system_or_jost falls back to the embedded Jost with a single
    // size+raster multiplier (kJost*Boost) so the visual size and weight
    // match what URW Gothic gave us — no need to edit every size below
    // when adjusting the Jost path.
    const auto ui_font = find_ui_font();
    const auto strong_font = find_strong_font();
    const auto mono_font = find_mono_font();

    g_fonts.small       = add_system_or_jost(ui_font, px(15.5f), 1.12f, false);
    g_fonts.body        = add_system_or_jost(ui_font, px(18.5f), 1.10f, false);
    g_fonts.body_italic = add_system_or_jost(ui_font, px(18.5f), 1.10f, false, true);
    g_fonts.strong      = add_system_or_jost(strong_font ? strong_font : ui_font, px(18.5f), 1.04f, true);
    g_fonts.section     = add_system_or_jost(strong_font ? strong_font : ui_font, px(20.5f), 1.04f, true);
    g_fonts.title       = add_system_or_jost(strong_font ? strong_font : ui_font, px(30.0f), 1.02f, true);
    g_fonts.mono        = add_system_or_jost(mono_font ? mono_font : ui_font, px(15.5f), 1.08f, false);

    io.FontDefault = g_fonts.body ? g_fonts.body : io.Fonts->Fonts[0];
}

void apply_style(float content_scale, bool dark_mode) {
    g_scale = std::clamp(content_scale, 1.0f, 2.0f);
    theme::apply_material3(dark_mode ? theme::Mode::Dark : theme::Mode::Light);
    theme::Palette const& p = theme::current_palette();

    g_colors.background   = p.surface;
    g_colors.surface      = p.surface_container;
    g_colors.surface_high = p.surface_container_high;
    g_colors.outline      = p.outline_variant;
    g_colors.text         = p.on_surface;
    g_colors.muted        = p.on_surface_variant;
    g_colors.accent       = p.primary;
    g_colors.accent_hover = dark_mode ? ImVec4(p.primary.x + 0.04f, p.primary.y + 0.04f,
                                               p.primary.z + 0.04f, 1.0f)
                                      : p.primary_container;
    g_colors.on_accent    = p.on_primary;
    g_colors.success      = p.success;
    g_colors.warning      = p.warning;
    g_colors.error        = p.error;

    ImGuiStyle& s = ImGui::GetStyle();
    s.WindowPadding = ImVec2(px(26), px(24));
    s.FramePadding = ImVec2(px(16), px(12));
    s.CellPadding = ImVec2(px(14), px(11));
    s.ItemSpacing = ImVec2(px(13), px(13));
    s.ItemInnerSpacing = ImVec2(px(10), px(8));
    s.IndentSpacing = px(18);
    s.ScrollbarSize = px(12);
    s.GrabMinSize = px(14);
    s.WindowRounding = px(0);
    s.ChildRounding = px(12);
    s.FrameRounding = px(10);
    s.PopupRounding = px(12);
    s.GrabRounding = px(10);
    s.ScrollbarRounding = px(8);
    s.TabRounding = px(8);
    s.WindowBorderSize = 0.0f;
    s.ChildBorderSize = 1.0f;
    s.FrameBorderSize = 0.0f;
    s.PopupBorderSize = 1.0f;

    s.Colors[ImGuiCol_ModalWindowDimBg] = alpha(rgb(0x000000), 0.55f);
}

Fonts const& fonts() { return g_fonts; }
Colors const& colors() { return g_colors; }
float scale() { return g_scale; }

void page_header(char const* title, char const* subtitle) {
    if (g_fonts.title) ImGui::PushFont(g_fonts.title);
    ImGui::TextUnformatted(title);
    if (g_fonts.title) ImGui::PopFont();
    if (subtitle && *subtitle) {
        if (g_fonts.body) ImGui::PushFont(g_fonts.body);
        ImGui::PushStyleColor(ImGuiCol_Text, g_colors.muted);
        ImGui::TextWrapped("%s", subtitle);
        ImGui::PopStyleColor();
        if (g_fonts.body) ImGui::PopFont();
    }
    ImGui::Dummy(ImVec2(0, px(10)));
}

void section_label(char const* label) {
    if (g_fonts.section) ImGui::PushFont(g_fonts.section);
    ImGui::TextUnformatted(label);
    if (g_fonts.section) ImGui::PopFont();
}

void field_label(char const* label) {
    // Material 3 outlined-text-field labels are smaller than body text and
    // sit tight above the input. Using the strong (body-sized) font here
    // made the label look like its own paragraph and pushed the input
    // visually below — the gap read as "label is a bit up".
    if (g_fonts.small) ImGui::PushFont(g_fonts.small);
    ImGui::PushStyleColor(ImGuiCol_Text, g_colors.muted);
    // No-wrap label: TextWrapped silently breaks short labels at narrow
    // table cells and shifts everything below it by a line.
    ImGui::TextUnformatted(label);
    ImGui::PopStyleColor();
    if (g_fonts.small) ImGui::PopFont();
    // Subtle negative spacing so the label and input live as one widget.
    // Keep it small so a row of side-by-side fields stays vertically
    // aligned even when their labels differ in length.
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() - px(4));
}

void muted_text(char const* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (g_fonts.body) ImGui::PushFont(g_fonts.body);
    ImGui::PushStyleColor(ImGuiCol_Text, g_colors.muted);
    ImGui::TextWrapped("%s", buf);
    ImGui::PopStyleColor();
    if (g_fonts.body) ImGui::PopFont();
}

void message_text(ImVec4 color, char const* fmt, ...) {
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (g_fonts.strong) ImGui::PushFont(g_fonts.strong);
    ImGui::PushStyleColor(ImGuiCol_Text, color);
    ImGui::TextWrapped("%s", buf);
    ImGui::PopStyleColor();
    if (g_fonts.strong) ImGui::PopFont();
}

float form_width(float max_width) {
    const float avail = std::max(80.0f, ImGui::GetContentRegionAvail().x - px(2));
    if (max_width <= 0.0f) return avail;
    return std::min(avail, px(max_width));
}

bool nav_item(char const* id, char const* label, bool selected, ImVec2 size) {
    ImGui::PushID(id);
    ImVec2 actual = size;
    if (actual.x <= 0.0f) {
        actual.x = std::max(px(44), ImGui::GetContentRegionAvail().x + actual.x);
    }
    if (actual.y <= 0.0f) actual.y = px(48);
    ImVec2 pos = ImGui::GetCursorScreenPos();
    bool pressed = ImGui::InvisibleButton("##nav", actual);
    const bool hovered = ImGui::IsItemHovered();
    ImDrawList* draw = ImGui::GetWindowDrawList();
    const float radius = px(10);
    ImVec4 fill = selected ? alpha(g_colors.accent, 0.18f)
                           : (hovered ? alpha(g_colors.surface_high, 0.9f)
                                      : alpha(g_colors.surface_high, 0.0f));
    draw->AddRectFilled(pos, ImVec2(pos.x + actual.x, pos.y + actual.y),
                        color_u32(fill), radius);
    if (selected) {
        draw->AddRectFilled(ImVec2(pos.x, pos.y + px(9)),
                            ImVec2(pos.x + px(4), pos.y + actual.y - px(9)),
                            color_u32(g_colors.accent), px(3));
    }
    ImFont* font = g_fonts.strong ? g_fonts.strong : ImGui::GetFont();
    const float font_size = font ? font->FontSize : ImGui::GetFontSize();
    ImVec2 text_size = font ? font->CalcTextSizeA(font_size, FLT_MAX, 0.0f, label)
                            : ImGui::CalcTextSize(label);
    draw->AddText(font, font_size,
                  ImVec2(pos.x + px(22), pos.y + (actual.y - text_size.y) * 0.5f),
                  color_u32(selected ? g_colors.text : g_colors.muted),
                  label);
    ImGui::PopID();
    return pressed;
}

float button_width(char const* label, float min_width) {
    ImFont* font = g_fonts.strong ? g_fonts.strong : ImGui::GetFont();
    const float font_size = font ? font->FontSize : ImGui::GetFontSize();
    ImVec2 text_size = font ? font->CalcTextSizeA(font_size, FLT_MAX, 0.0f, label)
                            : ImGui::CalcTextSize(label);
    return std::max(px(min_width), text_size.x + px(44));
}

bool primary_button(char const* label, ImVec2 size) {
    ImGui::PushStyleColor(ImGuiCol_Button, g_colors.accent);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, g_colors.accent_hover);
    // Slightly darker pressed state, derived from the accent so it works
    // in both light and dark palettes instead of hardcoding orange.
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,
                          ImVec4(g_colors.accent.x * 0.85f,
                                 g_colors.accent.y * 0.85f,
                                 g_colors.accent.z * 0.85f, 1.0f));
    // Force dark text on the pink accent button — Android's primary
    // button uses on_primary for the same reason; white-on-pink blends.
    ImGui::PushStyleColor(ImGuiCol_Text, g_colors.on_accent);
    if (g_fonts.strong) ImGui::PushFont(g_fonts.strong);
    bool pressed = ImGui::Button(label, size);
    if (g_fonts.strong) ImGui::PopFont();
    ImGui::PopStyleColor(4);
    return pressed;
}

bool secondary_button(char const* label, ImVec2 size) {
    ImGui::PushStyleColor(ImGuiCol_Button, g_colors.surface_high);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, alpha(g_colors.accent, 0.18f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, alpha(g_colors.accent, 0.28f));
    if (g_fonts.strong) ImGui::PushFont(g_fonts.strong);
    bool pressed = ImGui::Button(label, size);
    if (g_fonts.strong) ImGui::PopFont();
    ImGui::PopStyleColor(3);
    return pressed;
}

bool danger_button(char const* label, ImVec2 size) {
    const ImVec4 base = g_colors.error;
    ImGui::PushStyleColor(ImGuiCol_Button, alpha(base, 0.00f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, alpha(base, 0.16f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, alpha(base, 0.28f));
    ImGui::PushStyleColor(ImGuiCol_Border, base);
    ImGui::PushStyleColor(ImGuiCol_Text, base);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.4f);
    if (g_fonts.strong) ImGui::PushFont(g_fonts.strong);
    bool pressed = ImGui::Button(label, size);
    if (g_fonts.strong) ImGui::PopFont();
    ImGui::PopStyleVar();
    ImGui::PopStyleColor(5);
    return pressed;
}

bool quiet_button(char const* label, ImVec2 size) {
    ImGui::PushStyleColor(ImGuiCol_Button, alpha(g_colors.surface_high, 0.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, alpha(g_colors.surface_high, 0.9f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, alpha(g_colors.accent, 0.2f));
    if (g_fonts.strong) ImGui::PushFont(g_fonts.strong);
    bool pressed = ImGui::Button(label, size);
    if (g_fonts.strong) ImGui::PopFont();
    ImGui::PopStyleColor(3);
    return pressed;
}

bool disclosure_header(char const* label, bool open) {
    ImGui::PushID(label);
    const float h = px(46);
    const float w = std::max(px(180), ImGui::GetContentRegionAvail().x);
    ImVec2 pos = ImGui::GetCursorScreenPos();
    bool pressed = ImGui::InvisibleButton("##disclosure", ImVec2(w, h));
    if (pressed) open = !open;

    const bool hovered = ImGui::IsItemHovered();
    ImDrawList* draw = ImGui::GetWindowDrawList();
    ImVec4 fill = hovered ? alpha(g_colors.surface_high, 0.92f)
                          : alpha(g_colors.surface_high, 0.58f);
    draw->AddRectFilled(pos, ImVec2(pos.x + w, pos.y + h), color_u32(fill), px(12));
    draw->AddRect(pos, ImVec2(pos.x + w, pos.y + h),
                  color_u32(alpha(g_colors.outline, hovered ? 0.95f : 0.55f)), px(12));

    const float cx = pos.x + px(19);
    const float cy = pos.y + h * 0.5f;
    const float r = px(5.5f);
    const ImU32 chevron = color_u32(g_colors.muted);
    if (open) {
        draw->AddLine(ImVec2(cx - r, cy - r * 0.35f), ImVec2(cx, cy + r * 0.45f), chevron, px(2.0f));
        draw->AddLine(ImVec2(cx, cy + r * 0.45f), ImVec2(cx + r, cy - r * 0.35f), chevron, px(2.0f));
    } else {
        draw->AddLine(ImVec2(cx - r * 0.35f, cy - r), ImVec2(cx + r * 0.45f, cy), chevron, px(2.0f));
        draw->AddLine(ImVec2(cx + r * 0.45f, cy), ImVec2(cx - r * 0.35f, cy + r), chevron, px(2.0f));
    }

    ImFont* font = g_fonts.strong ? g_fonts.strong : ImGui::GetFont();
    const float font_size = font ? font->FontSize : ImGui::GetFontSize();
    ImVec2 text_size = font ? font->CalcTextSizeA(font_size, FLT_MAX, 0.0f, label)
                            : ImGui::CalcTextSize(label);
    draw->AddText(font, font_size,
                  ImVec2(pos.x + px(40), pos.y + (h - text_size.y) * 0.5f),
                  color_u32(g_colors.text), label);
    ImGui::PopID();
    return open;
}

bool begin_card(char const* id, ImVec2 size) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, g_colors.surface);
    ImGui::PushStyleColor(ImGuiCol_Border, g_colors.outline);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, px(14));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(px(24), px(24)));
    return ImGui::BeginChild(id, size,
                             ImGuiChildFlags_Border |
                             ImGuiChildFlags_AlwaysUseWindowPadding);
}

bool begin_auto_card(char const* id, float width) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, g_colors.surface);
    ImGui::PushStyleColor(ImGuiCol_Border, g_colors.outline);
    ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, px(14));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(px(24), px(24)));
    return ImGui::BeginChild(id,
                             ImVec2(width, 0),
                             ImGuiChildFlags_Border |
                                 ImGuiChildFlags_AlwaysUseWindowPadding |
                                 ImGuiChildFlags_AutoResizeY,
                             ImGuiWindowFlags_NoScrollbar |
                                 ImGuiWindowFlags_NoScrollWithMouse);
}

void end_card() {
    ImGui::EndChild();
    ImGui::PopStyleVar(2);
    ImGui::PopStyleColor(2);
}

bool checkbox(char const* label, bool* value) {
    if (!value) return false;
    ImGui::PushID(label);

    ImFont* font = g_fonts.body ? g_fonts.body : ImGui::GetFont();
    const float font_size = font ? font->FontSize : ImGui::GetFontSize();
    ImVec2 text_size = font
        ? font->CalcTextSizeA(font_size, FLT_MAX, 0.0f, label)
        : ImGui::CalcTextSize(label);

    // Slightly larger box with deeper rounding so it reads as a modern
    // "rounded square" rather than a sharp Win9x checkbox. The radius is
    // ~40% of the box edge — between a square and a pill.
    const float box = px(22);
    const float r   = px(9);
    const float gap = px(12);
    // Use the font's metric line height (not the bounding box) so the
    // checkbox row sits on the same baseline as adjacent text inside a
    // SameLine() group. text_size.y is already the line height for one
    // line of body font.
    const float row_h = std::max(box, font_size) + px(4);
    const float row_w = box + gap + text_size.x + px(2);

    ImVec2 pos = ImGui::GetCursorScreenPos();
    bool pressed = ImGui::InvisibleButton("##cb", ImVec2(row_w, row_h));
    if (pressed) *value = !*value;
    const bool hovered = ImGui::IsItemHovered();
    const bool held = ImGui::IsItemActive();

    ImDrawList* dl = ImGui::GetWindowDrawList();
    const float by = pos.y + (row_h - box) * 0.5f;
    const ImVec2 box_a(pos.x, by);
    const ImVec2 box_b(pos.x + box, by + box);

    // Press state derives from the accent so it stays consistent across
    // both themes (previously hardcoded orange).
    const ImVec4 accent_pressed(g_colors.accent.x * 0.85f,
                                g_colors.accent.y * 0.85f,
                                g_colors.accent.z * 0.85f, 1.0f);
    const ImVec4 accent = held ? accent_pressed
                               : (hovered ? g_colors.accent_hover
                                          : g_colors.accent);
    if (*value) {
        dl->AddRectFilled(box_a, box_b, color_u32(accent), r);
        // Two-segment checkmark with a thicker stroke; coordinates moved
        // slightly so the visual centre of the tick sits in the middle of
        // the box (the previous coords skewed it bottom-left).
        const float w = box;
        const float t = std::max(1.8f, px(2.4f));
        const ImU32 check = color_u32(g_colors.on_accent);
        const ImVec2 p0(box_a.x + w * 0.24f, box_a.y + w * 0.52f);
        const ImVec2 p1(box_a.x + w * 0.44f, box_a.y + w * 0.72f);
        const ImVec2 p2(box_a.x + w * 0.78f, box_a.y + w * 0.30f);
        dl->AddLine(p0, p1, check, t);
        dl->AddLine(p1, p2, check, t);
    } else {
        // Subtle accent halo on hover so the checkbox visibly responds
        // before the click.
        if (hovered) {
            dl->AddRectFilled(box_a, box_b,
                              color_u32(alpha(g_colors.accent, 0.12f)), r);
        }
        const ImVec4 stroke = hovered ? g_colors.accent : g_colors.outline;
        dl->AddRect(box_a, box_b, color_u32(stroke), r, 0,
                    std::max(1.2f, px(1.8f)));
    }

    // Centre the label on the box's vertical midpoint. Using font_size as
    // the height yields a tighter baseline match than using text_size.y
    // (which includes leading from CalcTextSizeA).
    dl->AddText(font, font_size,
                ImVec2(box_b.x + gap,
                       box_a.y + (box - font_size) * 0.5f),
                color_u32(g_colors.text), label);

    ImGui::PopID();
    return pressed;
}

int segmented_control(char const* id,
                      char const* const* labels,
                      int count,
                      int current,
                      float total_width) {
    if (count <= 0 || !labels) return current;
    ImGui::PushID(id);

    ImFont* font = g_fonts.strong ? g_fonts.strong : ImGui::GetFont();
    const float font_size = font ? font->FontSize : ImGui::GetFontSize();
    const float seg_h = px(40);
    const float h_pad = px(20);

    // Per-segment minimum that adapts to the actual label.
    //   - explicit total_width: divide it, no minimum padding inflation
    //   - implicit (tabs):      96px floor so big buttons read as tabs
    // Without the explicit branch, a "15s/60s/5m/15m" picker would each
    // claim 96px and overflow narrow card headers.
    float seg_w;
    if (total_width > 0.0f) {
        seg_w = total_width / static_cast<float>(count);
    } else {
        float min_seg_w = px(96);
        for (int i = 0; i < count; ++i) {
            ImVec2 ts = font
                ? font->CalcTextSizeA(font_size, FLT_MAX, 0.0f, labels[i])
                : ImGui::CalcTextSize(labels[i]);
            min_seg_w = std::max(min_seg_w, ts.x + h_pad * 2.0f);
        }
        const float avail = std::max(min_seg_w * count,
                                     ImGui::GetContentRegionAvail().x);
        seg_w = avail / static_cast<float>(count);
    }

    ImVec2 origin = ImGui::GetCursorScreenPos();
    ImVec2 size(seg_w * count, seg_h);
    ImGui::InvisibleButton("##container", size);
    bool container_hovered = ImGui::IsItemHovered();
    (void)container_hovered;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    const float radius = seg_h * 0.5f;
    // Container background + outline.
    dl->AddRectFilled(origin, ImVec2(origin.x + size.x, origin.y + size.y),
                      color_u32(g_colors.surface_high), radius);
    dl->AddRect(origin, ImVec2(origin.x + size.x, origin.y + size.y),
                color_u32(g_colors.outline), radius, 0, 1.0f);

    int new_current = current;
    for (int i = 0; i < count; ++i) {
        ImVec2 seg_a(origin.x + seg_w * i, origin.y);
        ImVec2 seg_b(seg_a.x + seg_w, origin.y + seg_h);

        // Hit-test inside the container's already-consumed area.
        ImVec2 mouse = ImGui::GetMousePos();
        const bool in_seg = mouse.x >= seg_a.x && mouse.x < seg_b.x &&
                            mouse.y >= seg_a.y && mouse.y < seg_b.y;
        const bool active = (i == current);
        const bool hovered = container_hovered && in_seg;
        if (hovered && ImGui::IsMouseClicked(ImGuiMouseButton_Left)) {
            new_current = i;
        }

        if (active) {
            // Active pill: rounded fill, slightly inset.
            const float inset = px(3);
            ImVec2 pa(seg_a.x + inset, seg_a.y + inset);
            ImVec2 pb(seg_b.x - inset, seg_b.y - inset);
            const float pill_r = (pb.y - pa.y) * 0.5f;
            dl->AddRectFilled(pa, pb,
                              color_u32(g_colors.accent), pill_r);
        } else if (hovered) {
            const float inset = px(3);
            ImVec2 pa(seg_a.x + inset, seg_a.y + inset);
            ImVec2 pb(seg_b.x - inset, seg_b.y - inset);
            const float pill_r = (pb.y - pa.y) * 0.5f;
            dl->AddRectFilled(pa, pb,
                              color_u32(alpha(g_colors.accent, 0.10f)),
                              pill_r);
        }

        ImVec2 ts = font
            ? font->CalcTextSizeA(font_size, FLT_MAX, 0.0f, labels[i])
            : ImGui::CalcTextSize(labels[i]);
        // Active segment is filled with the accent colour, so use the
        // matching on_accent (dark wine on pink, or white on plum) for
        // readability. Inactive segments live on surface_high so the
        // default text/muted colours apply.
        ImU32 text_color = color_u32(active ? g_colors.on_accent
                                            : (hovered ? g_colors.text
                                                       : g_colors.muted));
        dl->AddText(font, font_size,
                    ImVec2(seg_a.x + (seg_w - ts.x) * 0.5f,
                           seg_a.y + (seg_h - ts.y) * 0.5f),
                    text_color, labels[i]);
    }

    ImGui::PopID();
    return new_current;
}

bool combo(char const* id, int* current,
           char const* const* items, int count,
           float min_width) {
    if (count <= 0 || !current || !items) return false;
    if (*current < 0 || *current >= count) *current = 0;

    ImGui::PushID(id);

    ImFont* font = g_fonts.body ? g_fonts.body : ImGui::GetFont();
    const float font_size = font ? font->FontSize : ImGui::GetFontSize();

    // Width: max of caller minimum / widest label + chrome / available.
    float widest_label = 0.0f;
    for (int i = 0; i < count; ++i) {
        ImVec2 ts = font
            ? font->CalcTextSizeA(font_size, FLT_MAX, 0.0f, items[i])
            : ImGui::CalcTextSize(items[i]);
        if (ts.x > widest_label) widest_label = ts.x;
    }
    const float chrome = px(58);  // padding + chevron
    float w = std::max(px(min_width), widest_label + chrome);
    const float avail = ImGui::GetContentRegionAvail().x;
    if (avail > 0 && w > avail) w = avail;

    // Push a softer FrameBg specifically for the combo's preview button
    // (default theme already styles it, but we override Active so the open
    // state reads as accent-tinted rather than gray).
    ImGui::PushStyleColor(ImGuiCol_FrameBg, g_colors.surface_high);
    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, alpha(g_colors.accent, 0.16f));
    ImGui::PushStyleColor(ImGuiCol_FrameBgActive, alpha(g_colors.accent, 0.22f));
    ImGui::PushStyleColor(ImGuiCol_Border, g_colors.outline);
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_PopupBg, g_colors.surface_high);
    ImGui::PushStyleColor(ImGuiCol_Header, alpha(g_colors.accent, 0.18f));
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered, alpha(g_colors.accent, 0.22f));
    ImGui::PushStyleColor(ImGuiCol_HeaderActive, alpha(g_colors.accent, 0.32f));

    ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, px(12));
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(px(16), px(11)));
    ImGui::PushStyleVar(ImGuiStyleVar_PopupRounding, px(12));
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(px(8), px(4)));

    ImGui::SetNextItemWidth(w);
    bool changed = false;
    if (ImGui::BeginCombo("##combo", items[*current],
                          ImGuiComboFlags_HeightLargest)) {
        // We render each row ourselves rather than using Selectable so we
        // can give it a rounded hover/select background, vertically
        // centred text, and the same body font as the preview — the
        // default Selectable has square corners, top-aligned text, and
        // picks up whatever font is active (often the smaller default).
        ImFont* row_font = g_fonts.body ? g_fonts.body : ImGui::GetFont();
        const float row_font_size = row_font ? row_font->FontSize : ImGui::GetFontSize();
        const float row_h     = px(40);
        const float row_pad_x = px(14);
        const float row_radius = px(10);
        const float row_w     = std::max(w, ImGui::GetContentRegionAvail().x);

        for (int i = 0; i < count; ++i) {
            ImGui::PushID(i);
            const bool selected = (i == *current);
            const ImVec2 row_origin = ImGui::GetCursorScreenPos();
            const bool clicked = ImGui::InvisibleButton("##row",
                                                        ImVec2(row_w, row_h));
            const bool hovered = ImGui::IsItemHovered();
            if (selected) ImGui::SetItemDefaultFocus();

            ImDrawList* dl = ImGui::GetWindowDrawList();
            // Inset the highlight slightly inside the popup so the
            // rounded corners are visible — without the inset the row
            // butts up against the popup edge and looks square again.
            const float inset = px(4);
            const ImVec2 hl_a(row_origin.x + inset, row_origin.y + px(2));
            const ImVec2 hl_b(row_origin.x + row_w - inset,
                              row_origin.y + row_h - px(2));
            if (selected) {
                dl->AddRectFilled(hl_a, hl_b,
                                  color_u32(alpha(g_colors.accent,
                                                  hovered ? 0.32f : 0.22f)),
                                  row_radius);
            } else if (hovered) {
                dl->AddRectFilled(hl_a, hl_b,
                                  color_u32(alpha(g_colors.accent, 0.14f)),
                                  row_radius);
            }

            // Centre text vertically using font_size (not the bbox), and
            // left-pad by row_pad_x so it visually aligns with the combo
            // preview's text.
            ImVec2 ts = row_font
                ? row_font->CalcTextSizeA(row_font_size, FLT_MAX, 0.0f, items[i])
                : ImGui::CalcTextSize(items[i]);
            (void)ts;  // not used for layout; left for potential right-align
            dl->AddText(row_font, row_font_size,
                        ImVec2(row_origin.x + row_pad_x + inset,
                               row_origin.y + (row_h - row_font_size) * 0.5f),
                        color_u32(g_colors.text), items[i]);

            // Right-aligned accent dot marker for the selected row.
            if (selected) {
                const float cy = row_origin.y + row_h * 0.5f;
                const float cx = row_origin.x + row_w - inset - px(14);
                dl->AddCircleFilled(ImVec2(cx, cy), px(3.5f),
                                    color_u32(g_colors.accent));
            }

            if (clicked) {
                *current = i;
                changed = true;
                ImGui::CloseCurrentPopup();
            }
            ImGui::PopID();
        }
        ImGui::EndCombo();
    }

    ImGui::PopStyleVar(5);
    ImGui::PopStyleColor(11);

    ImGui::PopID();
    return changed;
}

bool begin_data_table(char const* id, int columns, ImGuiTableFlags extra_flags) {
    // Material 3 data tables: no harsh borders, generous row height, subtle
    // zebra striping, accent on hover. We override a handful of style vars
    // and colours just for the table scope; end_data_table() pops them.
    ImGui::PushStyleVar(ImGuiStyleVar_CellPadding, ImVec2(px(14), px(12)));
    ImGui::PushStyleColor(ImGuiCol_TableHeaderBg,
                          alpha(g_colors.surface_high, 0.55f));
    ImGui::PushStyleColor(ImGuiCol_TableBorderStrong,
                          alpha(g_colors.outline, 0.0f));
    ImGui::PushStyleColor(ImGuiCol_TableBorderLight,
                          alpha(g_colors.outline, 0.55f));
    ImGui::PushStyleColor(ImGuiCol_TableRowBg, alpha(rgb(0x000000), 0.0f));
    ImGui::PushStyleColor(ImGuiCol_TableRowBgAlt,
                          alpha(g_colors.surface_high, 0.38f));

    const ImGuiTableFlags base =
        ImGuiTableFlags_RowBg |
        ImGuiTableFlags_BordersInnerH |
        ImGuiTableFlags_NoBordersInBodyUntilResize |
        ImGuiTableFlags_SizingStretchProp;
    const bool ok = ImGui::BeginTable(id, columns, base | extra_flags);
    if (!ok) {
        ImGui::PopStyleColor(5);
        ImGui::PopStyleVar();
    }
    return ok;
}

void data_table_header_row() {
    if (g_fonts.strong) ImGui::PushFont(g_fonts.strong);
    ImGui::PushStyleColor(ImGuiCol_Text, g_colors.muted);
    ImGui::TableHeadersRow();
    ImGui::PopStyleColor();
    if (g_fonts.strong) ImGui::PopFont();
}

void data_table_headers(std::initializer_list<char const*> headers) {
    for (auto const* h : headers) {
        ImGui::TableSetupColumn(h ? h : "");
    }
    data_table_header_row();
}

void end_data_table() {
    ImGui::EndTable();
    ImGui::PopStyleColor(5);
    ImGui::PopStyleVar();
}

ImVec2 status_pill(char const* text, ImVec4 color) {
    ImFont* font = g_fonts.strong ? g_fonts.strong : ImGui::GetFont();
    const float font_size = font ? font->FontSize : ImGui::GetFontSize();
    ImVec2 text_size = font ? font->CalcTextSizeA(font_size, FLT_MAX, 0.0f, text)
                            : ImGui::CalcTextSize(text);
    ImVec2 pos = ImGui::GetCursorScreenPos();
    ImVec2 size(text_size.x + px(52), text_size.y + px(14));
    ImDrawList* draw = ImGui::GetWindowDrawList();
    draw->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y),
                        color_u32(alpha(color, 0.16f)), size.y * 0.5f);
    draw->AddCircleFilled(ImVec2(pos.x + px(17), pos.y + size.y * 0.5f),
                          px(3.5f), color_u32(color));
    draw->AddText(font, font_size,
                  ImVec2(pos.x + px(34),
                         pos.y + (size.y - text_size.y) * 0.5f),
                  color_u32(color), text);
    ImGui::Dummy(size);
    return size;
}

void unavailable_panel(char const* title, char const* message) {
    begin_card(title, ImVec2(0, px(150)));
    section_label(title);
    muted_text("%s", message);
    end_card();
}

}  // namespace yume::gui::ui
