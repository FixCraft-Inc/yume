/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "ui/design.hpp"

#include <algorithm>
#include <cfloat>
#include <cstdarg>
#include <cstdio>
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
        "/usr/share/fonts/truetype/roboto/unhinted/RobotoTTF/Roboto-Regular.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    });
}

std::optional<std::string> find_strong_font() {
#if YUME_GUI_FONTCONFIG
    for (char const* family : {
             "URW Gothic:style=Demi",
             "Inter:style=Medium",
             "Noto Sans:style=SemiBold",
             "Noto Sans:style=Medium",
             "Roboto:style=Medium",
             "DejaVu Sans:style=Bold"}) {
        if (auto p = fontconfig_match(family)) return p;
    }
#endif
    return existing_path({
        "/usr/share/fonts/opentype/urw-base35/URWGothic-Demi.otf",
        "/usr/share/fonts/opentype/inter/Inter-Medium.otf",
        "/usr/share/fonts/truetype/noto/NotoSans-SemiBold.ttf",
        "/usr/share/fonts/truetype/noto/NotoSans-Medium.ttf",
        "/usr/share/fonts/truetype/roboto/unhinted/RobotoTTF/Roboto-Medium.ttf",
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

ImFont* add_font_or_default(std::optional<std::string> const& path,
                            float size,
                            float rasterizer_multiply = 1.0f,
                            bool synthetic_bold = false) {
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
        if (synthetic_bold) cfg.FontBuilderFlags |= ImGuiFreeTypeBuilderFlags_Bold;
#else
        (void)synthetic_bold;
#endif
        std::snprintf(cfg.Name, sizeof(cfg.Name), "%s %.0f", path->c_str(), size);
        if (ImFont* font = io.Fonts->AddFontFromFileTTF(path->c_str(), size, &cfg)) {
            return font;
        }
    }
    return io.Fonts->AddFontDefault();
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

    const auto ui_font = find_ui_font();
    const auto strong_font = find_strong_font();
    const auto mono_font = find_mono_font();
    g_fonts.small = add_font_or_default(ui_font, px(15.5f), 1.12f);
    g_fonts.body = add_font_or_default(ui_font, px(18.5f), 1.10f);
    g_fonts.strong = add_font_or_default(strong_font ? strong_font : ui_font, px(18.5f), 1.04f);
    g_fonts.section = add_font_or_default(strong_font ? strong_font : ui_font, px(20.5f), 1.04f);
    g_fonts.title = add_font_or_default(strong_font ? strong_font : ui_font, px(30.0f), 1.02f);
    g_fonts.mono = add_font_or_default(mono_font ? mono_font : ui_font, px(15.5f), 1.08f);
    io.FontDefault = g_fonts.body ? g_fonts.body : io.Fonts->Fonts[0];
}

void apply_style(float content_scale, bool dark_mode) {
    g_scale = std::clamp(content_scale, 1.0f, 2.0f);
    if (dark_mode) {
        g_colors.background = rgb(0x101114);
        g_colors.surface = rgb(0x181A20);
        g_colors.surface_high = rgb(0x20232B);
        g_colors.outline = rgb(0x343843);
        g_colors.text = rgb(0xF4F1EA);
        g_colors.muted = rgb(0xA8ADB8);
        g_colors.accent = rgb(0xF26822);
        g_colors.accent_hover = rgb(0xFF7A35);
        g_colors.success = rgb(0x53D17C);
        g_colors.warning = rgb(0xF2B950);
        g_colors.error = rgb(0xFF6F6B);
    } else {
        g_colors.background = rgb(0xF5F5F7);
        g_colors.surface = rgb(0xFFFFFF);
        g_colors.surface_high = rgb(0xECEFF3);
        g_colors.outline = rgb(0xD6DAE1);
        g_colors.text = rgb(0x17191F);
        g_colors.muted = rgb(0x5E6673);
        g_colors.accent = rgb(0xD95A16);
        g_colors.accent_hover = rgb(0xF26822);
        g_colors.success = rgb(0x168A45);
        g_colors.warning = rgb(0xA86500);
        g_colors.error = rgb(0xC9332B);
    }

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

    ImVec4* c = s.Colors;
    c[ImGuiCol_Text] = g_colors.text;
    c[ImGuiCol_TextDisabled] = alpha(g_colors.muted, 0.62f);
    c[ImGuiCol_WindowBg] = g_colors.background;
    c[ImGuiCol_ChildBg] = g_colors.surface;
    c[ImGuiCol_PopupBg] = g_colors.surface_high;
    c[ImGuiCol_Border] = g_colors.outline;
    c[ImGuiCol_BorderShadow] = alpha(rgb(0x000000), 0.0f);
    c[ImGuiCol_FrameBg] = g_colors.surface_high;
    c[ImGuiCol_FrameBgHovered] = alpha(g_colors.accent, 0.18f);
    c[ImGuiCol_FrameBgActive] = alpha(g_colors.accent, 0.26f);
    c[ImGuiCol_Button] = g_colors.accent;
    c[ImGuiCol_ButtonHovered] = g_colors.accent_hover;
    c[ImGuiCol_ButtonActive] = rgb(0xC74D13);
    c[ImGuiCol_Header] = alpha(g_colors.accent, 0.16f);
    c[ImGuiCol_HeaderHovered] = alpha(g_colors.accent, 0.24f);
    c[ImGuiCol_HeaderActive] = alpha(g_colors.accent, 0.32f);
    c[ImGuiCol_Separator] = g_colors.outline;
    c[ImGuiCol_SeparatorHovered] = g_colors.accent_hover;
    c[ImGuiCol_SeparatorActive] = g_colors.accent;
    c[ImGuiCol_ScrollbarBg] = alpha(rgb(0x000000), 0.0f);
    c[ImGuiCol_ScrollbarGrab] = alpha(g_colors.muted, 0.28f);
    c[ImGuiCol_ScrollbarGrabHovered] = alpha(g_colors.muted, 0.45f);
    c[ImGuiCol_ScrollbarGrabActive] = alpha(g_colors.accent, 0.7f);
    c[ImGuiCol_CheckMark] = g_colors.accent;
    c[ImGuiCol_SliderGrab] = g_colors.accent;
    c[ImGuiCol_SliderGrabActive] = g_colors.accent_hover;
    c[ImGuiCol_Tab] = g_colors.surface_high;
    c[ImGuiCol_TabHovered] = alpha(g_colors.accent, 0.2f);
    c[ImGuiCol_TabActive] = alpha(g_colors.accent, 0.24f);
    c[ImGuiCol_TableHeaderBg] = g_colors.surface_high;
    c[ImGuiCol_TableBorderStrong] = g_colors.outline;
    c[ImGuiCol_TableBorderLight] = g_colors.outline;
    c[ImGuiCol_TableRowBg] = alpha(rgb(0x000000), 0.0f);
    c[ImGuiCol_TableRowBgAlt] = alpha(g_colors.surface_high, 0.45f);
    c[ImGuiCol_TextSelectedBg] = alpha(g_colors.accent, 0.32f);
    c[ImGuiCol_NavHighlight] = g_colors.accent;
    c[ImGuiCol_ModalWindowDimBg] = alpha(rgb(0x000000), 0.55f);
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
    if (g_fonts.strong) ImGui::PushFont(g_fonts.strong);
    ImGui::PushStyleColor(ImGuiCol_Text, g_colors.muted);
    ImGui::TextWrapped("%s", label);
    ImGui::PopStyleColor();
    if (g_fonts.strong) ImGui::PopFont();
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() - px(2));
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
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, rgb(0xC74D13));
    if (g_fonts.strong) ImGui::PushFont(g_fonts.strong);
    bool pressed = ImGui::Button(label, size);
    if (g_fonts.strong) ImGui::PopFont();
    ImGui::PopStyleColor(3);
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

    const float box = px(20);
    const float gap = px(12);
    const float row_h = std::max(box, text_size.y) + px(8);
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
    const float r = px(6);

    const ImVec4 accent = held ? rgb(0xC74D13)
                               : (hovered ? g_colors.accent_hover : g_colors.accent);
    if (*value) {
        dl->AddRectFilled(box_a, box_b, color_u32(accent), r);
        const float w = box;
        const float t = std::max(1.5f, px(2.1f));
        // Centred two-segment checkmark.
        const ImVec2 p0(box_a.x + w * 0.22f, box_a.y + w * 0.55f);
        const ImVec2 p1(box_a.x + w * 0.43f, box_a.y + w * 0.74f);
        const ImVec2 p2(box_a.x + w * 0.78f, box_a.y + w * 0.32f);
        dl->AddLine(p0, p1, IM_COL32_WHITE, t);
        dl->AddLine(p1, p2, IM_COL32_WHITE, t);
    } else {
        if (hovered) {
            dl->AddRectFilled(box_a, box_b,
                              color_u32(alpha(g_colors.accent, 0.10f)), r);
        }
        const ImVec4 stroke = hovered ? g_colors.accent : g_colors.outline;
        dl->AddRect(box_a, box_b, color_u32(stroke), r, 0,
                    std::max(1.0f, px(1.6f)));
    }

    dl->AddText(font, font_size,
                ImVec2(box_b.x + gap,
                       pos.y + (row_h - text_size.y) * 0.5f),
                color_u32(g_colors.text), label);

    ImGui::PopID();
    return pressed;
}

int segmented_control(char const* id,
                      char const* const* labels,
                      int count,
                      int current) {
    if (count <= 0 || !labels) return current;
    ImGui::PushID(id);

    ImFont* font = g_fonts.strong ? g_fonts.strong : ImGui::GetFont();
    const float font_size = font ? font->FontSize : ImGui::GetFontSize();
    const float seg_h = px(40);
    const float h_pad = px(20);

    // Width: equally split available area for a balanced look, but ensure
    // each segment is wide enough to fit its label.
    float min_seg_w = px(96);
    for (int i = 0; i < count; ++i) {
        ImVec2 ts = font
            ? font->CalcTextSizeA(font_size, FLT_MAX, 0.0f, labels[i])
            : ImGui::CalcTextSize(labels[i]);
        min_seg_w = std::max(min_seg_w, ts.x + h_pad * 2.0f);
    }
    const float avail = std::max(min_seg_w * count,
                                 ImGui::GetContentRegionAvail().x);
    const float seg_w = avail / static_cast<float>(count);

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
        ImU32 text_color = color_u32(active ? rgb(0xFFFFFF)
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
        for (int i = 0; i < count; ++i) {
            const bool selected = (i == *current);
            ImGui::PushID(i);
            // Use a Selectable so keyboard nav + hover work cleanly.
            if (ImGui::Selectable(items[i], selected,
                                  ImGuiSelectableFlags_None,
                                  ImVec2(0, px(28)))) {
                *current = i;
                changed = true;
            }
            if (selected) {
                ImGui::SetItemDefaultFocus();
                // Draw a tiny accent dot to the right of the selected row.
                ImDrawList* dl = ImGui::GetWindowDrawList();
                const ImVec2 r_min = ImGui::GetItemRectMin();
                const ImVec2 r_max = ImGui::GetItemRectMax();
                const float cy = (r_min.y + r_max.y) * 0.5f;
                const float cx = r_max.x - px(14);
                dl->AddCircleFilled(ImVec2(cx, cy), px(3.0f),
                                    color_u32(g_colors.accent));
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
