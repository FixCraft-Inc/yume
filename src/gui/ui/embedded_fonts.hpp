#pragma once

#include <cstddef>

namespace yume::gui::ui {

// Roboto Regular (Apache-2.0) baked into the binary at build time by
// bin2c_impl.cmake. Used as a guaranteed-available font so the GUI never
// has to fall back to ImGui's bitmap Proggy Clean default when system
// font discovery fails (notably on stripped Windows installs where
// segoeui.ttf isn't readable from the user's session).
extern const unsigned char roboto_regular_ttf[];
extern const std::size_t roboto_regular_ttf_len;

}  // namespace yume::gui::ui
