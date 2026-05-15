#pragma once

#include <cstddef>

namespace yume::gui::ui {

// Jost (SIL OFL 1.1) baked into the binary at build time by
// bin2c_impl.cmake. Used as the GUI's primary UI typeface on every OS so
// yume-gui renders identically on Linux, Windows, and macOS without
// depending on the host font catalogue. Jost is a Futura clone that
// matches the URW Gothic look we originally used on Linux.
extern const unsigned char jost_regular_ttf[];
extern const std::size_t jost_regular_ttf_len;

}  // namespace yume::gui::ui
