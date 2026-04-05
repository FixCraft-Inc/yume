#pragma once

#include <string_view>

#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
#include "basefwx/constants.hpp"
#endif

namespace yume {

constexpr const char kVersion[] = "1.0";

#if defined(YUME_USE_BASEFWX) && YUME_USE_BASEFWX
inline constexpr std::string_view kBasefwxVersion = basefwx::constants::kEngineVersion;
#else
inline constexpr std::string_view kBasefwxVersion = "disabled";
#endif

}  // namespace yume
