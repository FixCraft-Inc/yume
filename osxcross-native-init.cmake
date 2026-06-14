# Force native code generation with osxcross (no LLVM bitcode)
# Disable all LTO/IPO to prevent bitcode-wrapped objects
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION OFF CACHE BOOL "Disable IPO" FORCE)
# Force -fno-lto regardless of osxcross defaults
set(CMAKE_C_FLAGS "-fno-lto" CACHE STRING "Disable LTO" FORCE)
set(CMAKE_CXX_FLAGS "-fno-lto" CACHE STRING "Disable LTO" FORCE)
set(CMAKE_ASM_FLAGS "-fno-lto" CACHE STRING "Disable LTO" FORCE)
