/*
 * Check which library supplies the installed public ABI at runtime.
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include <yume/yume.h>

#include <dlfcn.h>
#include <filesystem>
#include <iostream>
#include <system_error>

int main(int argc, char** argv) {
    if (argc != 2) return 2;
    Dl_info loaded{};
    if (yume_abi_version() != YUME_ABI_VERSION ||
        ::dladdr(reinterpret_cast<const void*>(&yume_abi_version), &loaded) == 0 ||
        !loaded.dli_fname) {
        std::cerr << "installed ABI library could not be identified\n";
        return 1;
    }
    std::error_code error;
    if (!std::filesystem::equivalent(loaded.dli_fname, argv[1], error) || error) {
        std::cerr << "ABI symbol resolved outside the staged runtime library\n";
        return 1;
    }
    std::cout << "ABI symbol resolves to the staged runtime library\n";
    return 0;
}
