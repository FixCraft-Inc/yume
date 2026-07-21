/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "facade/security/secure_materials.hpp"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <string>

#ifndef _WIN32
#include <unistd.h>
#endif

int main() {
#ifdef _WIN32
    return 0;
#else
    char temporary_home[] = "/tmp/yume-secure-materials-XXXXXX";
    assert(::mkdtemp(temporary_home) != nullptr);

    const char* previous_home_value = std::getenv("HOME");
    const std::string previous_home = previous_home_value ? previous_home_value : "";
    assert(::setenv("HOME", temporary_home, 1) == 0);

    namespace sm = yume::facade::secure_materials;
    std::string error;
    auto materials = sm::list(sm::MaterialType::AnonymCa, &error);
    assert(error.empty());
    assert(std::any_of(materials.begin(), materials.end(), [](const auto& material) {
        return material.id == sm::kDefaultAnonymCaId;
    }));

    assert(sm::remove(sm::kDefaultAnonymCaId, &error));
    assert(error.empty());
    materials = sm::list(sm::MaterialType::AnonymCa, &error);
    assert(error.empty());
    assert(std::none_of(materials.begin(), materials.end(), [](const auto& material) {
        return material.id == sm::kDefaultAnonymCaId;
    }));
    assert(!sm::material_path(sm::kDefaultAnonymCaId, &error));

    if (previous_home_value) {
        assert(::setenv("HOME", previous_home.c_str(), 1) == 0);
    } else {
        assert(::unsetenv("HOME") == 0);
    }
    std::filesystem::remove_all(temporary_home);
    return 0;
#endif
}
