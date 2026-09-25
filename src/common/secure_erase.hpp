/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace yume::security {

// Best-effort compiler-resistant clearing for ordinary byte vectors. This
// reduces secret lifetime in retained vector capacity; it is not a locked-page
// secure allocator and does not erase copies made elsewhere.
inline void secure_erase(std::vector<std::uint8_t>& bytes) noexcept {
    // Restoring the allocated extent cannot allocate. It makes a tail left by
    // resize/erase reachable before the compiler-resistant overwrite.
    bytes.resize(bytes.capacity());
    volatile std::uint8_t* cursor = bytes.data();
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        cursor[i] = 0;
    }
    bytes.clear();
}

inline void secure_erase(std::string& text) noexcept {
    text.resize(text.capacity(), '\0');
    volatile char* cursor = text.data();
    for (std::size_t i = 0; i < text.size(); ++i) {
        cursor[i] = 0;
    }
    text.clear();
}

// Registration must not allocate after the secret has already been loaded.
// The buffer must outlive this guard. Moving its storage transfers the wiping
// obligation to the destination owner.
template <typename Buffer>
class ScopedErase {
public:
    explicit ScopedErase(Buffer& buffer) noexcept : buffer_(buffer) {}
    ScopedErase(const ScopedErase&) = delete;
    ScopedErase& operator=(const ScopedErase&) = delete;
    ~ScopedErase() noexcept { secure_erase(buffer_); }

private:
    Buffer& buffer_;
};

}  // namespace yume::security
