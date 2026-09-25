/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <utility>

namespace yume::common {

// RFC 1929 username and password for a SOCKS5 proxy, each 1 to 255 bytes.
// Moves and destruction wipe the storage they leave behind, including the
// inline storage of short strings. Wiping is best effort and does not reach
// copies made elsewhere.
class Socks5Credentials final {
public:
    static constexpr std::size_t kMaxFieldBytes = 255U;

    // nullopt when either field is empty or too long. The arguments are
    // wiped either way.
    static std::optional<Socks5Credentials> create(std::string username, std::string password) {
        std::optional<Socks5Credentials> made;
        if (valid(username) && valid(password)) {
            made.emplace(Socks5Credentials(std::move(username), std::move(password)));
        }
        wipe(username);
        wipe(password);
        return made;
    }

    Socks5Credentials(Socks5Credentials&& other) noexcept
        : username_(std::move(other.username_)), password_(std::move(other.password_)) {
        other.wipe_all();
    }
    Socks5Credentials& operator=(Socks5Credentials&& other) noexcept {
        if (this != &other) {
            wipe_all();
            username_ = std::move(other.username_);
            password_ = std::move(other.password_);
            other.wipe_all();
        }
        return *this;
    }
    Socks5Credentials(const Socks5Credentials&) = delete;
    Socks5Credentials& operator=(const Socks5Credentials&) = delete;
    ~Socks5Credentials() { wipe_all(); }

    const std::string& username() const noexcept { return username_; }
    const std::string& password() const noexcept { return password_; }

private:
    Socks5Credentials(std::string username, std::string password) noexcept
        : username_(std::move(username)), password_(std::move(password)) {
        wipe(username);
        wipe(password);
    }

    static bool valid(const std::string& field) noexcept {
        return !field.empty() && field.size() <= kMaxFieldBytes;
    }

    // Growing to the capacity cannot allocate. It makes the whole buffer,
    // inline or not, reachable for the overwrite.
    static void wipe(std::string& text) noexcept {
        text.resize(text.capacity(), '\0');
        volatile char* cursor = text.data();
        for (std::size_t index = 0U; index < text.size(); ++index) cursor[index] = 0;
        text.clear();
    }

    void wipe_all() noexcept {
        wipe(username_);
        wipe(password_);
    }

    std::string username_;
    std::string password_;
};

}  // namespace yume::common
