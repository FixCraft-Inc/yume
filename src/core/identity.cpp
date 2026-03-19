#include "core/identity.hpp"

#include <algorithm>
#include <array>
#include <cctype>

#include <openssl/sha.h>

#include "util.hpp"

namespace yume::identity {

namespace {
constexpr std::array<const char*, 32> kAdjectives{
    "silent", "shiny", "amber", "brisk", "calm", "cinder", "cloudy", "crisp",
    "ember", "frozen", "gentle", "glossy", "hidden", "ivory", "lunar", "mellow",
    "misty", "narrow", "neon", "nimble", "polar", "quiet", "rapid", "scarlet",
    "silver", "soft", "solar", "swift", "tidy", "velvet", "violet", "wild"};

constexpr std::array<const char*, 32> kAnimals{
    "badger", "falcon", "fish", "fox", "gecko", "heron", "ibis", "koala",
    "lemur", "lynx", "marten", "moose", "newt", "ocelot", "octopus", "otter",
    "owl", "panda", "quail", "raven", "seal", "shark", "sparrow", "stoat",
    "swift", "tiger", "viper", "walrus", "wolf", "yak", "zebra", "wren"};
}

std::string generate_endpoint_id() {
    return yume::util::random_hex(16);
}

std::string generate_display_name() {
    const std::string seed = yume::util::random_hex(2);
    const unsigned int left_index = !seed.empty() ? static_cast<unsigned int>(std::stoul(seed.substr(0, 2), nullptr, 16)) : 0U;
    const unsigned int right_index = seed.size() >= 4 ? static_cast<unsigned int>(std::stoul(seed.substr(2, 2), nullptr, 16)) : left_index;
    std::string left = kAdjectives[left_index % kAdjectives.size()];
    std::string right = kAnimals[right_index % kAnimals.size()];
    return left + "-" + right;
}

bool is_valid_hex_id(std::string_view value) {
    if (value.size() != 32) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](unsigned char c) {
        return std::isxdigit(c) != 0;
    });
}

std::string sanitize_display_name(std::string_view value) {
    std::string out;
    out.reserve(value.size());
    bool last_dash = false;
    for (unsigned char ch : value) {
        if (std::isalnum(ch) != 0) {
            out.push_back(static_cast<char>(std::tolower(ch)));
            last_dash = false;
        } else if (!last_dash) {
            out.push_back('-');
            last_dash = true;
        }
    }
    while (!out.empty() && out.front() == '-') {
        out.erase(out.begin());
    }
    while (!out.empty() && out.back() == '-') {
        out.pop_back();
    }
    if (out.empty()) {
        return generate_display_name();
    }
    return out;
}

std::string derive_instance_key(std::string_view material) {
    unsigned char digest[SHA256_DIGEST_LENGTH] = {0};
    SHA256(reinterpret_cast<const unsigned char*>(material.data()), material.size(), digest);
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(24);
    for (std::size_t i = 0; i < 12; ++i) {
        out.push_back(kHex[(digest[i] >> 4) & 0xF]);
        out.push_back(kHex[digest[i] & 0xF]);
    }
    return out;
}

}  // namespace yume::identity
