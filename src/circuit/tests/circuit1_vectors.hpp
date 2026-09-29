/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <charconv>
#include <cstdint>
#include <fstream>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// Reads circuit1_vectors.txt for the circuit tests: NAME=VALUE lines, where a
// value is hexadecimal bytes, a decimal number or words, as the generator
// writes them.
namespace yume::circuit1::test {

class Vectors final {
public:
    explicit Vectors(const char* path) {
        std::ifstream input(path);
        if (!input.is_open())
            throw std::runtime_error("cannot open circuit vectors");
        std::string line;
        while (std::getline(input, line)) {
            if (line.empty() || line.front() == '#') continue;
            const auto separator = line.find('=');
            if (separator == std::string::npos || separator == 0U) {
                throw std::runtime_error("malformed circuit vector line");
            }
            if (!values_
                     .emplace(line.substr(0U, separator),
                              line.substr(separator + 1U))
                     .second) {
                throw std::runtime_error("repeated circuit vector name");
            }
        }
    }

    const std::string& text(const std::string& name) const {
        const auto found = values_.find(name);
        if (found == values_.end()) {
            throw std::runtime_error("missing circuit vector " + name);
        }
        return found->second;
    }

    std::vector<std::uint8_t> bytes(const std::string& name) const {
        const auto& encoded = text(name);
        if (encoded.size() % 2U != 0U) {
            throw std::runtime_error("odd hex in circuit vector " + name);
        }
        std::vector<std::uint8_t> output(encoded.size() / 2U);
        for (std::size_t index = 0U; index < output.size(); ++index) {
            unsigned value = 0U;
            const auto* first = encoded.data() + 2U * index;
            const auto parsed = std::from_chars(first, first + 2, value, 16);
            if (parsed.ec != std::errc() || parsed.ptr != first + 2) {
                throw std::runtime_error("bad hex in circuit vector " + name);
            }
            output[index] = static_cast<std::uint8_t>(value);
        }
        return output;
    }

    std::uint64_t number(const std::string& name) const {
        const auto& encoded = text(name);
        std::uint64_t value = 0U;
        const auto parsed = std::from_chars(
            encoded.data(), encoded.data() + encoded.size(), value);
        if (parsed.ec != std::errc() ||
            parsed.ptr != encoded.data() + encoded.size()) {
            throw std::runtime_error("bad number in circuit vector " + name);
        }
        return value;
    }

    // Every name that starts with prefix, in order.
    std::vector<std::string> names(std::string_view prefix) const {
        std::vector<std::string> output;
        for (const auto& [name, value] : values_) {
            if (std::string_view(name).starts_with(prefix))
                output.push_back(name);
        }
        return output;
    }

private:
    std::map<std::string, std::string> values_;
};

}  // namespace yume::circuit1::test
