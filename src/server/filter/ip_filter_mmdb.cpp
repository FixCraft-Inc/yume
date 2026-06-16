/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#include "server/filter/ip_filter.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <fstream>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace yume::server {

namespace {

std::string upper_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    return value;
}

std::vector<std::uint8_t> read_file_bytes(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("cannot open " + path.string());
    in.seekg(0, std::ios::end);
    const auto end = in.tellg();
    if (end < 0) throw std::runtime_error("cannot size " + path.string());
    in.seekg(0, std::ios::beg);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(end));
    if (!data.empty() && !in.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()))) {
        throw std::runtime_error("cannot read " + path.string());
    }
    return data;
}

struct MmdbValue {
    enum class Type {
        Null,
        String,
        UInt,
        Map,
        Bool,
    };
    Type type{Type::Null};
    std::string text;
    std::uint64_t uint_value{0};
    bool bool_value{false};
    std::vector<std::pair<std::string, MmdbValue>> map;
};

struct MmdbControl {
    std::uint32_t type{0};
    std::uint32_t size{0};
    std::size_t offset{0};
    bool pointer{false};
};

bool read_mmdb_control(const std::vector<std::uint8_t>& data,
                       std::size_t offset,
                       MmdbControl* out) {
    if (!out || offset >= data.size()) return false;
    const std::uint8_t control = data[offset++];
    std::uint32_t type = static_cast<std::uint32_t>(control >> 5);
    std::uint32_t size = static_cast<std::uint32_t>(control & 0x1f);

    if (type == 1) {
        const std::uint32_t pointer_size = static_cast<std::uint32_t>(((control >> 3) & 0x03) + 1);
        const std::uint32_t low_bits = static_cast<std::uint32_t>(control & 0x07);
        std::uint32_t pointer = 0;
        if (pointer_size == 1) {
            if (offset + 1 > data.size()) return false;
            pointer = (low_bits << 8) | data[offset++];
        } else if (pointer_size == 2) {
            if (offset + 2 > data.size()) return false;
            pointer = (low_bits << 16) |
                      (static_cast<std::uint32_t>(data[offset]) << 8) |
                      static_cast<std::uint32_t>(data[offset + 1]);
            offset += 2;
            pointer += 2048u;
        } else if (pointer_size == 3) {
            if (offset + 3 > data.size()) return false;
            pointer = (low_bits << 24) |
                      (static_cast<std::uint32_t>(data[offset]) << 16) |
                      (static_cast<std::uint32_t>(data[offset + 1]) << 8) |
                      static_cast<std::uint32_t>(data[offset + 2]);
            offset += 3;
            pointer += 526336u;
        } else {
            if (offset + 4 > data.size()) return false;
            pointer = (static_cast<std::uint32_t>(data[offset]) << 24) |
                      (static_cast<std::uint32_t>(data[offset + 1]) << 16) |
                      (static_cast<std::uint32_t>(data[offset + 2]) << 8) |
                      static_cast<std::uint32_t>(data[offset + 3]);
            offset += 4;
        }
        *out = MmdbControl{type, pointer, offset, true};
        return true;
    }

    if (type == 0) {
        if (offset >= data.size()) return false;
        type = 7u + static_cast<std::uint32_t>(data[offset++]);
    }
    if (size == 29) {
        if (offset >= data.size()) return false;
        size = 29u + static_cast<std::uint32_t>(data[offset++]);
    } else if (size == 30) {
        if (offset + 2 > data.size()) return false;
        size = 285u +
               (static_cast<std::uint32_t>(data[offset]) << 8) +
               static_cast<std::uint32_t>(data[offset + 1]);
        offset += 2;
    } else if (size == 31) {
        if (offset + 3 > data.size()) return false;
        size = 65821u +
               (static_cast<std::uint32_t>(data[offset]) << 16) +
               (static_cast<std::uint32_t>(data[offset + 1]) << 8) +
               static_cast<std::uint32_t>(data[offset + 2]);
        offset += 3;
    }
    *out = MmdbControl{type, size, offset, false};
    return true;
}

bool read_mmdb_value(const std::vector<std::uint8_t>& data,
                     std::size_t pointer_base,
                     std::size_t offset,
                     int depth,
                     MmdbValue* out,
                     std::size_t* next) {
    if (!out || !next || depth > 32) return false;
    MmdbControl control;
    if (!read_mmdb_control(data, offset, &control)) return false;
    if (control.pointer) {
        if (pointer_base + control.size >= data.size()) return false;
        if (!read_mmdb_value(data, pointer_base, pointer_base + control.size, depth + 1, out, next)) {
            return false;
        }
        *next = control.offset;
        return true;
    }

    const auto ensure_size = [&](std::size_t bytes) {
        return control.offset <= data.size() && bytes <= data.size() - control.offset;
    };
    auto read_uint = [&](std::size_t bytes) {
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < bytes; ++i) {
            value = (value << 8) | data[control.offset + i];
        }
        return value;
    };

    MmdbValue value;
    switch (control.type) {
    case 2: {
        if (!ensure_size(control.size)) return false;
        value.type = MmdbValue::Type::String;
        value.text.assign(reinterpret_cast<const char*>(data.data() + control.offset), control.size);
        *next = control.offset + control.size;
        *out = std::move(value);
        return true;
    }
    case 5:
    case 6:
    case 8:
    case 9:
    case 10: {
        if (!ensure_size(control.size)) return false;
        value.type = MmdbValue::Type::UInt;
        const std::size_t bytes = std::min<std::size_t>(control.size, sizeof(std::uint64_t));
        value.uint_value = read_uint(bytes);
        *next = control.offset + control.size;
        *out = std::move(value);
        return true;
    }
    case 7: {
        value.type = MmdbValue::Type::Map;
        std::size_t pos = control.offset;
        value.map.reserve(control.size);
        for (std::uint32_t i = 0; i < control.size; ++i) {
            MmdbValue key;
            if (!read_mmdb_value(data, pointer_base, pos, depth + 1, &key, &pos) ||
                key.type != MmdbValue::Type::String) {
                return false;
            }
            MmdbValue child;
            if (!read_mmdb_value(data, pointer_base, pos, depth + 1, &child, &pos)) {
                return false;
            }
            value.map.emplace_back(std::move(key.text), std::move(child));
        }
        *next = pos;
        *out = std::move(value);
        return true;
    }
    case 11: {
        std::size_t pos = control.offset;
        for (std::uint32_t i = 0; i < control.size; ++i) {
            MmdbValue ignored;
            if (!read_mmdb_value(data, pointer_base, pos, depth + 1, &ignored, &pos)) {
                return false;
            }
        }
        value.type = MmdbValue::Type::Null;
        *next = pos;
        *out = std::move(value);
        return true;
    }
    case 14:
        value.type = MmdbValue::Type::Bool;
        value.bool_value = control.size != 0;
        *next = control.offset;
        *out = std::move(value);
        return true;
    case 3:
    case 4:
    case 12:
    case 15:
        if (!ensure_size(control.size)) return false;
        value.type = MmdbValue::Type::Null;
        *next = control.offset + control.size;
        *out = std::move(value);
        return true;
    default:
        return false;
    }
}

const MmdbValue* mmdb_map_find(const MmdbValue& value, std::string_view key) {
    if (value.type != MmdbValue::Type::Map) return nullptr;
    for (const auto& [item_key, item_value] : value.map) {
        if (item_key == key) return &item_value;
    }
    return nullptr;
}

std::optional<std::uint64_t> mmdb_map_uint(const MmdbValue& value, std::string_view key) {
    const auto* child = mmdb_map_find(value, key);
    if (!child || child->type != MmdbValue::Type::UInt) return std::nullopt;
    return child->uint_value;
}

std::optional<std::string> mmdb_map_string(const MmdbValue& value, std::string_view key) {
    const auto* child = mmdb_map_find(value, key);
    if (!child || child->type != MmdbValue::Type::String) return std::nullopt;
    return child->text;
}

}  // namespace

bool IpFilter::load_mmdb_country_db(const std::filesystem::path& path, std::string* error) {
    try {
        auto data = read_file_bytes(path);
        static const std::array<std::uint8_t, 14> kMetadataMarker{
            0xab, 0xcd, 0xef, 'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm'
        };
        auto marker = std::find_end(data.begin(), data.end(),
                                    kMetadataMarker.begin(), kMetadataMarker.end());
        if (marker == data.end()) {
            throw std::runtime_error("metadata marker not found");
        }
        const std::size_t marker_pos = static_cast<std::size_t>(std::distance(data.begin(), marker));
        const std::size_t metadata_offset = marker_pos + kMetadataMarker.size();
        MmdbValue metadata;
        std::size_t next = 0;
        if (!read_mmdb_value(data, 0, metadata_offset, 0, &metadata, &next) ||
            metadata.type != MmdbValue::Type::Map) {
            throw std::runtime_error("metadata decode failed");
        }
        const auto node_count = mmdb_map_uint(metadata, "node_count");
        const auto record_size = mmdb_map_uint(metadata, "record_size");
        const auto ip_version = mmdb_map_uint(metadata, "ip_version");
        const auto database_type = mmdb_map_string(metadata, "database_type").value_or("");
        if (!node_count.has_value() || !record_size.has_value() || !ip_version.has_value()) {
            throw std::runtime_error("metadata missing node_count, record_size, or ip_version");
        }
        if (*record_size != 24 && *record_size != 28 && *record_size != 32) {
            throw std::runtime_error("unsupported MMDB record_size " + std::to_string(*record_size));
        }
        if (*ip_version != 4 && *ip_version != 6) {
            throw std::runtime_error("unsupported MMDB ip_version " + std::to_string(*ip_version));
        }
        if (database_type.find("Country") == std::string::npos) {
            throw std::runtime_error("expected a Country MMDB, got " + database_type);
        }
        const std::uint64_t node_byte_size = (*record_size * 2u) / 8u;
        const std::uint64_t tree_size = *node_count * node_byte_size;
        if (tree_size + 16u >= data.size() ||
            tree_size > static_cast<std::uint64_t>(std::numeric_limits<std::uint32_t>::max())) {
            throw std::runtime_error("MMDB search tree is out of range");
        }

        mmdb_node_count_ = static_cast<std::uint32_t>(*node_count);
        mmdb_record_size_ = static_cast<std::uint32_t>(*record_size);
        mmdb_node_byte_size_ = static_cast<std::uint32_t>(node_byte_size);
        mmdb_search_tree_size_ = static_cast<std::uint32_t>(tree_size);
        mmdb_data_section_base_ = mmdb_search_tree_size_ + 16u;
        mmdb_ip_version_ = static_cast<std::uint32_t>(*ip_version);
        mmdb_data_ = std::move(data);
        geolite_loaded_ = true;
    } catch (const std::exception& ex) {
        if (error) *error = "failed to load GeoLite MMDB " + path.string() + ": " + ex.what();
        return false;
    }
    return true;
}

std::optional<std::string> IpFilter::lookup_mmdb_country(std::uint32_t ipv4) const {
    if (mmdb_data_.empty() || mmdb_node_count_ == 0 || mmdb_node_byte_size_ == 0) {
        return std::nullopt;
    }
    auto read_node = [&](std::uint32_t node, bool right) -> std::optional<std::uint32_t> {
        const std::size_t base =
            static_cast<std::size_t>(node) * static_cast<std::size_t>(mmdb_node_byte_size_);
        if (base + mmdb_node_byte_size_ > mmdb_data_.size()) return std::nullopt;
        if (mmdb_record_size_ == 24) {
            const std::size_t off = base + (right ? 3u : 0u);
            return (static_cast<std::uint32_t>(mmdb_data_[off]) << 16) |
                   (static_cast<std::uint32_t>(mmdb_data_[off + 1]) << 8) |
                   static_cast<std::uint32_t>(mmdb_data_[off + 2]);
        }
        if (mmdb_record_size_ == 28) {
            const auto* b = mmdb_data_.data() + base;
            if (!right) {
                return (static_cast<std::uint32_t>(b[0]) << 20) |
                       (static_cast<std::uint32_t>(b[1]) << 12) |
                       (static_cast<std::uint32_t>(b[2]) << 4) |
                       (static_cast<std::uint32_t>(b[3]) >> 4);
            }
            return ((static_cast<std::uint32_t>(b[3]) & 0x0f) << 24) |
                   (static_cast<std::uint32_t>(b[4]) << 16) |
                   (static_cast<std::uint32_t>(b[5]) << 8) |
                   static_cast<std::uint32_t>(b[6]);
        }
        if (mmdb_record_size_ == 32) {
            const std::size_t off = base + (right ? 4u : 0u);
            return (static_cast<std::uint32_t>(mmdb_data_[off]) << 24) |
                   (static_cast<std::uint32_t>(mmdb_data_[off + 1]) << 16) |
                   (static_cast<std::uint32_t>(mmdb_data_[off + 2]) << 8) |
                   static_cast<std::uint32_t>(mmdb_data_[off + 3]);
        }
        return std::nullopt;
    };

    enum class WalkState {
        Continue,
        Found,
        Missing,
    };
    std::uint32_t node = 0;
    const auto consume_bit = [&](bool bit, std::size_t* record_offset) -> WalkState {
        auto next = read_node(node, bit);
        if (!next.has_value()) return WalkState::Missing;
        if (*next == mmdb_node_count_) return WalkState::Missing;
        if (*next > mmdb_node_count_) {
            const std::size_t offset =
                static_cast<std::size_t>(mmdb_search_tree_size_) +
                static_cast<std::size_t>(*next - mmdb_node_count_);
            if (offset >= mmdb_data_.size()) return WalkState::Missing;
            *record_offset = offset;
            return WalkState::Found;
        }
        node = *next;
        return WalkState::Continue;
    };

    std::size_t record_offset = 0;
    WalkState state = WalkState::Continue;
    if (mmdb_ip_version_ == 6) {
        for (int i = 0; i < 96; ++i) {
            state = consume_bit(false, &record_offset);
            if (state != WalkState::Continue) {
                break;
            }
        }
    }
    if (state == WalkState::Continue) {
        for (int bit = 31; bit >= 0; --bit) {
            const bool value = ((ipv4 >> bit) & 1u) != 0;
            state = consume_bit(value, &record_offset);
            if (state != WalkState::Continue) {
                break;
            }
        }
    }
    if (state != WalkState::Found || record_offset == 0) {
        return std::nullopt;
    }

    MmdbValue record;
    std::size_t next = 0;
    if (!read_mmdb_value(mmdb_data_,
                         mmdb_data_section_base_,
                         record_offset,
                         0,
                         &record,
                         &next) ||
        record.type != MmdbValue::Type::Map) {
        return std::nullopt;
    }
    const auto iso_from = [&](std::string_view key) -> std::optional<std::string> {
        const auto* section = mmdb_map_find(record, key);
        if (!section) return std::nullopt;
        auto iso = mmdb_map_string(*section, "iso_code");
        if (!iso.has_value() || iso->size() != 2) return std::nullopt;
        return upper_ascii(*iso);
    };
    if (auto iso = iso_from("country"); iso.has_value()) {
        return iso;
    }
    return iso_from("registered_country");
}

}  // namespace yume::server
