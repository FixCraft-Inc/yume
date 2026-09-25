/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/egress_lists.hpp"

#include <algorithm>
#include <bit>
#include <cstring>
#include <new>
#include <queue>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

#include <nlohmann/json.hpp>

namespace yume::runtime {
namespace {

using common::IpFamily;
using engine::Status;
using engine::StatusCode;
using Address = std::array<std::uint8_t, 16>;

constexpr std::size_t address_bytes(IpFamily family) noexcept {
    return family == IpFamily::V4 ? 4U : 16U;
}

// Thrown inside the parsers and returned as InvalidArgument at their edge.
class ListError final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

[[noreturn]] void fail(const std::string& message) {
    throw ListError(message);
}

// The message is diagnostic. Losing it to allocation failure keeps the code.
Status status_of(StatusCode code, std::string_view message) noexcept {
    try {
        return Status(code, message);
    } catch (...) {
        return Status(code);
    }
}

template <typename Body>
Status guarded(Body&& body) noexcept {
    try {
        return body();
    } catch (const ListError& error) {
        return status_of(StatusCode::InvalidArgument, error.what());
    } catch (const std::bad_alloc&) {
        return status_of(StatusCode::ResourceExhausted, "egress lists exceed available memory");
    } catch (const std::length_error&) {
        return status_of(StatusCode::ResourceExhausted, "egress lists exceed available memory");
    }
}

bool increment(Address& address, IpFamily family) noexcept {
    for (std::size_t index = address_bytes(family); index-- > 0U;) {
        if (++address[index] != 0U) return true;
    }
    return false;
}

void decrement(Address& address, IpFamily family) noexcept {
    for (std::size_t index = address_bytes(family); index-- > 0U;) {
        if (address[index]-- != 0U) return;
    }
}

// The prefix length of the smallest network that holds both addresses.
std::uint8_t shared_prefix(const Address& first, const Address& last, IpFamily family) noexcept {
    unsigned bits = 0U;
    for (std::size_t index = 0U; index < address_bytes(family); ++index) {
        const auto difference = static_cast<std::uint8_t>(first[index] ^ last[index]);
        if (difference == 0U) {
            bits += 8U;
            continue;
        }
        bits += static_cast<unsigned>(std::countl_zero(difference));
        break;
    }
    return static_cast<std::uint8_t>(bits);
}

// Sets every bit from `from` to the end of the family's address.
Address with_host_bits(Address address, std::size_t from, IpFamily family) noexcept {
    for (std::size_t bit = from; bit < address_bytes(family) * 8U; ++bit) {
        address[bit / 8U] = static_cast<std::uint8_t>(address[bit / 8U] | (0x80U >> (bit % 8U)));
    }
    return address;
}

// Reads one JSON list without building a document, so a large list costs its
// entries and not a parse tree.
class JsonListReader final : public nlohmann::json_sax<nlohmann::json> {
public:
    std::vector<common::IpNetwork> networks;
    std::vector<std::array<char, 2>> countries;
    std::string error;

    bool null() override { return scalar(); }
    bool boolean(bool) override { return scalar(); }
    bool number_integer(number_integer_t) override { return scalar(); }
    bool number_unsigned(number_unsigned_t) override { return scalar(); }
    bool number_float(number_float_t, const string_t&) override { return scalar(); }
    bool binary(binary_t&) override { return scalar(); }

    bool string(string_t& value) override {
        if (field_ == Field::None) return scalar();
        const std::string pointer = entry_pointer();
        ++index_;
        if (networks.size() + countries.size() >= kMaxEgressListRanges) {
            return refuse("list has more than " + std::to_string(kMaxEgressListRanges) + " entries");
        }
        if (field_ == Field::Ips) {
            const auto network = common::parse_ip_network(value);
            if (!network) {
                return refuse(pointer +
                              ": must be an IPv4 or IPv6 address, or a network with zero host bits");
            }
            networks.push_back(*network);
            return true;
        }
        if (value.size() != 2U || !letter(value[0]) || !letter(value[1])) {
            return refuse(pointer + ": must be a two-letter country code");
        }
        countries.push_back({upper(value[0]), upper(value[1])});
        return true;
    }

    bool start_object(std::size_t) override {
        if (depth_ != 0) return container();
        depth_ = 1;
        return true;
    }

    bool key(string_t& value) override {
        if (value == "ips") {
            if (seen_ips_) return refuse("/ips: duplicate object key");
            seen_ips_ = true;
            pending_ = Field::Ips;
        } else if (value == "countries") {
            if (seen_countries_) return refuse("/countries: duplicate object key");
            seen_countries_ = true;
            pending_ = Field::Countries;
        } else {
            return refuse("list keys must be \"ips\" or \"countries\"");
        }
        return true;
    }

    bool end_object() override {
        depth_ = 0;
        complete_ = true;
        return true;
    }

    bool start_array(std::size_t) override {
        if (depth_ != 1) return container();
        depth_ = 2;
        field_ = pending_;
        index_ = 0U;
        return true;
    }

    bool end_array() override {
        depth_ = 1;
        field_ = Field::None;
        return true;
    }

    bool parse_error(std::size_t position,
                     const std::string&,
                     const nlohmann::detail::exception&) override {
        if (error.empty()) error = "invalid JSON syntax at byte " + std::to_string(position);
        return false;
    }

    bool complete() const noexcept { return complete_ && (seen_ips_ || seen_countries_); }

private:
    enum class Field : std::uint8_t {
        None,
        Ips,
        Countries,
    };

    static bool letter(char ch) noexcept {
        return (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z');
    }
    static char upper(char ch) noexcept {
        return ch >= 'a' && ch <= 'z' ? static_cast<char>(ch - 'a' + 'A') : ch;
    }

    std::string entry_pointer() const {
        return std::string(field_ == Field::Ips ? "/ips/" : "/countries/") + std::to_string(index_);
    }
    // A scalar in the root object or at the top level.
    bool scalar() {
        if (depth_ == 2) return refuse(entry_pointer() + ": must be a string");
        if (depth_ == 1) return refuse(member_pointer() + ": must be an array");
        return refuse("list must be a JSON object");
    }
    // An object or array where neither may appear.
    bool container() {
        if (depth_ == 2) return refuse(entry_pointer() + ": must be a string");
        if (depth_ == 1) return refuse(member_pointer() + ": must be an array");
        return refuse("list must be a JSON object");
    }
    std::string member_pointer() const {
        return pending_ == Field::Ips ? "/ips" : "/countries";
    }
    bool refuse(std::string message) {
        error = std::move(message);
        return false;
    }

    int depth_{0};
    Field pending_{Field::None};
    Field field_{Field::None};
    std::size_t index_{0};
    bool seen_ips_{false};
    bool seen_countries_{false};
    bool complete_{false};
};

class ByteReader final {
public:
    explicit ByteReader(std::span<const std::uint8_t> data) noexcept : data_(data) {}

    std::size_t remaining() const noexcept { return data_.size() - offset_; }

    std::span<const std::uint8_t> take(std::size_t count, const char* what) {
        if (count > remaining()) fail(std::string("truncated ") + what);
        const auto taken = data_.subspan(offset_, count);
        offset_ += count;
        return taken;
    }
    std::uint16_t u16le(const char* what) {
        const auto bytes = take(2U, what);
        return static_cast<std::uint16_t>(bytes[0] | (bytes[1] << 8U));
    }
    std::uint32_t u32le(const char* what) {
        const auto bytes = take(4U, what);
        return static_cast<std::uint32_t>(bytes[0]) |
               (static_cast<std::uint32_t>(bytes[1]) << 8U) |
               (static_cast<std::uint32_t>(bytes[2]) << 16U) |
               (static_cast<std::uint32_t>(bytes[3]) << 24U);
    }
    Address ipv4_le(const char* what) {
        const std::uint32_t value = u32le(what);
        return Address{static_cast<std::uint8_t>(value >> 24U), static_cast<std::uint8_t>(value >> 16U),
                       static_cast<std::uint8_t>(value >> 8U), static_cast<std::uint8_t>(value)};
    }
    Address ipv6(const char* what) {
        const auto bytes = take(16U, what);
        Address address{};
        std::copy(bytes.begin(), bytes.end(), address.begin());
        return address;
    }

private:
    std::span<const std::uint8_t> data_;
    std::size_t offset_{0};
};

// A read-only view of a MaxMind DB file. Construction checks the metadata and
// the layout, and every later read is bounded by the section it belongs to.
class MmdbFile final {
public:
    explicit MmdbFile(std::span<const std::uint8_t> data) : data_(data) {
        static constexpr std::array<std::uint8_t, 14> kMarker{
            0xab, 0xcd, 0xef, 'M', 'a', 'x', 'M', 'i', 'n', 'd', '.', 'c', 'o', 'm'};
        // The metadata sits in the last 128 KiB, after the last marker.
        const std::size_t window = std::min<std::size_t>(data_.size(), 128U * 1024U);
        const auto tail = data_.last(window);
        const auto marker = std::find_end(tail.begin(), tail.end(), kMarker.begin(), kMarker.end());
        if (marker == tail.end()) fail("country database has no MaxMind DB metadata");
        const auto marker_offset = data_.size() - window +
                                   static_cast<std::size_t>(marker - tail.begin());
        const Section metadata{marker_offset + kMarker.size(), data_.size()};

        std::size_t budget = kRecordBudget;
        const Value root = read(metadata, metadata.start);
        if (root.type != kMap) fail("country database metadata is not a map");
        const auto metadata_uint = [&](std::string_view key) {
            const auto offset = find(metadata, root, key, 0U, budget);
            if (!offset) fail("country database metadata has no " + std::string(key));
            return read_unsigned(metadata, *offset);
        };
        if (metadata_uint("binary_format_major_version") != 2U) {
            fail("country database is not MaxMind DB format 2");
        }
        const std::uint64_t node_count = metadata_uint("node_count");
        const std::uint64_t record_size = metadata_uint("record_size");
        const std::uint64_t ip_version = metadata_uint("ip_version");
        if (record_size != 24U && record_size != 28U && record_size != 32U) {
            fail("country database has an unsupported record size");
        }
        if (ip_version != 4U && ip_version != 6U) {
            fail("country database has an unsupported IP version");
        }
        node_bytes_ = static_cast<std::size_t>(record_size / 4U);
        // The data section follows the tree and sixteen zero bytes and ends
        // at the metadata marker.
        if (node_count == 0U || node_count > marker_offset / node_bytes_) {
            fail("country database search tree does not fit the file");
        }
        const std::size_t tree_bytes = static_cast<std::size_t>(node_count) * node_bytes_;
        if (marker_offset - tree_bytes < 16U) {
            fail("country database search tree does not fit the file");
        }
        const auto separator = data_.subspan(tree_bytes, 16U);
        if (std::any_of(separator.begin(), separator.end(), [](std::uint8_t byte) { return byte != 0U; })) {
            fail("country database has no data section separator");
        }
        node_count_ = static_cast<std::uint32_t>(node_count);
        record_bits_ = static_cast<unsigned>(record_size);
        ip_version_ = static_cast<unsigned>(ip_version);
        tree_bytes_ = tree_bytes;
        data_section_ = Section{tree_bytes + 16U, marker_offset};
    }

    // Calls emit(first, last, offset) for every range of the family that
    // leads to a data record, where offset is the record's position.
    template <typename Emit>
    void flatten(IpFamily family, std::size_t& visits, Emit&& emit) const {
        if (family == IpFamily::V6 && ip_version_ == 4U) return;
        const std::size_t bits = address_bytes(family) * 8U;
        std::uint32_t root = 0U;
        if (family == IpFamily::V4 && ip_version_ == 6U) {
            // IPv4 addresses live under ::/96.
            for (unsigned bit = 0U; bit < 96U && root < node_count_; ++bit) {
                root = record(root, false);
            }
            if (root >= node_count_) {
                if (root > node_count_) {
                    emit(Address{}, with_host_bits(Address{}, 0U, family), leaf_offset(root));
                }
                return;
            }
        }
        struct Pending final {
            std::uint32_t node;
            std::size_t depth;
            Address prefix;
        };
        std::vector<Pending> stack{{root, 0U, Address{}}};
        while (!stack.empty()) {
            const Pending current = stack.back();
            stack.pop_back();
            if (++visits > visit_limit()) {
                fail("country database search tree revisits too many nodes");
            }
            for (int side = 1; side >= 0; --side) {
                Address prefix = current.prefix;
                if (side == 1) {
                    prefix[current.depth / 8U] =
                        static_cast<std::uint8_t>(prefix[current.depth / 8U] | (0x80U >> (current.depth % 8U)));
                }
                const std::uint32_t next = record(current.node, side == 1);
                if (next < node_count_) {
                    if (current.depth + 1U >= bits) fail("country database search tree is too deep");
                    stack.push_back(Pending{next, current.depth + 1U, prefix});
                } else if (next > node_count_) {
                    emit(prefix, with_host_bits(prefix, current.depth + 1U, family), leaf_offset(next));
                }
            }
        }
    }

    // The country of the data record at an absolute offset: country.iso_code,
    // else registered_country.iso_code, else none.
    std::optional<std::array<char, 2>> country_at(std::size_t offset) const {
        std::size_t budget = kRecordBudget;
        const Value record = read(data_section_, offset);
        if (record.type != kMap) fail("country database record is not a map");
        for (const std::string_view section : {"country", "registered_country"}) {
            const auto found = find(data_section_, record, section, 0U, budget);
            if (!found) continue;
            const Value inner = read(data_section_, *found);
            if (inner.type != kMap) fail("country database record has a malformed country");
            const auto code = find(data_section_, inner, "iso_code", 1U, budget);
            if (!code) continue;
            const Value text = read(data_section_, *code);
            if (text.type != kString || text.size != 2U) {
                fail("country database record has a malformed country code");
            }
            const char first = static_cast<char>(data_[text.payload]);
            const char second = static_cast<char>(data_[text.payload + 1U]);
            if (first < 'A' || first > 'Z' || second < 'A' || second > 'Z') {
                fail("country database record has a malformed country code");
            }
            return std::array<char, 2>{first, second};
        }
        return std::nullopt;
    }

private:
    static constexpr unsigned kPointer = 1U;
    static constexpr unsigned kString = 2U;
    static constexpr unsigned kMap = 7U;
    static constexpr unsigned kArray = 11U;
    static constexpr unsigned kBoolean = 14U;
    // Values a single record decode may touch, and the nesting it may reach.
    static constexpr std::size_t kRecordBudget = 4096U;
    static constexpr unsigned kMaxDepth = 8U;

    struct Section final {
        std::size_t start;
        std::size_t end;
    };
    struct Value final {
        unsigned type{0};
        // Bytes for scalars, entries for maps and arrays, the value of a boolean.
        std::size_t size{0};
        std::size_t payload{0};
        // Where the next value starts when this one was reached through a
        // pointer. Zero otherwise.
        std::size_t after_pointer{0};
    };

    std::uint8_t byte_at(const Section& section, std::size_t offset) const {
        if (offset < section.start || offset >= section.end) fail("country database value is out of bounds");
        return data_[offset];
    }

    // Decodes the control bytes at an absolute offset, following one pointer.
    Value read(const Section& section, std::size_t offset) const {
        Value value = control(section, offset);
        if (value.type != kPointer) return value;
        const std::size_t after = value.payload;
        const std::size_t target = section.start + value.size;
        if (target >= section.end) fail("country database pointer is out of bounds");
        value = control(section, target);
        if (value.type == kPointer) fail("country database pointer points to a pointer");
        value.after_pointer = after;
        return value;
    }

    // For a pointer, size is the target relative to the section and payload
    // is the offset after the pointer.
    Value control(const Section& section, std::size_t offset) const {
        const std::uint8_t lead = byte_at(section, offset++);
        unsigned type = lead >> 5U;
        if (type == kPointer) {
            const unsigned length = ((lead >> 3U) & 0x03U) + 1U;
            std::size_t pointer = length == 4U ? 0U : (lead & 0x07U);
            for (unsigned index = 0U; index < length; ++index) {
                pointer = (pointer << 8U) | byte_at(section, offset++);
            }
            if (length == 2U) pointer += 2048U;
            if (length == 3U) pointer += 526336U;
            return Value{kPointer, pointer, offset, 0U};
        }
        if (type == 0U) {
            const std::uint8_t extended = byte_at(section, offset++);
            if (extended == 0U || extended > 8U) fail("country database has an unknown value type");
            type = 7U + extended;
        }
        std::size_t size = lead & 0x1fU;
        if (size >= 29U) {
            const unsigned extra = static_cast<unsigned>(size) - 28U;
            std::size_t tail = 0U;
            for (unsigned index = 0U; index < extra; ++index) {
                tail = (tail << 8U) | byte_at(section, offset++);
            }
            size = (size == 29U ? 29U : size == 30U ? 285U : 65821U) + tail;
        }
        switch (type) {
        case kMap:
        case kArray:
        case kBoolean:
            if (type == kBoolean && size > 1U) fail("country database has a malformed boolean");
            return Value{type, size, offset, 0U};
        case kString:
        case 4U:   // bytes
        case 5U:   // uint16
        case 6U:   // uint32
        case 8U:   // int32
        case 9U:   // uint64
        case 10U:  // uint128
        case 3U:   // double
        case 15U:  // float
            if ((type == 3U && size != 8U) || (type == 15U && size != 4U) ||
                (type == 5U && size > 2U) || ((type == 6U || type == 8U) && size > 4U) ||
                (type == 9U && size > 8U) || (type == 10U && size > 16U)) {
                fail("country database has a malformed number");
            }
            if (size > section.end - offset || offset < section.start) {
                fail("country database value is out of bounds");
            }
            return Value{type, size, offset, 0U};
        default:
            fail("country database has an unexpected value type");
        }
    }

    // Returns the offset after the value at `offset`.
    std::size_t skip(const Section& section, std::size_t offset, unsigned depth,
                     std::size_t& budget) const {
        if (budget-- == 0U || depth > kMaxDepth) fail("country database record is too complex");
        const Value value = read(section, offset);
        std::size_t end = value.payload;
        if (value.type == kMap || value.type == kArray) {
            const std::size_t items = value.type == kMap ? 2U : 1U;
            for (std::size_t index = 0U; index < value.size; ++index) {
                for (std::size_t part = 0U; part < items; ++part) {
                    end = skip(section, end, depth + 1U, budget);
                }
            }
        } else if (value.type != kBoolean) {
            end = value.payload + value.size;
        }
        return value.after_pointer != 0U ? value.after_pointer : end;
    }

    // The offset of the value stored under a key in a map, or nullopt.
    std::optional<std::size_t> find(const Section& section, const Value& map, std::string_view key,
                                    unsigned depth, std::size_t& budget) const {
        std::size_t position = map.payload;
        for (std::size_t index = 0U; index < map.size; ++index) {
            if (budget-- == 0U) fail("country database record is too complex");
            const Value name = read(section, position);
            if (name.type != kString) fail("country database map has a key that is not a string");
            position = name.after_pointer != 0U ? name.after_pointer : name.payload + name.size;
            if (std::string_view(reinterpret_cast<const char*>(data_.data() + name.payload), name.size) == key) {
                return position;
            }
            position = skip(section, position, depth + 1U, budget);
        }
        return std::nullopt;
    }

    std::uint64_t read_unsigned(const Section& section, std::size_t offset) const {
        const Value value = read(section, offset);
        if ((value.type != 5U && value.type != 6U && value.type != 9U) || value.size > 8U) {
            fail("country database metadata has a malformed number");
        }
        std::uint64_t result = 0U;
        for (std::size_t index = 0U; index < value.size; ++index) {
            result = (result << 8U) | data_[value.payload + index];
        }
        return result;
    }

    std::uint32_t record(std::uint32_t node, bool right) const noexcept {
        const std::uint8_t* bytes = data_.data() + static_cast<std::size_t>(node) * node_bytes_;
        const auto at = [bytes](std::size_t index) { return static_cast<std::uint32_t>(bytes[index]); };
        switch (record_bits_) {
        case 24U:
            return right ? (at(3) << 16U) | (at(4) << 8U) | at(5)
                         : (at(0) << 16U) | (at(1) << 8U) | at(2);
        case 28U:
            return right ? ((at(3) & 0x0fU) << 24U) | (at(4) << 16U) | (at(5) << 8U) | at(6)
                         : ((at(3) & 0xf0U) << 20U) | (at(0) << 16U) | (at(1) << 8U) | at(2);
        default:
            return right ? (at(4) << 24U) | (at(5) << 16U) | (at(6) << 8U) | at(7)
                         : (at(0) << 24U) | (at(1) << 16U) | (at(2) << 8U) | at(3);
        }
    }

    // A record past the node count points into the data section.
    std::size_t leaf_offset(std::uint32_t value) const {
        const std::size_t relative = static_cast<std::size_t>(value - node_count_);
        if (relative < 16U) fail("country database record points into the separator");
        const std::size_t offset = tree_bytes_ + relative;
        if (offset >= data_section_.end) fail("country database record is out of bounds");
        return offset;
    }

    // A tree visits each node once. MaxMind aliases the IPv4 subtree a few
    // times under IPv6, so allow that and refuse a shared-node explosion.
    std::size_t visit_limit() const noexcept {
        return static_cast<std::size_t>(node_count_) * 8U + 1024U;
    }

    std::span<const std::uint8_t> data_;
    std::uint32_t node_count_{0};
    unsigned record_bits_{0};
    unsigned ip_version_{0};
    std::size_t node_bytes_{0};
    std::size_t tree_bytes_{0};
    Section data_section_{0U, 0U};
};

// Active ranges per specificity and action, with the highest occupied
// specificity found from a bit mask.
class ActiveCounts final {
public:
    void add(std::uint8_t specificity, EgressListAction action) noexcept {
        if (total(specificity) == 0U) mask_[specificity / 64U] |= bit(specificity);
        ++counts_[specificity][index(action)];
    }
    void remove(std::uint8_t specificity, EgressListAction action) noexcept {
        --counts_[specificity][index(action)];
        if (total(specificity) == 0U) mask_[specificity / 64U] &= ~bit(specificity);
    }
    EgressListAction best() const noexcept {
        for (std::size_t word = mask_.size(); word-- > 0U;) {
            if (mask_[word] == 0U) continue;
            const std::size_t specificity =
                word * 64U + 63U - static_cast<std::size_t>(std::countl_zero(mask_[word]));
            return counts_[specificity][index(EgressListAction::Deny)] != 0U
                ? EgressListAction::Deny
                : EgressListAction::Allow;
        }
        return EgressListAction::Deny;
    }

private:
    static std::size_t index(EgressListAction action) noexcept {
        return action == EgressListAction::Deny ? 1U : 0U;
    }
    static std::uint64_t bit(std::uint8_t specificity) noexcept {
        return std::uint64_t{1} << (specificity % 64U);
    }
    std::uint32_t total(std::uint8_t specificity) const noexcept {
        return counts_[specificity][0] + counts_[specificity][1];
    }

    std::array<std::array<std::uint32_t, 2>, 129> counts_{};
    std::array<std::uint64_t, 3> mask_{};
};

}  // namespace

std::optional<EgressListAction> EgressListRules::match(
    IpFamily family, std::span<const std::uint8_t> address) const noexcept {
    if (address.size() != address_bytes(family)) return std::nullopt;
    Address key{};
    std::copy(address.begin(), address.end(), key.begin());
    const auto& segments = family == IpFamily::V4 ? v4_ : v6_;
    auto found = std::upper_bound(segments.begin(), segments.end(), key,
                                  [](const Address& value, const Segment& segment) {
                                      return value < segment.first;
                                  });
    if (found == segments.begin()) return std::nullopt;
    --found;
    if (key > found->last) return std::nullopt;
    return found->action;
}

Status EgressListBuilder::add_json_list(std::string_view text, EgressListAction action) {
    return guarded([&] {
        if (text.size() > kMaxJsonListBytes) fail("list is larger than 16 MiB");
        JsonListReader reader;
        const bool parsed = nlohmann::json::sax_parse(text.begin(), text.end(), &reader);
        if (!parsed || !reader.complete()) {
            fail(reader.error.empty() ? "list must name \"ips\" or \"countries\"" : reader.error);
        }
        std::vector<Range> v4;
        std::vector<Range> v6;
        for (const auto& network : reader.networks) {
            auto& family = network.family == IpFamily::V4 ? v4 : v6;
            family.push_back(Range{network.address,
                                   with_host_bits(network.address, network.prefix_length, network.family),
                                   network.prefix_length, action});
        }
        if (!reader.countries.empty() && country_database_added_) {
            return status_of(StatusCode::FailedPrecondition,
                             "a list that names countries must come before the country database");
        }
        std::vector<Country> countries;
        countries.reserve(reader.countries.size());
        for (const auto& code : reader.countries) countries.push_back(Country{code, action});
        return take(std::move(v4), std::move(v6), std::move(countries));
    });
}

Status EgressListBuilder::add_vpdb(std::span<const std::uint8_t> data, EgressListAction action) {
    return guarded([&] {
        if (data.size() > kMaxVpdbBytes) fail("VPN database is larger than 128 MiB");
        ByteReader reader(data);
        const auto magic = reader.take(4U, "VPN database header");
        if (std::memcmp(magic.data(), "VPDB", 4U) != 0) fail("not a VPN database");
        // The version and three reserved bytes.
        const std::uint8_t version = reader.take(4U, "VPN database header")[0];
        if (version != 1U) fail("unsupported VPN database version " + std::to_string(version));
        const std::uint64_t providers = reader.u32le("VPN database header");
        const std::uint64_t v4_exact = reader.u32le("VPN database header");
        const std::uint64_t v4_ranges = reader.u32le("VPN database header");
        const std::uint64_t v6_exact = reader.u32le("VPN database header");
        const std::uint64_t v6_ranges = reader.u32le("VPN database header");
        // Provider names only label entries. Each entry names one by index.
        for (std::uint64_t index = 0U; index < providers; ++index) {
            (void)reader.take(reader.u16le("VPN database provider"), "VPN database provider");
        }
        if (v4_exact + v4_ranges + v6_exact + v6_ranges > kMaxEgressListRanges) {
            fail("VPN database has more than " + std::to_string(kMaxEgressListRanges) + " entries");
        }
        if (v4_exact * 6U + v4_ranges * 10U + v6_exact * 18U + v6_ranges * 34U != reader.remaining()) {
            fail("VPN database size does not match its entry counts");
        }
        std::vector<Range> v4;
        std::vector<Range> v6;
        v4.reserve(static_cast<std::size_t>(v4_exact + v4_ranges));
        v6.reserve(static_cast<std::size_t>(v6_exact + v6_ranges));
        const auto add_range = [&](std::vector<Range>& family, IpFamily kind,
                                   const Address& first, const Address& last) {
            if (last < first) fail("VPN database has a range that ends before it starts");
            family.push_back(Range{first, last, shared_prefix(first, last, kind), action});
        };
        for (std::uint64_t index = 0U; index < v4_exact; ++index) {
            const Address address = reader.ipv4_le("VPN database entry");
            (void)reader.u16le("VPN database entry");
            add_range(v4, IpFamily::V4, address, address);
        }
        for (std::uint64_t index = 0U; index < v4_ranges; ++index) {
            const Address first = reader.ipv4_le("VPN database entry");
            const Address last = reader.ipv4_le("VPN database entry");
            (void)reader.u16le("VPN database entry");
            add_range(v4, IpFamily::V4, first, last);
        }
        for (std::uint64_t index = 0U; index < v6_exact; ++index) {
            const Address address = reader.ipv6("VPN database entry");
            (void)reader.u16le("VPN database entry");
            add_range(v6, IpFamily::V6, address, address);
        }
        for (std::uint64_t index = 0U; index < v6_ranges; ++index) {
            const Address first = reader.ipv6("VPN database entry");
            const Address last = reader.ipv6("VPN database entry");
            (void)reader.u16le("VPN database entry");
            add_range(v6, IpFamily::V6, first, last);
        }
        return take(std::move(v4), std::move(v6), {});
    });
}

Status EgressListBuilder::add_country_database(std::span<const std::uint8_t> data) {
    if (country_database_added_) {
        return status_of(StatusCode::FailedPrecondition, "a country database was already added");
    }
    return guarded([&] {
        if (data.size() > kMaxCountryDatabaseBytes) fail("country database is larger than 128 MiB");
        const MmdbFile file(data);
        // Each record's country is decoded once. Zero means no listed country.
        std::unordered_map<std::size_t, std::uint8_t> actions;
        const auto listed = [&](std::size_t offset) {
            const auto cached = actions.find(offset);
            if (cached != actions.end()) return cached->second;
            std::uint8_t mask = 0U;
            if (const auto code = file.country_at(offset)) {
                for (const auto& country : countries_) {
                    if (country.code == *code) {
                        mask = static_cast<std::uint8_t>(mask | (country.action == EgressListAction::Deny ? 2U : 1U));
                    }
                }
            }
            actions.emplace(offset, mask);
            return mask;
        };
        std::vector<Range> v4;
        std::vector<Range> v6;
        std::size_t visits = 0U;
        std::size_t added = 0U;
        for (const IpFamily family : {IpFamily::V4, IpFamily::V6}) {
            auto& ranges = family == IpFamily::V4 ? v4 : v6;
            file.flatten(family, visits, [&](const Address& first, const Address& last, std::size_t offset) {
                const std::uint8_t mask = listed(offset);
                for (const auto action : {EgressListAction::Allow, EgressListAction::Deny}) {
                    if ((mask & (action == EgressListAction::Deny ? 2U : 1U)) == 0U) continue;
                    if (++added + v4_.size() + v6_.size() > kMaxEgressListRanges) {
                        fail("egress lists have more than " + std::to_string(kMaxEgressListRanges) + " ranges");
                    }
                    ranges.push_back(Range{first, last, 0U, action});
                }
            });
        }
        Status status = take(std::move(v4), std::move(v6), {});
        if (status.ok()) country_database_added_ = true;
        return status;
    });
}

Status EgressListBuilder::take(std::vector<Range>&& v4, std::vector<Range>&& v6,
                               std::vector<Country>&& countries) {
    if (v4_.size() + v6_.size() + v4.size() + v6.size() > kMaxEgressListRanges) {
        fail("egress lists have more than " + std::to_string(kMaxEgressListRanges) + " ranges");
    }
    // Reserve everything first. The inserts below cannot fail after that.
    v4_.reserve(v4_.size() + v4.size());
    v6_.reserve(v6_.size() + v6.size());
    countries_.reserve(countries_.size() + countries.size());
    v4_.insert(v4_.end(), v4.begin(), v4.end());
    v6_.insert(v6_.end(), v6.begin(), v6.end());
    for (const auto& country : countries) {
        const bool known = std::any_of(countries_.begin(), countries_.end(), [&](const Country& seen) {
            return seen.code == country.code && seen.action == country.action;
        });
        if (!known) countries_.push_back(country);
    }
    return Status::success();
}

std::vector<EgressListRules::Segment> EgressListBuilder::flatten(std::vector<Range>& ranges,
                                                                 IpFamily family) {
    std::sort(ranges.begin(), ranges.end(),
              [](const Range& left, const Range& right) { return left.first < right.first; });
    struct Active final {
        Address last;
        std::uint8_t specificity;
        EgressListAction action;
    };
    const auto ends_later = [](const Active& left, const Active& right) { return left.last > right.last; };
    std::priority_queue<Active, std::vector<Active>, decltype(ends_later)> active(ends_later);
    ActiveCounts counts;
    std::vector<EgressListRules::Segment> segments;
    const auto emit = [&](const Address& first, const Address& last, EgressListAction action) {
        if (!segments.empty() && segments.back().action == action) {
            Address after = segments.back().last;
            if (increment(after, family) && after == first) {
                segments.back().last = last;
                return;
            }
        }
        segments.push_back(EgressListRules::Segment{first, last, action});
    };

    std::size_t next = 0U;
    Address position{};
    while (next < ranges.size() || !active.empty()) {
        if (active.empty()) position = ranges[next].first;
        while (next < ranges.size() && ranges[next].first == position) {
            active.push(Active{ranges[next].last, ranges[next].specificity, ranges[next].action});
            counts.add(ranges[next].specificity, ranges[next].action);
            ++next;
        }
        // The segment ends where the first active range ends or just before
        // the next range starts, whichever comes first.
        Address last = active.top().last;
        if (next < ranges.size() && ranges[next].first <= last) {
            last = ranges[next].first;
            decrement(last, family);
        }
        emit(position, last, counts.best());
        while (!active.empty() && active.top().last == last) {
            counts.remove(active.top().specificity, active.top().action);
            active.pop();
        }
        // A segment that reaches the top of the address space ends the sweep.
        if (!increment(last, family)) break;
        position = last;
    }
    return segments;
}

engine::Result<std::shared_ptr<const EgressListRules>> EgressListBuilder::build() {
    using Built = engine::Result<std::shared_ptr<const EgressListRules>>;
    if (!countries_.empty() && !country_database_added_) {
        return Built(status_of(StatusCode::FailedPrecondition,
                               "a list names countries, so a country database is required"));
    }
    try {
        auto rules = std::make_shared<EgressListRules>();
        rules->v4_ = flatten(v4_, IpFamily::V4);
        rules->v6_ = flatten(v6_, IpFamily::V6);
        return Built(std::shared_ptr<const EgressListRules>(std::move(rules)));
    } catch (const std::bad_alloc&) {
        return Built(status_of(StatusCode::ResourceExhausted, "egress lists exceed available memory"));
    } catch (const std::length_error&) {
        return Built(status_of(StatusCode::ResourceExhausted, "egress lists exceed available memory"));
    }
}

}  // namespace yume::runtime
