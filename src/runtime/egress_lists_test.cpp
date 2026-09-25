/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/egress_lists.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>

namespace {
using yume::common::IpFamily;
using yume::engine::StatusCode;
using yume::runtime::EgressListAction;
using yume::runtime::EgressListBuilder;
using yume::runtime::EgressListRules;
using Bytes = std::vector<std::uint8_t>;

#define CHECK(condition) do { if (!(condition)) { \
    std::cerr << "egress lists check failed at " << __LINE__ << ": " #condition "\n"; \
    std::abort(); \
} } while (false)

constexpr auto kAllow = EgressListAction::Allow;
constexpr auto kDeny = EgressListAction::Deny;

std::shared_ptr<const EgressListRules> build(EgressListBuilder& builder) {
    auto built = builder.build();
    CHECK(built.ok());
    return std::move(built).take_value();
}

std::optional<EgressListAction> v4(const EgressListRules& rules, std::array<std::uint8_t, 4> address) {
    return rules.match(IpFamily::V4, address);
}

std::array<std::uint8_t, 16> v6_bytes(const char* text) {
    const auto network = yume::common::parse_ip_network(text);
    CHECK(network && network->family == IpFamily::V6 && network->prefix_length == 128U);
    return network->address;
}

std::optional<EgressListAction> v6(const EgressListRules& rules, const char* text) {
    return rules.match(IpFamily::V6, v6_bytes(text));
}

void expect_refused(yume::engine::Status status, StatusCode code, const std::string& fragment) {
    CHECK(!status.ok());
    CHECK(status.code() == code);
    if (status.message().find(fragment) == std::string::npos) {
        std::cerr << "unexpected message: " << status.message() << "\n";
        std::abort();
    }
}

// --- VPN provider database -------------------------------------------------

struct VpdbRange final {
    std::array<std::uint8_t, 16> first{};
    std::array<std::uint8_t, 16> last{};
};

void put_u16(Bytes& out, std::uint16_t value) {
    out.push_back(static_cast<std::uint8_t>(value));
    out.push_back(static_cast<std::uint8_t>(value >> 8U));
}
void put_u32(Bytes& out, std::uint32_t value) {
    for (unsigned shift = 0U; shift < 32U; shift += 8U) out.push_back(static_cast<std::uint8_t>(value >> shift));
}
std::uint32_t ipv4_value(const std::array<std::uint8_t, 16>& address) {
    return (static_cast<std::uint32_t>(address[0]) << 24U) | (static_cast<std::uint32_t>(address[1]) << 16U) |
           (static_cast<std::uint32_t>(address[2]) << 8U) | address[3];
}

Bytes vpdb(const std::vector<std::array<std::uint8_t, 4>>& v4_exact,
           const std::vector<VpdbRange>& v4_ranges,
           const std::vector<std::array<std::uint8_t, 16>>& v6_exact,
           const std::vector<VpdbRange>& v6_ranges) {
    Bytes out{'V', 'P', 'D', 'B', 1, 0, 0, 0};
    put_u32(out, 2U);
    put_u32(out, static_cast<std::uint32_t>(v4_exact.size()));
    put_u32(out, static_cast<std::uint32_t>(v4_ranges.size()));
    put_u32(out, static_cast<std::uint32_t>(v6_exact.size()));
    put_u32(out, static_cast<std::uint32_t>(v6_ranges.size()));
    for (const std::string name : {"first", "second"}) {
        put_u16(out, static_cast<std::uint16_t>(name.size()));
        out.insert(out.end(), name.begin(), name.end());
    }
    for (const auto& address : v4_exact) {
        std::array<std::uint8_t, 16> padded{};
        std::copy(address.begin(), address.end(), padded.begin());
        put_u32(out, ipv4_value(padded));
        put_u16(out, 1U);
    }
    for (const auto& range : v4_ranges) {
        put_u32(out, ipv4_value(range.first));
        put_u32(out, ipv4_value(range.last));
        put_u16(out, 0U);
    }
    for (const auto& address : v6_exact) {
        out.insert(out.end(), address.begin(), address.end());
        put_u16(out, 0U);
    }
    for (const auto& range : v6_ranges) {
        out.insert(out.end(), range.first.begin(), range.first.end());
        out.insert(out.end(), range.last.begin(), range.last.end());
        put_u16(out, 1U);
    }
    return out;
}

VpdbRange v4_range(std::array<std::uint8_t, 4> first, std::array<std::uint8_t, 4> last) {
    VpdbRange range;
    std::copy(first.begin(), first.end(), range.first.begin());
    std::copy(last.begin(), last.end(), range.last.begin());
    return range;
}

// --- MaxMind DB writer -----------------------------------------------------

void control(Bytes& out, unsigned type, std::size_t size) {
    const unsigned stored = type > 7U ? 0U : type;
    std::uint8_t lead = static_cast<std::uint8_t>(stored << 5U);
    Bytes tail;
    if (size < 29U) {
        lead = static_cast<std::uint8_t>(lead | size);
    } else if (size < 285U) {
        lead = static_cast<std::uint8_t>(lead | 29U);
        tail.push_back(static_cast<std::uint8_t>(size - 29U));
    } else if (size < 65821U) {
        lead = static_cast<std::uint8_t>(lead | 30U);
        const std::size_t value = size - 285U;
        tail = {static_cast<std::uint8_t>(value >> 8U), static_cast<std::uint8_t>(value)};
    } else {
        lead = static_cast<std::uint8_t>(lead | 31U);
        const std::size_t value = size - 65821U;
        tail = {static_cast<std::uint8_t>(value >> 16U), static_cast<std::uint8_t>(value >> 8U),
                static_cast<std::uint8_t>(value)};
    }
    out.push_back(lead);
    if (type > 7U) out.push_back(static_cast<std::uint8_t>(type - 7U));
    out.insert(out.end(), tail.begin(), tail.end());
}
void text(Bytes& out, const std::string& value) {
    control(out, 2U, value.size());
    out.insert(out.end(), value.begin(), value.end());
}
void unsigned_value(Bytes& out, unsigned type, std::uint64_t value) {
    Bytes digits;
    for (; value != 0U; value >>= 8U) digits.insert(digits.begin(), static_cast<std::uint8_t>(value));
    control(out, type, digits.size());
    out.insert(out.end(), digits.begin(), digits.end());
}
void map(Bytes& out, std::size_t entries) { control(out, 7U, entries); }
void pointer(Bytes& out, std::size_t target) {
    if (target < 2048U) {
        out.push_back(static_cast<std::uint8_t>(0x20U | (target >> 8U)));
        out.push_back(static_cast<std::uint8_t>(target));
    } else if (target < 526336U) {
        const std::size_t value = target - 2048U;
        out.push_back(static_cast<std::uint8_t>(0x28U | (value >> 16U)));
        out.push_back(static_cast<std::uint8_t>(value >> 8U));
        out.push_back(static_cast<std::uint8_t>(value));
    } else {
        out.push_back(0x38U);
        for (unsigned shift = 32U; shift > 0U; shift -= 8U) out.push_back(static_cast<std::uint8_t>(target >> (shift - 8U)));
    }
}

class MmdbWriter final {
public:
    MmdbWriter(unsigned record_size, unsigned ip_version)
        : record_size_(record_size), ip_version_(ip_version), nodes_(1U) {}

    Bytes& data() { return data_; }

    // A record {"country": {"iso_code": code}} or the same under
    // registered_country. Returns its offset in the data section.
    std::size_t country(const std::string& code, bool registered = false) {
        const std::size_t offset = data_.size();
        map(data_, 2U);
        text(data_, "names");
        map(data_, 0U);
        text(data_, registered ? "registered_country" : "country");
        map(data_, 2U);
        text(data_, "geoname_id");
        unsigned_value(data_, 6U, 6252001U);
        text(data_, "iso_code");
        text(data_, code);
        return offset;
    }

    // Inserts a prefix of the tree's own width. Prefixes must not overlap.
    void insert(const std::array<std::uint8_t, 16>& address, unsigned length, std::size_t offset) {
        std::size_t node = 0U;
        for (unsigned bit = 0U;; ++bit) {
            const unsigned side = (address[bit / 8U] >> (7U - bit % 8U)) & 1U;
            if (bit + 1U == length) {
                nodes_[node][side] = Slot{Slot::Data, offset};
                return;
            }
            if (nodes_[node][side].kind != Slot::Node) {
                nodes_.push_back({});
                nodes_[node][side] = Slot{Slot::Node, nodes_.size() - 1U};
            }
            node = nodes_[node][side].value;
        }
    }
    void insert_v4(std::array<std::uint8_t, 4> address, unsigned length, std::size_t offset) {
        std::array<std::uint8_t, 16> full{};
        const std::size_t at = ip_version_ == 6U ? 12U : 0U;
        std::copy(address.begin(), address.end(), full.begin() + static_cast<std::ptrdiff_t>(at));
        insert(full, length + (ip_version_ == 6U ? 96U : 0U), offset);
    }
    // Points a slot at another node, which may form a cycle or a shared subtree.
    void link(std::size_t node, unsigned side, std::size_t target) {
        while (nodes_.size() <= std::max(node, target)) nodes_.push_back({});
        nodes_[node][side] = Slot{Slot::Node, target};
    }

    Bytes finish(bool separator_zero = true) const {
        const std::size_t count = nodes_.size();
        const auto value = [&](const Slot& slot) -> std::uint64_t {
            if (slot.kind == Slot::Node) return slot.value;
            if (slot.kind == Slot::Empty) return count;
            return count + 16U + slot.value;
        };
        Bytes out;
        for (const auto& node : nodes_) {
            const std::uint64_t left = value(node[0]);
            const std::uint64_t right = value(node[1]);
            if (record_size_ == 24U) {
                for (const std::uint64_t record : {left, right}) {
                    for (unsigned shift = 24U; shift > 0U; shift -= 8U) out.push_back(static_cast<std::uint8_t>(record >> (shift - 8U)));
                }
            } else if (record_size_ == 28U) {
                // The middle byte holds the top nibble of each record, left first.
                out.push_back(static_cast<std::uint8_t>(left >> 16U));
                out.push_back(static_cast<std::uint8_t>(left >> 8U));
                out.push_back(static_cast<std::uint8_t>(left));
                out.push_back(static_cast<std::uint8_t>(((left >> 24U) & 0x0fU) << 4U | ((right >> 24U) & 0x0fU)));
                out.push_back(static_cast<std::uint8_t>(right >> 16U));
                out.push_back(static_cast<std::uint8_t>(right >> 8U));
                out.push_back(static_cast<std::uint8_t>(right));
            } else {
                for (const std::uint64_t record : {left, right}) {
                    for (unsigned shift = 32U; shift > 0U; shift -= 8U) out.push_back(static_cast<std::uint8_t>(record >> (shift - 8U)));
                }
            }
        }
        for (int index = 0; index < 16; ++index) out.push_back(separator_zero ? 0U : 1U);
        out.insert(out.end(), data_.begin(), data_.end());
        out.insert(out.end(), {0xab, 0xcd, 0xef});
        const std::string marker = "MaxMind.com";
        out.insert(out.end(), marker.begin(), marker.end());
        map(out, 8U);
        text(out, "binary_format_major_version");
        unsigned_value(out, 5U, format_major_);
        text(out, "binary_format_minor_version");
        unsigned_value(out, 5U, 0U);
        text(out, "build_epoch");
        unsigned_value(out, 9U, 1700000000U);
        text(out, "database_type");
        text(out, "YUME-Test-Country");
        text(out, "ip_version");
        unsigned_value(out, 5U, ip_version_);
        text(out, "languages");
        control(out, 11U, 1U);
        text(out, "en");
        text(out, "node_count");
        unsigned_value(out, 6U, count);
        text(out, "record_size");
        unsigned_value(out, 5U, record_size_);
        return out;
    }

    void set_format_major(unsigned version) { format_major_ = version; }

private:
    struct Slot final {
        enum Kind { Empty, Node, Data } kind{Empty};
        std::size_t value{0};
    };

    unsigned record_size_;
    unsigned ip_version_;
    unsigned format_major_{2U};
    std::vector<std::array<Slot, 2>> nodes_;
    Bytes data_;
};

// --- tests ------------------------------------------------------------------

void test_specificity_and_ties() {
    EgressListBuilder builder;
    CHECK(builder.add_json_list(R"({"ips": ["10.0.0.0/8", "192.0.2.0/24", "2001:db8::/32"]})", kDeny).ok());
    CHECK(builder.add_json_list(R"({"ips": ["10.1.0.0/16", "192.0.2.0/24", "2001:db8:1::/48"]})", kAllow).ok());
    CHECK(builder.add_json_list(R"({"ips": ["10.1.2.3"]})", kDeny).ok());
    const auto rules = build(builder);
    CHECK(v4(*rules, {10, 2, 0, 1}) == kDeny);
    CHECK(v4(*rules, {10, 1, 9, 9}) == kAllow);
    CHECK(v4(*rules, {10, 1, 2, 3}) == kDeny);
    CHECK(v4(*rules, {10, 1, 2, 4}) == kAllow);
    CHECK(v4(*rules, {192, 0, 2, 7}) == kDeny);  // equal specificity, Deny wins
    CHECK(!v4(*rules, {11, 0, 0, 1}));
    CHECK(!v4(*rules, {9, 255, 255, 255}));
    CHECK(v6(*rules, "2001:db8:2::1") == kDeny);
    CHECK(v6(*rules, "2001:db8:1::1") == kAllow);
    CHECK(!v6(*rules, "2001:db9::1"));
    // The families never mix, and an address of the wrong size matches nothing.
    CHECK(!rules->match(IpFamily::V6, v6_bytes("a01:203::")));
    CHECK(!rules->match(IpFamily::V4, std::array<std::uint8_t, 3>{10, 1, 2}));
}

void test_address_space_edges() {
    EgressListBuilder builder;
    CHECK(builder.add_json_list(R"({"ips": ["0.0.0.0/0", "::/0"]})", kDeny).ok());
    CHECK(builder.add_json_list(
              R"({"ips": ["255.255.255.255", "0.0.0.0", "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", "::"]})",
              kAllow).ok());
    const auto rules = build(builder);
    CHECK(v4(*rules, {0, 0, 0, 0}) == kAllow);
    CHECK(v4(*rules, {0, 0, 0, 1}) == kDeny);
    CHECK(v4(*rules, {255, 255, 255, 254}) == kDeny);
    CHECK(v4(*rules, {255, 255, 255, 255}) == kAllow);
    CHECK(v6(*rules, "::") == kAllow);
    CHECK(v6(*rules, "::1") == kDeny);
    CHECK(v6(*rules, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe") == kDeny);
    CHECK(v6(*rules, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") == kAllow);

    EgressListBuilder empty;
    CHECK(build(empty)->empty());
}

// Random overlapping ranges against a direct evaluation of the rule.
void test_sweep_matches_direct_evaluation() {
    std::mt19937 random(20260924U);
    for (int round = 0; round < 40; ++round) {
        struct Rule final {
            std::uint32_t first;
            std::uint32_t last;
            unsigned specificity;
            EgressListAction action;
        };
        std::vector<Rule> rules;
        std::vector<VpdbRange> deny;
        std::vector<VpdbRange> allow;
        const int count = 1 + static_cast<int>(random() % 12U);
        for (int index = 0; index < count; ++index) {
            std::uint32_t first = 0x0a000000U + random() % 512U;
            std::uint32_t last = first + random() % 200U;
            unsigned specificity = 0U;
            while (specificity < 32U && ((first ^ last) >> (31U - specificity) & 1U) == 0U) ++specificity;
            const auto action = random() % 2U == 0U ? kDeny : kAllow;
            rules.push_back(Rule{first, last, specificity, action});
            const auto bytes = [](std::uint32_t value) {
                return std::array<std::uint8_t, 4>{static_cast<std::uint8_t>(value >> 24U),
                                                   static_cast<std::uint8_t>(value >> 16U),
                                                   static_cast<std::uint8_t>(value >> 8U),
                                                   static_cast<std::uint8_t>(value)};
            };
            (action == kDeny ? deny : allow).push_back(v4_range(bytes(first), bytes(last)));
        }
        EgressListBuilder builder;
        CHECK(builder.add_vpdb(vpdb({}, deny, {}, {}), kDeny).ok());
        CHECK(builder.add_vpdb(vpdb({}, allow, {}, {}), kAllow).ok());
        const auto built = build(builder);
        for (std::uint32_t address = 0x0a000000U - 2U; address < 0x0a000000U + 720U; ++address) {
            std::optional<EgressListAction> expected;
            int best = -1;
            for (const auto& rule : rules) {
                if (address < rule.first || address > rule.last) continue;
                const int specificity = static_cast<int>(rule.specificity);
                if (specificity > best || (specificity == best && rule.action == kDeny)) {
                    best = specificity;
                    expected = rule.action;
                }
            }
            const auto actual = v4(*built, {static_cast<std::uint8_t>(address >> 24U),
                                             static_cast<std::uint8_t>(address >> 16U),
                                             static_cast<std::uint8_t>(address >> 8U),
                                             static_cast<std::uint8_t>(address)});
            CHECK(actual == expected);
        }
    }
}

void test_json_list_rules() {
    EgressListBuilder builder;
    CHECK(builder.add_json_list(R"({"ips": ["2001:0DB8:0000::/48"], "countries": ["de", "US", "US"]})", kDeny).ok());
    CHECK(builder.needs_country_database());
    expect_refused(builder.build().status(), StatusCode::FailedPrecondition, "country database");

    const auto refused = [](const std::string& list, const std::string& fragment) {
        EgressListBuilder fresh;
        expect_refused(fresh.add_json_list(list, kDeny), StatusCode::InvalidArgument, fragment);
        CHECK(fresh.build().ok() && fresh.build().value()->empty());
    };
    refused(R"({"ips": ["10.0.0.0/8", "10.0.0.1/8"]})", "/ips/1: must be an IPv4 or IPv6 address");
    refused(R"({"ips": ["10.0.0.01"]})", "/ips/0:");
    refused(R"({"ips": ["10.0.0.0/33"]})", "/ips/0:");
    refused(R"({"ips": ["::ffff:1.2.3.4"]})", "/ips/0:");
    refused(R"({"ips": ["fe80::1%eth0"]})", "/ips/0:");
    refused(R"({"ips": [7]})", "/ips/0: must be a string");
    refused(R"({"ips": [["10.0.0.1"]]})", "/ips/0: must be a string");
    refused(R"({"ips": [{"ip": "10.0.0.1"}]})", "/ips/0: must be a string");
    refused(R"({"ips": "10.0.0.1"})", "/ips: must be an array");
    refused(R"({"countries": {"US": true}})", "/countries: must be an array");
    refused(R"({"countries": ["USA"]})", "/countries/0: must be a two-letter country code");
    refused(R"({"countries": ["U1"]})", "/countries/0:");
    refused(R"({"ips": [], "ips": []})", "/ips: duplicate object key");
    refused(R"({"ips": [], "networks": []})", "keys must be");
    refused(R"({})", "must name");
    refused(R"(["10.0.0.1"])", "must be a JSON object");
    refused(R"("10.0.0.1")", "must be a JSON object");
    refused(R"({"ips": ["10.0.0.1"])", "invalid JSON syntax");
    refused(R"({"ips": []} {})", "invalid JSON syntax");
    refused(std::string(yume::runtime::kMaxJsonListBytes + 1U, ' '), "larger than 16 MiB");

    // A refused list adds none of its entries.
    EgressListBuilder partial;
    CHECK(!partial.add_json_list(R"({"ips": ["10.0.0.0/8", "bad"], "countries": ["US"]})", kDeny).ok());
    CHECK(!partial.needs_country_database());
    CHECK(build(partial)->empty());
}

void test_vpdb() {
    const auto address = v6_bytes("2001:db8::7");
    VpdbRange v6range;
    v6range.first = v6_bytes("2001:db8:5::");
    v6range.last = v6_bytes("2001:db8:5::ff");
    const Bytes valid = vpdb({{198, 51, 100, 7}}, {v4_range({10, 0, 0, 0}, {10, 0, 0, 255})}, {address}, {v6range});

    EgressListBuilder builder;
    CHECK(builder.add_vpdb(valid, kDeny).ok());
    // The range 10.0.0.0 to 10.0.0.255 counts as a /24, so a /25 overrides it.
    CHECK(builder.add_json_list(R"({"ips": ["10.0.0.0/25", "2001:db8:5::/120"]})", kAllow).ok());
    const auto rules = build(builder);
    CHECK(v4(*rules, {198, 51, 100, 7}) == kDeny);
    CHECK(!v4(*rules, {198, 51, 100, 8}));
    CHECK(v4(*rules, {10, 0, 0, 1}) == kAllow);
    CHECK(v4(*rules, {10, 0, 0, 200}) == kDeny);
    CHECK(v6(*rules, "2001:db8::7") == kDeny);
    CHECK(v6(*rules, "2001:db8:5::80") == kDeny);  // the same /120 on both sides

    const auto refused = [](const Bytes& data, const std::string& fragment) {
        EgressListBuilder fresh;
        expect_refused(fresh.add_vpdb(data, kDeny), StatusCode::InvalidArgument, fragment);
        CHECK(build(fresh)->empty());
    };
    Bytes bad = valid;
    bad[0] = 'X';
    refused(bad, "not a VPN database");
    bad = valid;
    bad[4] = 2U;
    refused(bad, "version 2");
    refused(Bytes(valid.begin(), valid.begin() + 20), "truncated");
    refused(Bytes(valid.begin(), valid.end() - 1), "does not match");
    bad = valid;
    bad.push_back(0U);
    refused(bad, "does not match");
    refused(vpdb({}, {v4_range({10, 0, 0, 9}, {10, 0, 0, 1})}, {}, {}), "ends before it starts");
    // Counts past the range bound are refused before anything is allocated.
    bad = valid;
    for (std::size_t index = 12U; index < 16U; ++index) bad[index] = 0xffU;
    refused(bad, "more than");
}

MmdbWriter sample(unsigned record_size) {
    MmdbWriter writer(record_size, 6U);
    const std::size_t us = writer.country("US");
    const std::size_t de = writer.country("DE");
    const std::size_t jp = writer.country("JP", true);
    writer.insert_v4({8, 0, 0, 0}, 8U, us);
    writer.insert_v4({193, 0, 0, 0}, 8U, de);
    writer.insert_v4({133, 0, 0, 0}, 8U, jp);
    writer.insert(v6_bytes("2600::"), 12U, us);
    writer.insert(v6_bytes("2a02::"), 16U, de);
    return writer;
}

void test_country_database() {
    for (const unsigned record_size : {24U, 28U, 32U}) {
        const Bytes database = sample(record_size).finish();
        EgressListBuilder builder;
        CHECK(builder.add_json_list(R"({"countries": ["US", "JP"], "ips": ["8.8.8.0/24"]})", kDeny).ok());
        CHECK(builder.add_json_list(R"({"countries": ["DE"], "ips": ["8.8.8.8"]})", kAllow).ok());
        CHECK(builder.add_country_database(database).ok());
        const auto rules = build(builder);
        CHECK(v4(*rules, {8, 1, 2, 3}) == kDeny);
        CHECK(v4(*rules, {8, 8, 8, 8}) == kAllow);  // an address rule overrides a country
        CHECK(v4(*rules, {193, 99, 144, 80}) == kAllow);
        CHECK(v4(*rules, {133, 242, 0, 1}) == kDeny);  // registered_country
        CHECK(!v4(*rules, {9, 0, 0, 1}));
        CHECK(v6(*rules, "2600:1f18::1") == kDeny);
        CHECK(v6(*rules, "2a02:6b8::1") == kAllow);
        CHECK(!v6(*rules, "2a03::1"));
        // The database was read once. A second one, or a later list that
        // names a country, is refused.
        expect_refused(builder.add_country_database(database), StatusCode::FailedPrecondition, "already");
        expect_refused(builder.add_json_list(R"({"countries": ["FR"]})", kDeny),
                       StatusCode::FailedPrecondition, "before the country database");
        CHECK(builder.add_json_list(R"({"ips": ["9.0.0.0/8"]})", kDeny).ok());
    }

    // An IPv4 database answers no IPv6 address.
    MmdbWriter ipv4(24U, 4U);
    ipv4.insert_v4({8, 0, 0, 0}, 8U, ipv4.country("US"));
    EgressListBuilder builder;
    CHECK(builder.add_json_list(R"({"countries": ["US"]})", kDeny).ok());
    CHECK(builder.add_country_database(ipv4.finish()).ok());
    const auto rules = build(builder);
    CHECK(v4(*rules, {8, 8, 4, 4}) == kDeny);
    CHECK(!v6(*rules, "2600::1"));

    // A leaf above ::/96 covers every IPv4 address.
    MmdbWriter shallow(24U, 6U);
    shallow.insert(v6_bytes("::"), 1U, shallow.country("US"));
    EgressListBuilder wide;
    CHECK(wide.add_json_list(R"({"countries": ["US"]})", kDeny).ok());
    CHECK(wide.add_country_database(shallow.finish()).ok());
    const auto covered = build(wide);
    CHECK(v4(*covered, {0, 0, 0, 0}) == kDeny);
    CHECK(v4(*covered, {255, 255, 255, 255}) == kDeny);
    CHECK(v6(*covered, "7fff::1") == kDeny);
    CHECK(!v6(*covered, "8000::1"));
}

// 28-bit records keep the top nibble of both records in the middle byte.
// The left leaf lies past 16 MiB of padding and needs a top nibble of 1, the
// right one needs 0, so reading either nibble for the other record fails.
void test_wide_28_bit_records() {
    MmdbWriter writer(28U, 4U);
    const std::size_t near = writer.country("DE");
    writer.data().resize(std::size_t{1} << 24U, 0U);
    const std::size_t far = writer.country("US");
    writer.insert_v4({0, 0, 0, 0}, 1U, far);
    writer.insert_v4({128, 0, 0, 0}, 1U, near);
    EgressListBuilder builder;
    CHECK(builder.add_json_list(R"({"countries": ["US"]})", kDeny).ok());
    CHECK(builder.add_json_list(R"({"countries": ["DE"]})", kAllow).ok());
    CHECK(builder.add_country_database(writer.finish()).ok());
    const auto rules = build(builder);
    CHECK(v4(*rules, {1, 2, 3, 4}) == kDeny);
    CHECK(v4(*rules, {200, 2, 3, 4}) == kAllow);
}

void test_country_database_refusals() {
    const auto refused = [](const Bytes& database, const std::string& fragment) {
        EgressListBuilder builder;
        CHECK(builder.add_json_list(R"({"countries": ["US"]})", kDeny).ok());
        expect_refused(builder.add_country_database(database), StatusCode::InvalidArgument, fragment);
        expect_refused(builder.build().status(), StatusCode::FailedPrecondition, "country database");
    };
    const Bytes good = sample(24U).finish();
    refused(Bytes(good.begin(), good.begin() + 64), "no MaxMind DB metadata");
    refused(sample(24U).finish(false), "separator");

    MmdbWriter old = sample(24U);
    old.set_format_major(1U);
    refused(old.finish(), "format 2");

    // A record size the format does not define.
    Bytes odd = good;
    const std::string key = "record_size";
    const auto at = std::search(odd.begin(), odd.end(), key.begin(), key.end());
    CHECK(at != odd.end());
    *(at + static_cast<std::ptrdiff_t>(key.size()) + 1) = 20U;
    refused(odd, "record size");

    // A country code that is not two capital letters.
    MmdbWriter lower(24U, 6U);
    lower.insert_v4({8, 0, 0, 0}, 8U, lower.country("us"));
    refused(lower.finish(), "malformed country code");
    MmdbWriter longer(24U, 6U);
    longer.insert_v4({8, 0, 0, 0}, 8U, longer.country("USA"));
    refused(longer.finish(), "malformed country code");

    // A country stored as a name, as in databases with another layout.
    MmdbWriter flat(24U, 6U);
    const std::size_t offset = flat.data().size();
    map(flat.data(), 1U);
    text(flat.data(), "country");
    text(flat.data(), "United States");
    flat.insert_v4({8, 0, 0, 0}, 8U, offset);
    refused(flat.finish(), "malformed country");

    // Keys reached through pointers work. A pointer to a pointer does not.
    MmdbWriter pointers(24U, 6U);
    Bytes& data = pointers.data();
    const std::size_t country_key = data.size();
    text(data, "country");
    const std::size_t via_pointer = data.size();
    pointer(data, country_key);
    const std::size_t record = data.size();
    map(data, 1U);
    pointer(data, country_key);
    map(data, 1U);
    text(data, "iso_code");
    text(data, "US");
    const std::size_t broken = data.size();
    map(data, 1U);
    pointer(data, via_pointer);
    map(data, 0U);
    pointers.insert_v4({8, 0, 0, 0}, 8U, record);
    {
        EgressListBuilder builder;
        CHECK(builder.add_json_list(R"({"countries": ["US"]})", kDeny).ok());
        CHECK(builder.add_country_database(pointers.finish()).ok());
        CHECK(v4(*build(builder), {8, 0, 0, 1}) == kDeny);
    }
    pointers.insert_v4({9, 0, 0, 0}, 8U, broken);
    refused(pointers.finish(), "points to a pointer");

    // A record that points into the sixteen-byte separator.
    MmdbWriter separator(24U, 6U);
    separator.country("US");
    Bytes into_separator = separator.finish();
    into_separator[5] = 2U;  // right record of node 0: node count + 1
    refused(into_separator, "separator");

    // A cycle runs off the end of the address.
    MmdbWriter cycle(24U, 4U);
    cycle.country("US");
    cycle.link(0U, 0U, 1U);
    cycle.link(1U, 0U, 0U);
    refused(cycle.finish(), "too deep");

    // Shared subtrees that double at every level are refused, not walked.
    MmdbWriter doubling(24U, 6U);
    const std::size_t leaf = doubling.country("US");
    for (std::size_t node = 0U; node < 40U; ++node) {
        doubling.link(node, 0U, node + 1U);
        doubling.link(node, 1U, node + 1U);
    }
    doubling.insert(v6_bytes("ffff::"), 1U, leaf);
    refused(doubling.finish(), "revisits too many nodes");

    refused(Bytes(yume::runtime::kMaxCountryDatabaseBytes + 1U, 0U), "larger than 128 MiB");
}

}  // namespace

int main() {
    test_specificity_and_ties();
    test_address_space_edges();
    test_sweep_matches_direct_evaluation();
    test_json_list_rules();
    test_vpdb();
    test_country_database();
    test_wide_28_bit_records();
    test_country_database_refusals();
    return 0;
}
