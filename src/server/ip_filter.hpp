/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include <boost/asio/ip/address.hpp>

namespace yume::server {

enum class FilterAction {
    Allow,
    Deny,
};

enum class FilterMode {
    Blacklist,
    Whitelist,
};

enum FilterPlane : std::uint8_t {
    kFilterPlaneClient = 1u << 0,
    kFilterPlaneEgress = 1u << 1,
};

struct FilterListSpec {
    std::uint8_t planes{0};
    FilterAction action{FilterAction::Deny};
    std::string path;
};

struct FilterDecision {
    bool allowed{true};
    bool matched{false};
    FilterAction action{FilterAction::Allow};
    int specificity{-1};
    std::string source;
};

class IpFilter {
public:
    IpFilter() = default;
    ~IpFilter();

    IpFilter(const IpFilter&) = delete;
    IpFilter& operator=(const IpFilter&) = delete;

    void configure(FilterMode client_mode, FilterMode egress_mode);
    bool load(const std::vector<FilterListSpec>& specs,
              const std::string& geolite_archive,
              std::uint32_t memory_mib,
              std::string* error);

    bool active() const;
    std::string summary() const;

    FilterDecision check_client(const boost::asio::ip::address& address) const;
    FilterDecision check_egress(const boost::asio::ip::address& address) const;

    static std::optional<FilterMode> parse_mode(const std::string& text);
    static std::optional<FilterListSpec> parse_list_spec(const std::string& text, std::string* error);

private:
    struct Ipv4RangeRule {
        std::uint32_t start{0};
        std::uint32_t end{0};
        int specificity{0};
        FilterAction action{FilterAction::Deny};
        std::string source;
    };

    struct Ipv6RangeRule {
        std::array<std::uint8_t, 16> start{};
        std::array<std::uint8_t, 16> end{};
        int specificity{0};
        FilterAction action{FilterAction::Deny};
        std::string source;
    };

    struct CountryRule {
        std::string iso;
        FilterAction action{FilterAction::Deny};
        std::string source;
    };

    struct PlaneRules {
        std::vector<Ipv4RangeRule> ipv4;
        std::vector<Ipv6RangeRule> ipv6;
        std::vector<CountryRule> countries;
    };

    struct CountryRange {
        std::uint32_t start{0};
        std::uint32_t end{0};
        std::string iso;
    };

    FilterDecision check(const boost::asio::ip::address& address,
                         const PlaneRules& rules,
                         FilterMode mode) const;

    bool load_list_path(const FilterListSpec& spec, std::uint32_t memory_mib, std::string* error);
    bool load_custom_json(const std::filesystem::path& path,
                          const FilterListSpec& spec,
                          std::string* error);
    bool load_vpdb(const std::filesystem::path& path,
                   const FilterListSpec& spec,
                   std::string* error);
    bool load_geolite(const std::string& geolite_archive, std::string* error);
    bool load_compact_country_db(const std::filesystem::path& dir);
    bool load_mmdb_country_db(const std::filesystem::path& path, std::string* error);

    std::filesystem::path extract_archive(const std::filesystem::path& archive,
                                          const std::string& label,
                                          std::string* error);
    void add_ip_rule(std::uint8_t planes,
                     FilterAction action,
                     const std::string& text,
                     const std::string& source);
    void add_ipv4_rule(std::uint8_t planes,
                       FilterAction action,
                       std::uint32_t start,
                       std::uint32_t end,
                       int specificity,
                       const std::string& source);
    void add_ipv6_rule(std::uint8_t planes,
                       FilterAction action,
                       const std::array<std::uint8_t, 16>& start,
                       const std::array<std::uint8_t, 16>& end,
                       int specificity,
                       const std::string& source);
    void add_country_rule(std::uint8_t planes,
                          FilterAction action,
                          const std::string& iso,
                          const std::string& source);

    std::optional<std::string> lookup_country(std::uint32_t ipv4) const;
    std::optional<std::string> lookup_mmdb_country(std::uint32_t ipv4) const;
    std::size_t estimated_memory_bytes() const;
    void cleanup_runtime_dir();

    FilterMode client_mode_{FilterMode::Blacklist};
    FilterMode egress_mode_{FilterMode::Blacklist};
    PlaneRules client_;
    PlaneRules egress_;
    std::vector<CountryRange> countries_;
    std::vector<std::uint8_t> mmdb_data_;
    std::uint32_t mmdb_node_count_{0};
    std::uint32_t mmdb_record_size_{0};
    std::uint32_t mmdb_node_byte_size_{0};
    std::uint32_t mmdb_search_tree_size_{0};
    std::uint32_t mmdb_data_section_base_{0};
    std::uint32_t mmdb_ip_version_{0};
    std::filesystem::path runtime_dir_;
    std::uint32_t lists_loaded_{0};
    bool geolite_loaded_{false};
};

}  // namespace yume::server
