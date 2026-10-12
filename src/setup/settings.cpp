/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "setup/actions.hpp"

#include "config/v1/config.hpp"
#include "setup/files.hpp"
#include "setup/provision.hpp"

namespace yume::setup {

void tune_client(const std::filesystem::path& config,
                 const std::optional<std::string>& preset,
                 const std::optional<std::string>& setting) {
    namespace v1 = config::v1;
    if (preset.has_value() == setting.has_value())
        throw SetupError("tune needs exactly one preset or expert value");

    // Validate the original text first: materializing JSON would otherwise
    // discard duplicate keys and bypass the parser's nesting bound.
    const auto input = read_secret(config, v1::kMaxDocumentBytes);
    if (v1::ParseJson(input.text()).role() != v1::Role::Client)
        throw SetupError("tune requires a client configuration");
    auto document = Json::parse(input.text());
    if (preset) {
        const auto* chosen = find_preset(*preset);
        if (chosen == nullptr) throw SetupError("unknown tuning preset");
        document["limits"].update(chosen->limits);
    } else {
        const auto equals = setting->find('=');
        if (equals == std::string::npos)
            throw SetupError("--set needs KEY=JSON");
        const auto key = setting->substr(0, equals);
        // The table owns the tuning keys. The schema parser owns their
        // types, ranges and cross-field constraints, including expert input.
        if (!find_preset(default_preset())->limits.contains(key))
            throw SetupError("--set must name a tuning limit");
        const auto value = std::string_view(*setting).substr(equals + 1U);
        // Tuning accepts only scalar values. Bound work before JSON parsing.
        if (value.empty() || value.size() > 32U ||
            value.find_first_of("[{\"") != std::string_view::npos)
            throw SetupError("--set needs a numeric or boolean JSON value");
        auto parsed = Json::parse(value, nullptr, false);
        if (parsed.is_discarded()) throw SetupError("invalid --set JSON value");
        document["limits"][key] = std::move(parsed);
    }
    const auto output = json_text(document);
    static_cast<void>(v1::ParseJson(output));

    // One rename publishes a complete configuration. Staging owns cleanup
    // before any write, including allocation failure and termination.
    const auto target = std::filesystem::absolute(config);
    const auto owner = owner_of(target);
    Staging staging(target.parent_path());
    const auto replacement = staging.path() / "yume.json";
    write_new_file(replacement, as_bytes(output));
    if (running_as_root()) give_to(replacement, owner);
    rename_replace(replacement, target);
    try {
        fsync_directory(target.parent_path());
    } catch (const SetupError& error) {
        throw PartialCommitError(
            "configuration was replaced, but directory durability was not "
            "confirmed: " + std::string(error.what()));
    }
}

}  // namespace yume::setup
