/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <QJsonObject>
#include <QVariantList>
#include <QVariantMap>

namespace yume::gui {

// The tuning presets of config/tuning_presets.json, which the build embeds
// unchanged, so the GUI names a preset by the same table yume-setup writes
// and yume-doctor reads.
class Presets final {
public:
    // Loads the embedded table. An unreadable table leaves no presets, and
    // every configuration then shows as custom.
    Presets();

    // Each preset as {id, limits, levels}, in the table's order.
    const QVariantList& list() const noexcept { return list_; }
    // What each level measures, keyed by speed, security and stealth.
    const QVariantMap& level_notes() const noexcept { return notes_; }
    // The preset whose four limits equal limits, a status reply's
    // posture.limits, or an empty map for custom limits.
    QVariantMap match(const QJsonObject& limits) const;
    QVariantMap named(const QString& id) const;
    QVariantMap move(const QString& id, const QString& axis, int level) const;
    const QVariantMap& measurements() const noexcept { return measurements_; }
    const QVariantList& fields() const noexcept { return fields_; }
    QVariantMap defaults() const {
        return named(default_).value("limits").toMap();
    }

private:
    QVariantList list_;
    QVariantMap notes_;
    QVariantMap measurements_;
    QVariantList fields_;
    QString default_;
    bool coupling_supported_{false};
};

}  // namespace yume::gui
