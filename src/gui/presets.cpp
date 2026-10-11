/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "gui/presets.hpp"

#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <array>
#include <cstdlib>
#include <limits>

namespace yume::gui {
namespace {

// The limits a preset sets, compared exactly, as yume-doctor compares them.
constexpr const char* kLimitKeys[] = {"max_queued_bytes", "max_epoch_bytes",
                                      "credit_returns_per_window",
                                      "idle_epoch_rotation"};

bool same_value(const QJsonValue& left, const QJsonValue& right) {
    if (left.isBool() || right.isBool())
        return left.isBool() && right.isBool() &&
               left.toBool() == right.toBool();
    return left.isDouble() && right.isDouble() &&
           left.toDouble() == right.toDouble();
}

}  // namespace

Presets::Presets() {
    QFile file(QStringLiteral(":/yume/tuning_presets.json"));
    if (!file.open(QIODevice::ReadOnly)) return;
    const auto root = QJsonDocument::fromJson(file.readAll()).object();
    if (root.value(QStringLiteral("schema")).toInt() != 1) return;
    notes_ = root.value(QStringLiteral("levels")).toObject().toVariantMap();
    measurements_ = root.value("measurements").toObject().toVariantMap();
    fields_ = root.value("fields").toArray().toVariantList();
    default_ = root.value("default").toString();
    coupling_supported_ = root.value("coupling").toObject().value("rule") ==
                          QStringLiteral("nearest-levels-v1");
    for (const auto& value : root.value(QStringLiteral("presets")).toArray())
        list_.append(value.toObject().toVariantMap());
}

QVariantMap Presets::named(const QString& id) const {
    for (const auto& value : list_) {
        const auto entry = value.toMap();
        if (entry.value("id").toString() == id) return entry;
    }
    return {};
}

QVariantMap Presets::move(const QString& id, const QString& axis,
                          int level) const {
    const QStringList axes{"stealth", "security", "speed"};
    const auto current = named(id).value("levels").toMap();
    if (!coupling_supported_ || current.isEmpty() || !axes.contains(axis))
        return {};
    QVariantMap chosen;
    std::array<int, 4> best{std::numeric_limits<int>::max(), 0, 0, 0};
    for (const auto& value : list_) {
        const auto entry = value.toMap();
        const auto levels = entry.value("levels").toMap();
        if (levels.value(axis).toInt() != level) continue;
        int distance = 0;
        for (const auto& other : axes)
            if (other != axis)
                distance += std::abs(levels.value(other).toInt() -
                                     current.value(other).toInt());
        const std::array<int, 4> score{
            distance, -levels.value("stealth").toInt(),
            -levels.value("security").toInt(), levels.value("speed").toInt()};
        if (score < best) {
            best = score;
            chosen = entry;
        }
    }
    return chosen;
}

QVariantMap Presets::match(const QJsonObject& limits) const {
    for (const auto& entry : list_) {
        const auto preset = entry.toMap();
        const auto wanted = QJsonObject::fromVariantMap(
            preset.value(QStringLiteral("limits")).toMap());
        bool same = true;
        for (const char* key : kLimitKeys) {
            const auto name = QString::fromLatin1(key);
            if (!same_value(wanted.value(name), limits.value(name))) {
                same = false;
                break;
            }
        }
        if (same) return preset;
    }
    return {};
}

}  // namespace yume::gui
