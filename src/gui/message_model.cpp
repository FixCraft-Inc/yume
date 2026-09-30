/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "gui/message_model.hpp"

#include <algorithm>

#include <QJsonArray>

namespace yume::gui {

MessageModel::MessageModel(QObject* parent) : QAbstractListModel(parent) {}

int MessageModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : count();
}

QVariant MessageModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() < 0 || index.row() >= count())
        return {};
    const Line& line = lines_[static_cast<std::size_t>(index.row())];
    switch (role) {
        case SeqRole:
            return QVariant::fromValue(line.seq);
        case TimeRole:
            return line.time.isValid() ? line.time.toLocalTime().toString(
                                             QStringLiteral("HH:mm:ss.zzz"))
                                       : QString();
        case TextRole:
        case Qt::DisplayRole:
            return line.text;
        case WarningRole:
            // The programs mark the lines that warn the user this way.
            return line.text.startsWith(QStringLiteral("warning:"));
        default:
            return {};
    }
}

QHash<int, QByteArray> MessageModel::roleNames() const {
    return {{SeqRole, "seq"},
            {TimeRole, "time"},
            {TextRole, "text"},
            {WarningRole, "warning"}};
}

bool MessageModel::add_reply(const QJsonObject& reply) {
    const QString instance = reply.value(QStringLiteral("instance")).toString();
    if (instance != instance_) {
        clear();
        instance_ = instance;
    }
    missed_ += static_cast<quint64>(
        reply.value(QStringLiteral("missed")).toInteger(0));
    const auto messages = reply.value(QStringLiteral("messages")).toArray();
    std::deque<Line> added;
    for (const auto& value : messages) {
        const auto message = value.toObject();
        const auto seq = static_cast<quint64>(
            message.value(QStringLiteral("seq")).toInteger(0));
        // Numbers only grow within an instance, so an old or repeated line
        // is not shown twice.
        if (seq <= last_seq_) continue;
        last_seq_ = seq;
        added.push_back({seq,
                         QDateTime::fromString(
                             message.value(QStringLiteral("time")).toString(),
                             Qt::ISODateWithMs),
                         message.value(QStringLiteral("text")).toString()});
    }
    if (!added.empty()) {
        const int drop =
            std::max(0, count() + static_cast<int>(added.size()) - kCapacity);
        if (drop > 0) {
            const int removed = std::min(drop, count());
            beginRemoveRows({}, 0, removed - 1);
            lines_.erase(lines_.begin(), lines_.begin() + removed);
            endRemoveRows();
            while (static_cast<int>(added.size()) > kCapacity)
                added.pop_front();
        }
        beginInsertRows({}, count(),
                        count() + static_cast<int>(added.size()) - 1);
        for (auto& line : added) lines_.push_back(std::move(line));
        endInsertRows();
        emit countChanged();
    }
    return reply.value(QStringLiteral("more")).toBool(false);
}

void MessageModel::clear() {
    beginResetModel();
    lines_.clear();
    last_seq_ = 0;
    missed_ = 0;
    instance_.clear();
    endResetModel();
    emit countChanged();
}

QString MessageModel::text() const {
    QString all;
    for (const auto& line : lines_) {
        all +=
            line.time.toLocalTime().toString(QStringLiteral("HH:mm:ss.zzz")) +
            QStringLiteral("  ") + line.text + u'\n';
    }
    return all;
}

}  // namespace yume::gui
