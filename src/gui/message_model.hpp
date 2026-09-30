/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <deque>

#include <QAbstractListModel>
#include <QDateTime>
#include <QJsonObject>
#include <QString>

namespace yume::gui {

// The lines a running yume printed, as its messages replies deliver them,
// oldest first. It keeps at most kCapacity lines, as the program does.
class MessageModel final : public QAbstractListModel {
    Q_OBJECT
    Q_PROPERTY(int count READ count NOTIFY countChanged)

public:
    static constexpr int kCapacity = 256;

    enum Role { SeqRole = Qt::UserRole + 1, TimeRole, TextRole, WarningRole };

    explicit MessageModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = {}) const override;
    QVariant data(const QModelIndex& index, int role) const override;
    QHash<int, QByteArray> roleNames() const override;
    int count() const { return static_cast<int>(lines_.size()); }

    // The number to ask after, and the program instance these lines are from.
    quint64 last_seq() const noexcept { return last_seq_; }
    const QString& instance() const noexcept { return instance_; }
    // Lines the program no longer kept when this model asked for them.
    quint64 missed() const noexcept { return missed_; }

    // Adds a messages reply. A reply from another instance, a restarted
    // program, replaces what the model holds. Returns whether the reply
    // said more lines are waiting.
    bool add_reply(const QJsonObject& reply);
    void clear();

    // Every line as text, for copying.
    Q_INVOKABLE QString text() const;

signals:
    void countChanged();

private:
    struct Line final {
        quint64 seq;
        QDateTime time;
        QString text;
    };
    std::deque<Line> lines_;
    quint64 last_seq_{0};
    quint64 missed_{0};
    QString instance_;
};

}  // namespace yume::gui
