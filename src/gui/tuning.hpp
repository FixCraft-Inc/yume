/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */
#pragma once

#include <QPointer>
#include "gui/presets.hpp"
#include "gui/tunnel.hpp"

namespace yume::gui {

// An editable configuration draft, separate from the live posture. The only
// writer is yume-setup. One operation owns its kit through save and restart.
class Tuning final : public QObject {
    Q_OBJECT
    Q_PROPERTY(QVariantMap selection READ selection NOTIFY changed)
    Q_PROPERTY(QVariantMap limits READ limits NOTIFY changed)
    Q_PROPERTY(QVariantList fields READ fields CONSTANT)
    Q_PROPERTY(QVariantMap measurements READ measurements CONSTANT)
    Q_PROPERTY(bool ready READ ready NOTIFY changed)
    Q_PROPERTY(bool busy READ busy NOTIFY changed)
    Q_PROPERTY(bool expertUnlocked READ expert_unlocked NOTIFY changed)
    Q_PROPERTY(QString message READ message NOTIFY changed)
public:
    Tuning(const Presets& presets, QObject* parent);
    void set_kit(Tunnel* tunnel, const QString& program);
    void set_blocked(bool blocked) { blocked_ = blocked; }
    QVariantMap selection() const { return selection_; }
    QVariantMap limits() const { return limits_; }
    QVariantList fields() const { return presets_.fields(); }
    QVariantMap measurements() const { return presets_.measurements(); }
    bool ready() const { return ready_; }
    bool busy() const { return stage_ != Stage::Idle; }
    bool expert_unlocked() const { return expert_unlocked_; }
    QString message() const { return message_; }
    Q_INVOKABLE void reload();
    Q_INVOKABLE void choose(const QString& id);
    Q_INVOKABLE void move_slider(const QString& axis, int level);
    Q_INVOKABLE void unlock_expert();
    Q_INVOKABLE void apply_preset();
    // One field per atomic core action; no partially applied multi-field batch.
    Q_INVOKABLE void apply_expert(const QString& key, const QString& value);
signals:
    void changed();

private:
    enum class Stage { Idle, Checking, Saving, Stopping, Starting };
    void apply(const QStringList& arguments);
    void save();
    void advance();
    void finish(const QString& message);
    const Presets& presets_;
    QPointer<Tunnel> tunnel_;
    QString program_;
    QVariantMap selection_;
    QVariantMap limits_;
    bool ready_{false};
    bool expert_unlocked_{false};
    bool restart_{false};
    bool saved_{false};
    bool partial_commit_{false};
    bool blocked_{false};
    Stage stage_{Stage::Idle};
    QString message_;
    QStringList arguments_;
    QTimer deadline_;
    QPointer<QProcess> process_;
    QMetaObject::Connection poll_connection_;
};

}  // namespace yume::gui
