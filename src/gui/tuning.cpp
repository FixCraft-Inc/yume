/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */
#include "gui/tuning.hpp"

#include <QFileInfo>
#include <memory>

namespace yume::gui {

Tuning::Tuning(const Presets& presets, QObject* parent)
    : QObject(parent), presets_(presets) {
    deadline_.setSingleShot(true);
    connect(&deadline_, &QTimer::timeout, this, [this] {
        if (process_) {
            process_->kill();
            return;  // finished reports the uncertain save, and never restarts.
        }
        finish(
            qtTrId("desktop.restart.did.not.finish.check.the.client.before.reconnecting.saved.settin"));
    });
}

void Tuning::set_kit(Tunnel* tunnel, const QString& program) {
    if (busy()) return;
    disconnect(poll_connection_);
    tunnel_ = tunnel;
    program_ = program;
    expert_unlocked_ = false;
    if (tunnel_) {
        poll_connection_ =
            connect(tunnel_, &Tunnel::polled, this, &Tuning::advance);
    }
    reload();
}

void Tuning::reload() {
    if (busy()) return;
    selection_.clear();
    limits_.clear();
    message_.clear();
    ready_ = false;
    if (tunnel_) {
        const auto limits = read_kit_limits(tunnel_->kit(), message_);
        if (limits) {
            limits_ = presets_.defaults();
            for (auto it = limits->begin(); it != limits->end(); ++it)
                if (limits_.contains(it.key()))
                    limits_[it.key()] = it.value().toVariant();
            selection_ = presets_.match(QJsonObject::fromVariantMap(limits_));
            ready_ = true;
        }
    }
    emit changed();
}

void Tuning::choose(const QString& id) {
    if (busy() || !ready_) return;
    const auto chosen = presets_.named(id);
    if (chosen.isEmpty()) return;
    selection_ = chosen;
    limits_ = chosen.value("limits").toMap();
    message_.clear();
    emit changed();
}

void Tuning::move_slider(const QString& axis, int level) {
    const auto chosen =
        presets_.move(selection_.value("id").toString(), axis, level);
    if (!chosen.isEmpty()) choose(chosen.value("id").toString());
}

void Tuning::unlock_expert() {
    if (busy() || !ready_) return;
    expert_unlocked_ = true;
    emit changed();
}

void Tuning::apply_preset() {
    if (selection_.isEmpty()) return;
    apply({QStringLiteral("--preset"), selection_.value("id").toString()});
}

void Tuning::apply_expert(const QString& key, const QString& value) {
    if (!expert_unlocked_ || !presets_.defaults().contains(key) ||
        value.isEmpty() || value.size() > 32)
        return;
    // Keep the scalar text intact; schema 1 in yume-setup owns its validation.
    apply({QStringLiteral("--set"), key + u'=' + value});
}

void Tuning::apply(const QStringList& arguments) {
    if (!ready_ || busy() || blocked_ || !tunnel_) return;
    if (tunnel_->phase() != Tunnel::Phase::Stopped &&
        tunnel_->phase() != Tunnel::Phase::Running)
        return;
    const QFileInfo program(program_);
    if (!program.isFile() || !program.isExecutable()) {
        finish(qtTrId("desktop.cannot.run.yume.setup.beside.the.selected.yume.program"));
        return;
    }
    arguments_ = arguments;
    saved_ = false;
    stage_ = Stage::Checking;
    message_ = qtTrId("desktop.checking.the.client");
    emit changed();
    deadline_.start(35000);
    // Refresh stale GUI state before deciding whether this is save or restart.
    tunnel_->poll(Tunnel::kFastPollMs);
}

void Tuning::advance() {
    if (!tunnel_ || !busy()) return;
    if (stage_ == Stage::Checking) {
        if (!tunnel_->state_confirmed()) {
            finish(qtTrId("desktop.cannot.confirm.the.client.s.state")
                       .arg(tunnel_->error()));
            return;
        }
        restart_ = tunnel_->phase() == Tunnel::Phase::Running;
        if (!restart_ && tunnel_->phase() != Tunnel::Phase::Stopped) {
            finish(qtTrId("desktop.wait.for.the.client.to.finish.starting.or.stopping"));
            return;
        }
        save();
    } else if (stage_ == Stage::Stopping) {
        if (tunnel_->phase() == Tunnel::Phase::Running &&
            !tunnel_->error().isEmpty()) {
            finish(qtTrId("desktop.settings.saved.restart.stopped")
                       .arg(tunnel_->error()));
        } else if (tunnel_->phase() == Tunnel::Phase::Stopped) {
            stage_ = Stage::Starting;
            message_ = qtTrId("desktop.settings.saved.reconnecting");
            emit changed();
            deadline_.start(35000);
            tunnel_->start();
        }
    } else if (stage_ == Stage::Starting) {
        if (!tunnel_->error().isEmpty() ||
            tunnel_->phase() == Tunnel::Phase::Stopped)
            finish(qtTrId("desktop.settings.saved.reconnect.failed")
                       .arg(tunnel_->error()));
        else if (tunnel_->phase() == Tunnel::Phase::Running)
            finish(
                qtTrId("desktop.settings.saved.and.client.restarted.see.the.live.posture.for.negotiated"));
    }
}

void Tuning::save() {
    stage_ = Stage::Saving;
    message_ = qtTrId("desktop.saving.settings");
    emit changed();
    auto* process = new QProcess(this);
    process_ = process;
    process->setProgram(program_);
    QStringList arguments{QStringLiteral("tune"), QStringLiteral("--config"),
                          tunnel_->kit().config};
    arguments.append(arguments_);
    process->setArguments(arguments);
    process->setStandardInputFile(QProcess::nullDevice());
    process->setProcessChannelMode(QProcess::MergedChannels);
    // Bound diagnostics while draining the pipe; no configuration is printed.
    auto output = std::make_shared<QByteArray>();
    connect(process, &QProcess::readyRead, process, [process, output] {
        output->append(process->readAll());
        if (output->size() > 4096) *output = output->right(4096);
    });
    connect(
        process, &QProcess::errorOccurred, this,
        [this, process](QProcess::ProcessError error) {
            if (error != QProcess::FailedToStart) return;
            process_ = nullptr;
            process->deleteLater();
            finish(qtTrId("desktop.could.not.start.yume.setup.settings.were.not.saved"));
        });
    connect(
        process, &QProcess::finished, this,
        [this, process, output](int code, QProcess::ExitStatus status) {
            output->append(process->readAll());
            process_ = nullptr;
            process->deleteLater();
            if (status != QProcess::NormalExit) {
                finish(
                    qtTrId("desktop.saving.was.interrupted.reload.settings.to.check.the.file.the.client.was"));
                return;
            }
            if (code != 0) {
                finish(
                    qtTrId("desktop.settings.were.refused")
                        .arg(QString::fromUtf8(output->right(4096)).trimmed()));
                return;
            }
            saved_ = true;
            if (!restart_) {
                finish(
                    qtTrId("desktop.settings.saved.they.will.be.used.on.the.next.connection"));
                return;
            }
            stage_ = Stage::Stopping;
            message_ = qtTrId("desktop.settings.saved.waiting.for.the.client.to.stop");
            emit changed();
            deadline_.start(35000);
            tunnel_->stop();
        });
    deadline_.start(30000);
    process->start();
}

void Tuning::finish(const QString& message) {
    deadline_.stop();
    stage_ = Stage::Idle;
    if (saved_) {
        reload();
        saved_ = false;
    }
    message_ = message;
    if (tunnel_) tunnel_->poll();
    emit changed();
}

}  // namespace yume::gui
