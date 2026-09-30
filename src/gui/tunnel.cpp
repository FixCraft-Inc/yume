/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "gui/tunnel.hpp"

#include <signal.h>

#include <utility>

#include <QDir>
#include <QFile>
#include <QJsonArray>

namespace yume::gui {
namespace {

using Outcome = ControlReply::Outcome;

constexpr qint64 kOutputTailBytes = 16 * 1024;
constexpr qint64 kMaxCommandLineBytes = 16 * 1024;
constexpr int kValidationMs = 30'000;

QString strip_program(QString line) {
    line = line.trimmed();
    if (line.startsWith(QStringLiteral("yume: "))) line.remove(0, 6);
    return line;
}

}  // namespace

Tunnel::Tunnel(Places places, Kit kit, QObject* parent)
    : QObject(parent), places_(std::move(places)), kit_(std::move(kit)) {
    poll_timer_.setSingleShot(true);
    connect(&poll_timer_, &QTimer::timeout, this, [this] { request_status(); });
    since_phase_.start();
}

QString Tunnel::socket_path() const {
    return QDir(places_.runtime).filePath(kit_.name + QStringLiteral(".sock"));
}

QString Tunnel::output_path() const {
    return QDir(places_.runtime).filePath(kit_.name + QStringLiteral(".log"));
}

QStringList Tunnel::requests() const {
    QStringList names;
    for (const auto& value :
         status_.value(QStringLiteral("requests")).toArray())
        names.append(value.toString());
    return names;
}

qint64 Tunnel::status_age_ms() const {
    return since_status_.isValid() ? since_status_.elapsed() : -1;
}

void Tunnel::set_phase(Phase phase) {
    if (phase_ == phase) return;
    phase_ = phase;
    since_phase_.restart();
    if (phase_ == Phase::Stopped) {
        status_ = {};
        since_status_.invalidate();
    }
    emit changed();
}

void Tunnel::set_error(const QString& error, bool from_status) {
    error_from_status_ = from_status && !error.isEmpty();
    if (error_ == error) return;
    error_ = error;
    emit changed();
}

void Tunnel::poll(int interval_ms) {
    interval_ms_ = interval_ms;
    poll_timer_.stop();
    request_status();
}

void Tunnel::request_status() {
    if (status_in_flight_) return;
    status_in_flight_ = true;
    control_exchange(this, socket_path(), status_request(),
                     [this](const ControlReply& reply) {
                         status_in_flight_ = false;
                         on_status(reply);
                         emit polled();
                         const bool busy = phase_ == Phase::Starting ||
                                           phase_ == Phase::Stopping;
                         poll_timer_.start(busy ? kFastPollMs : interval_ms_);
                     });
}

void Tunnel::on_status(const ControlReply& reply) {
    if (reply.ok()) {
        status_ = reply.value;
        since_status_.restart();
        if (reply.peer_pid > 0) pid_ = reply.peer_pid;
        if (phase_ == Phase::Stopping &&
            since_phase_.elapsed() >
                std::chrono::milliseconds(kStopLimit).count()) {
            set_error(tr("yume did not stop within %1 seconds")
                          .arg(kStopLimit.count()));
            set_phase(Phase::Running);
        } else if (phase_ != Phase::Stopping && phase_ != Phase::Validating) {
            if (phase_ != Phase::Running || error_from_status_) set_error({});
            set_phase(Phase::Running);
        }
        emit changed();
        emit status_received();
        return;
    }
    if (reply.outcome == Outcome::NotRunning) {
        switch (phase_) {
            case Phase::Starting:
                if (process_alive()) {
                    if (since_phase_.elapsed() >
                        std::chrono::milliseconds(kStartLimit).count())
                        set_error(tr(
                            "yume runs but has not opened its control socket"));
                    return;
                }
                // The reason comes from this start's output while pid_
                // still names the process that wrote it.
                set_error(output_reason(tr("yume stopped while starting")));
                pid_ = 0;
                set_phase(Phase::Stopped);
                return;
            case Phase::Running:
                set_error(output_reason(tr("yume stopped")));
                pid_ = 0;
                set_phase(Phase::Stopped);
                return;
            case Phase::Stopping:
                // yume closes its socket first and then its sessions, so the
                // tunnel is stopped once its process is gone.
                if (process_alive() &&
                    since_phase_.elapsed() <=
                        std::chrono::milliseconds(kStopLimit).count())
                    return;
                if (process_alive())
                    set_error(
                        tr("yume closed its control socket but has not ended"));
                else
                    set_error({});
                pid_ = 0;
                set_phase(Phase::Stopped);
                return;
            case Phase::Stopped:
            case Phase::Validating:
                return;
        }
    }
    // Refused, timed out, malformed or refused by the program: the socket
    // says nothing trustworthy, so the phase stays and the reason shows.
    set_error(reply.outcome == Outcome::Error
                  ? tr("status refused: %1").arg(reply.text)
                  : reply.text,
              true);
}

void Tunnel::start() {
    if (phase_ != Phase::Stopped) return;
    QString error;
    if (!ensure_private_directory(places_.runtime, error)) {
        set_error(error);
        return;
    }
    set_error({});
    set_phase(Phase::Validating);
    // Validation reports a bad kit at once, in yume's own words, instead of
    // leaving it to a process that exits in the background.
    validation_ = new QProcess(this);
    validation_->setProgram(places_.yume);
    validation_->setArguments({QStringLiteral("--config"), kit_.config,
                               QStringLiteral("--control-socket"),
                               socket_path(), QStringLiteral("--validate")});
    validation_->setProcessChannelMode(QProcess::MergedChannels);
    validation_->setStandardInputFile(QProcess::nullDevice());
    auto* process = validation_;
    auto* limit = new QTimer(process);
    limit->setSingleShot(true);
    connect(limit, &QTimer::timeout, process, [process] { process->kill(); });
    connect(process, &QProcess::finished, this,
            [this, process](int code, QProcess::ExitStatus status) {
                const QString output = QString::fromUtf8(process->readAll());
                process->deleteLater();
                validation_ = nullptr;
                if (status != QProcess::NormalExit || code != 0) {
                    const auto lines = output.split(u'\n', Qt::SkipEmptyParts);
                    set_error(lines.isEmpty() ? tr("yume refused the kit")
                                              : strip_program(lines.last()));
                    set_phase(Phase::Stopped);
                    return;
                }
                spawn();
            });
    connect(process, &QProcess::errorOccurred, this,
            [this, process](QProcess::ProcessError kind) {
                if (kind != QProcess::FailedToStart) return;
                process->deleteLater();
                validation_ = nullptr;
                set_error(tr("cannot run %1").arg(places_.yume));
                set_phase(Phase::Stopped);
            });
    limit->start(kValidationMs);
    process->start();
}

void Tunnel::spawn() {
    // yume writes its lines to standard error. They go to a private file in
    // the runtime directory, replaced at every start, so a start that fails
    // before the socket opens still says why.
    QFile output(output_path());
    if (!output.open(QIODevice::WriteOnly | QIODevice::Truncate) ||
        !output.setPermissions(QFileDevice::ReadOwner |
                               QFileDevice::WriteOwner)) {
        set_error(tr("cannot write %1").arg(output_path()));
        set_phase(Phase::Stopped);
        return;
    }
    output.close();
    QProcess process;
    process.setProgram(places_.yume);
    process.setArguments({QStringLiteral("--config"), kit_.config,
                          QStringLiteral("--control-socket"), socket_path()});
    process.setStandardInputFile(QProcess::nullDevice());
    process.setStandardOutputFile(QProcess::nullDevice());
    process.setStandardErrorFile(output_path(), QIODevice::Append);
    process.setWorkingDirectory(kit_.directory);
    // On Unix a detached process runs in its own session: it outlives this
    // GUI, and a signal to the GUI's process group does not reach it.
    qint64 pid = 0;
    if (!process.startDetached(&pid)) {
        set_error(tr("cannot start %1").arg(places_.yume));
        set_phase(Phase::Stopped);
        return;
    }
    pid_ = pid;
    started_pid_ = pid;
    set_phase(Phase::Starting);
    poll(interval_ms_);
}

// The process counts as this kit's client only while its command line names
// this kit's control socket, so a process id the kernel has since reused is
// neither waited for nor signalled. An exited process has no command line.
bool Tunnel::process_alive() const {
    if (pid_ <= 0) return false;
    QFile file(QStringLiteral("/proc/%1/cmdline").arg(pid_));
    if (!file.open(QIODevice::ReadOnly)) return false;
    const QList<QByteArray> words = file.read(kMaxCommandLineBytes).split('\0');
    const QByteArray socket = QFile::encodeName(socket_path());
    for (qsizetype at = 0; at + 1 < words.size(); ++at) {
        if (words[at] == "--control-socket" && words[at + 1] == socket)
            return true;
    }
    return false;
}

void Tunnel::stop() {
    if (phase_ == Phase::Starting && process_alive()) {
        // Its socket is not open yet, so the process this GUI started gets
        // the signal that the stop request stands for.
        ::kill(static_cast<pid_t>(pid_), SIGTERM);
        set_phase(Phase::Stopping);
        poll(interval_ms_);
        return;
    }
    if (phase_ != Phase::Running) return;
    if (!requests().contains(QStringLiteral("stop"))) {
        set_error(tr("this yume does not take stop requests"));
        return;
    }
    set_error({});
    control_exchange(
        this, socket_path(), stop_request(), [this](const ControlReply& reply) {
            if (reply.ok() &&
                reply.value.value(QStringLiteral("stopping")).toBool()) {
                set_phase(Phase::Stopping);
                poll(interval_ms_);
                return;
            }
            if (reply.outcome == Outcome::NotRunning) {
                set_phase(Phase::Stopped);
                return;
            }
            set_error(reply.text.isEmpty() ? tr("the stop request failed")
                                           : reply.text);
        });
}

void Tunnel::accept_route(const QString& id,
                          std::function<void(const ControlReply&)> done) {
    control_exchange(this, socket_path(), accept_route_request(id),
                     [this, done = std::move(done)](const ControlReply& reply) {
                         done(reply);
                         poll(interval_ms_);
                     });
}

void Tunnel::messages(quint64 after,
                      std::function<void(const ControlReply&)> done) {
    control_exchange(this, socket_path(), messages_request(after),
                     std::move(done));
}

QString Tunnel::output_tail() const {
    QFile file(output_path());
    if (!file.open(QIODevice::ReadOnly)) return {};
    if (file.size() > kOutputTailBytes)
        file.seek(file.size() - kOutputTailBytes);
    return QString::fromUtf8(file.read(kOutputTailBytes));
}

// The last line yume printed before it ended, or fallback. Only a client
// this Tunnel started wrote the output file, so another one's end gets no
// line from an earlier run.
QString Tunnel::output_reason(const QString& fallback) const {
    if (started_pid_ == 0 || pid_ != started_pid_) return fallback;
    const auto lines = output_tail().split(u'\n', Qt::SkipEmptyParts);
    for (auto line = lines.crbegin(); line != lines.crend(); ++line) {
        const QString text = strip_program(*line);
        if (!text.isEmpty() && text != QStringLiteral("stopping"))
            return fallback + QStringLiteral(": ") + text;
    }
    return fallback;
}

}  // namespace yume::gui
