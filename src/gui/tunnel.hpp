/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <chrono>
#include <functional>

#include <QElapsedTimer>
#include <QJsonObject>
#include <QObject>
#include <QProcess>
#include <QString>
#include <QStringList>
#include <QTimer>

#include "gui/control_client.hpp"
#include "gui/kit_store.hpp"

namespace yume::gui {

// One kit's client process, seen only through its control socket. The GUI
// starts yume as a detached process in its own session, so closing or
// killing the GUI leaves the tunnel running, and stops it with the control
// protocol's stop request. A later GUI finds a running client by asking its
// socket, which lives at a path fixed by the kit's name.
class Tunnel final : public QObject {
    Q_OBJECT

public:
    enum class Phase {
        Stopped,     // nothing answers on the kit's socket
        Validating,  // yume --validate runs before a start
        Starting,    // yume runs, and its socket has not answered yet
        Running,     // the socket answers status requests
        Stopping,    // a stop was requested, and the socket still answers
    };
    Q_ENUM(Phase)

    // How often the socket is asked while nothing is changing, and while a
    // start or stop is under way.
    static constexpr int kPollMs = 1000;
    static constexpr int kFastPollMs = 250;
    // A start or stop that takes longer is reported, and the start keeps
    // waiting while its process lives.
    static constexpr std::chrono::seconds kStartLimit{20};
    static constexpr std::chrono::seconds kStopLimit{20};

    Tunnel(Places places, Kit kit, QObject* parent = nullptr);

    const Kit& kit() const noexcept { return kit_; }
    QString socket_path() const;
    QString output_path() const;

    Phase phase() const noexcept { return phase_; }
    // The latest status reply while Running or Stopping, otherwise empty.
    const QJsonObject& status() const noexcept { return status_; }
    // The requests the latest status reply names.
    QStringList requests() const;
    // What went wrong with the latest start, stop or status request, for
    // people. Empty when nothing did.
    const QString& error() const noexcept { return error_; }

    // Validates the kit with yume, then starts yume detached with the kit's
    // control socket. Does nothing unless Stopped.
    void start();
    // Asks the running yume to stop and waits until its socket is gone.
    void stop();
    // Asks for status now, and then every interval milliseconds.
    void poll(int interval_ms = kPollMs);

    void accept_route(const QString& id,
                      std::function<void(const ControlReply&)> done);
    void messages(quint64 after, std::function<void(const ControlReply&)> done);

    // The last lines yume wrote to its standard error during its latest start
    // from this GUI, at most 16 KiB.
    QString output_tail() const;

signals:
    // The phase, status or error changed.
    void changed();
    // A status reply arrived, after changed() for it.
    void status_received();
    // A status request ended, with or without a reply.
    void polled();

private:
    void set_phase(Phase phase);
    // from_status marks an error of the status request itself, which the
    // next answered status clears.
    void set_error(const QString& error, bool from_status = false);
    void request_status();
    void on_status(const ControlReply& reply);
    void spawn();
    // Whether pid_ still runs yume for this kit.
    bool process_alive() const;
    // Whether pid_, whose command line is empty, is a process inside execve.
    bool process_between_programs() const;
    QString output_reason(const QString& fallback) const;

    Places places_;
    Kit kit_;
    Phase phase_{Phase::Stopped};
    QJsonObject status_;
    QString error_;
    bool error_from_status_{false};
    QTimer poll_timer_;
    QElapsedTimer since_phase_;
    int interval_ms_{kPollMs};
    bool status_in_flight_{false};
    // The client's process: the one this GUI started, or the one its socket
    // last answered from. 0 when neither is known.
    qint64 pid_{0};
    // The process this Tunnel last started, whose standard error the output
    // file holds. A client started elsewhere has no output file of its own.
    qint64 started_pid_{0};
    QProcess* validation_{nullptr};
};

}  // namespace yume::gui
