/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "gui/headless.hpp"

#include <cstdio>
#include <deque>

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTimer>

#include "gui/tunnel.hpp"

namespace yume::gui {
namespace {

using Phase = Tunnel::Phase;

// A connect waits this long for "connected", a stop for the socket to go.
constexpr int kLegLimitMs = 60'000;

QString phase_text(Phase phase) {
    switch (phase) {
        case Phase::Stopped:
            return QStringLiteral("stopped");
        case Phase::Validating:
            return QStringLiteral("validating");
        case Phase::Starting:
            return QStringLiteral("starting");
        case Phase::Running:
            return QStringLiteral("running");
        case Phase::Stopping:
            return QStringLiteral("stopping");
    }
    return QStringLiteral("stopped");
}

void print_line(const QJsonObject& report) {
    const QByteArray line =
        QJsonDocument(report).toJson(QJsonDocument::Compact);
    std::fprintf(stdout, "%s\n", line.constData());
    std::fflush(stdout);
}

// Runs legs one after another on one Tunnel and reports each.
class Runner final : public QObject {
public:
    Runner(const Places& places, const Kit& kit, std::deque<QString> legs)
        : tunnel_(places, kit, this), legs_(std::move(legs)) {
        limit_.setSingleShot(true);
        connect(&limit_, &QTimer::timeout, this, [this] {
            finish_leg(false, tr("the leg did not finish within %1 seconds")
                                  .arg(kLegLimitMs / 1000));
        });
        connect(&tunnel_, &Tunnel::polled, this, [this] { check(); });
        connect(&tunnel_, &Tunnel::changed, this, [this] { check(); });
    }

    // The first status tells whether the kit already runs.
    void begin() { tunnel_.poll(Tunnel::kFastPollMs); }

    int result() const {
        if (!exercised_) return kHeadlessNothingExercised;
        return failed_ ? kHeadlessLegFailed : kHeadlessPassed;
    }

private:
    void check() {
        if (!first_status_) {
            first_status_ = true;
            next();
            return;
        }
        if (leg_.isEmpty()) return;
        const bool connected =
            tunnel_.phase() == Phase::Running &&
            tunnel_.status().value(QStringLiteral("state")).toString() ==
                QStringLiteral("connected");
        if (leg_ == QStringLiteral("connect")) {
            if (connected) finish_leg(true, {});
            // A start that ended stays stopped with its reason.
            else if (started_ && tunnel_.phase() == Phase::Stopped)
                finish_leg(false, tunnel_.error());
            return;
        }
        if (leg_ == QStringLiteral("stop") && tunnel_.phase() == Phase::Stopped)
            finish_leg(true, {});
    }

    void next() {
        if (legs_.empty()) {
            QCoreApplication::exit(result());
            return;
        }
        leg_ = legs_.front();
        legs_.pop_front();
        clock_.restart();
        started_ = false;
        if (leg_ == QStringLiteral("status")) {
            exercised_ = true;
            finish_leg(
                tunnel_.error().isEmpty() || tunnel_.phase() == Phase::Running,
                tunnel_.error());
            return;
        }
        if (leg_ == QStringLiteral("connect")) {
            exercised_ = true;
            limit_.start(kLegLimitMs);
            if (tunnel_.phase() == Phase::Stopped) {
                started_ = true;
                tunnel_.start();
            }
            check();
            return;
        }
        // stop: a kit that does not run has nothing to stop.
        if (tunnel_.phase() == Phase::Stopped) {
            report(false, tr("the kit is not running"));
            leg_.clear();
            if (!exercised_) {
                QCoreApplication::exit(kHeadlessNothingExercised);
                return;
            }
            failed_ = true;
            next();
            return;
        }
        exercised_ = true;
        limit_.start(kLegLimitMs);
        tunnel_.stop();
        check();
    }

    void finish_leg(bool ok, const QString& error) {
        if (leg_.isEmpty()) return;
        limit_.stop();
        if (!ok) failed_ = true;
        report(ok, error);
        leg_.clear();
        // A failed leg ends the run: later legs would test a broken state.
        if (!ok) legs_.clear();
        QTimer::singleShot(0, this, [this] { next(); });
    }

    void report(bool ok, const QString& error) {
        const auto& status = tunnel_.status();
        QJsonObject line{
            {QStringLiteral("leg"), leg_},
            {QStringLiteral("ok"), ok},
            {QStringLiteral("kit"), tunnel_.kit().name},
            {QStringLiteral("phase"), phase_text(tunnel_.phase())},
            {QStringLiteral("elapsed_ms"), clock_.elapsed()},
            {QStringLiteral("socket"), tunnel_.socket_path()},
        };
        if (!error.isEmpty()) line.insert(QStringLiteral("error"), error);
        if (!status.isEmpty()) {
            for (const char* key :
                 {"state", "server", "server_identity", "sessions",
                  "failed_attempts", "socks5", "requests", "last_failure"}) {
                const QString name = QString::fromLatin1(key);
                if (status.contains(name))
                    line.insert(name, status.value(name));
            }
        }
        if (leg_ == QStringLiteral("stop"))
            line.insert(QStringLiteral("socket_removed"),
                        !QFile::exists(tunnel_.socket_path()));
        if (leg_ == QStringLiteral("stop") && ok)
            line.insert(QStringLiteral("process_ended"), true);
        print_line(line);
    }

    Tunnel tunnel_;
    std::deque<QString> legs_;
    QString leg_;
    QTimer limit_;
    QElapsedTimer clock_;
    bool first_status_{false};
    bool started_{false};
    bool exercised_{false};
    bool failed_{false};
};

std::optional<Kit> find_kit(const Places& places, const QString& name) {
    for (auto& kit : list_kits(places))
        if (kit.name == name) return kit;
    return std::nullopt;
}

}  // namespace

int run_headless_action(const Places& places, const QString& action,
                        const QString& name) {
    std::deque<QString> legs;
    if (action == QStringLiteral("cycle")) {
        legs = {QStringLiteral("connect"), QStringLiteral("stop"),
                QStringLiteral("connect"), QStringLiteral("stop")};
    } else if (action == QStringLiteral("status") ||
               action == QStringLiteral("connect") ||
               action == QStringLiteral("stop")) {
        legs = {action};
    } else {
        std::fprintf(stderr, "yume-gui: unknown headless action %s\n",
                     qPrintable(action));
        return kHeadlessNothingExercised;
    }
    const auto kit = find_kit(places, name);
    if (!kit) {
        std::fprintf(stderr, "yume-gui: no kit named %s in %s\n",
                     qPrintable(name), qPrintable(places.kits));
        return kHeadlessNothingExercised;
    }
    Runner runner(places, *kit, std::move(legs));
    QTimer::singleShot(0, &runner, [&runner] { runner.begin(); });
    return QCoreApplication::exec();
}

int run_headless_import(const Places& places, const QString& file,
                        const QString& name) {
    QFile input;
    if (!input.open(stdin, QIODevice::ReadOnly))
        return kHeadlessNothingExercised;
    QByteArray code = input.readLine(256).trimmed();
    int status = kHeadlessLegFailed;
    QObject context;
    import_kit(&context, places, file, name, code, [&](const QString& error) {
        print_line({{QStringLiteral("leg"), QStringLiteral("import")},
                    {QStringLiteral("ok"), error.isEmpty()},
                    {QStringLiteral("kit"), name},
                    {QStringLiteral("error"), error}});
        status = error.isEmpty() ? kHeadlessPassed : kHeadlessLegFailed;
        QCoreApplication::exit(status);
    });
    code.fill('\0');
    QCoreApplication::exec();
    return status;
}

}  // namespace yume::gui
