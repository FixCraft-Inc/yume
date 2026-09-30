/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "gui/capture.hpp"

#include <cstdio>
#include <memory>

#include <QCoreApplication>
#include <QDir>
#include <QGuiApplication>
#include <QImage>
#include <QQuickWindow>
#include <QTimer>
#include <QVariant>

#include "gui/app_state.hpp"
#include "gui/mark.hpp"
#include "gui/tray.hpp"

namespace yume::gui {
namespace {

// Long enough for a page's bindings, a status poll and the first frame.
constexpr int kSettleMs = 700;
constexpr int kFirstStatusMs = 8000;
// A running kit is watched this long first, so the rates have a history.
constexpr int kRunningWarmupMs = 6000;

struct Capture final {
    QQuickWindow* window;
    AppState* state;
    QDir directory;
    QString suffix;
    QStringList shots;
    int failures{0};
};

void save(const std::shared_ptr<Capture>& capture, const QString& name) {
    const QImage image = capture->window->grabWindow();
    const QString path = capture->directory.filePath(
        name + QStringLiteral("-") + capture->suffix + QStringLiteral(".png"));
    if (image.isNull() || !image.save(path)) {
        ++capture->failures;
        std::fprintf(stderr, "yume-gui: cannot write %s\n", qPrintable(path));
        return;
    }
    std::fprintf(stdout, "%s\n", qPrintable(path));
    std::fflush(stdout);
}

// The tray's icon in each state, which no offscreen tray can show.
void save_tray_icons(const std::shared_ptr<Capture>& capture) {
    for (const char* kind : {"rest", "busy", "good", "bad"}) {
        const QString path = capture->directory.filePath(
            QStringLiteral("tray-%1.png").arg(QString::fromLatin1(kind)));
        const QPixmap icon =
            mark_icon(Tray::dot_colour(QString::fromLatin1(kind)))
                .pixmap(64, 64);
        if (icon.isNull() || !icon.save(path)) {
            ++capture->failures;
            std::fprintf(stderr, "yume-gui: cannot write %s\n",
                         qPrintable(path));
            continue;
        }
        std::fprintf(stdout, "%s\n", qPrintable(path));
    }
}

void shoot(const std::shared_ptr<Capture>& capture) {
    if (capture->shots.isEmpty()) {
        save_tray_icons(capture);
        QCoreApplication::exit(capture->failures == 0 ? 0 : 1);
        return;
    }
    const QString shot = capture->shots.takeFirst();
    if (shot == QStringLiteral("route-review")) {
        // The dialog opens only over a proposal, as a user would see it.
        const auto circuits =
            capture->state->status().value(QStringLiteral("circuits")).toMap();
        if (circuits.value(QStringLiteral("proposal")).isNull() ||
            !circuits.value(QStringLiteral("proposal")).isValid()) {
            shoot(capture);
            return;
        }
        capture->state->set_page(QStringLiteral("overview"));
        QMetaObject::invokeMethod(capture->window, "openRouteReview");
    } else {
        QMetaObject::invokeMethod(capture->window, "closeDialogs");
        capture->state->set_page(shot);
    }
    QTimer::singleShot(kSettleMs, capture->window, [capture, shot] {
        save(capture, shot);
        shoot(capture);
    });
}

}  // namespace

void start_capture(QQuickWindow* window, AppState* state,
                   const QString& directory) {
    auto capture = std::make_shared<Capture>();
    capture->window = window;
    capture->state = state;
    capture->directory = QDir(directory);
    capture->suffix =
        (state->dark() ? QStringLiteral("dark") : QStringLiteral("light")) +
        QStringLiteral("-") +
        (state->right_to_left() ? QStringLiteral("rtl")
                                : QStringLiteral("ltr"));
    capture->shots = AppState::pages();
    capture->shots.append(QStringLiteral("route-review"));
    if (!capture->directory.mkpath(QStringLiteral("."))) {
        std::fprintf(stderr, "yume-gui: cannot create %s\n",
                     qPrintable(directory));
        QTimer::singleShot(0, [] { QCoreApplication::exit(1); });
        return;
    }
    // Start once the selected kit has answered, or after the limit when it
    // does not run, so a stopped kit is captured as stopped.
    auto begun = std::make_shared<bool>(false);
    const auto begin = [capture, begun] {
        if (*begun) return;
        *begun = true;
        const bool running =
            capture->state->phase() == QStringLiteral("running");
        QTimer::singleShot(running ? kRunningWarmupMs : kSettleMs,
                           capture->window, [capture] { shoot(capture); });
    };
    if (auto* tunnel = state->tunnel()) {
        QObject::connect(tunnel, &Tunnel::status_received, window, begin);
        QTimer::singleShot(kFirstStatusMs, window, begin);
    } else {
        begin();
    }
}

}  // namespace yume::gui
