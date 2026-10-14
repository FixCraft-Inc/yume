/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "gui/tray.hpp"

#include <QCoreApplication>
#include <QQuickWindow>

#include "gui/app_state.hpp"
#include "gui/mark.hpp"
#include "gui/palette.hpp"

namespace yume::gui {

Tray::Tray(AppState* state, QQuickWindow* window, QObject* parent)
    : QObject(parent), state_(state), window_(window) {
    header_ = menu_.addAction(QString());
    header_->setEnabled(false);
    menu_.addSeparator();
    action_ = menu_.addAction(QString());
    connect(action_, &QAction::triggered, state_, &AppState::runAction);
    visibility_ = menu_.addAction(QString());
    connect(visibility_, &QAction::triggered, this,
            [this] { toggle_window(); });
    menu_.addSeparator();
    quit_ = menu_.addAction(qtTrId("desktop.quit.yume.tunnels.keep.running"));
    connect(quit_, &QAction::triggered, qApp, &QCoreApplication::quit);
    icon_.setContextMenu(&menu_);
    connect(&icon_, &QSystemTrayIcon::activated, this,
            [this](QSystemTrayIcon::ActivationReason reason) {
                if (reason == QSystemTrayIcon::Trigger) toggle_window();
            });
    connect(state_, &AppState::tunnelChanged, this, [this] { update(); });
    connect(state_, &AppState::kitChanged, this, [this] { update(); });
    connect(window_, &QWindow::visibleChanged, this, [this](bool visible) {
        update();
        // The first time the window hides into the tray, say where it went.
        if (!visible && icon_.isVisible() && !told_about_tray_) {
            told_about_tray_ = true;
            icon_.showMessage(
                QStringLiteral("YUME"),
                qtTrId("desktop.yume.keeps.running.in.the.tray.closing.the.window.does.not.stop.a.tunnel"),
                QSystemTrayIcon::Information, 6000);
        }
    });
    update();
}

bool Tray::available() {
    return QSystemTrayIcon::isSystemTrayAvailable();
}

// The palette's state roles, sage, apricot, rose and grey, as their
// saturated dot tones so a 16-pixel dot reads on light and dark panels.
QColor Tray::dot_colour(const QString& kind) {
    if (kind == QStringLiteral("good")) return QColor(QRgb(palette::kDotGood));
    if (kind == QStringLiteral("busy")) return QColor(QRgb(palette::kDotBusy));
    if (kind == QStringLiteral("bad")) return QColor(QRgb(palette::kDotBad));
    if (kind == QStringLiteral("rest")) return QColor(QRgb(palette::kDotRest));
    return {};
}

void Tray::show() {
    icon_.show();
}

void Tray::update() {
    const QString phase = state_->phase();
    const QString reported =
        state_->status().value(QStringLiteral("state")).toString();
    kind_ = state_->kit_name().isEmpty()
                ? QString()
                : AppState::state_kind(phase, reported);
    auto found = icons_.find(kind_);
    if (found == icons_.end())
        found = icons_.emplace(kind_, mark_icon(dot_colour(kind_))).first;
    icon_.setIcon(found->second);
    const QString label = AppState::state_label(phase, reported);
    const QString title =
        state_->kit_name().isEmpty()
            ? qtTrId("desktop.yume.no.kit")
            : qtTrId("desktop.yume.2").arg(state_->kit_name(), label);
    icon_.setToolTip(title);
    header_->setText(title);
    action_->setText(state_->action_text());
    action_->setEnabled(state_->action_enabled());
    visibility_->setText(window_->isVisible() ? qtTrId("desktop.hide.window")
                                              : qtTrId("desktop.show.window"));
}

void Tray::toggle_window() {
    if (window_->isVisible() && window_->isActive()) {
        window_->hide();
        return;
    }
    window_->show();
    window_->raise();
    window_->requestActivate();
}

}  // namespace yume::gui
