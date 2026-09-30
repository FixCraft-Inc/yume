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
    quit_ = menu_.addAction(tr("Quit YUME (tunnels keep running)"));
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
                tr("YUME keeps running in the tray. Closing the window "
                   "does not stop a tunnel."),
                QSystemTrayIcon::Information, 6000);
        }
    });
    update();
}

bool Tray::available() {
    return QSystemTrayIcon::isSystemTrayAvailable();
}

// Theme.qml's state roles, mint, amber, coral and grey, saturated so a
// 16-pixel dot reads on light and dark panels.
QColor Tray::dot_colour(const QString& kind) {
    if (kind == QStringLiteral("good")) return QColor(0x25, 0x69, 0x4f);
    if (kind == QStringLiteral("busy")) return QColor(0xd9, 0x8a, 0x3d);
    if (kind == QStringLiteral("bad")) return QColor(0xc9, 0x3f, 0x3b);
    if (kind == QStringLiteral("rest")) return QColor(0x8a, 0x7c, 0x86);
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
            ? tr("YUME: no kit")
            : tr("YUME: %1, %2").arg(state_->kit_name(), label);
    icon_.setToolTip(title);
    header_->setText(title);
    action_->setText(state_->action_text());
    action_->setEnabled(state_->action_enabled());
    visibility_->setText(window_->isVisible() ? tr("Hide window")
                                              : tr("Show window"));
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
