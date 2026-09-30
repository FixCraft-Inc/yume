/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <map>

#include <QAction>
#include <QIcon>
#include <QMenu>
#include <QObject>
#include <QString>
#include <QSystemTrayIcon>

class QQuickWindow;

namespace yume::gui {

class AppState;

// The tray icon: the YUME mark with the selected kit's state as a dot,
// green while connected, amber while it works towards a connection, red when
// the running client reports a failure and grey at rest. Its menu names the
// state, runs the window's main action, shows or hides the window and quits
// the GUI, which leaves every tunnel running.
class Tray final : public QObject {
    Q_OBJECT

public:
    Tray(AppState* state, QQuickWindow* window, QObject* parent = nullptr);

    // Whether the desktop shows tray icons at all.
    static bool available();
    // The dot's colour for a state kind, invalid for none.
    static QColor dot_colour(const QString& kind);

    void show();
    // What the icon and menu show now, for tests.
    const QString& kind() const noexcept { return kind_; }
    QAction* header() const noexcept { return header_; }
    QAction* action() const noexcept { return action_; }
    QAction* visibility() const noexcept { return visibility_; }
    QIcon icon() const { return icon_.icon(); }

private:
    void update();
    void toggle_window();

    AppState* state_;
    QQuickWindow* window_;
    QMenu menu_;
    QAction* header_;
    QAction* action_;
    QAction* visibility_;
    QAction* quit_;
    QSystemTrayIcon icon_;
    QString kind_;
    std::map<QString, QIcon> icons_;
    bool told_about_tray_{false};
};

}  // namespace yume::gui
