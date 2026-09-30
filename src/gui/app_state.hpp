/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <map>
#include <optional>
#include <utility>

#include <QElapsedTimer>
#include <QObject>
#include <QSettings>
#include <QString>
#include <QTimer>
#include <QUrl>
#include <QVariantList>
#include <QVariantMap>

#include "gui/kit_store.hpp"
#include "gui/message_model.hpp"
#include "gui/presets.hpp"
#include "gui/tunnel.hpp"

namespace yume::gui {

// What the QML pages see: the kits, the selected kit's tunnel as its control
// socket reports it, the printed lines, the posture and the actions. Every
// state shown comes from a status or messages reply. Only a kit's label is
// read from its files.
class AppState final : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString setupError READ setup_error CONSTANT)
    Q_PROPERTY(QString version READ version CONSTANT)
    Q_PROPERTY(QString kitsDirectory READ kits_directory CONSTANT)
    Q_PROPERTY(bool rightToLeft READ right_to_left CONSTANT)
    Q_PROPERTY(QVariantList kits READ kits NOTIFY kitsChanged)
    Q_PROPERTY(
        QString kitName READ kit_name WRITE set_kit_name NOTIFY kitChanged)
    Q_PROPERTY(QString kitServer READ kit_server NOTIFY kitChanged)
    Q_PROPERTY(QString phase READ phase NOTIFY tunnelChanged)
    Q_PROPERTY(QVariantMap status READ status NOTIFY tunnelChanged)
    Q_PROPERTY(QString error READ error NOTIFY tunnelChanged)
    Q_PROPERTY(QString outputTail READ output_tail NOTIFY tunnelChanged)
    Q_PROPERTY(QVariantMap preset READ preset NOTIFY tunnelChanged)
    Q_PROPERTY(double sendRate READ send_rate NOTIFY ratesChanged)
    Q_PROPERTY(double receiveRate READ receive_rate NOTIFY ratesChanged)
    Q_PROPERTY(QVariantList rateHistory READ rate_history NOTIFY ratesChanged)
    Q_PROPERTY(QObject* messages READ messages CONSTANT)
    Q_PROPERTY(
        double messagesMissed READ messages_missed NOTIFY messagesChanged)
    Q_PROPERTY(QVariantList presets READ presets CONSTANT)
    Q_PROPERTY(QVariantMap presetNotes READ preset_notes CONSTANT)
    Q_PROPERTY(QString page READ page WRITE set_page NOTIFY pageChanged)
    Q_PROPERTY(QString themeMode READ theme_mode WRITE set_theme_mode NOTIFY
                   themeChanged)
    Q_PROPERTY(bool dark READ dark NOTIFY themeChanged)
    Q_PROPERTY(bool importing READ importing NOTIFY importChanged)
    Q_PROPERTY(QString importMessage READ import_message NOTIFY importChanged)
    Q_PROPERTY(bool importFailed READ import_failed NOTIFY importChanged)
    Q_PROPERTY(QString notice READ notice NOTIFY noticeChanged)
    Q_PROPERTY(QString actionText READ action_text NOTIFY tunnelChanged)
    Q_PROPERTY(bool actionStops READ action_stops NOTIFY tunnelChanged)
    Q_PROPERTY(bool actionEnabled READ action_enabled NOTIFY tunnelChanged)
    Q_PROPERTY(QString markPath READ mark_path CONSTANT)
    Q_PROPERTY(bool trayActive READ tray_active NOTIFY trayChanged)

public:
    // The pages, in navigation order.
    static const QStringList& pages();

    // What a phase of a kit's tunnel and the state its status names mean:
    // "good" while connected, "busy" while working towards it or waiting,
    // "bad" when a running client reports neither, and "rest" otherwise.
    // The pages and the tray colour and word states by these alone.
    static QString state_kind(const QString& phase, const QString& state);
    static QString state_label(const QString& phase, const QString& state);

    // places is empty when the GUI cannot run clients, and setup_error says
    // why. theme overrides the saved choice for this run when not empty.
    AppState(std::optional<Places> places, QString setup_error, QString theme,
             QObject* parent = nullptr);

    QString setup_error() const { return setup_error_; }
    QString version() const;
    QString kits_directory() const;
    bool right_to_left() const;
    QVariantList kits() const;
    QString kit_name() const { return kit_name_; }
    // The selected kit's configured server, a label read from its file.
    QString kit_server() const;
    void set_kit_name(const QString& name);
    QString phase() const;
    QVariantMap status() const;
    QString error() const;
    QString output_tail() const;
    QVariantMap preset() const;
    double send_rate() const { return send_rate_; }
    double receive_rate() const { return receive_rate_; }
    QVariantList rate_history() const { return history_; }
    QObject* messages() { return &messages_; }
    double messages_missed() const {
        return static_cast<double>(messages_.missed());
    }
    QVariantList presets() const { return presets_.list(); }
    QVariantMap preset_notes() const { return presets_.level_notes(); }
    QString page() const { return page_; }
    void set_page(const QString& page);
    QString theme_mode() const { return theme_mode_; }
    void set_theme_mode(const QString& mode);
    bool dark() const;
    bool importing() const { return importing_; }
    QString import_message() const { return import_message_; }
    bool import_failed() const { return import_failed_; }
    QString notice() const { return notice_; }
    QString mark_path() const { return mark_path_; }
    bool tray_active() const { return tray_active_; }
    // A window whose tray icon is shown hides on close instead of quitting.
    void set_tray_active(bool active);
    // The selected kit's main action, which the header button and the tray
    // offer: connect when stopped, disconnect while running, cancel a start.
    QString action_text() const;
    bool action_stops() const;
    bool action_enabled() const;

    // The selected kit's tunnel, or nullptr.
    Tunnel* tunnel() const;

    Q_INVOKABLE void connectKit();
    Q_INVOKABLE void stopKit();
    // Runs the main action, if it is enabled.
    Q_INVOKABLE void runAction();
    // Accepts exactly the proposal with this id, as the user reviewed it.
    Q_INVOKABLE void acceptRoute(const QString& id);
    Q_INVOKABLE void importKit(const QUrl& file, const QString& name,
                               const QString& code);
    Q_INVOKABLE QString suggestKitName(const QUrl& file) const;
    Q_INVOKABLE void removeKit(const QString& name);
    Q_INVOKABLE void refreshKits();
    Q_INVOKABLE void copyText(const QString& text);
    Q_INVOKABLE void openKitFolder(const QString& name);
    Q_INVOKABLE void clearNotice();
    Q_INVOKABLE QString formatBytes(double bytes) const;
    Q_INVOKABLE QString formatRate(double bytes_per_second) const;
    Q_INVOKABLE QString formatDuration(double milliseconds) const;
    Q_INVOKABLE QString stateKind(const QString& phase,
                                  const QString& state) const {
        return state_kind(phase, state);
    }
    Q_INVOKABLE QString stateLabel(const QString& phase,
                                   const QString& state) const {
        return state_label(phase, state);
    }

signals:
    void kitsChanged();
    void kitChanged();
    void tunnelChanged();
    void ratesChanged();
    void messagesChanged();
    void pageChanged();
    void themeChanged();
    void importChanged();
    void noticeChanged();
    void trayChanged();

private:
    void on_status_received();
    void fetch_messages();
    void reset_readings();
    void set_notice(const QString& text);

    std::optional<Places> places_;
    QString setup_error_;
    QSettings settings_;
    Presets presets_;
    MessageModel messages_;
    std::map<QString, Tunnel*> tunnels_;
    QString kit_name_;
    QString page_;
    QString theme_mode_;
    // Traffic rates from successive status replies, and their last 90.
    double send_rate_{0};
    double receive_rate_{0};
    QVariantList history_;
    std::optional<std::pair<double, double>> last_totals_;
    QElapsedTimer since_totals_;
    QTimer messages_timer_;
    bool messages_in_flight_{false};
    bool importing_{false};
    QString import_message_;
    bool import_failed_{false};
    QString notice_;
    QTimer notice_timer_;
    QString mark_path_;
    bool tray_active_{false};
};

}  // namespace yume::gui
