/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "gui/app_state.hpp"

#include <cmath>

#include <QClipboard>
#include <QDesktopServices>
#include <QDir>
#include <QGuiApplication>
#include <QJsonObject>
#include <QLocale>
#include <QPalette>
#include <QStandardPaths>
#include <QStyleHints>

#include "common/version.hpp"
#include "gui/mark.hpp"

namespace yume::gui {
namespace {

using Phase = Tunnel::Phase;

constexpr int kHistory = 90;
constexpr int kOtherKitPollMs = 3000;
constexpr int kMessagesPollMs = 1500;
constexpr int kNoticeMs = 6000;

QString settings_path() {
    return QDir(QStandardPaths::writableLocation(
                    QStandardPaths::GenericConfigLocation))
        .filePath(QStringLiteral("yume/gui.conf"));
}

QString phase_name(Phase phase) {
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

double total(const QJsonObject& status, const char* key) {
    return status.value(QStringLiteral("traffic"))
        .toObject()
        .value(QString::fromLatin1(key))
        .toDouble(0);
}

}  // namespace

const QStringList& AppState::pages() {
    static const QStringList names{
        QStringLiteral("overview"), QStringLiteral("connect"),
        QStringLiteral("logs"), QStringLiteral("posture")};
    return names;
}

AppState::AppState(std::optional<Places> places, QString setup_error,
                   QString theme, QObject* parent)
    : QObject(parent),
      places_(std::move(places)),
      setup_error_(std::move(setup_error)),
      settings_(settings_path(), QSettings::IniFormat),
      page_(pages().front()),
      mark_path_(mark_path_data()) {
    theme_mode_ =
        theme.isEmpty()
            ? settings_.value(QStringLiteral("theme"), QStringLiteral("light"))
                  .toString()
            : theme;
    if (theme_mode_ != QStringLiteral("light") &&
        theme_mode_ != QStringLiteral("dark") &&
        theme_mode_ != QStringLiteral("system"))
        theme_mode_ = QStringLiteral("light");
    messages_timer_.setInterval(kMessagesPollMs);
    connect(&messages_timer_, &QTimer::timeout, this,
            [this] { fetch_messages(); });
    notice_timer_.setSingleShot(true);
    connect(&notice_timer_, &QTimer::timeout, this, [this] { set_notice({}); });
    if (const auto* hints = QGuiApplication::styleHints()) {
#if QT_VERSION >= QT_VERSION_CHECK(6, 5, 0)
        connect(hints, &QStyleHints::colorSchemeChanged, this, [this] {
            if (theme_mode_ == QStringLiteral("system")) emit themeChanged();
        });
#else
        static_cast<void>(hints);
#endif
    }
    refreshKits();
    const QString saved = settings_.value(QStringLiteral("kit")).toString();
    set_kit_name(tunnels_.count(saved) ? saved
                 : tunnels_.empty()    ? QString()
                                       : tunnels_.begin()->first);
}

QString AppState::state_kind(const QString& phase, const QString& state) {
    if (phase == QStringLiteral("running")) {
        if (state == QStringLiteral("connected")) return QStringLiteral("good");
        if (state == QStringLiteral("connecting") ||
            state == QStringLiteral("waiting") ||
            state == QStringLiteral("idle"))
            return QStringLiteral("busy");
        return QStringLiteral("bad");
    }
    if (phase == QStringLiteral("validating") ||
        phase == QStringLiteral("starting") ||
        phase == QStringLiteral("stopping"))
        return QStringLiteral("busy");
    return QStringLiteral("rest");
}

QString AppState::state_label(const QString& phase, const QString& state) {
    if (phase == QStringLiteral("none")) return tr("No kit");
    if (phase == QStringLiteral("stopped")) return tr("Not running");
    if (phase == QStringLiteral("validating")) return tr("Checking the kit");
    if (phase == QStringLiteral("starting")) return tr("Starting");
    if (phase == QStringLiteral("stopping")) return tr("Stopping");
    if (state == QStringLiteral("connected")) return tr("Connected");
    if (state == QStringLiteral("connecting")) return tr("Connecting");
    if (state == QStringLiteral("waiting")) return tr("Waiting to retry");
    if (state == QStringLiteral("idle")) return tr("Idle");
    if (state == QStringLiteral("closed")) return tr("Closed");
    return tr("Running");
}

QString AppState::action_text() const {
    const QString now = phase();
    if (now == QStringLiteral("running")) return tr("Disconnect");
    if (now == QStringLiteral("starting")) return tr("Cancel");
    if (now == QStringLiteral("validating")) return tr("Checking…");
    if (now == QStringLiteral("stopping")) return tr("Stopping…");
    return tr("Connect");
}

bool AppState::action_stops() const {
    const QString now = phase();
    return now == QStringLiteral("running") ||
           now == QStringLiteral("starting") ||
           now == QStringLiteral("stopping");
}

bool AppState::action_enabled() const {
    const QString now = phase();
    return !renaming_ && setup_error_.isEmpty() &&
           (now == QStringLiteral("stopped") ||
            now == QStringLiteral("running") ||
            now == QStringLiteral("starting"));
}

void AppState::runAction() {
    if (!action_enabled()) return;
    if (action_stops())
        stopKit();
    else
        connectKit();
}

void AppState::set_tray_active(bool active) {
    if (active == tray_active_) return;
    tray_active_ = active;
    emit trayChanged();
}

QString AppState::version() const {
    return QString::fromLatin1(yume::kVersion);
}

QString AppState::kits_directory() const {
    return places_ ? QDir::toNativeSeparators(places_->kits) : QString();
}

bool AppState::right_to_left() const {
    return QGuiApplication::layoutDirection() == Qt::RightToLeft;
}

QVariantList AppState::kits() const {
    QVariantList list;
    for (const auto& [name, tunnel] : tunnels_) {
        const auto& status = tunnel->status();
        list.append(QVariantMap{
            {QStringLiteral("name"), name},
            {QStringLiteral("server"), tunnel->kit().server},
            {QStringLiteral("directory"),
             QDir::toNativeSeparators(tunnel->kit().directory)},
            {QStringLiteral("phase"), phase_name(tunnel->phase())},
            {QStringLiteral("state"),
             status.value(QStringLiteral("state")).toString()},
        });
    }
    return list;
}

QString AppState::kit_server() const {
    const auto* current = tunnel();
    return current ? current->kit().server : QString();
}

Tunnel* AppState::tunnel() const {
    const auto found = tunnels_.find(kit_name_);
    return found == tunnels_.end() ? nullptr : found->second;
}

void AppState::refreshKits() {
    if (!places_ || renaming_) return;
    std::map<QString, Tunnel*> next;
    for (auto& kit : list_kits(*places_)) {
        const auto found = tunnels_.find(kit.name);
        if (found != tunnels_.end()) {
            next.emplace(kit.name, found->second);
            tunnels_.erase(found);
            continue;
        }
        auto* tunnel = new Tunnel(*places_, kit, this);
        const QString name = kit.name;
        QString last_phase = phase_name(tunnel->phase());
        connect(tunnel, &Tunnel::changed, this,
                [this, tunnel, name, last_phase]() mutable {
                    if (name == kit_name_) emit tunnelChanged();
                    // The kit list shows each kit's phase, and rebuilding it
                    // for every status reply would reset the page's focus.
                    const QString now = phase_name(tunnel->phase());
                    if (now != last_phase) {
                        last_phase = now;
                        emit kitsChanged();
                    }
                });
        connect(tunnel, &Tunnel::status_received, this, [this, name] {
            if (name == kit_name_) on_status_received();
        });
        tunnel->poll(kOtherKitPollMs);
        next.emplace(kit.name, tunnel);
    }
    // Kits that are gone from the directory. Their clients, if any, keep
    // running, since only a stop request ends one.
    for (auto& [name, tunnel] : tunnels_) tunnel->deleteLater();
    tunnels_ = std::move(next);
    if (!kit_name_.isEmpty() && !tunnels_.count(kit_name_)) set_kit_name({});
    emit kitsChanged();
}

void AppState::set_kit_name(const QString& name) {
    if (name == kit_name_ && (name.isEmpty() || tunnels_.count(name))) return;
    if (auto* previous = tunnel()) previous->poll(kOtherKitPollMs);
    kit_name_ = tunnels_.count(name) ? name : QString();
    reset_readings();
    if (auto* current = tunnel()) {
        settings_.setValue(QStringLiteral("kit"), kit_name_);
        current->poll(Tunnel::kPollMs);
        messages_timer_.start();
        fetch_messages();
    } else {
        messages_timer_.stop();
    }
    emit kitChanged();
    emit tunnelChanged();
}

void AppState::reset_readings() {
    messages_.clear();
    messages_in_flight_ = false;
    last_totals_.reset();
    history_.clear();
    send_rate_ = 0;
    receive_rate_ = 0;
    emit ratesChanged();
    emit messagesChanged();
}

QString AppState::phase() const {
    const auto* current = tunnel();
    return current ? phase_name(current->phase()) : QStringLiteral("none");
}

QVariantMap AppState::status() const {
    const auto* current = tunnel();
    return current ? current->status().toVariantMap() : QVariantMap();
}

QString AppState::error() const {
    const auto* current = tunnel();
    return current ? current->error() : QString();
}

QString AppState::output_tail() const {
    const auto* current = tunnel();
    return current ? current->output_tail() : QString();
}

QVariantMap AppState::preset() const {
    const auto* current = tunnel();
    if (!current) return {};
    const auto posture =
        current->status().value(QStringLiteral("posture")).toObject();
    if (posture.isEmpty()) return {};
    return presets_.match(posture.value(QStringLiteral("limits")).toObject());
}

void AppState::on_status_received() {
    const auto* current = tunnel();
    if (!current) return;
    const auto& status = current->status();
    const double sent = total(status, "payload_bytes_sent");
    const double received = total(status, "payload_bytes_received");
    // A rate needs two readings of one run. The first reading, or totals that
    // went down because yume restarted, only start a new series.
    const bool rated = last_totals_ && since_totals_.isValid() &&
                       since_totals_.elapsed() > 0 &&
                       sent >= last_totals_->first &&
                       received >= last_totals_->second;
    if (rated) {
        const double seconds =
            static_cast<double>(since_totals_.elapsed()) / 1000.0;
        send_rate_ = (sent - last_totals_->first) / seconds;
        receive_rate_ = (received - last_totals_->second) / seconds;
        history_.append(
            QVariant::fromValue(QVariantList{send_rate_, receive_rate_}));
        while (history_.size() > kHistory) history_.removeFirst();
    } else {
        send_rate_ = 0;
        receive_rate_ = 0;
        history_.clear();
    }
    last_totals_ = std::make_pair(sent, received);
    since_totals_.restart();
    emit ratesChanged();
}

void AppState::fetch_messages() {
    auto* current = tunnel();
    if (!current || messages_in_flight_) return;
    if (current->phase() != Phase::Running &&
        current->phase() != Phase::Stopping)
        return;
    if (!current->requests().contains(QStringLiteral("messages"))) return;
    messages_in_flight_ = true;
    const QString name = kit_name_;
    current->messages(
        messages_.last_seq(), [this, name](const ControlReply& reply) {
            messages_in_flight_ = false;
            if (name != kit_name_ || !reply.ok()) return;
            // A restarted program numbers from 1 again under a new instance, so
            // it is read again from its first line.
            const QString instance =
                reply.value.value(QStringLiteral("instance")).toString();
            if (!messages_.instance().isEmpty() &&
                instance != messages_.instance()) {
                messages_.clear();
                emit messagesChanged();
                fetch_messages();
                return;
            }
            const bool more = messages_.add_reply(reply.value);
            emit messagesChanged();
            if (more) fetch_messages();
        });
}

void AppState::set_page(const QString& page) {
    if (!pages().contains(page) || page == page_) return;
    page_ = page;
    emit pageChanged();
}

void AppState::set_theme_mode(const QString& mode) {
    if (mode == theme_mode_) return;
    if (mode != QStringLiteral("light") && mode != QStringLiteral("dark") &&
        mode != QStringLiteral("system"))
        return;
    theme_mode_ = mode;
    settings_.setValue(QStringLiteral("theme"), mode);
    emit themeChanged();
}

bool AppState::dark() const {
    if (theme_mode_ == QStringLiteral("dark")) return true;
    if (theme_mode_ == QStringLiteral("light")) return false;
#if QT_VERSION >= QT_VERSION_CHECK(6, 5, 0)
    if (const auto* hints = QGuiApplication::styleHints();
        hints && hints->colorScheme() != Qt::ColorScheme::Unknown)
        return hints->colorScheme() == Qt::ColorScheme::Dark;
#endif
    return QGuiApplication::palette().color(QPalette::Window).lightness() < 128;
}

void AppState::connectKit() {
    if (renaming_) return;
    if (auto* current = tunnel()) current->start();
}

void AppState::stopKit() {
    if (auto* current = tunnel()) current->stop();
}

void AppState::acceptRoute(const QString& id) {
    auto* current = tunnel();
    if (!current) return;
    current->accept_route(id, [this](const ControlReply& reply) {
        if (reply.ok()) {
            set_notice(tr("Shorter route accepted"));
        } else if (reply.code == QStringLiteral("not_found")) {
            set_notice(
                tr("The proposal changed before it was accepted. Review the "
                   "new one."));
        } else {
            set_notice(tr("The route was not accepted: %1").arg(reply.text));
        }
    });
}

QString AppState::suggestKitName(const QUrl& file) const {
    return suggested_kit_name(file.toLocalFile());
}

void AppState::importKit(const QUrl& file, const QString& name,
                         const QString& code) {
    if (!places_ || importing_ || renaming_) return;
    importing_ = true;
    import_failed_ = false;
    import_message_ = tr("Opening the kit…");
    emit importChanged();
    QByteArray bytes = code.toUtf8();
    import_kit(this, *places_, file.toLocalFile(), name, bytes,
               [this, name](const QString& error) {
                   importing_ = false;
                   import_failed_ = !error.isEmpty();
                   import_message_ =
                       error.isEmpty() ? tr("Imported %1").arg(name) : error;
                   emit importChanged();
                   if (error.isEmpty()) {
                       refreshKits();
                       set_kit_name(name);
                   }
               });
    bytes.fill('\0');
}

void AppState::removeKit(const QString& name) {
    if (renaming_) return;
    const auto found = tunnels_.find(name);
    if (!places_ || found == tunnels_.end()) return;
    if (found->second->phase() != Phase::Stopped) {
        set_notice(tr("Stop %1 before removing it").arg(name));
        return;
    }
    QString error;
    if (!remove_kit(*places_, name, error)) {
        set_notice(error);
        return;
    }
    set_notice(tr("Removed %1").arg(name));
    refreshKits();
    if (kit_name_.isEmpty() && !tunnels_.empty())
        set_kit_name(tunnels_.begin()->first);
}

void AppState::renameKit(const QString& name, const QString& new_name) {
    if (!places_ || renaming_ || importing_) return;
    const auto found = tunnels_.find(name);
    if (found == tunnels_.end()) return;
    if (!valid_kit_name(new_name) || name == new_name) {
        set_notice(
            tr("Choose a different name of 1 to 48 letters, digits, dots, "
               "dashes or underscores, starting with a letter, digit or "
               "underscore"));
        return;
    }
    if (found->second->phase() != Phase::Stopped) {
        set_notice(tr("Stop %1 before renaming it").arg(name));
        return;
    }
    renaming_ = true;
    emit renameChanged();
    emit tunnelChanged();
    const auto finish = [this](const QString& message) {
        renaming_ = false;
        emit renameChanged();
        emit tunnelChanged();
        set_notice(message);
    };
    // Recheck a client another GUI started since the cached UI state. Only a
    // definite absence authorizes a move: an unanswered, refused or malformed
    // socket proves nothing.
    const auto absent = [](const ControlReply& reply) {
        return reply.outcome == ControlReply::Outcome::NotRunning &&
               reply.peer_pid == 0;
    };
    const QString target_socket =
        QDir(places_->runtime).filePath(new_name + QStringLiteral(".sock"));
    control_exchange(
        this, target_socket, status_request(),
        [this, name, new_name, finish, absent](const ControlReply& target) {
            if (!absent(target)) {
                finish(target.ok()
                           ? tr("Stop %1 before using its name").arg(new_name)
                           : tr("Cannot confirm that %1 is stopped: %2")
                                 .arg(new_name, target.text));
                return;
            }
            const auto source = tunnels_.find(name);
            if (source == tunnels_.end() ||
                source->second->phase() != Phase::Stopped) {
                finish(tr("Stop %1 before renaming it").arg(name));
                return;
            }
            control_exchange(
                this, source->second->socket_path(), status_request(),
                [this, name, new_name, finish,
                 absent](const ControlReply& reply) {
                    const auto current = tunnels_.find(name);
                    if (!absent(reply) || current == tunnels_.end() ||
                        current->second->phase() != Phase::Stopped) {
                        finish(reply.ok()
                                   ? tr("Stop %1 before renaming it").arg(name)
                                   : tr("Cannot confirm that %1 is stopped: %2")
                                         .arg(name, reply.text));
                        return;
                    }
                    QString error;
                    if (!rename_kit(*places_, name, new_name, error)) {
                        finish(error);
                        return;
                    }
                    const bool selected = kit_name_ == name;
                    renaming_ = false;
                    refreshKits();
                    if (selected)
                        set_kit_name(new_name);
                    else if (settings_.value(QStringLiteral("kit"))
                                 .toString() == name)
                        settings_.setValue(QStringLiteral("kit"), new_name);
                    settings_.sync();
                    finish(settings_.status() == QSettings::NoError
                               ? tr("Renamed %1 to %2").arg(name, new_name)
                               : tr("Renamed %1 to %2, but the selection could "
                                    "not be saved")
                                     .arg(name, new_name));
                });
        });
}

void AppState::copyText(const QString& text) {
    if (auto* clipboard = QGuiApplication::clipboard()) {
        clipboard->setText(text);
        set_notice(tr("Copied"));
    }
}

void AppState::openKitFolder(const QString& name) {
    const auto found = tunnels_.find(name);
    if (found == tunnels_.end()) return;
    QDesktopServices::openUrl(
        QUrl::fromLocalFile(found->second->kit().directory));
}

void AppState::set_notice(const QString& text) {
    notice_ = text;
    emit noticeChanged();
    if (!text.isEmpty()) notice_timer_.start(kNoticeMs);
}

void AppState::clearNotice() {
    set_notice({});
}

QString AppState::formatBytes(double bytes) const {
    return QLocale().formattedDataSize(static_cast<qint64>(std::llround(bytes)),
                                       1, QLocale::DataSizeIecFormat);
}

// Rates in bits per second, as network links are measured.
QString AppState::formatRate(double bytes_per_second) const {
    const double bits = bytes_per_second * 8.0;
    const QLocale locale;
    if (bits < 1e3) return tr("%1 bit/s").arg(locale.toString(bits, 'f', 0));
    if (bits < 1e6)
        return tr("%1 kbit/s").arg(locale.toString(bits / 1e3, 'f', 1));
    if (bits < 1e9)
        return tr("%1 Mbit/s").arg(locale.toString(bits / 1e6, 'f', 1));
    return tr("%1 Gbit/s").arg(locale.toString(bits / 1e9, 'f', 2));
}

QString AppState::formatDuration(double milliseconds) const {
    const auto seconds = static_cast<qint64>(milliseconds / 1000.0);
    const qint64 hours = seconds / 3600;
    const qint64 minutes = seconds / 60 % 60;
    if (hours > 0) return tr("%1 h %2 min").arg(hours).arg(minutes);
    if (minutes > 0) return tr("%1 min %2 s").arg(minutes).arg(seconds % 60);
    return tr("%1 s").arg(seconds);
}

}  // namespace yume::gui
