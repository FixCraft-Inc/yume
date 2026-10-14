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
#include <QFileInfo>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
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
        QStringLiteral("logs"), QStringLiteral("posture"),
        QStringLiteral("credits")};
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
    connect(&tuning_, &Tuning::changed, this, &AppState::tunnelChanged);
    const auto block_tuning = [this] {
        tuning_.set_blocked(importing_ || renaming_ || removing_);
    };
    connect(this, &AppState::importChanged, this, block_tuning);
    connect(this, &AppState::renameChanged, this, block_tuning);
    connect(this, &AppState::removeChanged, this, block_tuning);
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
    if (phase == QStringLiteral("none")) return qtTrId("desktop.no.kit");
    if (phase == QStringLiteral("stopped")) return qtTrId("desktop.not.running");
    if (phase == QStringLiteral("validating")) return qtTrId("desktop.checking.the.kit");
    if (phase == QStringLiteral("starting")) return qtTrId("desktop.starting");
    if (phase == QStringLiteral("stopping")) return qtTrId("desktop.stopping");
    if (state == QStringLiteral("connected")) return qtTrId("desktop.connected");
    if (state == QStringLiteral("connecting")) return qtTrId("connecting");
    if (state == QStringLiteral("waiting")) return qtTrId("desktop.waiting.to.retry");
    if (state == QStringLiteral("idle")) return qtTrId("desktop.idle");
    if (state == QStringLiteral("closed")) return qtTrId("desktop.closed");
    return qtTrId("desktop.running");
}

QString AppState::action_text() const {
    const QString now = phase();
    if (now == QStringLiteral("running")) return qtTrId("disconnect");
    if (now == QStringLiteral("starting")) return qtTrId("cancel");
    if (now == QStringLiteral("validating")) return qtTrId("desktop.checking");
    if (now == QStringLiteral("stopping")) return qtTrId("desktop.stopping.2");
    return qtTrId("connect");
}

bool AppState::action_stops() const {
    const QString now = phase();
    return now == QStringLiteral("running") ||
           now == QStringLiteral("starting") ||
           now == QStringLiteral("stopping");
}

bool AppState::action_enabled() const {
    const QString now = phase();
    return !renaming_ && !removing_ && !tuning_.busy() && setup_error_.isEmpty() &&
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

QVariantMap AppState::credits() const {
    QFile file(QStringLiteral(":/yume/credits.json"));
    if (!file.open(QIODevice::ReadOnly)) return {};
    auto credits = QJsonDocument::fromJson(file.readAll()).object().toVariantMap();
    // Each language's translators come from the translation catalog, which
    // owns them, through its generated listing.
    QFile translations(QStringLiteral(":/yume/translation_credits.json"));
    if (translations.open(QIODevice::ReadOnly))
        credits.insert(QStringLiteral("translations"),
                       QJsonDocument::fromJson(translations.readAll()).object().value(
                           QStringLiteral("languages")).toArray().toVariantList());
    return credits;
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
    if (!places_ || renaming_ || removing_ || tuning_.busy()) return;
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
    if (tuning_.busy()) return;
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
    tuning_.set_kit(tunnel(), places_
                                  ? QFileInfo(places_->yume)
                                        .dir()
                                        .filePath(QStringLiteral("yume-setup"))
                                  : QString());
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
    if (renaming_ || removing_ || tuning_.busy()) return;
    if (auto* current = tunnel()) current->start();
}

void AppState::stopKit() {
    if (removing_ || tuning_.busy()) return;
    if (auto* current = tunnel()) current->stop();
}

void AppState::acceptRoute(const QString& id) {
    auto* current = tunnel();
    if (!current) return;
    current->accept_route(id, [this](const ControlReply& reply) {
        if (reply.ok()) {
            set_notice(qtTrId("desktop.shorter.route.accepted"));
        } else if (reply.code == QStringLiteral("not_found")) {
            set_notice(
                qtTrId("desktop.the.proposal.changed.before.it.was.accepted.review.the.new.one"));
        } else {
            set_notice(qtTrId("desktop.the.route.was.not.accepted").arg(reply.text));
        }
    });
}

QString AppState::suggestKitName(const QUrl& file) const {
    return suggested_kit_name(file.toLocalFile());
}

void AppState::importKit(const QUrl& file, const QString& name,
                         const QString& code) {
    if (!places_ || importing_ || renaming_ || removing_ || tuning_.busy())
        return;
    importing_ = true;
    import_failed_ = false;
    import_message_ = qtTrId("desktop.opening.the.kit");
    emit importChanged();
    QByteArray bytes = code.toUtf8();
    import_kit(this, *places_, file.toLocalFile(), name, bytes,
               [this, name](const QString& error) {
                   importing_ = false;
                   import_failed_ = !error.isEmpty();
                   import_message_ =
                       error.isEmpty() ? qtTrId("desktop.imported").arg(name) : error;
                   emit importChanged();
                   if (error.isEmpty()) {
                       refreshKits();
                       set_kit_name(name);
                   }
               });
    bytes.fill('\0');
}

void AppState::removeKit(const QString& name) {
    if (importing_ || renaming_ || removing_ || tuning_.busy()) return;
    const auto found = tunnels_.find(name);
    if (!places_ || found == tunnels_.end()) return;
    if (found->second->phase() != Phase::Stopped) {
        set_notice(qtTrId("desktop.stop.before.removing.it").arg(name));
        return;
    }
    removing_ = true;
    emit removeChanged();
    emit tunnelChanged();
    const auto finish = [this](const QString& message) {
        removing_ = false;
        emit removeChanged();
        emit tunnelChanged();
        set_notice(message);
    };
    const auto absent = [](const ControlReply& reply) {
        return reply.outcome == ControlReply::Outcome::NotRunning &&
               reply.peer_pid == 0;
    };
    control_exchange(
        this, found->second->socket_path(), status_request(),
        [this, name, finish, absent](const ControlReply& reply) {
            const auto current = tunnels_.find(name);
            if (!absent(reply) || current == tunnels_.end() ||
                current->second->phase() != Phase::Stopped) {
                finish(reply.ok()
                           ? qtTrId("desktop.stop.before.removing.it").arg(name)
                           : qtTrId("desktop.cannot.confirm.that.is.stopped")
                                 .arg(name, reply.text));
                return;
            }
            QString error;
            if (!remove_kit(*places_, name, error)) {
                finish(error);
                return;
            }
            finish(qtTrId("desktop.removed").arg(name));
            refreshKits();
            if (kit_name_.isEmpty() && !tunnels_.empty())
                set_kit_name(tunnels_.begin()->first);
        });
}

void AppState::renameKit(const QString& name, const QString& new_name) {
    if (!places_ || renaming_ || importing_ || removing_ || tuning_.busy())
        return;
    const auto found = tunnels_.find(name);
    if (found == tunnels_.end()) return;
    if (!valid_kit_name(new_name) || name == new_name) {
        set_notice(
            qtTrId("desktop.choose.a.different.name.of.1.to.48.letters.digits.dots.dashes.or.undersc"));
        return;
    }
    if (found->second->phase() != Phase::Stopped) {
        set_notice(qtTrId("desktop.stop.before.renaming.it").arg(name));
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
                           ? qtTrId("desktop.stop.before.using.its.name").arg(new_name)
                           : qtTrId("desktop.cannot.confirm.that.is.stopped")
                                 .arg(new_name, target.text));
                return;
            }
            const auto source = tunnels_.find(name);
            if (source == tunnels_.end() ||
                source->second->phase() != Phase::Stopped) {
                finish(qtTrId("desktop.stop.before.renaming.it").arg(name));
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
                                   ? qtTrId("desktop.stop.before.renaming.it").arg(name)
                                   : qtTrId("desktop.cannot.confirm.that.is.stopped")
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
                               ? qtTrId("desktop.renamed.to").arg(name, new_name)
                               : qtTrId("desktop.renamed.1.to.2.but.the.selection.could.not.be.saved")
                                     .arg(name, new_name));
                });
        });
}

void AppState::copyText(const QString& text) {
    if (auto* clipboard = QGuiApplication::clipboard()) {
        clipboard->setText(text);
        set_notice(qtTrId("desktop.copied"));
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
    if (bits < 1e3) return qtTrId("desktop.bit.s").arg(locale.toString(bits, 'f', 0));
    if (bits < 1e6)
        return qtTrId("desktop.kbit.s").arg(locale.toString(bits / 1e3, 'f', 1));
    if (bits < 1e9)
        return qtTrId("desktop.mbit.s").arg(locale.toString(bits / 1e6, 'f', 1));
    return qtTrId("desktop.gbit.s").arg(locale.toString(bits / 1e9, 'f', 2));
}

QString AppState::formatDuration(double milliseconds) const {
    const auto seconds = static_cast<qint64>(milliseconds / 1000.0);
    const qint64 hours = seconds / 3600;
    const qint64 minutes = seconds / 60 % 60;
    if (hours > 0) return qtTrId("desktop.h.min").arg(hours).arg(minutes);
    if (minutes > 0) return qtTrId("desktop.min.s").arg(minutes).arg(seconds % 60);
    return qtTrId("desktop.s").arg(seconds);
}

}  // namespace yume::gui
