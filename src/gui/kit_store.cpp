/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "gui/kit_store.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <utility>

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QProcess>
#include <QRegularExpression>
#include <QStandardPaths>

namespace yume::gui {
namespace {

// A kit's yume.json is at most this large, as schema 1 bounds a document.
constexpr qint64 kMaxConfigBytes = 1024 * 1024;

// The last line yume printed, without its "yume: " prefix.
QString last_line(const QByteArray& output) {
    const auto lines =
        QString::fromUtf8(output).split(u'\n', Qt::SkipEmptyParts);
    if (lines.isEmpty()) return {};
    QString line = lines.last().trimmed();
    if (line.startsWith(QStringLiteral("yume: "))) line.remove(0, 6);
    return line;
}

QString read_server(const QString& config) {
    QFile file(config);
    if (file.size() > kMaxConfigBytes || !file.open(QIODevice::ReadOnly))
        return {};
    const auto document = QJsonDocument::fromJson(file.read(kMaxConfigBytes));
    const auto endpoint =
        document.object().value(QStringLiteral("endpoint")).toObject();
    const auto host = endpoint.value(QStringLiteral("host")).toString();
    const int port = endpoint.value(QStringLiteral("port")).toInt(0);
    if (host.isEmpty() || port <= 0) return {};
    return host.contains(u':') ? QStringLiteral("[%1]:%2").arg(host).arg(port)
                               : QStringLiteral("%1:%2").arg(host).arg(port);
}

}  // namespace

bool valid_kit_name(const QString& name) {
    static const QRegularExpression pattern(
        QStringLiteral("^[A-Za-z0-9_][A-Za-z0-9._-]{0,47}$"));
    return pattern.match(name).hasMatch();
}

QString suggested_kit_name(const QString& file) {
    QString base = QFileInfo(file).completeBaseName();
    QString name;
    for (const QChar ch : std::as_const(base)) {
        const bool plain = (ch >= u'a' && ch <= u'z') ||
                           (ch >= u'A' && ch <= u'Z') ||
                           (ch >= u'0' && ch <= u'9') || ch == u'-' ||
                           ch == u'_' || ch == u'.';
        name.append(plain ? ch : u'-');
    }
    while (name.startsWith(u'.') || name.startsWith(u'-')) name.remove(0, 1);
    name.truncate(48);
    return valid_kit_name(name) ? name : QStringLiteral("kit");
}

bool ensure_private_directory(const QString& dir, QString& error) {
    if (!QDir().mkpath(dir)) {
        error = QStringLiteral("cannot create %1").arg(dir);
        return false;
    }
    const QByteArray native = QFile::encodeName(dir);
    struct stat info{};
    if (::lstat(native.constData(), &info) != 0 || !S_ISDIR(info.st_mode) ||
        info.st_uid != ::geteuid()) {
        error = QStringLiteral("%1 is not a directory of this user").arg(dir);
        return false;
    }
    if ((info.st_mode & 0077) != 0 && ::chmod(native.constData(), 0700) != 0) {
        error = QStringLiteral("cannot make %1 private").arg(dir);
        return false;
    }
    return true;
}

std::optional<Places> find_places(const QString& yume, QString& error) {
    Places places;
    const QString config =
        QStandardPaths::writableLocation(QStandardPaths::GenericConfigLocation);
    if (config.isEmpty() || !QDir::isAbsolutePath(config)) {
        error = QStringLiteral(
            "no configuration directory (XDG_CONFIG_HOME or HOME)");
        return std::nullopt;
    }
    places.kits = QDir(config).filePath(QStringLiteral("yume/kits"));
    // The control socket must live in a directory only this user can reach,
    // and the runtime directory is that place on a desktop. There is no
    // shared fallback such as /tmp.
    const QString runtime = qEnvironmentVariable("XDG_RUNTIME_DIR");
    if (runtime.isEmpty() || !QDir::isAbsolutePath(runtime)) {
        error =
            QStringLiteral("XDG_RUNTIME_DIR is not set to an absolute path");
        return std::nullopt;
    }
    places.runtime = QDir(runtime).filePath(QStringLiteral("yume"));
    places.yume = yume.isEmpty() ? QDir(QCoreApplication::applicationDirPath())
                                       .filePath(QStringLiteral("yume"))
                                 : QFileInfo(yume).absoluteFilePath();
    const QFileInfo program(places.yume);
    if (!program.isFile() || !program.isExecutable()) {
        error = QStringLiteral("no yume program at %1").arg(places.yume);
        return std::nullopt;
    }
    return places;
}

std::vector<Kit> list_kits(const Places& places) {
    std::vector<Kit> kits;
    const QDir root(places.kits);
    const auto entries = root.entryInfoList(
        QDir::Dirs | QDir::NoDotAndDotDot | QDir::NoSymLinks, QDir::Name);
    for (const auto& entry : entries) {
        if (!valid_kit_name(entry.fileName())) continue;
        const QFileInfo config(
            QDir(entry.filePath()).filePath(QStringLiteral("yume.json")));
        if (!config.isFile() || config.isSymLink()) continue;
        kits.push_back({entry.fileName(), entry.filePath(), config.filePath(),
                        read_server(config.filePath())});
    }
    return kits;
}

void import_kit(QObject* context, const Places& places, const QString& file,
                const QString& name, QByteArray code,
                std::function<void(const QString& error)> done) {
    const auto fail = [&](const QString& reason) {
        code.fill('\0');
        QMetaObject::invokeMethod(
            context, [done, reason] { done(reason); }, Qt::QueuedConnection);
    };
    if (!valid_kit_name(name)) {
        fail(
            QStringLiteral("a kit name is 1 to 48 letters, digits, dots, "
                           "dashes or underscores"));
        return;
    }
    QString error;
    if (!ensure_private_directory(places.kits, error)) {
        fail(error);
        return;
    }
    const QString into = QDir(places.kits).filePath(name);
    if (QFileInfo::exists(into)) {
        fail(QStringLiteral("a kit named %1 already exists").arg(name));
        return;
    }
    auto* process = new QProcess(context);
    process->setProgram(places.yume);
    process->setArguments(
        {QStringLiteral("--import-kit"), file, QStringLiteral("--into"), into});
    process->setProcessChannelMode(QProcess::MergedChannels);
    QObject::connect(
        process, &QProcess::finished, context,
        [process, done](int code_exit, QProcess::ExitStatus status) {
            const QByteArray output = process->readAll();
            process->deleteLater();
            if (status == QProcess::NormalExit && code_exit == 0) {
                done({});
                return;
            }
            const QString reason = last_line(output);
            done(reason.isEmpty()
                     ? QStringLiteral("yume could not import the kit")
                     : reason);
        });
    QObject::connect(process, &QProcess::errorOccurred, context,
                     [process, done](QProcess::ProcessError error_kind) {
                         if (error_kind != QProcess::FailedToStart) return;
                         process->deleteLater();
                         done(QStringLiteral("cannot run yume"));
                     });
    process->start();
    // The code goes to yume's standard input, never its arguments or a file.
    code.append('\n');
    process->write(code);
    code.fill('\0');
    process->closeWriteChannel();
}

bool remove_kit(const Places& places, const QString& name, QString& error) {
    if (!valid_kit_name(name)) {
        error = QStringLiteral("not a kit name");
        return false;
    }
    const QFileInfo entry(QDir(places.kits).filePath(name));
    if (!entry.exists() || entry.isSymLink() || !entry.isDir() ||
        QDir(entry.absolutePath()) != QDir(places.kits)) {
        error = QStringLiteral("%1 is not a kit directory").arg(name);
        return false;
    }
    if (!QDir(entry.filePath()).removeRecursively()) {
        error = QStringLiteral("cannot remove %1").arg(entry.filePath());
        return false;
    }
    return true;
}

}  // namespace yume::gui
