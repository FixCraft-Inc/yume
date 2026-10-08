/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// Drives the real pages with the keyboard against the fake yume of
// tests/gui/fake_yume.py: page shortcuts, a focus order that reaches every
// action with an accessible name, connect and disconnect from the keyboard,
// and route consent that accepts only the reviewed proposal. With --rtl it
// checks the mirrored layout instead.

#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QApplication>
#include <QFontDatabase>
#include <QImage>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QQmlApplicationEngine>
#include <QQuickItem>
#include <QQuickStyle>
#include <QQuickWindow>
#include <QSet>
#include <QSettings>
#include <QTemporaryDir>
#include <QQmlComponent>
#include <QTcpServer>
#include <QTest>
#include <QtQml>

#include "gui/app_state.hpp"
#include "gui/kit_store.hpp"
#include "gui/mark.hpp"
#include "gui/offline_network.hpp"
#include "gui/tray.hpp"
#include "gui/tunnel.hpp"

namespace {

using namespace yume::gui;

bool g_rtl = false;

void write_json(const QString& path, const QJsonObject& value) {
    QFile file(path);
    QVERIFY(file.open(QIODevice::WriteOnly));
    file.write(QJsonDocument(value).toJson());
}

QString accessible_name(QQuickItem* item) {
    for (QObject* child : item->children()) {
        if (QString(child->metaObject()->className())
                .startsWith(QStringLiteral("QQuickAccessibleAttached")))
            return child->property("name").toString();
    }
    return {};
}

// The text of an item, or of its button, for finding one by what it says.
QString text_of(QQuickItem* item) {
    const QVariant text = item->property("text");
    return text.isValid() ? text.toString() : QString();
}

QQuickItem* find_button(QQuickItem* root, const QString& text) {
    const auto children = root->childItems();
    for (QQuickItem* child : children) {
        if (child->isVisible() && child->inherits("QQuickAbstractButton") &&
            text_of(child) == text)
            return child;
        if (QQuickItem* found = find_button(child, text)) return found;
    }
    return nullptr;
}

class UiTest final : public QObject {
    Q_OBJECT

private slots:
    void initTestCase() {
        QVERIFY(dir_.isValid());
        const QString config = dir_.filePath(QStringLiteral("config"));
        const QString runtime = dir_.filePath(QStringLiteral("run"));
        QVERIFY(QDir().mkpath(config + QStringLiteral("/yume/kits/work")));
        QVERIFY(QDir().mkpath(runtime));
        QFile::setPermissions(runtime, QFileDevice::ReadOwner |
                                           QFileDevice::WriteOwner |
                                           QFileDevice::ExeOwner);
        qputenv("XDG_CONFIG_HOME", config.toUtf8());
        qputenv("XDG_RUNTIME_DIR", runtime.toUtf8());
        kit_ = config + QStringLiteral("/yume/kits/work");
        QString directory_error;
        QVERIFY2(ensure_private_directory(QFileInfo(kit_).dir().path(),
                                          directory_error),
                 qPrintable(directory_error));
        QVERIFY2(ensure_private_directory(kit_, directory_error),
                 qPrintable(directory_error));
        write_json(kit_ + QStringLiteral("/yume.json"),
                   {{QStringLiteral("endpoint"),
                     QJsonObject{{QStringLiteral("host"),
                                  QStringLiteral("origin.example.net")},
                                 {QStringLiteral("port"), 443}}}});
        write_json(kit_ + QStringLiteral("/fake.json"),
                   {{QStringLiteral("circuits"), true},
                    {QStringLiteral("connect_after_ms"), 200}});

        QString error;
        auto places = find_places(QStringLiteral(YUME_GUI_FAKE_YUME), error);
        QVERIFY2(places.has_value(), qPrintable(error));
        if (g_rtl) QGuiApplication::setLayoutDirection(Qt::RightToLeft);
        state_ = new AppState(places, {}, QStringLiteral("light"), this);
        state_->set_kit_name(QStringLiteral("work"));
        qmlRegisterSingletonInstance("YumeBackend", 1, 0, "App", state_);
        make_engine_offline(engine_);
        engine_.load(QUrl(QStringLiteral("qrc:/yume/qml/Main.qml")));
        QVERIFY(!engine_.rootObjects().isEmpty());
        window_ = qobject_cast<QQuickWindow*>(engine_.rootObjects().first());
        QVERIFY(window_);
        window_->resize(1280, 800);
        window_->show();
        window_->requestActivate();
        QVERIFY(QTest::qWaitForWindowExposed(window_));
    }

    void cleanupTestCase() {
        // Whatever the tests left running is stopped, so no fake outlives them.
        if (state_ && state_->phase() == QStringLiteral("running")) {
            state_->stopKit();
            QTRY_COMPARE_WITH_TIMEOUT(state_->phase(),
                                      QStringLiteral("stopped"), 10000);
        }
    }

    void pages_switch_by_shortcut() {
        if (g_rtl) QSKIP("the left-to-right run covers shortcuts");
        const QStringList pages = AppState::pages();
        for (int index = pages.size() - 1; index >= 0; --index) {
            QTest::keyClick(window_, static_cast<Qt::Key>(Qt::Key_1 + index),
                            Qt::ControlModifier);
            QTRY_COMPARE(state_->page(), pages[index]);
        }
    }

    // Tab walks every page's controls, each focused control has a name a
    // screen reader can say, and the walk comes back around.
    void focus_order_names_every_control() {
        if (g_rtl) QSKIP("the left-to-right run covers focus");
        for (const QString& page : AppState::pages()) {
            state_->set_page(page);
            QTest::qWait(200);
            QSet<QQuickItem*> seen;
            QQuickItem* first = nullptr;
            for (int step = 0; step < 60; ++step) {
                QTest::keyClick(window_, Qt::Key_Tab);
                QQuickItem* focused = window_->activeFocusItem();
                QVERIFY2(focused, qPrintable(page));
                if (focused == first) break;
                if (!first) first = focused;
                seen.insert(focused);
                const QString name = accessible_name(focused);
                const QString text = text_of(focused);
                QVERIFY2(
                    !name.isEmpty() || !text.isEmpty() ||
                        focused->inherits("QQuickTextInput"),
                    qPrintable(
                        QStringLiteral("%1: a control without a name: %2")
                            .arg(page, focused->metaObject()->className())));
            }
            // The four page tabs and the primary action at least.
            QVERIFY2(seen.size() >= 5, qPrintable(page));
        }
    }

    // Connect from the keyboard, review the proposal, refuse it with Escape,
    // then accept exactly that proposal, and disconnect.
    void keyboard_lifecycle_and_route_consent() {
        if (g_rtl) QSKIP("the left-to-right run covers the lifecycle");
        state_->set_page(QStringLiteral("overview"));
        QQuickItem* primary = named(QStringLiteral("primaryAction"));
        QVERIFY(primary);
        QCOMPARE(text_of(primary), QStringLiteral("Connect"));
        primary->forceActiveFocus(Qt::TabFocusReason);
        QTest::keyClick(window_, Qt::Key_Space);
        QTRY_COMPARE_WITH_TIMEOUT(state_->phase(), QStringLiteral("running"),
                                  15000);
        QTRY_COMPARE_WITH_TIMEOUT(
            state_->status().value(QStringLiteral("state")).toString(),
            QStringLiteral("connected"), 15000);
        const auto proposal = [this] {
            return state_->status()
                .value(QStringLiteral("circuits"))
                .toMap()
                .value(QStringLiteral("proposal"))
                .toMap();
        };
        QTRY_VERIFY_WITH_TIMEOUT(!proposal().isEmpty(), 5000);
        const QString id = proposal().value(QStringLiteral("id")).toString();

        QQuickItem* review = named(QStringLiteral("reviewRoute"));
        QVERIFY(review);
        review->forceActiveFocus(Qt::TabFocusReason);
        QTest::keyClick(window_, Qt::Key_Return);
        QTRY_VERIFY(window_->activeFocusItem() &&
                    text_of(window_->activeFocusItem()) ==
                        QStringLiteral("Keep waiting"));
        QTest::keyClick(window_, Qt::Key_Escape);
        QTest::qWait(400);
        QVERIFY2(!QFile::exists(kit_ + QStringLiteral("/accepted.log")),
                 "closing the review accepted the route");

        review->forceActiveFocus(Qt::TabFocusReason);
        QTest::keyClick(window_, Qt::Key_Return);
        QTRY_VERIFY(window_->activeFocusItem() &&
                    text_of(window_->activeFocusItem()) ==
                        QStringLiteral("Keep waiting"));
        QTest::keyClick(window_, Qt::Key_Tab);
        QCOMPARE(text_of(window_->activeFocusItem()),
                 QStringLiteral("Accept this route"));
        QTest::keyClick(window_, Qt::Key_Space);
        QTRY_VERIFY_WITH_TIMEOUT(
            QFile::exists(kit_ + QStringLiteral("/accepted.log")), 5000);
        QFile accepted(kit_ + QStringLiteral("/accepted.log"));
        QVERIFY(accepted.open(QIODevice::ReadOnly));
        QCOMPARE(QString::fromUtf8(accepted.readAll()).trimmed(), id);
        QTRY_VERIFY_WITH_TIMEOUT(proposal().isEmpty(), 5000);

        QQuickItem* disconnect = named(QStringLiteral("primaryAction"));
        QVERIFY(disconnect);
        QCOMPARE(text_of(disconnect), QStringLiteral("Disconnect"));
        disconnect->forceActiveFocus(Qt::TabFocusReason);
        QTest::keyClick(window_, Qt::Key_Space);
        QTRY_COMPARE_WITH_TIMEOUT(state_->phase(), QStringLiteral("stopped"),
                                  15000);
    }

    void kit_directory_rename_preserves_files_and_rejects_unsafe_targets() {
        if (g_rtl) QSKIP("the left-to-right run covers kit storage");
        QTemporaryDir storage;
        QVERIFY(storage.isValid());
        Places places{storage.filePath(QStringLiteral("kits")), {}, {}};
        const QString source = places.kits + QStringLiteral("/original");
        QVERIFY(QDir().mkpath(source + QStringLiteral("/keys")));
        QString directory_error;
        QVERIFY2(ensure_private_directory(places.kits, directory_error),
                 qPrintable(directory_error));
        QVERIFY2(ensure_private_directory(source, directory_error),
                 qPrintable(directory_error));
        const QString credential =
            source + QStringLiteral("/keys/identity.pem");
        QFile key(credential);
        QVERIFY(key.open(QIODevice::WriteOnly));
        QCOMPARE(key.write("credential preservation fixture\n"), qint64(32));
        key.close();
        QVERIFY(key.setPermissions(QFileDevice::ReadOwner |
                                   QFileDevice::WriteOwner));
        const QJsonObject config{
            {QStringLiteral("credentials"),
             QJsonObject{{QStringLiteral("composite_key"),
                          QJsonObject{{QStringLiteral("file"),
                                       QStringLiteral("keys/identity.pem")}}}}},
            // A label is not a file reference and must not block the move.
            {QStringLiteral("label"), source}};
        write_json(source + QStringLiteral("/yume.json"), config);
        QFile document(source + QStringLiteral("/yume.json"));
        QVERIFY(document.open(QIODevice::ReadOnly));
        const QByteArray original = document.readAll();
        document.close();
        struct stat before{};
        QVERIFY(::stat(QFile::encodeName(credential).constData(), &before) ==
                0);
        QString error;
        for (const QString& invalid :
             {QString(), QStringLiteral("../outside"),
              QStringLiteral(".hidden"), QStringLiteral("-hidden"),
              QStringLiteral("two/names"), QStringLiteral("<b>kit</b>"),
              QString(49, u'a')}) {
            QVERIFY(!rename_kit(places, QStringLiteral("original"), invalid,
                                error));
            QVERIFY(QFileInfo::exists(credential));
        }
        const QString duplicate = places.kits + QStringLiteral("/duplicate");
        QVERIFY(QDir().mkpath(duplicate));
        write_json(duplicate + QStringLiteral("/yume.json"),
                   {{QStringLiteral("sentinel"), true}});
        QVERIFY(!rename_kit(places, QStringLiteral("original"),
                            QStringLiteral("duplicate"), error));
        QVERIFY(QFileInfo::exists(credential));
        QFile existing(duplicate + QStringLiteral("/yume.json"));
        QVERIFY(existing.open(QIODevice::ReadOnly));
        QVERIFY(existing.readAll().contains("sentinel"));
        const QString empty = places.kits + QStringLiteral("/empty");
        QVERIFY(QDir().mkpath(empty));
        QVERIFY(!rename_kit(places, QStringLiteral("original"),
                            QStringLiteral("empty"), error));
        QVERIFY(QFileInfo::exists(credential));
        QVERIFY(QFileInfo(empty).isDir());

        const QByteArray link =
            QFile::encodeName(places.kits + QStringLiteral("/linked"));
        QVERIFY(::symlink("original", link.constData()) == 0);
        QVERIFY(!rename_kit(places, QStringLiteral("linked"),
                            QStringLiteral("other"), error));
        const QByteArray dangling =
            QFile::encodeName(places.kits + QStringLiteral("/dangling"));
        QVERIFY(::symlink("missing", dangling.constData()) == 0);
        QVERIFY(!rename_kit(places, QStringLiteral("original"),
                            QStringLiteral("dangling"), error));
        QVERIFY(QFileInfo(QString::fromLocal8Bit(dangling)).isSymLink());

        const QByteArray root_link =
            QFile::encodeName(storage.filePath(QStringLiteral("root-link")));
        QVERIFY(::symlink(QFile::encodeName(places.kits).constData(),
                          root_link.constData()) == 0);
        Places linked_places = places;
        linked_places.kits = QString::fromLocal8Bit(root_link);
        QVERIFY(!rename_kit(linked_places, QStringLiteral("original"),
                            QStringLiteral("renamed"), error));
        const QString config_path = source + QStringLiteral("/yume.json");
        QVERIFY(QFile::remove(config_path));

        QVERIFY(::mkfifo(QFile::encodeName(config_path).constData(), 0600) ==
                0);
        QVERIFY(!rename_kit(places, QStringLiteral("original"),
                            QStringLiteral("renamed"), error));
        QVERIFY(QFileInfo::exists(credential));
        QVERIFY(QFile::remove(config_path));
        QFile oversized(config_path);
        QVERIFY(oversized.open(QIODevice::WriteOnly));
        const QByteArray too_large(1024 * 1024 + 1, ' ');
        QCOMPARE(oversized.write(too_large), qint64(too_large.size()));
        oversized.close();
        QVERIFY(!rename_kit(places, QStringLiteral("original"),
                            QStringLiteral("renamed"), error));
        QVERIFY(QFileInfo::exists(credential));
        QVERIFY(QFile::remove(config_path));
        QVERIFY(::symlink("keys/identity.pem",
                          QFile::encodeName(config_path).constData()) == 0);
        QVERIFY(!rename_kit(places, QStringLiteral("original"),
                            QStringLiteral("renamed"), error));
        QVERIFY(QFileInfo::exists(credential));
        QVERIFY(QFile::remove(config_path));

        write_json(source + QStringLiteral("/yume.json"),
                   {{QStringLiteral("credentials"),
                     QJsonObject{{QStringLiteral("composite_key"),
                                  QJsonObject{{QStringLiteral("file"),
                                               credential}}}}}});
        QVERIFY(!rename_kit(places, QStringLiteral("original"),
                            QStringLiteral("renamed"), error));
        QVERIFY2(error.contains(QStringLiteral("absolute path")),
                 qPrintable(error));
        QVERIFY(QFileInfo::exists(credential));
        for (const QString& traversal :
             {QStringLiteral("../original/key"),
              QStringLiteral("../external/key"),
              QStringLiteral("..\\original\\key"),
              QStringLiteral("..\\external\\key")}) {
            write_json(config_path,
                       {{QStringLiteral("credentials"),
                         QJsonObject{{QStringLiteral("composite_key"),
                                      QJsonObject{{QStringLiteral("file"),
                                                   traversal}}}}}});
            QVERIFY(!rename_kit(places, QStringLiteral("original"),
                                QStringLiteral("renamed"), error));
            QVERIFY(error.contains(QStringLiteral("parent traversal")));
            QVERIFY(QFileInfo::exists(credential));
        }
        write_json(source + QStringLiteral("/yume.json"), config);
        QVERIFY2(rename_kit(places, QStringLiteral("original"),
                            QStringLiteral("renamed"), error),
                 qPrintable(error));
        QVERIFY(!QFileInfo::exists(source));
        const QString moved =
            places.kits + QStringLiteral("/renamed/keys/identity.pem");
        struct stat after{};
        QVERIFY(::stat(QFile::encodeName(moved).constData(), &after) == 0);
        QCOMPARE(after.st_ino, before.st_ino);
        QCOMPARE(after.st_mode, before.st_mode);
        QFile preserved(moved);
        QVERIFY(preserved.open(QIODevice::ReadOnly));
        QCOMPARE(preserved.readAll(),
                 QByteArray("credential preservation fixture\n"));
        QFile moved_config(places.kits + QStringLiteral("/renamed/yume.json"));
        QVERIFY(moved_config.open(QIODevice::ReadOnly));
        QCOMPARE(moved_config.readAll(), original);
    }

    void keyboard_kit_rename_cancels_and_keeps_selection() {
        QCOMPARE(state_->phase(), QStringLiteral("stopped"));
        state_->set_page(QStringLiteral("connect"));
        QQuickItem* rename =
            find_button(window_->contentItem(), QStringLiteral("Rename"));
        QVERIFY(rename);
        QCOMPARE(accessible_name(rename), QStringLiteral("Rename work"));
        rename->forceActiveFocus(Qt::TabFocusReason);
        QTest::keyClick(window_, Qt::Key_Return);
        auto* dialog =
            window_->findChild<QObject*>(QStringLiteral("renameKitDialog"));
        QVERIFY(dialog);
        QTRY_VERIFY(dialog->property("visible").toBool());
        QQuickItem* field = named(QStringLiteral("renameKitName"));
        QVERIFY(field);
        QTRY_COMPARE(window_->activeFocusItem(), field);
        QCOMPARE(accessible_name(field), QStringLiteral("New kit name"));
        const QString artifacts =
            qEnvironmentVariable("YUME_GUI_TEST_ARTIFACTS");
        if (!artifacts.isEmpty()) {
            QTest::qWait(100);
            const QString image = QDir(artifacts).filePath(
                g_rtl ? QStringLiteral("rename-dialog-rtl.png")
                      : QStringLiteral("rename-dialog-ltr.png"));
            const QImage captured = window_->grabWindow();
            QVERIFY(!captured.isNull());
            QVERIFY2(captured.save(image), qPrintable(image));
        }
        QTest::keyClick(window_, 'x');
        QCOMPARE(field->property("text").toString(), QStringLiteral("x"));
        QTest::keyClick(window_, Qt::Key_Escape);
        QTRY_VERIFY(!dialog->property("visible").toBool());
        QCOMPARE(state_->kit_name(), QStringLiteral("work"));
        QVERIFY(QFileInfo::exists(kit_ + QStringLiteral("/yume.json")));

        rename = find_button(window_->contentItem(), QStringLiteral("Rename"));
        QVERIFY(rename);
        rename->forceActiveFocus(Qt::TabFocusReason);
        QTest::keyClick(window_, Qt::Key_Space);
        QTRY_VERIFY(dialog->property("visible").toBool());
        QTRY_COMPARE(window_->activeFocusItem(), field);
        for (const char ch : QByteArray("renamed"))
            QTest::keyClick(window_, ch);
        QCOMPARE(field->property("text").toString(), QStringLiteral("renamed"));
        QTest::keyClick(window_, Qt::Key_Tab);
        QCOMPARE(text_of(window_->activeFocusItem()), QStringLiteral("Cancel"));
        QTest::keyClick(window_, Qt::Key_Tab);
        QCOMPARE(text_of(window_->activeFocusItem()), QStringLiteral("Rename"));
        QTest::keyClick(window_, Qt::Key_Return);
        QTRY_COMPARE_WITH_TIMEOUT(state_->kit_name(), QStringLiteral("renamed"),
                                  5000);
        QVERIFY(!state_->renaming());
        QVERIFY(!QFileInfo::exists(kit_));
        QSettings saved(dir_.filePath(QStringLiteral("config/yume/gui.conf")),
                        QSettings::IniFormat);
        QCOMPARE(saved.value(QStringLiteral("kit")).toString(),
                 QStringLiteral("renamed"));
        // The renamed Tunnel uses the new path for a complete start and stop.
        state_->connectKit();
        QTRY_COMPARE_WITH_TIMEOUT(state_->phase(), QStringLiteral("running"),
                                  15000);
        state_->renameKit(QStringLiteral("renamed"),
                          QStringLiteral("forbidden"));
        QVERIFY(!state_->renaming());
        QCOMPARE(state_->kit_name(), QStringLiteral("renamed"));
        QVERIFY(state_->notice().contains(QStringLiteral("Stop renamed")));
        state_->stopKit();
        QTRY_COMPARE_WITH_TIMEOUT(state_->phase(), QStringLiteral("stopped"),
                                  15000);
        state_->renameKit(QStringLiteral("renamed"), QStringLiteral("work"));
        QTRY_COMPARE_WITH_TIMEOUT(state_->kit_name(), QStringLiteral("work"),
                                  5000);
        QVERIFY(QFileInfo::exists(kit_ + QStringLiteral("/yume.json")));
        saved.sync();
        QCOMPARE(saved.value(QStringLiteral("kit")).toString(),
                 QStringLiteral("work"));
    }

    void kit_rename_refuses_uncertain_control_reply() {
        if (g_rtl) QSKIP("the left-to-right run covers control checks");
        QString error;
        const auto places =
            find_places(QStringLiteral(YUME_GUI_FAKE_YUME), error);
        QVERIFY2(places.has_value(), qPrintable(error));
        QLocalServer uncertain;
        QVERIFY(uncertain.listen(
            QDir(places->runtime).filePath(QStringLiteral("uncertain.sock"))));
        connect(&uncertain, &QLocalServer::newConnection, &uncertain, [&] {
            while (auto* socket = uncertain.nextPendingConnection()) {
                socket->write("not control protocol 1\n");
                socket->disconnectFromServer();
                connect(socket, &QLocalSocket::disconnected, socket,
                        &QObject::deleteLater);
            }
        });
        state_->renameKit(QStringLiteral("work"), QStringLiteral("uncertain"));
        QTRY_VERIFY_WITH_TIMEOUT(!state_->renaming(), 5000);
        QCOMPARE(state_->kit_name(), QStringLiteral("work"));
        QVERIFY(QFileInfo::exists(kit_ + QStringLiteral("/yume.json")));
        QVERIFY(state_->notice().contains(QStringLiteral("Cannot confirm")));
    }

    void control_resource_error_does_not_authorize_mutation() {
        if (g_rtl)
            QSKIP("the left-to-right run covers injected control errors");
        QObject context;
        bool completed = false;
        ControlReply result;
        control_exchange(&context, QStringLiteral("/unreached.sock"),
                         status_request(), [&](const ControlReply& reply) {
                             completed = true;
                             result = reply;
                         });
        auto* socket = context.findChild<QLocalSocket*>();
        QVERIFY(socket);
        // Trigger Qt's actual error signal before the deferred connect runs;
        // a local resource failure establishes no absence of a peer.
        socket->errorOccurred(QLocalSocket::SocketResourceError);
        QVERIFY(completed);
        QCOMPARE(result.outcome, ControlReply::Outcome::Refused);
        QCOMPARE(result.peer_pid, qint64(0));
    }

    void kit_rename_rechecks_a_client_started_elsewhere() {
        if (g_rtl) QSKIP("the left-to-right run covers control checks");
        QString error;
        const auto places =
            find_places(QStringLiteral(YUME_GUI_FAKE_YUME), error);
        QVERIFY2(places.has_value(), qPrintable(error));
        const QString name = QStringLiteral("late-client");
        const QString directory = QDir(places->kits).filePath(name);
        QVERIFY(QDir().mkpath(directory));
        write_json(directory + QStringLiteral("/yume.json"),
                   {{QStringLiteral("endpoint"),
                     QJsonObject{{QStringLiteral("host"),
                                  QStringLiteral("example.net")},
                                 {QStringLiteral("port"), 443}}}});
        AppState local(places, {}, QStringLiteral("light"));
        local.set_kit_name(name);
        QVERIFY(local.tunnel());
        local.tunnel()->poll(60'000);
        QTest::qWait(100);
        QCOMPARE(local.phase(), QStringLiteral("stopped"));
        QProcess client;
        client.setProgram(QStringLiteral(YUME_GUI_FAKE_YUME));
        client.setArguments({QStringLiteral("--config"),
                             directory + QStringLiteral("/yume.json"),
                             QStringLiteral("--control-socket"),
                             local.tunnel()->socket_path()});
        client.start();
        QVERIFY(client.waitForStarted());
        QTRY_VERIFY_WITH_TIMEOUT(
            QFileInfo::exists(local.tunnel()->socket_path()), 5000);
        // The cached view remains stopped; only rename's fresh status request
        // discovers the process that started after it was last polled.
        QCOMPARE(local.phase(), QStringLiteral("stopped"));
        local.renameKit(name, QStringLiteral("late-renamed"));
        QTRY_VERIFY_WITH_TIMEOUT(!local.renaming(), 5000);
        QCOMPARE(local.kit_name(), name);
        QVERIFY(QFileInfo::exists(directory + QStringLiteral("/yume.json")));
        QVERIFY(local.notice().contains(QStringLiteral("Stop late-client")));
        client.terminate();
        QVERIFY(client.waitForFinished(10000));
        const QString target = QStringLiteral("late-destination");
        const QString target_socket =
            QDir(places->runtime).filePath(target + QStringLiteral(".sock"));
        client.setArguments({QStringLiteral("--config"),
                             directory + QStringLiteral("/yume.json"),
                             QStringLiteral("--control-socket"),
                             target_socket});
        client.start();
        QVERIFY(client.waitForStarted());
        QTRY_VERIFY_WITH_TIMEOUT(QFileInfo::exists(target_socket), 5000);
        local.renameKit(name, target);
        QTRY_VERIFY_WITH_TIMEOUT(!local.renaming(), 5000);
        QCOMPARE(local.kit_name(), name);
        QVERIFY(QFileInfo::exists(directory + QStringLiteral("/yume.json")));
        QVERIFY(
            local.notice().contains(QStringLiteral("Stop late-destination")));
        client.terminate();
        QVERIFY(client.waitForFinished(10000));
    }

    // Rich text that names a remote image loads nothing through an offline
    // engine. An ordinary engine does fetch it, which shows the probe works.
    void offline_engine_fetches_nothing() {
        if (g_rtl) QSKIP("the left-to-right run covers the network guard");
        QTcpServer probe;
        QVERIFY(probe.listen(QHostAddress::LocalHost, 0));
        int fetches = 0;
        connect(&probe, &QTcpServer::newConnection, &probe, [&] {
            while (auto* connection = probe.nextPendingConnection()) {
                ++fetches;
                connection->deleteLater();
            }
        });
        const QByteArray source =
            "import QtQuick\nText { textFormat: Text.RichText; text: "
            "'<img src=\"http://127.0.0.1:" +
            QByteArray::number(probe.serverPort()) + "/leak.png\">' }\n";
        const auto render = [&source](QQmlEngine& engine) {
            QQmlComponent component(&engine);
            component.setData(source, QUrl(QStringLiteral("qrc:/probe.qml")));
            std::unique_ptr<QObject> text(component.create());
            QVERIFY2(text, qPrintable(component.errorString()));
            QTest::qWait(1500);
        };
        QQmlEngine offline;
        make_engine_offline(offline);
        render(offline);
        QCOMPARE(fetches, 0);
        QQmlEngine ordinary;
        render(ordinary);
        QVERIFY2(fetches > 0, "the probe saw no fetch from an ordinary engine");
    }

    // A client this GUI did not start ends without a reason from the output
    // file, which holds an earlier start's lines.
    void a_client_started_elsewhere_ends_without_a_stale_reason() {
        if (g_rtl) QSKIP("the left-to-right run covers the lifecycle");
        QString error;
        auto places = find_places(QStringLiteral(YUME_GUI_FAKE_YUME), error);
        QVERIFY2(places.has_value(), qPrintable(error));
        const QString directory =
            QFileInfo(kit_).dir().filePath(QStringLiteral("elsewhere"));
        QVERIFY(QDir().mkpath(directory));
        write_json(directory + QStringLiteral("/yume.json"),
                   {{QStringLiteral("endpoint"),
                     QJsonObject{{QStringLiteral("host"), QStringLiteral("h")},
                                 {QStringLiteral("port"), 1}}}});
        write_json(directory + QStringLiteral("/fake.json"),
                   {{QStringLiteral("linger_ms"), 1500}});
        Kit kit;
        for (auto& listed : list_kits(*places))
            if (listed.name == QStringLiteral("elsewhere")) kit = listed;
        QCOMPARE(kit.name, QStringLiteral("elsewhere"));
        QVERIFY(ensure_private_directory(places->runtime, error));
        Tunnel tunnel(*places, kit);
        QFile stale(tunnel.output_path());
        QVERIFY(stale.open(QIODevice::WriteOnly | QIODevice::Truncate));
        stale.write("yume: an earlier start failed\n");
        stale.close();
        qint64 pid = 0;
        QProcess client;
        client.setProgram(QStringLiteral(YUME_GUI_FAKE_YUME));
        client.setArguments({QStringLiteral("--config"), kit.config,
                             QStringLiteral("--control-socket"),
                             tunnel.socket_path()});
        client.setStandardErrorFile(QProcess::nullDevice());
        QVERIFY(client.startDetached(&pid));
        tunnel.poll(Tunnel::kFastPollMs);
        QTRY_COMPARE_WITH_TIMEOUT(tunnel.phase(), Tunnel::Phase::Running,
                                  10000);
        QVERIFY(::kill(static_cast<pid_t>(pid), SIGTERM) == 0);
        QTRY_VERIFY_WITH_TIMEOUT(tunnel.status().isEmpty(), 1000);
        QCOMPARE(tunnel.phase(), Tunnel::Phase::Running);
        QVERIFY(tunnel.error().contains(QStringLiteral("has not ended")));
        QTRY_COMPARE_WITH_TIMEOUT(tunnel.phase(), Tunnel::Phase::Stopped,
                                  10000);
        QCOMPARE(tunnel.error(), QStringLiteral("yume stopped"));
    }

    // Layouts size a child by its implicit size, so an Icon's size must set
    // it. Qt 6.4 gave icons in layouts their default 20 pixels otherwise.
    void layout_children_keep_their_size() {
        if (g_rtl) QSKIP("the left-to-right run covers layout sizes");
        QQmlComponent component(&engine_);
        component.setData(
            "import QtQuick\nimport QtQuick.Layouts\n"
            "RowLayout { width: 400\n"
            "  Icon { objectName: 'icon'; name: 'key'; size: 14 }\n"
            "  Text { text: 'e'; Layout.fillWidth: true } }\n",
            QUrl(QStringLiteral("qrc:/yume/qml/LayoutProbe.qml")));
        std::unique_ptr<QObject> root(component.create());
        QVERIFY2(root, qPrintable(component.errorString()));
        qobject_cast<QQuickItem*>(root.get())
            ->setParentItem(window_->contentItem());
        QTest::qWait(100);
        auto* icon = root->findChild<QQuickItem*>(QStringLiteral("icon"));
        QVERIFY(icon);
        QCOMPARE(icon->width(), 14.0);
        QCOMPARE(icon->height(), 14.0);
    }

    // The mark comes from assets/icon.svg, and the parser takes only well
    // formed path text.
    void mark_is_read_from_the_icon() {
        if (g_rtl) QSKIP("the left-to-right run covers the mark");
        const QPainterPath mark = parse_svg_path(mark_path_data());
        QVERIFY(!mark.isEmpty());
        const QRectF bounds = mark.boundingRect();
        QVERIFY2(bounds.left() > 0 && bounds.top() > 0 &&
                     bounds.right() < 256 && bounds.bottom() < 256 &&
                     bounds.width() > 200,
                 "the mark does not fill its 256-unit box");
        QCOMPARE(state_->mark_path(), mark_path_data());
        for (const char* text : {"M 1", "X 1 2", "1 2", "c 1 2 3 4 5", "z 1"})
            QVERIFY2(parse_svg_path(QString::fromLatin1(text)).isEmpty(), text);
        QVERIFY(!parse_svg_path(QStringLiteral("M1 2l3-4-5 6z")).isEmpty());
    }

    // The tray names the state, colours its dot by it, runs the main action
    // and shows or hides the window.
    void tray_follows_the_selected_kit() {
        if (g_rtl) QSKIP("the left-to-right run covers the tray");
        QCOMPARE(state_->phase(), QStringLiteral("stopped"));
        Tray tray(state_, window_);
        QCOMPARE(tray.kind(), QStringLiteral("rest"));
        QCOMPARE(tray.action()->text(), QStringLiteral("Connect"));
        QVERIFY(tray.action()->isEnabled());
        QCOMPARE(tray.header()->text(),
                 QStringLiteral("YUME: work, Not running"));
        const qint64 resting = tray.icon().cacheKey();
        tray.action()->trigger();
        QTRY_COMPARE_WITH_TIMEOUT(tray.kind(), QStringLiteral("good"), 15000);
        QCOMPARE(tray.action()->text(), QStringLiteral("Disconnect"));
        QCOMPARE(tray.header()->text(),
                 QStringLiteral("YUME: work, Connected"));
        QVERIFY(tray.icon().cacheKey() != resting);
        QSet<QRgb> dots;
        for (const char* kind : {"good", "busy", "bad", "rest"})
            dots.insert(Tray::dot_colour(QString::fromLatin1(kind)).rgb());
        QCOMPARE(dots.size(), 4);

        QVERIFY(window_->isVisible());
        tray.visibility()->trigger();
        QTRY_VERIFY(!window_->isVisible());
        QCOMPARE(tray.visibility()->text(), QStringLiteral("Show window"));
        tray.visibility()->trigger();
        QTRY_VERIFY(window_->isVisible());

        tray.action()->trigger();
        QTRY_COMPARE_WITH_TIMEOUT(tray.kind(), QStringLiteral("rest"), 15000);
        QCOMPARE(state_->phase(), QStringLiteral("stopped"));
    }

    // In right-to-left the sidebar sits on the right and the page's content
    // starts at the right edge.
    void right_to_left_mirrors_the_layout() {
        if (!g_rtl) QSKIP("run with --rtl");
        QVERIFY(state_->right_to_left());
        QQuickItem* overview =
            find_button(window_->contentItem(), QStringLiteral("Overview"));
        QVERIFY(overview);
        const QPointF at = overview->mapToScene(QPointF(0, 0));
        QVERIFY2(
            at.x() > window_->width() / 2.0,
            qPrintable(QStringLiteral("the sidebar is at x %1").arg(at.x())));
    }

private:
    QQuickItem* named(const QString& name) const {
        // QML objects are QObject children of the object that declares them,
        // and Main.qml's root is the window itself.
        return window_->findChild<QQuickItem*>(name);
    }

    QTemporaryDir dir_;
    QString kit_;
    AppState* state_{nullptr};
    QQmlApplicationEngine engine_;
    QQuickWindow* window_{nullptr};
};

}  // namespace

int main(int argc, char** argv) {
    // --rtl is this test's own flag, not QtTest's.
    int kept = 0;
    for (int index = 0; index < argc; ++index) {
        if (std::strcmp(argv[index], "--rtl") == 0) {
            g_rtl = true;
            continue;
        }
        argv[kept++] = argv[index];
    }
    argc = kept;
    QApplication application(argc, argv);
    QQuickStyle::setStyle(QStringLiteral("Basic"));
    QFontDatabase::addApplicationFont(
        QStringLiteral(":/yume/fonts/Jost-Regular.ttf"));
    UiTest test;
    return QTest::qExec(&test, argc, argv);
}

#include "ui_test.moc"
