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

#include <cstdlib>
#include <cstring>

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QApplication>
#include <QFontDatabase>
#include <QJsonDocument>
#include <QJsonObject>
#include <QQmlApplicationEngine>
#include <QQuickItem>
#include <QQuickStyle>
#include <QQuickWindow>
#include <QSet>
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
                   {{QStringLiteral("linger_ms"), 0}});
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
        ::kill(static_cast<pid_t>(pid), SIGKILL);
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
