/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

// yume-gui: the desktop GUI. It runs unprivileged and talks to each yume it
// shows only through that yume's control socket (docs/protocol/CONTROL_1.md).
// It starts a kit's yume as a detached process, so the tunnel outlives the
// GUI, and stops it with the control protocol's stop request.

#include <atomic>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <string_view>

#include <QApplication>
#include <QCoreApplication>
#include <QFontDatabase>
#include <QGuiApplication>
#include <QIcon>
#include <QQmlApplicationEngine>
#include <QQuickStyle>
#include <QQuickWindow>
#include <QRegularExpression>
#include <QSurfaceFormat>
#include <QUrl>
#include <QtGlobal>

#include "common/version.hpp"
#include "gui/app_state.hpp"
#include "gui/capture.hpp"
#include "gui/headless.hpp"
#include "gui/kit_store.hpp"
#include "gui/mark.hpp"
#include "gui/offline_network.hpp"
#include "gui/tray.hpp"
#include "gui/yume_gui_help_text.hpp"

namespace {

using namespace yume::gui;

constexpr int kExitUsage = 2;

struct Arguments final {
    QString kit;
    QString page;
    QString theme;
    QString direction;
    QString size;
    QString yume;
    QString capture;
    QString headless;
    QString import_kit;
    QString name;
    bool version{false};
    bool help{false};
    bool no_tray{false};
};

// The flags that take one value, and where each goes.
struct ValueFlag final {
    const char* flag;
    QString Arguments::* value;
};
constexpr ValueFlag kValueFlags[] = {
    {"--kit", &Arguments::kit},
    {"--page", &Arguments::page},
    {"--theme", &Arguments::theme},
    {"--layout-direction", &Arguments::direction},
    {"--size", &Arguments::size},
    {"--yume", &Arguments::yume},
    {"--capture", &Arguments::capture},
    {"--headless", &Arguments::headless},
    {"--import-kit", &Arguments::import_kit},
    {"--name", &Arguments::name},
};

bool one_of(const QString& value, std::initializer_list<const char*> allowed) {
    for (const char* item : allowed)
        if (value == QLatin1String(item)) return true;
    return false;
}

std::optional<Arguments> parse(const QStringList& list, QString& error) {
    Arguments arguments;
    for (qsizetype index = 1; index < list.size(); ++index) {
        const QString& argument = list[index];
        const ValueFlag* matched = nullptr;
        for (const auto& flag : kValueFlags)
            if (argument == QLatin1String(flag.flag)) matched = &flag;
        if (matched) {
            QString& value = arguments.*(matched->value);
            if (index + 1 >= list.size() || !value.isEmpty() ||
                list[index + 1].isEmpty()) {
                error = argument + QStringLiteral(" needs exactly one value");
                return std::nullopt;
            }
            value = list[++index];
        } else if (argument == QLatin1String("--version")) {
            arguments.version = true;
        } else if (argument == QLatin1String("--no-tray")) {
            arguments.no_tray = true;
        } else if (argument == QLatin1String("--help") ||
                   argument == QLatin1String("-h")) {
            arguments.help = true;
        } else {
            error = QStringLiteral("unknown argument: ") + argument;
            return std::nullopt;
        }
    }
    if (!arguments.page.isEmpty() &&
        !AppState::pages().contains(arguments.page)) {
        error = QStringLiteral("--page takes ") +
                AppState::pages().join(QStringLiteral(", "));
        return std::nullopt;
    }
    if (!arguments.theme.isEmpty() &&
        !one_of(arguments.theme, {"light", "dark", "system"})) {
        error = QStringLiteral("--theme takes light, dark or system");
        return std::nullopt;
    }
    if (!arguments.direction.isEmpty() &&
        !one_of(arguments.direction, {"ltr", "rtl"})) {
        error = QStringLiteral("--layout-direction takes ltr or rtl");
        return std::nullopt;
    }
    if (!arguments.size.isEmpty() &&
        !QRegularExpression(QStringLiteral("^[1-9][0-9]{2,3}x[1-9][0-9]{2,3}$"))
             .match(arguments.size)
             .hasMatch()) {
        error = QStringLiteral("--size takes WIDTHxHEIGHT, such as 1280x800");
        return std::nullopt;
    }
    if (!arguments.headless.isEmpty() &&
        !one_of(arguments.headless, {"status", "connect", "stop", "cycle"})) {
        error =
            QStringLiteral("--headless takes status, connect, stop or cycle");
        return std::nullopt;
    }
    const bool window_flags =
        !arguments.page.isEmpty() || !arguments.theme.isEmpty() ||
        !arguments.direction.isEmpty() || !arguments.size.isEmpty() ||
        !arguments.capture.isEmpty() || arguments.no_tray;
    if (!arguments.headless.isEmpty() &&
        (arguments.kit.isEmpty() || window_flags ||
         !arguments.import_kit.isEmpty() || !arguments.name.isEmpty())) {
        error = QStringLiteral("--headless takes --kit and --yume");
        return std::nullopt;
    }
    if (!arguments.import_kit.isEmpty() || !arguments.name.isEmpty()) {
        if (arguments.import_kit.isEmpty() || arguments.name.isEmpty() ||
            window_flags || !arguments.kit.isEmpty()) {
            error = QStringLiteral("--import-kit takes --name and --yume");
            return std::nullopt;
        }
    }
    return arguments;
}

void print_version() {
    std::printf("yume-gui %s\n", yume::kVersion);
    std::printf("Qt %s, built with %s, control protocol 1\n", qVersion(),
                QT_VERSION_STR);
}

// QML warnings fail a capture, since a broken binding shows a wrong page.
std::atomic<int> g_qml_warnings{0};
QtMessageHandler g_previous_handler = nullptr;

void count_qml_warnings(QtMsgType type, const QMessageLogContext& context,
                        const QString& text) {
    const bool qml =
        (context.file && std::string_view(context.file).find(".qml") !=
                             std::string_view::npos) ||
        (context.category && (std::strcmp(context.category, "qml") == 0 ||
                              std::strcmp(context.category, "js") == 0));
    if (qml &&
        (type == QtWarningMsg || type == QtCriticalMsg || type == QtFatalMsg))
        ++g_qml_warnings;
    if (g_previous_handler) g_previous_handler(type, context, text);
}

int run_window(int argc, char** argv) {
    // QApplication rather than QGuiApplication, for the tray icon.
    QApplication application(argc, argv);
    QGuiApplication::setApplicationName(QStringLiteral("yume-gui"));
    QGuiApplication::setApplicationDisplayName(QStringLiteral("YUME"));
    QGuiApplication::setDesktopFileName(QStringLiteral("yume-gui"));
    QString error;
    const auto arguments = parse(QCoreApplication::arguments(), error);
    if (!arguments) {
        std::fprintf(stderr, "yume-gui: %s\n%s", qPrintable(error),
                     yume::gui::help::kHelpBody);
        return kExitUsage;
    }
    if (arguments->direction == QLatin1String("rtl"))
        QGuiApplication::setLayoutDirection(Qt::RightToLeft);
    else if (arguments->direction == QLatin1String("ltr"))
        QGuiApplication::setLayoutDirection(Qt::LeftToRight);
    g_previous_handler = qInstallMessageHandler(count_qml_warnings);
    // One style everywhere, drawn by the GUI's own theme, so a desktop's
    // style plugin cannot change what the pages look like.
    QQuickStyle::setStyle(QStringLiteral("Basic"));
    // Multisampling smooths the drawn icons and logo, which Qt 6.4's shape
    // renderer draws without antialiasing of its own.
    QSurfaceFormat format = QSurfaceFormat::defaultFormat();
    format.setSamples(4);
    QSurfaceFormat::setDefaultFormat(format);
    QFontDatabase::addApplicationFont(
        QStringLiteral(":/yume/fonts/Jost-Regular.ttf"));
    QGuiApplication::setWindowIcon(mark_icon());

    QString setup_error;
    auto places = find_places(arguments->yume, setup_error);
    AppState state(places, setup_error, arguments->theme);
    if (!arguments->kit.isEmpty()) state.set_kit_name(arguments->kit);
    if (!arguments->page.isEmpty()) state.set_page(arguments->page);
    qmlRegisterSingletonInstance("YumeBackend", 1, 0, "App", &state);

    QQmlApplicationEngine engine;
    make_engine_offline(engine);
    engine.load(QUrl(QStringLiteral("qrc:/yume/qml/Main.qml")));
    auto* window =
        engine.rootObjects().isEmpty()
            ? nullptr
            : qobject_cast<QQuickWindow*>(engine.rootObjects().first());
    if (!window) {
        std::fprintf(stderr, "yume-gui: the interface did not load\n");
        return 1;
    }
    if (!arguments->size.isEmpty()) {
        const auto parts = arguments->size.split(u'x');
        window->resize(parts[0].toInt(), parts[1].toInt());
    }
    // A capture renders the window alone, and a desktop without a tray
    // closes the GUI with its window.
    std::unique_ptr<Tray> tray;
    if (!arguments->capture.isEmpty()) {
        start_capture(window, &state, arguments->capture);
    } else if (!arguments->no_tray && Tray::available()) {
        tray = std::make_unique<Tray>(&state, window);
        tray->show();
        state.set_tray_active(true);
    }
    const int code = QGuiApplication::exec();
    if (!arguments->capture.isEmpty() && g_qml_warnings.load() != 0) {
        std::fprintf(stderr, "yume-gui: %d QML warnings during the capture\n",
                     g_qml_warnings.load());
        return 1;
    }
    return code;
}

int run_console(int argc, char** argv) {
    QCoreApplication application(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("yume-gui"));
    QString error;
    const auto arguments = parse(QCoreApplication::arguments(), error);
    if (!arguments) {
        std::fprintf(stderr, "yume-gui: %s\n%s", qPrintable(error),
                     yume::gui::help::kHelpBody);
        return kExitUsage;
    }
    if (arguments->help) {
        std::fputs(yume::gui::help::kHelpBody, stdout);
        return 0;
    }
    if (arguments->version) {
        print_version();
        return 0;
    }
    const auto places = find_places(arguments->yume, error);
    if (!places) {
        std::fprintf(stderr, "yume-gui: %s\n", qPrintable(error));
        return kHeadlessNothingExercised;
    }
    if (!arguments->import_kit.isEmpty())
        return run_headless_import(*places, arguments->import_kit,
                                   arguments->name);
    return run_headless_action(*places, arguments->headless, arguments->kit);
}

}  // namespace

int main(int argc, char** argv) {
    // The console actions need no display, so they never open one.
    bool console = false;
    for (int index = 1; index < argc; ++index) {
        const std::string_view argument(argv[index]);
        if (argument == "--headless" || argument == "--import-kit" ||
            argument == "--version" || argument == "--help" || argument == "-h")
            console = true;
    }
    return console ? run_console(argc, argv) : run_window(argc, argv);
}
