/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "gui/offline_network.hpp"

#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QQmlEngine>
#include <QQmlNetworkAccessManagerFactory>
#include <QUrl>

namespace yume::gui {
namespace {

// Every request becomes one for a scheme no handler serves, which fails
// with ProtocolUnknownError without touching the network.
class OfflineAccessManager final : public QNetworkAccessManager {
public:
    using QNetworkAccessManager::QNetworkAccessManager;

protected:
    QNetworkReply* createRequest(Operation operation,
                                 const QNetworkRequest& request,
                                 QIODevice* data) override {
        static_cast<void>(request);
        static_cast<void>(data);
        return QNetworkAccessManager::createRequest(
            operation, QNetworkRequest(QUrl(QStringLiteral("refused:"))),
            nullptr);
    }
};

class OfflineFactory final : public QQmlNetworkAccessManagerFactory {
public:
    QNetworkAccessManager* create(QObject* parent) override {
        return new OfflineAccessManager(parent);
    }
};

}  // namespace

void make_engine_offline(QQmlEngine& engine) {
    // The engine does not own its factory, which lives as long as the program.
    static OfflineFactory factory;
    engine.setNetworkAccessManagerFactory(&factory);
}

}  // namespace yume::gui
