/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "gui/control_client.hpp"

#include <sys/socket.h>
#include <unistd.h>

#include <utility>

#include <QByteArray>
#include <QJsonDocument>
#include <QJsonParseError>
#include <QLocalSocket>
#include <QTimer>

namespace yume::gui {
namespace {

using Outcome = ControlReply::Outcome;

// One connection's state. It is a child of the caller's context object, so
// destroying the context ends the exchange without a callback.
class Exchange final : public QObject {
public:
    Exchange(QObject* context, QString path, QByteArray line,
             std::function<void(const ControlReply&)> done, int timeout_ms)
        : QObject(context),
          path_(std::move(path)),
          line_(std::move(line)),
          done_(std::move(done)),
          socket_(new QLocalSocket(this)),
          timer_(new QTimer(this)) {
        timer_->setSingleShot(true);
        connect(timer_, &QTimer::timeout, this, [this] {
            finish(
                {Outcome::TimedOut,
                 {},
                 {},
                 QStringLiteral("the control socket did not answer in time")});
        });
        connect(socket_, &QLocalSocket::connected, this,
                [this] { on_connected(); });
        connect(socket_, &QLocalSocket::readyRead, this,
                [this] { on_ready_read(); });
        connect(socket_, &QLocalSocket::disconnected, this,
                [this] { on_closed(); });
        connect(
            socket_, &QLocalSocket::errorOccurred, this,
            [this](QLocalSocket::LocalSocketError error) { on_error(error); });
        timer_->start(timeout_ms);
        // Started from the event loop, so an immediate failure never calls
        // back into the caller's own stack.
        QTimer::singleShot(0, this,
                           [this] { socket_->connectToServer(path_); });
    }

private:
    void on_connected() {
        // The program checks its peers, and this client checks the program:
        // a socket of another user could forge any state.
        ucred peer{};
        socklen_t size = sizeof(peer);
        const int fd = static_cast<int>(socket_->socketDescriptor());
        if (fd < 0 ||
            ::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) != 0 ||
            size != sizeof(peer) || peer.uid != ::geteuid()) {
            finish(
                {Outcome::Refused,
                 {},
                 {},
                 QStringLiteral("the control socket belongs to another user")});
            return;
        }
        connected_ = true;
        peer_pid_ = peer.pid;
        socket_->write(line_);
    }

    void on_ready_read() {
        reply_ += socket_->readAll();
        if (reply_.size() > kControlReplyBytes) {
            finish({Outcome::Malformed,
                    {},
                    {},
                    QStringLiteral("the control reply is too large")});
        }
    }

    void on_error(QLocalSocket::LocalSocketError error) {
        if (error == QLocalSocket::PeerClosedError) {
            on_closed();
            return;
        }
        if (connected_) {
            finish({Outcome::Malformed, {}, {}, socket_->errorString()});
            return;
        }
        switch (error) {
            case QLocalSocket::ServerNotFoundError:
            case QLocalSocket::ConnectionRefusedError:
                finish(
                    {Outcome::NotRunning,
                     {},
                     {},
                     QStringLiteral("nothing listens on the control socket")});
                return;
            case QLocalSocket::SocketAccessError:
                finish(
                    {Outcome::Refused,
                     {},
                     {},
                     QStringLiteral("the control socket is not accessible")});
                return;
            default:
                finish({Outcome::NotRunning, {}, {}, socket_->errorString()});
                return;
        }
    }

    // The program closes the connection after its one reply line.
    void on_closed() {
        if (finished_) return;
        reply_ += socket_->readAll();
        if (reply_.isEmpty() && !connected_) {
            finish({Outcome::NotRunning,
                    {},
                    {},
                    QStringLiteral("nothing listens on the control socket")});
            return;
        }
        if (reply_.isEmpty() || !reply_.endsWith('\n') ||
            reply_.indexOf('\n') != reply_.size() - 1) {
            finish({Outcome::Malformed,
                    {},
                    {},
                    QStringLiteral("the control reply is incomplete")});
            return;
        }
        QJsonParseError error{};
        const auto document =
            QJsonDocument::fromJson(reply_.chopped(1), &error);
        if (error.error != QJsonParseError::NoError || !document.isObject() ||
            document.object().value(QStringLiteral("control")).toInt(-1) != 1) {
            finish({Outcome::Malformed,
                    {},
                    {},
                    QStringLiteral("the reply is not control protocol 1")});
            return;
        }
        const auto value = document.object();
        if (value.contains(QStringLiteral("error"))) {
            finish({Outcome::Error, value,
                    value.value(QStringLiteral("code")).toString(),
                    value.value(QStringLiteral("error")).toString()});
            return;
        }
        finish({Outcome::Ok, value, {}, {}});
    }

    void finish(ControlReply reply) {
        if (finished_) return;
        finished_ = true;
        reply.peer_pid = peer_pid_;
        timer_->stop();
        socket_->abort();
        auto done = std::move(done_);
        deleteLater();
        if (done) done(reply);
    }

    QString path_;
    QByteArray line_;
    std::function<void(const ControlReply&)> done_;
    QLocalSocket* socket_;
    QTimer* timer_;
    QByteArray reply_;
    qint64 peer_pid_{0};
    bool connected_{false};
    bool finished_{false};
};

}  // namespace

void control_exchange(QObject* context, const QString& path,
                      const QJsonObject& request,
                      std::function<void(const ControlReply&)> done,
                      int timeout_ms) {
    QByteArray line = QJsonDocument(request).toJson(QJsonDocument::Compact);
    line.append('\n');
    if (line.size() > kControlRequestBytes) {
        QTimer::singleShot(0, context, [done = std::move(done)] {
            done({Outcome::Malformed,
                  {},
                  {},
                  QStringLiteral("the request is too long")});
        });
        return;
    }
    new Exchange(context, path, std::move(line), std::move(done), timeout_ms);
}

QJsonObject status_request() {
    return {{QStringLiteral("control"), 1},
            {QStringLiteral("request"), QStringLiteral("status")}};
}

QJsonObject messages_request(quint64 after) {
    return {{QStringLiteral("control"), 1},
            {QStringLiteral("request"), QStringLiteral("messages")},
            {QStringLiteral("after"), static_cast<qint64>(after)}};
}

QJsonObject stop_request() {
    return {{QStringLiteral("control"), 1},
            {QStringLiteral("request"), QStringLiteral("stop")}};
}

QJsonObject accept_route_request(const QString& id) {
    return {{QStringLiteral("control"), 1},
            {QStringLiteral("request"), QStringLiteral("accept-route")},
            {QStringLiteral("id"), id}};
}

}  // namespace yume::gui
