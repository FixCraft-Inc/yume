/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <functional>

#include <QJsonObject>
#include <QObject>
#include <QString>

namespace yume::gui {

// One exchange of control protocol 1 (docs/protocol/CONTROL_1.md): connect to
// the owner-only socket, refuse a peer of another user, send one request line
// and read one reply line until the program closes the connection.
struct ControlReply final {
    enum class Outcome {
        Ok,          // value holds a protocol 1 reply without an error
        NotRunning,  // nothing listens on the socket
        Refused,     // the socket is not this user's or not accessible
        TimedOut,    // no complete reply within the deadline
        Malformed,   // the reply is not one protocol 1 JSON line
        Error,       // the program answered with an error: code and text
    };

    Outcome outcome{Outcome::NotRunning};
    QJsonObject value;
    // For Error, the reply's code, which a caller acts on. Otherwise empty.
    QString code;
    // For people: the reply's error text or what went wrong locally.
    QString text;
    // The process that answered, from the socket's peer credentials, 0 when
    // none did. A stop waits for it to end, not only for its socket.
    qint64 peer_pid{0};

    bool ok() const noexcept { return outcome == Outcome::Ok; }
};

// The protocol's bounds, as the programs enforce them.
inline constexpr int kControlRequestBytes = 512;
inline constexpr int kControlReplyBytes = 64 * 1024;
inline constexpr int kControlTimeoutMs = 3000;

// Sends request to the socket at path. done runs once, on the thread of
// context, unless context is destroyed first. It never blocks the caller.
void control_exchange(QObject* context, const QString& path,
                      const QJsonObject& request,
                      std::function<void(const ControlReply&)> done,
                      int timeout_ms = kControlTimeoutMs);

// The request objects this program sends, each closed as the protocol
// requires.
QJsonObject status_request();
QJsonObject messages_request(quint64 after);
QJsonObject stop_request();
QJsonObject accept_route_request(const QString& id);

}  // namespace yume::gui
