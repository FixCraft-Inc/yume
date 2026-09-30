/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "gui/mark.hpp"

#include <QFile>
#include <QLinearGradient>
#include <QPainter>
#include <QPixmap>
#include <QRegularExpression>

namespace yume::gui {
namespace {

// The icon file is a few kilobytes, and its path is shorter still.
constexpr qint64 kMaxIconBytes = 64 * 1024;

// The gradient of the light theme's mark, as Logo.qml draws it, in the
// icon's coordinates.
void fill_mark(QPainter& painter, const QPainterPath& mark) {
    QLinearGradient gradient(QPointF(145.1, 251.9), QPointF(125.8, 22.0));
    gradient.setColorAt(0.0, QColor(0xec, 0x9e, 0xd6));
    gradient.setColorAt(1.0, QColor(0xb0, 0x56, 0x9c));
    painter.fillPath(mark, gradient);
}

}  // namespace

QString mark_path_data() {
    QFile file(QStringLiteral(":/yume/icon.svg"));
    if (file.size() > kMaxIconBytes || !file.open(QIODevice::ReadOnly))
        return {};
    static const QRegularExpression pattern(
        QStringLiteral(R"re(<path\b[^>]*?\sd="([^"]*)")re"));
    const auto match =
        pattern.match(QString::fromUtf8(file.read(kMaxIconBytes)));
    return match.hasMatch() ? match.captured(1) : QString();
}

QPainterPath parse_svg_path(const QString& data) {
    static const QRegularExpression token(QStringLiteral(
        R"([MmLlCcZz]|[-+]?(?:\d+\.?\d*|\.\d+)(?:[eE][-+]?\d+)?)"));
    QPainterPath path;
    QPointF current;
    QPointF start;
    QChar command;
    QList<double> numbers;
    // Runs the pending command over its numbers, repeating it as SVG allows.
    const auto flush = [&]() -> bool {
        const bool relative = command.isLower();
        const QChar kind = command.toLower();
        if (kind == u'z') {
            if (!numbers.isEmpty()) return false;
            path.closeSubpath();
            current = start;
            return true;
        }
        const qsizetype arity = kind == u'c' ? 6 : 2;
        if (numbers.isEmpty() || numbers.size() % arity != 0) return false;
        for (qsizetype at = 0; at < numbers.size(); at += arity) {
            const QPointF anchor = relative ? current : QPointF();
            if (kind == u'c') {
                const QPointF one =
                    anchor + QPointF(numbers[at], numbers[at + 1]);
                const QPointF two =
                    anchor + QPointF(numbers[at + 2], numbers[at + 3]);
                current = anchor + QPointF(numbers[at + 4], numbers[at + 5]);
                path.cubicTo(one, two, current);
            } else if (kind == u'm' && at == 0) {
                current = anchor + QPointF(numbers[at], numbers[at + 1]);
                start = current;
                path.moveTo(current);
            } else {
                // Pairs after a moveto's first are linetos.
                current = anchor + QPointF(numbers[at], numbers[at + 1]);
                path.lineTo(current);
            }
        }
        return true;
    };
    auto matches = token.globalMatch(data);
    while (matches.hasNext()) {
        const QString text = matches.next().captured(0);
        if (text.size() == 1 && text[0].isLetter()) {
            if (!command.isNull() && !flush()) return {};
            command = text[0];
            numbers.clear();
            continue;
        }
        if (command.isNull()) return {};
        numbers.append(text.toDouble());
    }
    if (!command.isNull() && !flush()) return {};
    return path;
}

QIcon mark_icon(const QColor& dot) {
    const QPainterPath mark = parse_svg_path(mark_path_data());
    QIcon icon;
    for (const int size : {16, 22, 24, 32, 48, 64, 128, 256}) {
        QPixmap pixmap(size, size);
        pixmap.fill(Qt::transparent);
        QPainter painter(&pixmap);
        painter.setRenderHint(QPainter::Antialiasing);
        painter.save();
        painter.scale(size / 256.0, size / 256.0);
        fill_mark(painter, mark);
        painter.restore();
        if (dot.isValid()) {
            // A state dot with a light ring, so it reads on any panel.
            const double diameter = size * 0.46;
            const QRectF where(size - diameter, size - diameter, diameter,
                               diameter);
            painter.setPen(QPen(QColor(0xff, 0xfc, 0xfe), size * 0.07));
            painter.setBrush(dot);
            painter.drawEllipse(where.adjusted(size * 0.035, size * 0.035,
                                               -size * 0.035, -size * 0.035));
        }
        painter.end();
        icon.addPixmap(pixmap);
    }
    return icon;
}

}  // namespace yume::gui
