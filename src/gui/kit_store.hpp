/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#pragma once

#include <functional>
#include <optional>
#include <vector>

#include <QByteArray>
#include <QObject>
#include <QString>

namespace yume::gui {

// A client kit the GUI manages: a directory under the kits root that holds
// a yume.json, as `yume --import-kit` writes it.
struct Kit final {
    QString name;
    QString directory;
    QString config;
    // The configured server as host:port, read only to label the kit. The
    // running yume's status names the server it actually uses.
    QString server;
};

// Where the GUI keeps kits and the per-user runtime files of the clients it
// starts. Each path is fixed by the XDG directories, never guessed.
struct Places final {
    // $XDG_CONFIG_HOME/yume/kits, one directory per kit.
    QString kits;
    // $XDG_RUNTIME_DIR/yume, holding each running client's control socket
    // and the output of its latest start.
    QString runtime;
    // The yume program the GUI runs.
    QString yume;
};

// A kit name: 1 to 48 characters of [A-Za-z0-9._-], not starting with a dot
// or a dash. It names the kit's directory, control socket and output file.
bool valid_kit_name(const QString& name);

// A name for a kit imported from file, derived from its base name.
QString suggested_kit_name(const QString& file);

// The standard places, with yume next to this program unless one is given.
// Fails with a reason when XDG_RUNTIME_DIR is unusable or yume is missing.
std::optional<Places> find_places(const QString& yume, QString& error);

// Creates dir with mode 0700 if needed and requires it to be a directory of
// this user that group and others cannot write, as the control socket's
// directory must be.
bool ensure_private_directory(const QString& dir, QString& error);

// The kits under places.kits, sorted by name. Entries that are not a
// directory holding a regular yume.json are skipped.
std::vector<Kit> list_kits(const Places& places);

// Imports a sealed kit by running `yume --import-kit FILE --into DIR` with the
// code on its standard input, so the one implementation in yume checks and
// writes it. done runs once on context's thread with an empty string on
// success or the reason for failure. This function's copy of the code is
// overwritten once it is handed to yume. The caller clears its own.
void import_kit(QObject* context, const Places& places, const QString& file,
                const QString& name, QByteArray code,
                std::function<void(const QString& error)> done);

// Removes a kit's directory, which must be a real directory directly under
// places.kits. The caller makes sure its client is not running.
bool remove_kit(const Places& places, const QString& name, QString& error);

// Renames a real kit directory without replacing any existing target. The
// configuration and credentials are not rewritten. Absolute references into
// the old directory are refused. The caller checks both clients are stopped.
bool rename_kit(const Places& places, const QString& name,
                const QString& new_name, QString& error);

}  // namespace yume::gui
