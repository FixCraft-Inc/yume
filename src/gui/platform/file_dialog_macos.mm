/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

// macOS implementation of the GUI file pickers using AppKit's NSOpenPanel /
// NSSavePanel. Compiled INSTEAD of file_dialog.cpp on Apple targets (see
// src/gui/CMakeLists.txt). This is Objective-C++ (.mm) so it can talk to Cocoa
// directly instead of shelling out to zenity/kdialog (which don't exist on
// macOS — the old POSIX path failed at runtime there).
//
// NSApp already exists because GLFW creates it during window init, and the GUI
// invokes these from its main-thread frame loop, so runModal is safe. No ARC is
// assumed: every Cocoa object used here is autoreleased and freed by the
// enclosing @autoreleasepool, which behaves identically under MRC and ARC.

#include "platform/file_dialog.hpp"

#import <AppKit/AppKit.h>

#include <string>

namespace yume::gui::platform {

namespace {

NSString* to_nsstring(std::string const& s) {
    NSString* out = [NSString stringWithUTF8String:s.c_str()];
    return out ? out : @"";
}

std::optional<std::filesystem::path> url_to_path(NSURL* url, std::string* err) {
    if (!url || ![url isFileURL]) {
        if (err) *err = "no file selected";
        return std::nullopt;
    }
    const char* path = [[url path] fileSystemRepresentation];
    if (!path) {
        if (err) *err = "could not resolve the selected path";
        return std::nullopt;
    }
    return std::filesystem::path(path);
}

}  // namespace

std::optional<std::filesystem::path> open_file_dialog(std::string const& title,
                                                       std::string* err) {
    @autoreleasepool {
        NSOpenPanel* panel = [NSOpenPanel openPanel];
        panel.canChooseFiles = YES;
        panel.canChooseDirectories = NO;
        panel.allowsMultipleSelection = NO;
        panel.resolvesAliases = YES;
        if (!title.empty()) {
            panel.message = to_nsstring(title);
        }
        if ([panel runModal] != NSModalResponseOK) {
            if (err) *err = "file selection cancelled";
            return std::nullopt;
        }
        return url_to_path([panel URL], err);
    }
}

std::optional<std::filesystem::path> save_file_dialog(std::string const& title,
                                                       std::string const& default_name,
                                                       std::string* err) {
    @autoreleasepool {
        NSSavePanel* panel = [NSSavePanel savePanel];
        panel.canCreateDirectories = YES;
        if (!title.empty()) {
            panel.message = to_nsstring(title);
        }
        if (!default_name.empty()) {
            panel.nameFieldStringValue = to_nsstring(default_name);
        }
        if ([panel runModal] != NSModalResponseOK) {
            if (err) *err = "save cancelled";
            return std::nullopt;
        }
        return url_to_path([panel URL], err);
    }
}

void set_dialog_parent_window(void* /*glfw_window*/) {}

}  // namespace yume::gui::platform
