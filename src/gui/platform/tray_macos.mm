/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "platform/tray.hpp"
#include "platform/tray_icon.hpp"

#import <AppKit/AppKit.h>

#include <algorithm>
#include <filesystem>
#include <string>
#include <vector>

namespace yume::gui {

namespace {

NSString* to_nsstring(std::string const& s) {
    NSString* out = [NSString stringWithUTF8String:s.c_str()];
    return out ? out : @"";
}

void remove_icon_files(std::vector<std::string> const& paths) {
    for (auto const& p : paths) {
        std::error_code ec;
        std::filesystem::remove(p, ec);
    }
}

std::string write_icon_for_status(TrayStatus const& st,
                                  std::filesystem::path const& icon_dir) {
    return tray_icon::write_status_png(st, icon_dir,
                                       tray_icon::status_digest(st));
}

NSImage* image_from_png_path(std::string const& path) {
    if (path.empty()) return nil;
    NSString* ns = to_nsstring(path);
    NSImage* img = [[NSImage alloc] initWithContentsOfFile:ns];
    if (!img) return nil;
    [img setSize:NSMakeSize(18, 18)];
    return img;
}

}  // namespace

struct Tray::Impl {
    std::string name;
    Callbacks callbacks;
    NSStatusItem* status_item{nil};
    void* delegate{nil};
    TrayStatus last_status;
    TrayInfo last_info;
    std::string last_info_digest;
    std::filesystem::path icon_dir;
    std::vector<std::string> temp_icons;
    bool available{false};
};

namespace {

@interface YumeTrayDelegate : NSObject
@property(nonatomic, assign) Tray::Impl* tray;
- (void)showWindow:(id)sender;
- (void)quit:(id)sender;
@end

@implementation YumeTrayDelegate
- (void)showWindow:(id) /*sender*/ {
    if (self.tray && self.tray->callbacks.on_show_window) {
        self.tray->callbacks.on_show_window();
    }
}
- (void)quit:(id) /*sender*/ {
    if (self.tray && self.tray->callbacks.on_quit) {
        self.tray->callbacks.on_quit();
    }
}
@end

void rebuild_info_menu(NSMenu* menu, TrayInfo const& info) {
    while ([menu numberOfItems] > 2) {
        [menu removeItemAtIndex:1];
    }
    NSInteger insert = 1;
    auto add_line = [&](std::string const& text) {
        if (text.empty()) return;
        NSMenuItem* item = [[NSMenuItem alloc] initWithTitle:to_nsstring(text)
                                                      action:nil
                                               keyEquivalent:@""];
        [item setEnabled:NO];
        [menu insertItem:item atIndex:insert++];
    };
    if (!info.client_state.empty()) {
        add_line("Yume: " + info.client_state);
    }
    if (!info.client_server.empty()) add_line("Server: " + info.client_server);
    if (!info.client_profile.empty()) add_line("Profile: " + info.client_profile);
    if (!info.exit_country.empty()) add_line("Exit: " + info.exit_country);
    if (!info.exit_ip.empty()) add_line("Exit IP: " + info.exit_ip);
    if (!info.client_rates.empty()) add_line(info.client_rates);
    if (!info.server_state.empty()) {
        add_line("Local daemon: " + info.server_state);
    }
    if (insert > 1) {
        [menu insertItem:[NSMenuItem separatorItem] atIndex:insert];
    }
}

}  // namespace

Tray::Tray(std::string app_name, Callbacks cb)
    : impl_(std::make_unique<Impl>()) {
    impl_->name = std::move(app_name);
    impl_->callbacks = std::move(cb);
    impl_->icon_dir = tray_icon::icon_directory();

    @autoreleasepool {
        auto* delegate = [[YumeTrayDelegate alloc] init];
        delegate.tray = impl_.get();
        impl_->delegate = delegate;

        NSStatusItem* item =
            [[NSStatusBar systemStatusBar] statusItemWithLength:NSSquareStatusItemLength];
        if (!item) return;

        const std::string initial = write_icon_for_status(TrayStatus{}, impl_->icon_dir);
        if (!initial.empty()) {
            impl_->temp_icons.push_back(initial);
            item.button.image = image_from_png_path(initial);
        }
        item.button.toolTip = @"Yume";

        NSMenu* menu = [[NSMenu alloc] init];
        NSMenuItem* show_item =
            [[NSMenuItem alloc] initWithTitle:@"Show Yume"
                                       action:@selector(showWindow:)
                                keyEquivalent:@""];
        [show_item setTarget:delegate];
        [menu addItem:show_item];

        NSMenuItem* quit_item =
            [[NSMenuItem alloc] initWithTitle:@"Quit Yume"
                                       action:@selector(quit:)
                                keyEquivalent:@"q"];
        [quit_item setTarget:delegate];
        [menu addItem:quit_item];

        item.menu = menu;
        impl_->status_item = item;
        impl_->available = true;
    }
}

Tray::~Tray() {
    if (impl_) {
        remove_icon_files(impl_->temp_icons);
        @autoreleasepool {
            if (impl_->status_item) {
                [[NSStatusBar systemStatusBar] removeStatusItem:impl_->status_item];
                impl_->status_item = nil;
            }
            impl_->delegate = nil;
        }
    }
}

bool Tray::available() const {
    return impl_ && impl_->available;
}

void Tray::set_status(TrayStatus const& status) {
    if (!impl_ || !impl_->available || !impl_->status_item) return;
    if (status.client == impl_->last_status.client &&
        status.server == impl_->last_status.server) {
        return;
    }
    impl_->last_status = status;
    @autoreleasepool {
        const std::string path = write_icon_for_status(status, impl_->icon_dir);
        if (path.empty()) return;
        if (std::find(impl_->temp_icons.begin(), impl_->temp_icons.end(), path) ==
            impl_->temp_icons.end()) {
            impl_->temp_icons.push_back(path);
        }
        impl_->status_item.button.image = image_from_png_path(path);
    }
}

void Tray::set_info(TrayInfo const& info) {
    if (!impl_ || !impl_->available || !impl_->status_item) return;
    std::string digest;
    digest.reserve(256);
    auto add = [&](std::string const& v) {
        digest.append(v);
        digest.push_back('\x1f');
    };
    add(info.client_state);
    add(info.client_server);
    add(info.client_profile);
    add(info.exit_ip);
    add(info.exit_country);
    add(info.client_rates);
    add(info.server_state);
    if (digest == impl_->last_info_digest) return;
    impl_->last_info_digest = digest;
    impl_->last_info = info;

    @autoreleasepool {
        NSMenu* menu = impl_->status_item.menu;
        if (!menu) return;
        rebuild_info_menu(menu, info);
        std::string tip = "Yume";
        if (!info.client_state.empty()) {
            tip += " - " + info.client_state;
        }
        impl_->status_item.button.toolTip = to_nsstring(tip);
    }
}

void Tray::pump_events() {
    @autoreleasepool {
        NSEvent* event = nil;
        do {
            event = [NSApp nextEventMatchingMask:NSEventMaskAny
                                       untilDate:[NSDate distantPast]
                                          inMode:NSDefaultRunLoopMode
                                         dequeue:YES];
            if (event) {
                [NSApp sendEvent:event];
            }
        } while (event);
    }
}

}  // namespace yume::gui
