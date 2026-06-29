/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "client/cli/config/input.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <mutex>
#include <thread>
#include <utility>

#if defined(_WIN32)
#include <conio.h>
#include <io.h>
#else
#include <sys/select.h>
#include <unistd.h>
#endif

#include "util.hpp"

namespace yume::client {
namespace {

#if !defined(_WIN32)
std::mutex g_terminal_mode_mutex;
bool g_terminal_mode_saved = false;
std::size_t g_terminal_mode_depth = 0;
termios g_terminal_mode_original{};

void push_terminal_mode(const termios& original) {
    std::lock_guard<std::mutex> lock(g_terminal_mode_mutex);
    if (g_terminal_mode_depth == 0) {
        g_terminal_mode_original = original;
        g_terminal_mode_saved = true;
    }
    ++g_terminal_mode_depth;
}

void pop_terminal_mode() {
    std::lock_guard<std::mutex> lock(g_terminal_mode_mutex);
    if (g_terminal_mode_depth == 0) {
        return;
    }
    --g_terminal_mode_depth;
    if (g_terminal_mode_depth == 0) {
        g_terminal_mode_saved = false;
    }
}
#endif

}  // namespace

bool is_tty_stdin() {
#if defined(_WIN32)
    return _isatty(_fileno(stdin)) != 0;
#else
    return isatty(fileno(stdin)) != 0;
#endif
}

#if defined(_WIN32)
bool read_stdin_line_with_timeout(std::string* out, int timeout_ms) {
    if (!out) {
        return false;
    }
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (_kbhit()) {
            return static_cast<bool>(std::getline(std::cin, *out));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return false;
}
#endif

std::string trim_copy(std::string s) {
    auto is_space = [](unsigned char ch) { return std::isspace(ch) != 0; };
    while (!s.empty() && is_space(static_cast<unsigned char>(s.front()))) {
        s.erase(s.begin());
    }
    while (!s.empty() && is_space(static_cast<unsigned char>(s.back()))) {
        s.pop_back();
    }
    return s;
}

std::string ltrim_copy(std::string s) {
    auto is_space = [](unsigned char ch) { return std::isspace(ch) != 0; };
    while (!s.empty() && is_space(static_cast<unsigned char>(s.front()))) {
        s.erase(s.begin());
    }
    return s;
}

bool split_first_token(std::string input, std::string* token, std::string* rest) {
    if (!token || !rest) {
        return false;
    }
    input = ltrim_copy(std::move(input));
    if (input.empty()) {
        token->clear();
        rest->clear();
        return false;
    }
    std::size_t pos = 0;
    while (pos < input.size() && !std::isspace(static_cast<unsigned char>(input[pos]))) {
        ++pos;
    }
    *token = input.substr(0, pos);
    while (pos < input.size() && std::isspace(static_cast<unsigned char>(input[pos]))) {
        ++pos;
    }
    *rest = input.substr(pos);
    return !token->empty();
}

#if !defined(_WIN32)
void restore_tracked_terminal_mode() {
    std::lock_guard<std::mutex> lock(g_terminal_mode_mutex);
    if (!g_terminal_mode_saved) {
        return;
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &g_terminal_mode_original);
    g_terminal_mode_depth = 0;
    g_terminal_mode_saved = false;
}

InteractiveLineReader::InteractiveLineReader() {
    enabled_ = enable_raw_mode();
    if (enabled_) {
        redraw_line();
    }
}

InteractiveLineReader::~InteractiveLineReader() {
    if (enabled_) {
        restore_raw_mode();
    }
}

bool InteractiveLineReader::read_line(std::string* out, int timeout_ms) {
    if (!out) {
        return false;
    }
    if (!enabled_) {
        return fallback_read_line(out, timeout_ms);
    }

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = static_cast<suseconds_t>((timeout_ms % 1000) * 1000);
    const int rc = select(STDIN_FILENO + 1, &rfds, nullptr, nullptr, &tv);
    if (rc <= 0 || !FD_ISSET(STDIN_FILENO, &rfds)) {
        return false;
    }

    char buf[32];
    const ssize_t bytes = ::read(STDIN_FILENO, buf, sizeof(buf));
    if (bytes <= 0) {
        return false;
    }

    for (ssize_t i = 0; i < bytes; ++i) {
        if (process_char(buf[i], out)) {
            return true;
        }
    }
    return false;
}

bool InteractiveLineReader::fallback_read_line(std::string* out, int timeout_ms) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = static_cast<suseconds_t>((timeout_ms % 1000) * 1000);
    const int rc = select(STDIN_FILENO + 1, &rfds, nullptr, nullptr, &tv);
    if (rc <= 0 || !FD_ISSET(STDIN_FILENO, &rfds)) {
        return false;
    }
    return static_cast<bool>(std::getline(std::cin, *out));
}

bool InteractiveLineReader::enable_raw_mode() {
    if (!is_tty_stdin()) {
        return false;
    }
    if (tcgetattr(STDIN_FILENO, &original_termios_) != 0) {
        return false;
    }
    termios raw = original_termios_;
    raw.c_lflag &= static_cast<unsigned int>(~(ICANON | ECHO));
    raw.c_iflag &= static_cast<unsigned int>(~(IXON | ICRNL));
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) != 0) {
        return false;
    }
    push_terminal_mode(original_termios_);
    raw_active_ = true;
    return true;
}

void InteractiveLineReader::restore_raw_mode() {
    if (!raw_active_) {
        return;
    }
    tcsetattr(STDIN_FILENO, TCSANOW, &original_termios_);
    pop_terminal_mode();
    raw_active_ = false;
}

void InteractiveLineReader::redraw_line() {
    util::clear_status_line();
    std::cout << "\r\033[2K" << kPrompt << buffer_ << std::flush;
}

void InteractiveLineReader::commit_history(const std::string& line) {
    if (line.empty()) {
        return;
    }
    if (history_.empty() || history_.back() != line) {
        history_.push_back(line);
    }
    history_index_ = history_.size();
    browsing_history_ = false;
    draft_buffer_.clear();
}

void InteractiveLineReader::browse_history_up() {
    if (history_.empty()) {
        return;
    }
    if (!browsing_history_) {
        draft_buffer_ = buffer_;
        browsing_history_ = true;
        history_index_ = history_.size();
    }
    if (history_index_ == 0) {
        return;
    }
    --history_index_;
    buffer_ = history_[history_index_];
    redraw_line();
}

void InteractiveLineReader::browse_history_down() {
    if (!browsing_history_) {
        return;
    }
    if (history_index_ + 1 < history_.size()) {
        ++history_index_;
        buffer_ = history_[history_index_];
    } else {
        browsing_history_ = false;
        history_index_ = history_.size();
        buffer_ = draft_buffer_;
    }
    redraw_line();
}

bool InteractiveLineReader::process_char(char ch, std::string* out) {
    if (escape_state_ == EscapeState::esc) {
        escape_state_ = (ch == '[') ? EscapeState::bracket : EscapeState::none;
        return false;
    }
    if (escape_state_ == EscapeState::bracket) {
        escape_state_ = EscapeState::none;
        if (ch == 'A') {
            browse_history_up();
        } else if (ch == 'B') {
            browse_history_down();
        }
        return false;
    }
    if (ch == '\x1b') {
        escape_state_ = EscapeState::esc;
        return false;
    }
    if (ch == '\r' || ch == '\n') {
        std::cout << "\r\033[2K" << kPrompt << buffer_ << std::endl;
        *out = buffer_;
        commit_history(*out);
        buffer_.clear();
        return true;
    }
    if (ch == 0x7f || ch == '\b') {
        if (!buffer_.empty()) {
            buffer_.pop_back();
            redraw_line();
        }
        return false;
    }
    if (ch == 0x04) {
        return false;
    }
    if (std::isprint(static_cast<unsigned char>(ch)) || ch == '\t') {
        buffer_.push_back(ch);
        redraw_line();
    }
    return false;
}
#endif

bool prompt_hidden_input(const std::string& prompt, std::string* out, std::string* error) {
    if (!out) {
        if (error) {
            *error = "password output is null";
        }
        return false;
    }
    if (!is_tty_stdin()) {
        if (error) {
            *error = "interactive password prompt requires a TTY";
        }
        return false;
    }

    util::clear_status_line();
    std::cout << prompt << std::flush;

#if defined(_WIN32)
    out->clear();
    for (;;) {
        const int ch = _getch();
        if (ch == '\r' || ch == '\n') {
            break;
        }
        if (ch == 0 || ch == 224) {
            (void)_getch();
            continue;
        }
        if (ch == '\b') {
            if (!out->empty()) {
                out->pop_back();
            }
            continue;
        }
        if (ch == 3) {
            if (error) {
                *error = "password prompt cancelled";
            }
            std::cout << std::endl;
            return false;
        }
        if (ch >= 0 && std::isprint(static_cast<unsigned char>(ch))) {
            out->push_back(static_cast<char>(ch));
        }
    }
    std::cout << std::endl;
    return true;
#else
    termios original{};
    if (tcgetattr(STDIN_FILENO, &original) != 0) {
        if (error) {
            *error = "failed to read terminal settings";
        }
        std::cout << std::endl;
        return false;
    }
    termios prompt_mode = original;
    prompt_mode.c_lflag |= ICANON;
    prompt_mode.c_lflag &= static_cast<unsigned int>(~ECHO);
    prompt_mode.c_iflag |= ICRNL;
    prompt_mode.c_cc[VMIN] = 1;
    prompt_mode.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSANOW, &prompt_mode) != 0) {
        if (error) {
            *error = "failed to enable hidden password prompt";
        }
        std::cout << std::endl;
        return false;
    }
    push_terminal_mode(original);

    std::string value;
    for (;;) {
        char ch = '\0';
        const ssize_t n = ::read(STDIN_FILENO, &ch, 1);
        if (n <= 0) {
            tcsetattr(STDIN_FILENO, TCSANOW, &original);
            pop_terminal_mode();
            std::cout << std::endl;
            if (error) {
                *error = "password prompt interrupted";
            }
            return false;
        }
        if (ch == '\n') {
            break;
        }
        if (ch != '\r') {
            value.push_back(ch);
        }
    }
    std::cout << std::endl;
    tcsetattr(STDIN_FILENO, TCSANOW, &original);
    pop_terminal_mode();
    *out = std::move(value);
    return true;
#endif
}

}  // namespace yume::client
