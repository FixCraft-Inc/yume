/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU General Public License v3.0.
 */

#pragma once

#include <cstddef>
#include <string>
#include <vector>

#if !defined(_WIN32)
#include <termios.h>
#endif

namespace yume::client {

bool is_tty_stdin();
std::string trim_copy(std::string s);
std::string ltrim_copy(std::string s);
bool split_first_token(std::string input, std::string* token, std::string* rest);
bool prompt_hidden_input(const std::string& prompt, std::string* out, std::string* error);

#if defined(_WIN32)
bool read_stdin_line_with_timeout(std::string* out, int timeout_ms);
#else
void restore_tracked_terminal_mode();

class InteractiveLineReader {
public:
    InteractiveLineReader();
    ~InteractiveLineReader();

    bool read_line(std::string* out, int timeout_ms);

private:
    enum class EscapeState {
        none,
        esc,
        bracket,
    };

    bool fallback_read_line(std::string* out, int timeout_ms);
    bool enable_raw_mode();
    void restore_raw_mode();
    void redraw_line();
    void commit_history(const std::string& line);
    void browse_history_up();
    void browse_history_down();
    bool process_char(char ch, std::string* out);

    termios original_termios_{};
    bool enabled_{false};
    bool raw_active_{false};
    static constexpr const char* kPrompt = "yume> ";
    EscapeState escape_state_{EscapeState::none};
    std::vector<std::string> history_;
    std::size_t history_index_{0};
    bool browsing_history_{false};
    std::string draft_buffer_;
    std::string buffer_;
};
#endif

}  // namespace yume::client
