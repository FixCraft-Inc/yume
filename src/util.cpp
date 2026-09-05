/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "util.hpp"

#include "util_json.hpp"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cerrno>
#include <condition_variable>
#include <cstdio>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#if defined(_WIN32)
#include <io.h>
#else
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <unistd.h>
#endif

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <cctype>

#if YUME_USE_SPDLOG
#include <spdlog/spdlog.h>
#endif

namespace yume::util {

namespace {
bool g_logging_enabled = true;
std::mutex g_status_mutex;
std::string g_status_text;
std::size_t g_status_lines = 0;
bool g_status_enabled = true;
bool g_status_active = false;
bool g_status_supported = true;
std::mutex g_rate_log_mutex;
std::unordered_map<std::string, int64_t> g_rate_log_last_ms;

bool is_tty_stdout() {
#if defined(_WIN32)
    return _isatty(_fileno(stdout)) != 0;
#else
    return isatty(fileno(stdout)) != 0;
#endif
}

#if !YUME_USE_SPDLOG
bool is_tty_stderr() {
#if defined(_WIN32)
    return _isatty(_fileno(stderr)) != 0;
#else
    return isatty(fileno(stderr)) != 0;
#endif
}
#endif

bool read_env_flag(const char* name, bool fallback) {
    const char* raw = std::getenv(name);
    if (!raw || !*raw) {
        return fallback;
    }
    std::string value(raw);
    for (char& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    if (value == "1" || value == "true" || value == "yes" || value == "on") {
        return true;
    }
    if (value == "0" || value == "false" || value == "no" || value == "off") {
        return false;
    }
    return fallback;
}

#if !YUME_USE_SPDLOG
bool log_colors_enabled() {
    if (!is_tty_stderr()) {
        return false;
    }
    if (std::getenv("NO_COLOR") != nullptr) {
        return false;
    }
    return read_env_flag("YUME_COLOR", true) && !read_env_flag("YUME_NO_COLOR", false);
}

void print_plain_log(const char* level, const std::string& msg) {
    std::cerr << "[" << level << "] " << msg << std::endl;
}

void print_colored_log(const char* level, const char* color_code, const std::string& msg) {
    if (!log_colors_enabled()) {
        print_plain_log(level, msg);
        return;
    }
    std::cerr << "\033[" << color_code << "m[" << level << "]\033[0m " << msg << std::endl;
}
#endif

std::size_t count_status_lines(const std::string& text) {
    if (text.empty()) {
        return 0;
    }
    std::size_t lines = 1;
    for (char ch : text) {
        if (ch == '\n') {
            ++lines;
        }
    }
    return lines;
}

void clear_status_line_locked() {
    if (!g_status_supported || !g_status_enabled) {
        return;
    }
    if (!g_status_active && g_status_text.empty()) {
        return;
    }
    if (g_status_lines == 0) {
        g_status_active = false;
        return;
    }
    for (std::size_t i = 0; i < g_status_lines; ++i) {
        std::cout << "\r\033[2K";
        if (i + 1 < g_status_lines) {
            std::cout << "\033[1A";
        }
    }
    std::cout << std::flush;
    g_status_active = false;
}

void render_status_line_locked() {
    if (!g_status_supported || !g_status_enabled) {
        return;
    }
    if (g_status_text.empty()) {
        return;
    }
    std::cout << "\r" << g_status_text << "\033[2K" << std::flush;
    g_status_active = true;
}

bool is_env_char(char ch) {
    return std::isalnum(static_cast<unsigned char>(ch)) != 0 || ch == '_';
}

#if !defined(_WIN32)
struct DropPrivilegeTarget {
    uid_t uid{0};
    gid_t gid{0};
    std::string name;
};

template <typename Lookup>
std::optional<DropPrivilegeTarget> lookup_passwd_entry(Lookup&& lookup) {
    constexpr std::size_t kFallbackBufferSize = 16 * 1024;
    constexpr std::size_t kMaxBufferSize = 1024 * 1024;

    const long configured_size = sysconf(_SC_GETPW_R_SIZE_MAX);
    std::size_t buffer_size =
        configured_size > 0
            ? std::min<std::size_t>(
                  static_cast<std::size_t>(configured_size),
                  kMaxBufferSize)
            : kFallbackBufferSize;

    for (;;) {
        std::vector<char> buffer(buffer_size);
        struct passwd entry {};
        struct passwd* result = nullptr;
        const int rc =
            lookup(&entry, buffer.data(), buffer.size(), &result);
        if (rc == 0) {
            if (!result) {
                return std::nullopt;
            }
            DropPrivilegeTarget target;
            target.uid = result->pw_uid;
            target.gid = result->pw_gid;
            if (result->pw_name) {
                target.name = result->pw_name;
            }
            return target;
        }
        if (rc != ERANGE || buffer_size == kMaxBufferSize) {
            return std::nullopt;
        }
        buffer_size =
            std::min(buffer_size * 2, kMaxBufferSize);
    }
}

std::optional<DropPrivilegeTarget> lookup_passwd_by_uid(uid_t uid) {
    return lookup_passwd_entry(
        [uid](struct passwd* entry,
              char* buffer,
              std::size_t buffer_size,
              struct passwd** result) {
            return getpwuid_r(
                uid, entry, buffer, buffer_size, result);
        });
}

std::optional<DropPrivilegeTarget> lookup_passwd_by_name(
    const char* name) {
    return lookup_passwd_entry(
        [name](struct passwd* entry,
               char* buffer,
               std::size_t buffer_size,
               struct passwd** result) {
            return getpwnam_r(
                name, entry, buffer, buffer_size, result);
        });
}

bool parse_env_id(const char* name, unsigned long* out) {
    if (!out) {
        return false;
    }
    const char* raw = std::getenv(name);
    if (!raw || !*raw) {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    unsigned long value = std::strtoul(raw, &end, 10);
    if (errno != 0 || !end || *end != '\0') {
        return false;
    }
    *out = value;
    return true;
}

std::optional<DropPrivilegeTarget> resolve_drop_target(std::string* error) {
    unsigned long sudo_uid = 0;
    unsigned long sudo_gid = 0;
    if (parse_env_id("SUDO_UID", &sudo_uid) &&
        parse_env_id("SUDO_GID", &sudo_gid) &&
        sudo_uid != 0) {
        DropPrivilegeTarget target;
        target.uid = static_cast<uid_t>(sudo_uid);
        target.gid = static_cast<gid_t>(sudo_gid);
        const char* sudo_user = std::getenv("SUDO_USER");
        if (sudo_user && *sudo_user) {
            target.name = sudo_user;
        } else if (const auto pwd = lookup_passwd_by_uid(target.uid);
                   pwd.has_value()) {
            target.name = pwd->name;
        }
        return target;
    }

    unsigned long pkexec_uid = 0;
    if (parse_env_id("PKEXEC_UID", &pkexec_uid) && pkexec_uid != 0) {
        if (auto target =
                lookup_passwd_by_uid(static_cast<uid_t>(pkexec_uid));
            target.has_value()) {
            return target;
        }
    }

    if (auto nobody = lookup_passwd_by_name("nobody");
        nobody.has_value() && nobody->uid != 0) {
        return nobody;
    }

    if (error) {
        *error = "failed to determine an unprivileged account for privilege drop";
    }
    return std::nullopt;
}
#endif

std::string expand_env_vars(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    for (size_t i = 0; i < input.size();) {
        if (input[i] == '%') {
            size_t end = input.find('%', i + 1);
            if (end != std::string::npos && end > i + 1) {
                std::string key = input.substr(i + 1, end - i - 1);
                const char* val = std::getenv(key.c_str());
                if (val) {
                    out.append(val);
                } else {
                    out.append(input, i, end - i + 1);
                }
                i = end + 1;
                continue;
            }
        } else if (input[i] == '$') {
            if (i + 1 < input.size() && input[i + 1] == '{') {
                size_t end = input.find('}', i + 2);
                if (end != std::string::npos && end > i + 2) {
                    std::string key = input.substr(i + 2, end - i - 2);
                    const char* val = std::getenv(key.c_str());
                    if (val) {
                        out.append(val);
                    } else {
                        out.append(input, i, end - i + 1);
                    }
                    i = end + 1;
                    continue;
                }
            } else {
                size_t j = i + 1;
                while (j < input.size() && is_env_char(input[j])) {
                    ++j;
                }
                if (j > i + 1) {
                    std::string key = input.substr(i + 1, j - i - 1);
                    const char* val = std::getenv(key.c_str());
                    if (val) {
                        out.append(val);
                    } else {
                        out.append(input, i, j - i);
                    }
                    i = j;
                    continue;
                }
            }
        }
        out.push_back(input[i]);
        ++i;
    }
    return out;
}

struct RegisteredSignalHandler {
    RegisteredSignalHandler(std::uint64_t registration_generation,
                            std::function<void(int)> registration_callback)
        : generation(registration_generation),
          callback(std::move(registration_callback)) {}

    bool begin_callback() noexcept {
        std::lock_guard<std::mutex> lock(mutex);
        if (!enabled) return false;
        ++active_callbacks;
        return true;
    }

    void end_callback() noexcept {
        std::lock_guard<std::mutex> lock(mutex);
        if (active_callbacks > 0) --active_callbacks;
        cv.notify_all();
    }

    void disable_and_wait(bool called_from_this_callback) noexcept {
        std::unique_lock<std::mutex> lock(mutex);
        enabled = false;
        const std::size_t allowed_callbacks = called_from_this_callback ? 1U : 0U;
        cv.wait(lock, [&]() { return active_callbacks <= allowed_callbacks; });
    }

    const std::uint64_t generation;
    const std::function<void(int)> callback;
    std::mutex mutex;
    std::condition_variable cv;
    bool enabled{true};
    std::size_t active_callbacks{0};
};

thread_local RegisteredSignalHandler* g_active_signal_handler = nullptr;

#if defined(_WIN32)
static_assert(std::atomic<unsigned int>::is_always_lock_free);
static_assert(std::atomic<int>::is_always_lock_free);
std::atomic<unsigned int> g_pending_signal_count{0};
std::atomic<int> g_pending_signal{SIGTERM};

void signal_dispatch(int signum) noexcept {
    g_pending_signal.store(signum, std::memory_order_relaxed);
    unsigned int pending = g_pending_signal_count.load(std::memory_order_relaxed);
    while (pending < 4U &&
           !g_pending_signal_count.compare_exchange_weak(
               pending, pending + 1U, std::memory_order_release,
               std::memory_order_relaxed)) {
    }
}
#else
volatile std::sig_atomic_t g_signal_write_fd = -1;

void signal_dispatch(int signum) noexcept {
    const int saved_errno = errno;
    const int write_fd = static_cast<int>(g_signal_write_fd);
    if (write_fd >= 0) {
        const unsigned char encoded = static_cast<unsigned char>(signum);
        // One non-blocking, one-byte write keeps handler work strictly
        // bounded even under nested SIGINT/SIGTERM storms. A full or
        // interrupted pipe drops this event; ordinary first/second delivery
        // has ample capacity and the managed queue is bounded independently.
        const ssize_t result = ::write(write_fd, &encoded, sizeof(encoded));
        (void)result;
    }
    errno = saved_errno;
}
#endif

class SignalDispatcher final {
public:
    SignalDispatcher() {
#if !defined(_WIN32)
        int descriptors[2]{-1, -1};
        if (::pipe(descriptors) != 0) {
            throw std::system_error(
                errno, std::generic_category(), "create signal dispatch pipe");
        }
        read_fd_ = descriptors[0];
        write_fd_ = descriptors[1];
        try {
            set_fd_flag(read_fd_, F_GETFD, F_SETFD, FD_CLOEXEC);
            set_fd_flag(write_fd_, F_GETFD, F_SETFD, FD_CLOEXEC);
            set_fd_flag(write_fd_, F_GETFL, F_SETFL, O_NONBLOCK);
        } catch (...) {
            ::close(read_fd_);
            ::close(write_fd_);
            read_fd_ = -1;
            write_fd_ = -1;
            throw;
        }
#endif
        try {
            callback_workers_.reserve(kCallbackWorkerCount);
            for (std::size_t i = 0; i < kCallbackWorkerCount; ++i) {
                callback_workers_.emplace_back([this]() { callback_worker(); });
            }
            reader_thread_ = std::thread([this]() { reader_loop(); });
        } catch (...) {
            stop_threads();
            close_descriptors();
            throw;
        }

    }

    ~SignalDispatcher() {
        std::shared_ptr<RegisteredSignalHandler> previous;
        {
            std::lock_guard<std::mutex> lock(registration_mutex_);
            previous = std::move(current_handler_);
            restore_os_handlers();
        }
        if (previous) {
            previous->disable_and_wait(
                g_active_signal_handler == previous.get());
        }
        restore_os_handlers();
        stop_threads();
        close_descriptors();
    }

    SignalDispatcher(const SignalDispatcher&) = delete;
    SignalDispatcher& operator=(const SignalDispatcher&) = delete;

    std::uint64_t install(std::function<void(int)> callback) {
        if (!callback) return 0;

        std::shared_ptr<RegisteredSignalHandler> previous;
        std::shared_ptr<RegisteredSignalHandler> replacement;
        {
            std::lock_guard<std::mutex> lock(registration_mutex_);
            replacement = std::make_shared<RegisteredSignalHandler>(
                next_generation_, std::move(callback));
            if (!handlers_installed_) {
                install_os_handlers();
            }
            ++next_generation_;
            previous = std::exchange(current_handler_, replacement);
        }
        if (previous) {
            previous->disable_and_wait(
                g_active_signal_handler == previous.get());
        }
        return replacement->generation;
    }

    void reset(std::uint64_t generation) noexcept {
        if (generation == 0) return;
        std::shared_ptr<RegisteredSignalHandler> previous;
        {
            std::lock_guard<std::mutex> lock(registration_mutex_);
            if (!current_handler_ ||
                current_handler_->generation != generation) {
                return;
            }
            previous = std::move(current_handler_);
            restore_os_handlers();
        }
        previous->disable_and_wait(
            g_active_signal_handler == previous.get());
    }

private:
    struct PendingSignal {
        int signum{0};
        std::shared_ptr<RegisteredSignalHandler> handler;
    };

    static constexpr std::size_t kCallbackWorkerCount = 2;
    static constexpr std::size_t kMaxPendingSignals = 4;

#if !defined(_WIN32)
    static void set_fd_flag(int fd, int get_command, int set_command,
                            int flag) {
        const int current = ::fcntl(fd, get_command);
        if (current < 0 || ::fcntl(fd, set_command, current | flag) != 0) {
            throw std::system_error(
                errno, std::generic_category(), "configure signal dispatch pipe");
        }
    }
#endif

    void enqueue(int signum) {
        std::shared_ptr<RegisteredSignalHandler> handler;
        {
            std::lock_guard<std::mutex> lock(registration_mutex_);
            handler = current_handler_;
        }
        if (!handler) return;

        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (pending_signals_.size() >= kMaxPendingSignals) {
                return;
            }
            pending_signals_.push_back(PendingSignal{signum, std::move(handler)});
        }
        queue_cv_.notify_one();
    }

    void reader_loop() noexcept {
#if defined(_WIN32)
        while (!reader_stop_.load(std::memory_order_acquire)) {
            const unsigned int count =
                g_pending_signal_count.exchange(0, std::memory_order_acq_rel);
            const int signum = g_pending_signal.load(std::memory_order_acquire);
            for (unsigned int i = 0; i < count; ++i) enqueue(signum);
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
#else
        std::array<unsigned char, 64> encoded{};
        while (!reader_stop_.load(std::memory_order_acquire)) {
            pollfd descriptor{read_fd_, POLLIN, 0};
            const int poll_result = ::poll(&descriptor, 1, -1);
            if (poll_result < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 &&
                (descriptor.revents & POLLIN) == 0) {
                break;
            }
            const ssize_t count = ::read(read_fd_, encoded.data(), encoded.size());
            if (count < 0) {
                if (errno == EINTR || errno == EAGAIN) continue;
                break;
            }
            for (ssize_t i = 0; i < count; ++i) {
                if (encoded[static_cast<std::size_t>(i)] != 0U) {
                    enqueue(static_cast<int>(encoded[static_cast<std::size_t>(i)]));
                }
            }
        }
#endif
    }

    void callback_worker() noexcept {
        for (;;) {
            PendingSignal pending;
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                queue_cv_.wait(lock, [&]() {
                    return callback_stop_ || !pending_signals_.empty();
                });
                if (callback_stop_ && pending_signals_.empty()) return;
                pending = std::move(pending_signals_.front());
                pending_signals_.pop_front();
            }
            if (!pending.handler || !pending.handler->begin_callback()) {
                continue;
            }
            RegisteredSignalHandler* const previous_active =
                g_active_signal_handler;
            g_active_signal_handler = pending.handler.get();
            try {
                pending.handler->callback(pending.signum);
            } catch (...) {
                // A signal callback cannot report failure back to the sender.
                // Keep the dispatcher alive so a later signal can still force
                // termination or cancel another registered runtime.
            }
            g_active_signal_handler = previous_active;
            pending.handler->end_callback();
        }
    }

    void stop_threads() noexcept {
        reader_stop_.store(true, std::memory_order_release);
#if !defined(_WIN32)
        if (write_fd_ >= 0) {
            const unsigned char wake = 0;
            const ssize_t ignored = ::write(write_fd_, &wake, sizeof(wake));
            (void)ignored;
        }
#endif
        if (reader_thread_.joinable()) reader_thread_.join();
        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            callback_stop_ = true;
        }
        queue_cv_.notify_all();
        for (auto& worker : callback_workers_) {
            if (worker.joinable()) worker.join();
        }
    }

    void close_descriptors() noexcept {
#if !defined(_WIN32)
        if (read_fd_ >= 0) {
            ::close(read_fd_);
            read_fd_ = -1;
        }
        if (write_fd_ >= 0) {
            ::close(write_fd_);
            write_fd_ = -1;
        }
#endif
    }

    void install_os_handlers() {
#if defined(_WIN32)
        previous_sigint_ = std::signal(SIGINT, signal_dispatch);
        if (previous_sigint_ == SIG_ERR) {
            throw std::runtime_error("install SIGINT handler failed");
        }
        previous_sigterm_ = std::signal(SIGTERM, signal_dispatch);
        if (previous_sigterm_ == SIG_ERR) {
            std::signal(SIGINT, previous_sigint_);
            previous_sigint_ = SIG_DFL;
            throw std::runtime_error("install SIGTERM handler failed");
        }
        handlers_installed_ = true;
#else
        struct sigaction action {};
        action.sa_handler = signal_dispatch;
        ::sigemptyset(&action.sa_mask);
        action.sa_flags = SA_RESTART;
        g_signal_write_fd = static_cast<std::sig_atomic_t>(write_fd_);
        if (::sigaction(SIGINT, &action, &previous_sigint_) != 0) {
            g_signal_write_fd = -1;
            throw std::system_error(
                errno, std::generic_category(), "install SIGINT handler");
        }
        if (::sigaction(SIGTERM, &action, &previous_sigterm_) != 0) {
            const int saved_errno = errno;
            ::sigaction(SIGINT, &previous_sigint_, nullptr);
            g_signal_write_fd = -1;
            throw std::system_error(
                saved_errno, std::generic_category(), "install SIGTERM handler");
        }
        handlers_installed_ = true;
#endif
    }

    void restore_os_handlers() noexcept {
        if (!handlers_installed_) return;
#if defined(_WIN32)
        std::signal(SIGINT, previous_sigint_);
        std::signal(SIGTERM, previous_sigterm_);
#else
        ::sigaction(SIGINT, &previous_sigint_, nullptr);
        ::sigaction(SIGTERM, &previous_sigterm_, nullptr);
        g_signal_write_fd = -1;
#endif
        handlers_installed_ = false;
    }

    std::mutex registration_mutex_;
    std::shared_ptr<RegisteredSignalHandler> current_handler_;
    std::uint64_t next_generation_{1};

    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
    std::deque<PendingSignal> pending_signals_;
    bool callback_stop_{false};
    std::vector<std::thread> callback_workers_;
    std::thread reader_thread_;
    std::atomic<bool> reader_stop_{false};

    bool handlers_installed_{false};
#if defined(_WIN32)
    using SignalFunction = void (*)(int);
    SignalFunction previous_sigint_{SIG_DFL};
    SignalFunction previous_sigterm_{SIG_DFL};
#else
    int read_fd_{-1};
    int write_fd_{-1};
    struct sigaction previous_sigint_ {};
    struct sigaction previous_sigterm_ {};
#endif
};

SignalDispatcher& signal_dispatcher() {
    static SignalDispatcher dispatcher;
    return dispatcher;
}

bool should_log_rate_limited(const std::string& key, int64_t interval_ms) {
    const int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    std::lock_guard<std::mutex> lock(g_rate_log_mutex);
    auto it = g_rate_log_last_ms.find(key);
    if (it != g_rate_log_last_ms.end() && interval_ms > 0 && now - it->second < interval_ms) {
        return false;
    }
    g_rate_log_last_ms[key] = now;
    return true;
}
}  // namespace

bool stdout_is_terminal() {
    return is_tty_stdout();
}

bool stdout_colors_enabled() {
    if (!is_tty_stdout() || std::getenv("NO_COLOR") != nullptr) {
        return false;
    }
    return read_env_flag("YUME_COLOR", true) &&
           !read_env_flag("YUME_NO_COLOR", false);
}

nlohmann::json read_json_config(const std::string& path) {
    std::ifstream in(expand_user(path));
    if (!in.is_open()) {
        throw std::runtime_error("failed to open config: " + path);
    }
    nlohmann::json cfg;
    in >> cfg;
    return cfg;
}

std::string expand_user(const std::string& path) {
    if (path.rfind("~/", 0) == 0 || path.rfind("~\\", 0) == 0) {
        const char* home = std::getenv("HOME");
#if defined(_WIN32)
        if (!home) {
            home = std::getenv("USERPROFILE");
        }
#endif
        if (home) {
            return std::string(home) + path.substr(1);
        }
    }
    return path;
}

std::string resolve_path(const std::string& path,
                         const std::string& base_dir,
                         const std::string& exe_dir) {
    if (path.empty()) {
        return {};
    }
    std::string expanded = expand_env_vars(expand_user(path));
    std::filesystem::path p(expanded);
    if (p.is_absolute() || p.has_root_name()) {
        return p.lexically_normal().string();
    }
    if (!base_dir.empty()) {
        return (std::filesystem::path(base_dir) / p).lexically_normal().string();
    }
    if (!exe_dir.empty()) {
        return (std::filesystem::path(exe_dir) / p).lexically_normal().string();
    }
    return expanded;
}

void init_logging() {
#if YUME_USE_SPDLOG
    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
    spdlog::set_level(spdlog::level::info);
#endif
    {
        std::lock_guard<std::mutex> lock(g_status_mutex);
        g_status_supported = is_tty_stdout();
        if (!g_status_supported) {
            g_status_enabled = false;
            g_status_text.clear();
            g_status_lines = 0;
            g_status_active = false;
        }
    }
}

void log_info(const std::string& msg) {
    if (!g_logging_enabled) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_status_mutex);
    clear_status_line_locked();
#if YUME_USE_SPDLOG
    spdlog::info(msg);
#else
    print_colored_log("INFO", "1;36", msg);
#endif
    render_status_line_locked();
}

void log_warn(const std::string& msg) {
    if (!g_logging_enabled) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_status_mutex);
    clear_status_line_locked();
#if YUME_USE_SPDLOG
    spdlog::warn(msg);
#else
    print_colored_log("WARN", "1;33", msg);
#endif
    render_status_line_locked();
}

void log_error(const std::string& msg) {
    if (!g_logging_enabled) {
        return;
    }
    std::lock_guard<std::mutex> lock(g_status_mutex);
    clear_status_line_locked();
#if YUME_USE_SPDLOG
    spdlog::error(msg);
#else
    print_colored_log("ERROR", "1;31", msg);
#endif
    render_status_line_locked();
}

void log_info_rate_limited(const std::string& key, const std::string& msg, int64_t interval_ms) {
    if (should_log_rate_limited("info:" + key, interval_ms)) {
        log_info(msg);
    }
}

void log_warn_rate_limited(const std::string& key, const std::string& msg, int64_t interval_ms) {
    if (should_log_rate_limited("warn:" + key, interval_ms)) {
        log_warn(msg);
    }
}

void set_logging_enabled(bool enabled) {
    g_logging_enabled = enabled;
}

bool is_logging_enabled() {
    return g_logging_enabled;
}

bool env_flag(const char* name, bool fallback) {
    return read_env_flag(name, fallback);
}

void set_status_enabled(bool enabled) {
    std::lock_guard<std::mutex> lock(g_status_mutex);
    g_status_enabled = enabled;
    if (!g_status_enabled) {
        clear_status_line_locked();
        g_status_text.clear();
        g_status_lines = 0;
        return;
    }
    render_status_line_locked();
}

void set_status_line(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_status_mutex);
    if (!g_status_enabled || !g_status_supported) {
        return;
    }
    if (g_status_active) {
        clear_status_line_locked();
    }
    g_status_text = line;
    g_status_lines = count_status_lines(line);
    render_status_line_locked();
}

void clear_status_line() {
    std::lock_guard<std::mutex> lock(g_status_mutex);
    clear_status_line_locked();
}

bool drop_privileges(std::string* error, std::string* summary) {
#if defined(_WIN32)
    if (summary) {
        summary->clear();
    }
    (void)error;
    return true;
#else
    if (summary) {
        summary->clear();
    }
    if (geteuid() != 0) {
        return true;
    }

    auto target = resolve_drop_target(error);
    if (!target.has_value()) {
        return false;
    }
    if (target->uid == 0) {
        if (error) {
            *error = "refusing to keep uid 0 without --root";
        }
        return false;
    }

    if (!target->name.empty()) {
        if (initgroups(target->name.c_str(), target->gid) != 0) {
            if (error) {
                *error = "initgroups failed: " + std::string(std::strerror(errno));
            }
            return false;
        }
    } else if (setgroups(0, nullptr) != 0) {
        if (error) {
            *error = "setgroups failed: " + std::string(std::strerror(errno));
        }
        return false;
    }

    if (setgid(target->gid) != 0) {
        if (error) {
            *error = "setgid failed: " + std::string(std::strerror(errno));
        }
        return false;
    }
    if (setuid(target->uid) != 0) {
        if (error) {
            *error = "setuid failed: " + std::string(std::strerror(errno));
        }
        return false;
    }
    if (geteuid() == 0) {
        if (error) {
            *error = "privilege drop did not clear effective uid 0";
        }
        return false;
    }

    if (summary) {
        std::string label = target->name.empty() ? "unprivileged-user" : target->name;
        *summary = "dropped privileges to " + label +
                   " (uid=" + std::to_string(static_cast<unsigned long long>(target->uid)) +
                   ", gid=" + std::to_string(static_cast<unsigned long long>(target->gid)) + ")";
    }
    return true;
#endif
}

std::string random_hex(size_t bytes) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(bytes * 2);
    std::vector<unsigned char> buf(bytes);
    if (bytes > 0) {
        if (RAND_bytes(buf.data(), static_cast<int>(buf.size())) != 1) {
            return {};
        }
    }
    for (size_t i = 0; i < bytes; ++i) {
        out[i * 2] = kHex[(buf[i] >> 4) & 0xF];
        out[i * 2 + 1] = kHex[buf[i] & 0xF];
    }
    return out;
}

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::size_t relay_read_buf_size() {
    // Size (in bytes) of the per-stream relay read buffers that set the
    // outgoing DATA frame size for client SOCKS/forward reads. Larger buffers
    // coalesce more bytes per read into fewer, larger frames, which cuts
    // per-frame overhead. Server target/source reads apply their own bounded
    // record size in server_relay_read_buf_size(). Tunable via
    // YUME_RELAY_READ_BUF (in KiB); default 64 KiB preserves historical
    // client behavior. Read once and cached.
    static const std::size_t cached = [] {
        std::size_t kib = 64;
        if (const char* raw = std::getenv("YUME_RELAY_READ_BUF")) {
            try {
                const long v = std::stol(raw);
                // Keep the operator-selected read size within one 256 KiB
                // transport epoch.
                if (v >= 4 && v <= 256) {
                    kib = static_cast<std::size_t>(v);
                }
            } catch (...) {
            }
        }
        return kib * 1024u;
    }();
    return cached;
}

std::size_t server_relay_read_buf_size() {
    // Eight 32 KiB DATA records retain the exact 256 KiB rekey boundary while
    // allowing TLS/H2 receive, AEAD open, and application delivery to overlap.
    // Preserve smaller operator-selected records, but do not let the generic
    // tuning knob recreate the server-to-client head-of-line stall.
    constexpr std::size_t kServerDataRecordBytes = 32U * 1024U;
    return std::min(relay_read_buf_size(), kServerDataRecordBytes);
}

std::string base64_decode(const std::string& input) {
    if (input.empty()) {
        return {};
    }
    std::string clean;
    clean.reserve(input.size());
    for (unsigned char c : input) {
        if (c == '=' || std::isalnum(c) || c == '+' || c == '/') {
            clean.push_back(static_cast<char>(c));
        }
    }

    std::string out((clean.size() * 3) / 4 + 2, '\0');
    int len = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(&out[0]),
                              reinterpret_cast<const unsigned char*>(clean.data()),
                              static_cast<int>(clean.size()));
    if (len < 0) {
        return {};
    }
    size_t padding = 0;
    if (!clean.empty() && clean.back() == '=') {
        padding++;
        if (clean.size() > 1 && clean[clean.size() - 2] == '=') {
            padding++;
        }
    }
    if (padding > 0 && static_cast<size_t>(len) >= padding) {
        len -= static_cast<int>(padding);
    }
    out.resize(static_cast<size_t>(len));
    return out;
}

std::string base64_encode(const std::string& input) {
    if (input.empty()) {
        return {};
    }
    std::string out(((input.size() + 2) / 3) * 4, '\0');
    int len = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&out[0]),
                              reinterpret_cast<const unsigned char*>(input.data()),
                              static_cast<int>(input.size()));
    if (len <= 0) {
        return {};
    }
    out.resize(static_cast<size_t>(len));
    return out;
}

SignalHandlerRegistration::SignalHandlerRegistration(
        std::function<void(int)> handler) {
    if (handler) {
        generation_ = signal_dispatcher().install(std::move(handler));
    }
}

SignalHandlerRegistration::~SignalHandlerRegistration() {
    reset();
}

SignalHandlerRegistration::SignalHandlerRegistration(
        SignalHandlerRegistration&& other) noexcept
    : generation_(std::exchange(other.generation_, 0)) {}

SignalHandlerRegistration& SignalHandlerRegistration::operator=(
        SignalHandlerRegistration&& other) noexcept {
    if (this != &other) {
        reset();
        generation_ = std::exchange(other.generation_, 0);
    }
    return *this;
}

void SignalHandlerRegistration::reset() noexcept {
    if (generation_ == 0) return;
    signal_dispatcher().reset(std::exchange(generation_, 0));
}

}  // namespace yume::util
