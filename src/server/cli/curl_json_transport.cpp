/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/cli/curl_json_transport.hpp"

#include "core/security/secret_file.hpp"
#include "util.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include <boost/asio/ip/address.hpp>

#if defined(__linux__)
#include <fcntl.h>
#include <spawn.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#endif

namespace yume::server::cli::detail {
namespace {

constexpr std::size_t kMaxCurlResponseBytes = 1024U * 1024U;
constexpr std::size_t kMaxOperatorProofSignatureBytes = 128U;

bool contains_http_control(std::string_view value) noexcept {
    return std::any_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch < 0x20U || ch == 0x7fU;
    });
}

bool valid_dns_name(std::string_view host) noexcept {
    if (host.empty() || host.size() > 253U || host.front() == '.' ||
        host.back() == '.') {
        return false;
    }
    std::size_t label_begin = 0;
    while (label_begin < host.size()) {
        const std::size_t label_end = host.find('.', label_begin);
        const std::size_t end = label_end == std::string_view::npos
            ? host.size()
            : label_end;
        const std::size_t label_size = end - label_begin;
        if (label_size == 0U || label_size > 63U ||
            host[label_begin] == '-' || host[end - 1U] == '-') {
            return false;
        }
        for (std::size_t index = label_begin; index < end; ++index) {
            const unsigned char ch =
                static_cast<unsigned char>(host[index]);
            const bool ascii_alphanumeric =
                (ch >= 'a' && ch <= 'z') ||
                (ch >= 'A' && ch <= 'Z') ||
                (ch >= '0' && ch <= '9');
            if (!ascii_alphanumeric && ch != '-') {
                return false;
            }
        }
        if (label_end == std::string_view::npos) {
            break;
        }
        label_begin = label_end + 1U;
    }
    return true;
}

std::string parse_port(std::string_view port) {
    if (port.empty()) {
        return "443";
    }
    unsigned int parsed = 0;
    const auto result = std::from_chars(
        port.data(), port.data() + port.size(), parsed);
    if (result.ec != std::errc{} || result.ptr != port.data() + port.size() ||
        parsed == 0U || parsed > 65535U) {
        throw std::invalid_argument(
            "operator proof HTTPS URL has an invalid port");
    }
    return std::to_string(parsed);
}

bool parse_env_bool_local(const char* name, bool fallback) {
    const char* raw = std::getenv(name);
    if (!raw || !*raw) {
        return fallback;
    }
    std::string value(raw);
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) {
                       return static_cast<char>(std::tolower(ch));
                   });
    if (value == "1" || value == "true" || value == "yes" ||
        value == "on") {
        return true;
    }
    if (value == "0" || value == "false" || value == "no" ||
        value == "off") {
        return false;
    }
    return fallback;
}

void wipe_string(std::string& value) noexcept {
    volatile char* cursor = value.data();
    for (std::size_t index = 0; index < value.size(); ++index) {
        cursor[index] = 0;
    }
    value.clear();
}

class StringWiper final {
public:
    explicit StringWiper(std::string& value) noexcept : value_(value) {}
    StringWiper(const StringWiper&) = delete;
    StringWiper& operator=(const StringWiper&) = delete;
    ~StringWiper() { wipe_string(value_); }

private:
    std::string& value_;
};

class PrivateTemporaryDirectory final {
public:
    PrivateTemporaryDirectory(const PrivateTemporaryDirectory&) = delete;
    PrivateTemporaryDirectory& operator=(const PrivateTemporaryDirectory&) =
        delete;

    PrivateTemporaryDirectory(PrivateTemporaryDirectory&& other) noexcept
        : path_(std::move(other.path_)), active_(other.active_) {
        other.active_ = false;
    }

    ~PrivateTemporaryDirectory() { Remove(); }

    static PrivateTemporaryDirectory Create() {
#if !defined(__linux__)
        // The curl fallback is a static-Linux compatibility path. Other
        // platforms use the in-process HTTPS transport and stay fail-closed
        // if an environment override tries to select this implementation.
        throw std::runtime_error(
            "private curl transport is supported only on Linux");
#else
        std::string pattern =
            (std::filesystem::temp_directory_path() /
             "yume-anonym-curl-XXXXXX").string();
        if (!::mkdtemp(pattern.data())) {
            throw std::runtime_error(
                "failed to create private curl temporary directory");
        }
        return PrivateTemporaryDirectory(pattern);
#endif
    }

    const std::filesystem::path& path() const noexcept { return path_; }

    void RemoveOrThrow() {
        if (!active_) {
            return;
        }
        std::error_code error;
        const bool removed = std::filesystem::remove(path_, error);
        if (error || !removed) {
            throw std::runtime_error(
                "failed to remove private curl temporary directory" +
                (error ? ": " + error.message() : std::string{}));
        }
        active_ = false;
    }

private:
    explicit PrivateTemporaryDirectory(std::filesystem::path path)
        : path_(std::move(path)) {}

    void Remove() noexcept {
        if (!active_) {
            return;
        }
        std::error_code ignored;
        (void)std::filesystem::remove_all(path_, ignored);
        if (!ignored) {
            active_ = false;
        }
    }

    std::filesystem::path path_;
    bool active_{true};
};

class PrivateTemporaryFile final {
public:
    PrivateTemporaryFile(const PrivateTemporaryFile&) = delete;
    PrivateTemporaryFile& operator=(const PrivateTemporaryFile&) = delete;

    PrivateTemporaryFile(PrivateTemporaryFile&& other) noexcept
        : path_(std::move(other.path_)), active_(other.active_) {
        other.active_ = false;
    }

    PrivateTemporaryFile& operator=(PrivateTemporaryFile&& other) noexcept {
        if (this != &other) {
            Remove();
            path_ = std::move(other.path_);
            active_ = other.active_;
            other.active_ = false;
        }
        return *this;
    }

    ~PrivateTemporaryFile() { Remove(); }

    static PrivateTemporaryFile Create(
            const std::filesystem::path& directory,
            std::string_view purpose,
            std::span<const std::uint8_t> contents) {
        std::string last_error;
        for (int attempt = 0; attempt < 16; ++attempt) {
            const std::string random_suffix = yume::util::random_hex(16);
            if (random_suffix.empty()) {
                throw std::runtime_error(
                    "secure RNG failed while naming curl temporary file");
            }
            const auto path = directory /
                ("yume-anonym-" + std::string(purpose) + "-" +
                 random_suffix + ".tmp");
            if (yume::security::WriteFileExclusive0600(
                    path, contents, &last_error)) {
                return PrivateTemporaryFile(path);
            }
        }
        throw std::runtime_error(
            "failed to create private curl temporary file: " + last_error);
    }

    const std::filesystem::path& path() const noexcept { return path_; }

    void RemoveOrThrow() {
        if (!active_) {
            return;
        }
        std::error_code error;
        const bool removed = std::filesystem::remove(path_, error);
        if (error) {
            throw std::runtime_error(
                "failed to remove private curl temporary file: " +
                error.message());
        }
        (void)removed;
        active_ = false;
    }

private:
    explicit PrivateTemporaryFile(std::filesystem::path path)
        : path_(std::move(path)) {}

    void Remove() noexcept {
        if (!active_) {
            return;
        }
        std::error_code ignored;
        const bool removed = std::filesystem::remove(path_, ignored);
        if (!ignored) {
            (void)removed;
            active_ = false;
        }
    }

    std::filesystem::path path_;
    bool active_{true};
};

std::span<const std::uint8_t> bytes_of(const std::string& value) noexcept {
    return {reinterpret_cast<const std::uint8_t*>(value.data()),
            value.size()};
}

std::string curl_config_quote(std::string_view input) {
    std::string out;
    out.reserve(input.size() + 2);
    out.push_back('"');
    for (const unsigned char ch : input) {
        // A curl config line is a second parser boundary. Reject controls
        // instead of depending on curl-version-specific escape handling.
        if (ch < 0x20U || ch == 0x7fU) {
            throw std::invalid_argument(
                "curl request values must not contain control characters");
        }
        if (ch == '\\' || ch == '"') {
            out.push_back('\\');
        }
        out.push_back(static_cast<char>(ch));
    }
    out.push_back('"');
    return out;
}

void append_curl_config_value(std::string& config,
                              std::string_view option,
                              std::string_view value) {
    config.append(option);
    config.append(" = ");
    config.append(curl_config_quote(value));
    config.push_back('\n');
}

#if defined(__linux__)

class FileDescriptor final {
public:
    explicit FileDescriptor(int fd = -1) noexcept : fd_(fd) {}
    FileDescriptor(const FileDescriptor&) = delete;
    FileDescriptor& operator=(const FileDescriptor&) = delete;
    FileDescriptor(FileDescriptor&& other) noexcept
        : fd_(std::exchange(other.fd_, -1)) {}
    FileDescriptor& operator=(FileDescriptor&& other) noexcept {
        if (this != &other) {
            Close();
            fd_ = std::exchange(other.fd_, -1);
        }
        return *this;
    }
    ~FileDescriptor() { Close(); }

    int get() const noexcept { return fd_; }

    void Close() noexcept {
        if (fd_ >= 0) {
            (void)::close(fd_);
            fd_ = -1;
        }
    }

private:
    int fd_{-1};
};

class ChildProcess final {
public:
    explicit ChildProcess(pid_t pid) noexcept : pid_(pid) {}
    ChildProcess(const ChildProcess&) = delete;
    ChildProcess& operator=(const ChildProcess&) = delete;
    ~ChildProcess() { TerminateAndReap(); }

    int Wait() {
        int status = -1;
        while (::waitpid(pid_, &status, 0) < 0) {
            if (errno == EINTR) {
                continue;
            }
            const int wait_error = errno;
            if (wait_error == ECHILD) {
                pid_ = -1;
            }
            throw std::system_error(
                wait_error, std::generic_category(), "wait for curl process");
        }
        pid_ = -1;
        return status;
    }

private:
    void TerminateAndReap() noexcept {
        if (pid_ <= 0) {
            return;
        }

        int status = -1;
        while (true) {
            const pid_t result = ::waitpid(pid_, &status, WNOHANG);
            if (result == pid_ || (result < 0 && errno == ECHILD)) {
                pid_ = -1;
                return;
            }
            if (result < 0 && errno == EINTR) {
                continue;
            }
            break;
        }

        (void)::kill(pid_, SIGKILL);
        while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {
        }
        pid_ = -1;
    }

    pid_t pid_{-1};
};

class SpawnFileActions final {
public:
    SpawnFileActions() {
        const int error = ::posix_spawn_file_actions_init(&actions_);
        if (error != 0) {
            throw std::system_error(
                error, std::generic_category(),
                "initialize curl spawn file actions");
        }
        initialized_ = true;
    }
    SpawnFileActions(const SpawnFileActions&) = delete;
    SpawnFileActions& operator=(const SpawnFileActions&) = delete;
    ~SpawnFileActions() {
        if (initialized_) {
            (void)::posix_spawn_file_actions_destroy(&actions_);
        }
    }

    void Dup2(int source, int destination) {
        Check(::posix_spawn_file_actions_adddup2(
                  &actions_, source, destination),
              "add curl spawn dup2 action");
    }

    void CloseFrom(int fd) {
        Check(::posix_spawn_file_actions_addclosefrom_np(&actions_, fd),
              "add curl spawn close-from action");
    }

    posix_spawn_file_actions_t* get() noexcept { return &actions_; }

private:
    static void Check(int error, const char* operation) {
        if (error != 0) {
            throw std::system_error(
                error, std::generic_category(), operation);
        }
    }

    posix_spawn_file_actions_t actions_{};
    bool initialized_{false};
};

FileDescriptor open_verified_curl_executable() {
    const char* configured = std::getenv("YUME_ANONYM_CURL_EXECUTABLE");
    const std::filesystem::path path =
        configured && *configured ? configured : "/usr/bin/curl";
    if (!path.is_absolute()) {
        throw std::runtime_error(
            "YUME_ANONYM_CURL_EXECUTABLE must be an absolute path");
    }

    const int raw_fd = ::open(
        path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (raw_fd < 0) {
        throw std::system_error(
            errno, std::generic_category(),
            "open verified curl executable " + path.string());
    }
    FileDescriptor fd(raw_fd);
    struct stat info {};
    if (::fstat(fd.get(), &info) != 0) {
        throw std::system_error(
            errno, std::generic_category(),
            "stat verified curl executable " + path.string());
    }
    if (!S_ISREG(info.st_mode)) {
        throw std::runtime_error(
            "curl executable must be a regular non-symlink file");
    }
    if (info.st_uid != 0 && info.st_uid != ::geteuid()) {
        throw std::runtime_error(
            "curl executable must be owned by root or the current user");
    }
    if ((info.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
        throw std::runtime_error(
            "curl executable must not be group/world writable");
    }
    if ((info.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) == 0) {
        throw std::runtime_error("curl executable is not executable");
    }
    if ((info.st_mode & (S_ISUID | S_ISGID)) != 0) {
        throw std::runtime_error(
            "curl executable must not have set-user/group-ID bits");
    }
    return fd;
}

std::vector<std::string> curl_child_environment() {
    std::vector<std::string> environment{
        "LANG=C",
        "LC_ALL=C",
    };
    const auto inherit = [&environment](const char* name) {
        if (const char* value = std::getenv(name); value && *value) {
            environment.emplace_back(std::string(name) + "=" + value);
        }
    };
    // Preserve explicit CA deployment policy, but do not give the helper
    // unrelated daemon secrets, proxy variables, loader injection variables,
    // HOME, or a command-search path. Curl uses its compiled system trust when
    // none of these operator-owned overrides is present.
    inherit("SSL_CERT_FILE");
    inherit("SSL_CERT_DIR");
    inherit("CURL_CA_BUNDLE");
#if defined(YUME_CURL_TRANSPORT_TESTING)
    inherit("YUME_TEST_CURL_RECORD");
    inherit("YUME_TEST_CURL_FAIL");
    inherit("YUME_TEST_CURL_LEAK_FD");
#endif
    return environment;
}

FileDescriptor move_above_child_standard_descriptors(FileDescriptor fd) {
    constexpr int kFirstPrivateDescriptor = 4;
    if (fd.get() >= kFirstPrivateDescriptor) {
        return fd;
    }
    const int copied = ::fcntl(
        fd.get(), F_DUPFD_CLOEXEC, kFirstPrivateDescriptor);
    if (copied < 0) {
        throw std::system_error(
            errno, std::generic_category(),
            "move curl descriptor above child standard descriptors");
    }
    return FileDescriptor(copied);
}

std::string run_curl_capture(FileDescriptor executable,
                             std::vector<std::string> arguments,
                             int* status_out,
                             bool* response_too_large) {
    if (status_out) {
        *status_out = -1;
    }
    if (response_too_large) {
        *response_too_large = false;
    }
    int raw_pipe[2]{-1, -1};
    if (::pipe2(raw_pipe, O_CLOEXEC) != 0) {
        throw std::system_error(
            errno, std::generic_category(), "create curl response pipe");
    }
    FileDescriptor read_end(raw_pipe[0]);
    FileDescriptor write_end(raw_pipe[1]);
    executable = move_above_child_standard_descriptors(std::move(executable));
    read_end = move_above_child_standard_descriptors(std::move(read_end));
    write_end = move_above_child_standard_descriptors(std::move(write_end));
    const int raw_null_input = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (raw_null_input < 0) {
        throw std::system_error(
            errno, std::generic_category(), "open curl null input");
    }
    FileDescriptor null_input = move_above_child_standard_descriptors(
        FileDescriptor(raw_null_input));

    // Keep only one non-standard descriptor in the child: fd 3 names the
    // already-open, verified executable. A fixed low descriptor lets the
    // close-from action remove every daemon socket, secret file, and control
    // descriptor that would otherwise survive a missing FD_CLOEXEC flag.
    constexpr int child_executable_fd = 3;
    const std::string child_executable_path =
        "/proc/self/fd/" + std::to_string(child_executable_fd);

    SpawnFileActions file_actions;
    file_actions.Dup2(executable.get(), child_executable_fd);
    file_actions.Dup2(null_input.get(), STDIN_FILENO);
    file_actions.Dup2(write_end.get(), STDOUT_FILENO);
    file_actions.Dup2(write_end.get(), STDERR_FILENO);
    file_actions.CloseFrom(child_executable_fd + 1);

    std::vector<char*> argv;
    argv.reserve(arguments.size() + 1);
    for (std::string& argument : arguments) {
        argv.push_back(argument.data());
    }
    argv.push_back(nullptr);

    std::vector<std::string> environment = curl_child_environment();
    std::vector<char*> envp;
    envp.reserve(environment.size() + 1U);
    for (std::string& variable : environment) {
        envp.push_back(variable.data());
    }
    envp.push_back(nullptr);

    pid_t child = -1;
    const int spawn_error = ::posix_spawn(
        &child, child_executable_path.c_str(), file_actions.get(), nullptr,
        argv.data(), envp.data());
    if (spawn_error != 0) {
        throw std::system_error(
            spawn_error, std::generic_category(), "launch verified curl");
    }
    ChildProcess child_process(child);
    write_end.Close();

    std::string output;
    std::array<char, 4096> buffer{};
    bool oversized = false;
    int read_error = 0;
    while (true) {
        const ssize_t count =
            ::read(read_end.get(), buffer.data(), buffer.size());
        if (count > 0 && !oversized) {
            const std::size_t remaining =
                kMaxCurlResponseBytes - output.size();
            const std::size_t available = static_cast<std::size_t>(count);
            const std::size_t retained = std::min(remaining, available);
            output.append(buffer.data(), retained);
            oversized = retained != available;
        }
        if (count == 0) {
            break;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count < 0) {
            read_error = errno;
            break;
        }
    }
    read_end.Close();

    const int status = child_process.Wait();
    if (status_out) {
        *status_out = status;
    }
    if (response_too_large) {
        *response_too_large = oversized;
    }
    if (read_error != 0) {
        throw std::system_error(
            read_error, std::generic_category(),
            "read curl response");
    }
    return output;
}

#endif

}  // namespace

HttpsEndpoint parse_https_endpoint(std::string_view url) {
    constexpr std::string_view scheme = "https://";
    if (!url.starts_with(scheme)) {
        throw std::invalid_argument(
            "operator proof API URL must use https://");
    }
    if (contains_http_control(url)) {
        throw std::invalid_argument(
            "operator proof API URL contains control characters");
    }
    if (url.find('#') != std::string_view::npos) {
        throw std::invalid_argument(
            "operator proof API URL must not contain a fragment");
    }

    const std::string_view remainder = url.substr(scheme.size());
    const std::size_t authority_end = remainder.find_first_of("/?");
    const std::string_view authority = remainder.substr(0, authority_end);
    if (authority.empty() || authority.find('@') != std::string_view::npos) {
        throw std::invalid_argument(
            "operator proof API URL has an invalid authority");
    }

    std::string_view host;
    std::string_view port;
    bool explicit_port = false;
    if (authority.front() == '[') {
        const std::size_t closing = authority.find(']');
        if (closing == std::string_view::npos || closing == 1U) {
            throw std::invalid_argument(
                "operator proof API URL has an invalid IPv6 authority");
        }
        host = authority.substr(1U, closing - 1U);
        const std::string_view suffix = authority.substr(closing + 1U);
        if (!suffix.empty()) {
            if (suffix.front() != ':') {
                throw std::invalid_argument(
                    "operator proof API URL has trailing authority data");
            }
            explicit_port = true;
            port = suffix.substr(1U);
        }
        if (host.find('%') != std::string_view::npos) {
            throw std::invalid_argument(
                "operator proof API IPv6 literals must not use a zone ID");
        }
        boost::system::error_code address_error;
        const auto address = boost::asio::ip::make_address(host, address_error);
        if (address_error || !address.is_v6()) {
            throw std::invalid_argument(
                "operator proof API URL has an invalid IPv6 literal");
        }
    } else {
        const std::size_t colon = authority.find(':');
        if (colon != std::string_view::npos &&
            authority.find(':', colon + 1U) != std::string_view::npos) {
            throw std::invalid_argument(
                "operator proof API IPv6 literals must be bracketed");
        }
        host = authority.substr(0, colon);
        if (colon != std::string_view::npos) {
            explicit_port = true;
            port = authority.substr(colon + 1U);
        }
        boost::system::error_code address_error;
        const auto address = boost::asio::ip::make_address(host, address_error);
        if (address_error && !valid_dns_name(host)) {
            throw std::invalid_argument(
                "operator proof API URL has an invalid host");
        }
        if (!address_error && address.is_v6()) {
            throw std::invalid_argument(
                "operator proof API IPv6 literals must be bracketed");
        }
    }

    if (explicit_port && port.empty()) {
        throw std::invalid_argument(
            "operator proof API URL has an empty port");
    }

    std::string target = "/";
    if (authority_end != std::string_view::npos) {
        const std::string_view suffix = remainder.substr(authority_end);
        target = suffix.front() == '?' ? "/" + std::string(suffix)
                                       : std::string(suffix);
    }
    if (target.size() > 8192U || target.empty() || target.front() != '/' ||
        contains_http_control(target) ||
        target.find(' ') != std::string::npos) {
        throw std::invalid_argument(
            "operator proof API URL has an invalid request target");
    }

    return {std::string(host), parse_port(port), std::move(target)};
}

std::string https_authority(const HttpsEndpoint& endpoint) {
    if (endpoint.host.empty()) {
        throw std::invalid_argument("operator proof HTTPS host is empty");
    }
    const bool ipv6 = endpoint.host.find(':') != std::string::npos;
    std::string authority =
        ipv6 ? "[" + endpoint.host + "]" : endpoint.host;
    if (!endpoint.port.empty() && endpoint.port != "443") {
        authority += ":" + parse_port(endpoint.port);
    }
    return authority;
}

void validate_http_field_value(std::string_view value,
                               std::string_view field_name) {
    if (contains_http_control(value)) {
        throw std::invalid_argument(
            std::string(field_name) +
            " must not contain HTTP control characters");
    }
}

std::string require_operator_proof_signature(
        const nlohmann::json& response) {
    if (!response.is_object()) {
        throw std::runtime_error(
            "operator proof API response must be a JSON object");
    }
    const auto signature = response.find("sig");
    if (signature == response.end() || !signature->is_string()) {
        throw std::runtime_error(
            "external operator proof signature is missing");
    }
    const auto& value = signature->get_ref<const std::string&>();
    if (value.empty() || value.size() > kMaxOperatorProofSignatureBytes ||
        contains_http_control(value)) {
        throw std::runtime_error(
            "external operator proof signature is invalid");
    }
    return value;
}

bool use_curl_for_anonym_https() {
#if defined(YUME_STATIC_BUILD) && defined(__linux__)
    return parse_env_bool_local("YUME_ANONYM_USE_CURL", true);
#else
    return parse_env_bool_local("YUME_ANONYM_USE_CURL", false);
#endif
}

nlohmann::json post_json_https_via_curl(
        const HttpsEndpoint& endpoint,
        const nlohmann::json& payload,
        const std::string& token,
        const std::string& outbound_proxy_url) {
#if !defined(__linux__)
    (void)endpoint;
    (void)payload;
    (void)token;
    (void)outbound_proxy_url;
    throw std::runtime_error(
        "private curl transport is supported only on Linux");
#else
    auto curl_executable = open_verified_curl_executable();
    validate_http_field_value(token, "operator proof token");

    const std::string url =
        "https://" + https_authority(endpoint) + endpoint.target;

    auto temporary_directory = PrivateTemporaryDirectory::Create();
    std::string serialized_payload = payload.dump();
    StringWiper serialized_payload_wiper(serialized_payload);
    auto payload_file = PrivateTemporaryFile::Create(
        temporary_directory.path(), "payload", bytes_of(serialized_payload));

    std::string private_proxy;
    StringWiper private_proxy_wiper(private_proxy);
    if (!outbound_proxy_url.empty()) {
        private_proxy = outbound_proxy_url;
        constexpr std::string_view socks5 = "socks5://";
        if (private_proxy.rfind(socks5, 0) == 0) {
            private_proxy =
                "socks5h://" + private_proxy.substr(socks5.size());
        }
    }

    // Curl reads all sensitive options from one mode-0600 file. Neither the
    // bearer token nor optional SOCKS credentials enter argv or the process
    // environment. --disable remains the first command-line option below so
    // an operator/user .curlrc cannot add a second request or change policy.
    std::string private_config;
    StringWiper private_config_wiper(private_config);
    private_config =
        "silent\n"
        "show-error\n"
        "fail\n"
        "connect-timeout = 10\n"
        "max-time = 30\n";
    append_curl_config_value(private_config, "proto", "=https");
    append_curl_config_value(private_config, "proto-redir", "=https");
    append_curl_config_value(
        private_config, "header", "Content-Type: application/json");
    if (!token.empty()) {
        append_curl_config_value(
            private_config, "header", "X-FC-VERITY-TOKEN: " + token);
    }
    if (private_proxy.empty()) {
        // Match the in-process transport's direct-connect semantics instead
        // of silently inheriting HTTPS_PROXY from the daemon environment.
        append_curl_config_value(private_config, "noproxy", "*");
    } else {
        append_curl_config_value(private_config, "proxy", private_proxy);
    }
    append_curl_config_value(
        private_config, "data-binary", "@" + payload_file.path().string());
    append_curl_config_value(private_config, "url", url);
    auto config_file = PrivateTemporaryFile::Create(
        temporary_directory.path(), "config", bytes_of(private_config));

    int status = -1;
    bool response_too_large = false;
    const std::string output = run_curl_capture(
        std::move(curl_executable),
        {"curl", "--disable", "--config", config_file.path().string()},
        &status, &response_too_large);
    config_file.RemoveOrThrow();
    payload_file.RemoveOrThrow();
    temporary_directory.RemoveOrThrow();
    if (response_too_large) {
        throw std::runtime_error(
            "curl response exceeds the 1 MiB control-response limit");
    }
    if (status != 0) {
        std::string snippet = output;
        if (snippet.size() > 240) {
            snippet.resize(240);
            snippet += "...";
        }
        throw std::runtime_error("curl request failed: " + snippet);
    }

    try {
        return nlohmann::json::parse(output);
    } catch (...) {
        throw std::runtime_error("verity API returned invalid JSON");
    }
#endif
}

}  // namespace yume::server::cli::detail
