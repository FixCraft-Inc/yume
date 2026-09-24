/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_cli.hpp"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <netdb.h>
#include <string>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

// Only this test executable wraps getaddrinfo. It runs the production daemon
// entry point, providers and authorization with deterministic answers. Name
// lookups run in a re-executed copy of this binary, the SystemResolver
// helper, so each wrapped query appends its answer-set index to a log that
// the daemon checks when it exits. The route-provider test proves that a
// refused answer opens no socket. Here the harness requires the SOCKS
// refusal for every refused set, which a connection to its allowed member
// would turn into success.
extern "C" int __real_getaddrinfo(const char*, const char*, const addrinfo*, addrinfo**);

namespace {
struct AnswerSet {
    const char* name;
    const char* first;
    const char* second;
    unsigned int expected_queries;
};

constexpr std::array<AnswerSet, 4> kAnswers{{
    {"allowed.yume.test", "127.0.0.1", nullptr, 2U},
    {"denied.yume.test", "127.0.0.2", nullptr, 1U},
    {"allowed-first.yume.test", "127.0.0.1", "127.0.0.2", 1U},
    {"denied-first.yume.test", "127.0.0.2", "127.0.0.1", 1U},
}};
constexpr const char* kQueryLog = "YUME_TEST_DNS_QUERY_LOG";

void record_query(std::size_t index) noexcept {
    const char* path = std::getenv(kQueryLog);
    if (!path) return;
    const int fd = ::open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
    if (fd < 0) return;
    const char entry = static_cast<char>('0' + index);
    [[maybe_unused]] const auto written = ::write(fd, &entry, 1U);
    ::close(fd);
}

int numeric_answer(const char* address, const addrinfo& hints, addrinfo** result) noexcept {
    addrinfo numeric = hints;
    numeric.ai_family = AF_INET;
    numeric.ai_flags |= AI_NUMERICHOST;
    return __real_getaddrinfo(address, nullptr, &numeric, result);
}
}  // namespace

extern "C" int __wrap_getaddrinfo(const char* node, const char* service,
                                   const addrinfo* hints, addrinfo** result) {
    if (!node || !hints || !result) return EAI_FAIL;
    for (std::size_t index = 0U; index < kAnswers.size(); ++index) {
        const auto& answer = kAnswers[index];
        if (std::strcmp(node, answer.name) != 0) continue;
        record_query(index);
        *result = nullptr;
        // The helper asks for addresses only, one entry per address.
        if (service != nullptr || hints->ai_socktype != SOCK_STREAM) return EAI_FAIL;
        addrinfo* first = nullptr;
        int status = numeric_answer(answer.first, *hints, &first);
        if (status != 0) return status;
        std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> owned(first, freeaddrinfo);
        if (answer.second) {
            addrinfo* second = nullptr;
            status = numeric_answer(answer.second, *hints, &second);
            if (status != 0) return status;
            addrinfo* tail = first;
            while (tail->ai_next) tail = tail->ai_next;
            tail->ai_next = second;
        }
        *result = owned.release();
        return 0;
    }
    // Unexpected names must not reach external DNS or silently skip the fixture.
    *result = nullptr;
    return EAI_NONAME;
}

int main(int argc, char** argv) {
    bool validate = false;
    for (int index = 1; index < argc; ++index) {
        if (std::strcmp(argv[index], "--validate") == 0) validate = true;
    }
    // The helper inherits this process's environment and appends to the log.
    std::string log;
    if (argc > 1 && !validate && !std::getenv(kQueryLog)) {
        char path[] = "/tmp/yume-dns-queries-XXXXXX";
        const int fd = ::mkstemp(path);
        if (fd < 0) return 1;
        ::close(fd);
        log = path;
        ::setenv(kQueryLog, path, 1);
    }
    const int result = yume::runtime::run_native_cli(
        yume::runtime::NativeCliRole::Server, argc, argv);
    // Validation starts no resolver. The ordinary process harness validates
    // the same daemon before starting its long-lived serving process.
    if (result != 0 || validate || log.empty()) return result;
    std::array<unsigned int, kAnswers.size()> queries{};
    if (FILE* file = std::fopen(log.c_str(), "rb")) {
        for (int entry = std::fgetc(file); entry != EOF; entry = std::fgetc(file)) {
            const auto index = static_cast<std::size_t>(entry - '0');
            if (index < queries.size()) ++queries[index];
        }
        std::fclose(file);
    }
    ::unlink(log.c_str());
    for (std::size_t index = 0U; index < kAnswers.size(); ++index) {
        if (queries[index] != kAnswers[index].expected_queries) {
            std::fputs("DNS fixture query count differs\n", stderr);
            return 1;
        }
    }
    std::puts("DNS answer sets verified through the resolver helper");
    return 0;
}
