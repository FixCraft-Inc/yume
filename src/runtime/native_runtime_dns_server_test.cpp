/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026 FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "runtime/native_cli.hpp"

#include <array>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <memory>
#include <netdb.h>
#include <sys/socket.h>

// Only this test executable wraps the OS boundary. It runs the production
// daemon entry point, providers and authorization with deterministic answers.
extern "C" int __real_getaddrinfo(const char*, const char*, const addrinfo*, addrinfo**);
extern "C" int __real_socket(int, int, int);

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
std::array<std::atomic<unsigned int>, kAnswers.size()> queries{};
std::atomic<bool> refused_answers{false};
std::atomic<unsigned int> refused_socket_opens{0U};

int numeric_answer(const char* address, const char* service,
                   const addrinfo& hints, addrinfo** result) noexcept {
    addrinfo numeric = hints;
    numeric.ai_family = AF_INET;
    numeric.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;
    return __real_getaddrinfo(address, service, &numeric, result);
}
}  // namespace

extern "C" int __wrap_getaddrinfo(const char* node, const char* service,
                                   const addrinfo* hints, addrinfo** result) {
    if (!node || !hints || !result) return EAI_FAIL;
    for (std::size_t index = 0U; index < kAnswers.size(); ++index) {
        const auto& answer = kAnswers[index];
        if (std::strcmp(node, answer.name) != 0) continue;
        queries[index].fetch_add(1U);
        // The process harness issues one OPEN at a time. This flag crosses
        // from Asio's resolver thread to its runner before socket creation.
        refused_answers.store(index != 0U);
        *result = nullptr;
        if (hints->ai_socktype != SOCK_STREAM || !(hints->ai_flags & AI_NUMERICSERV)) {
            return EAI_FAIL;
        }
        addrinfo* first = nullptr;
        int status = numeric_answer(answer.first, service, *hints, &first);
        if (status != 0) return status;
        std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> owned(first, freeaddrinfo);
        if (answer.second) {
            addrinfo* second = nullptr;
            status = numeric_answer(answer.second, service, *hints, &second);
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

extern "C" int __wrap_socket(int domain, int type, int protocol) {
    if (refused_answers.load()) refused_socket_opens.fetch_add(1U);
    return __real_socket(domain, type, protocol);
}

int main(int argc, char** argv) {
    const int result = yume::runtime::run_native_cli(
        yume::runtime::NativeCliRole::Server, argc, argv);
    if (result != 0) return result;
    // Validation starts no resolver. The ordinary process harness validates
    // the same daemon before starting its long-lived serving process.
    for (int index = 1; index < argc; ++index) {
        if (std::strcmp(argv[index], "--validate") == 0) return 0;
    }
    for (std::size_t index = 0U; index < kAnswers.size(); ++index) {
        if (queries[index].load() != kAnswers[index].expected_queries) {
            std::fputs("DNS fixture query count differs\n", stderr);
            return 1;
        }
    }
    if (refused_socket_opens.load() != 0U) {
        std::fputs("DNS refusal opened a socket\n", stderr);
        return 1;
    }
    std::puts("DNS answer sets verified; refused routes opened no sockets");
    return 0;
}
