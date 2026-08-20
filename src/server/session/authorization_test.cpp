/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "server/session/authorization.hpp"

#include <array>
#include <cassert>
#include <cstdio>

namespace {

using yume::protocol::FrameType;
using yume::server::authorization::FrameContext;
using yume::server::authorization::SessionTier;

void test_preauth_service_only_frame_families() {
    using yume::server::authorization::post_auth_frame_allowed;

    assert(post_auth_frame_allowed(SessionTier::PreauthServiceOnly,
                                   yume::protocol::OPEN,
                                   FrameContext{.service_open = true}));
    assert(!post_auth_frame_allowed(SessionTier::PreauthServiceOnly,
                                    yume::protocol::OPEN));
    assert(post_auth_frame_allowed(SessionTier::PreauthServiceOnly,
                                   yume::protocol::DATA,
                                   FrameContext{.existing_service_stream = true}));
    assert(post_auth_frame_allowed(SessionTier::PreauthServiceOnly,
                                   yume::protocol::CLOSE,
                                   FrameContext{.existing_service_stream = true}));
    assert(!post_auth_frame_allowed(SessionTier::PreauthServiceOnly,
                                    yume::protocol::DATA));
    assert(!post_auth_frame_allowed(SessionTier::PreauthServiceOnly,
                                    yume::protocol::CLOSE));
    assert(post_auth_frame_allowed(SessionTier::PreauthServiceOnly,
                                   yume::protocol::PING));
    assert(post_auth_frame_allowed(SessionTier::PreauthServiceOnly,
                                   yume::protocol::PONG));

    constexpr std::array<FrameType, 7> denied{
        yume::protocol::AUTH,
        yume::protocol::EXEC,
        yume::protocol::ANON,
        yume::protocol::RLISTEN,
        yume::protocol::ROPEN,
        yume::protocol::CONTROL,
        yume::protocol::SOPEN,
    };
    for (FrameType type : denied) {
        assert(!post_auth_frame_allowed(SessionTier::PreauthServiceOnly, type));
    }
}

void test_preauth_service_open_payload_is_unambiguous() {
    using yume::server::authorization::preauth_service_open_payload;

    assert(preauth_service_open_payload(
        R"({"proto":"service.v1","service":"bootstrap-v1"})"));
    assert(!preauth_service_open_payload(
        R"({"proto":"service.v1","service":"bootstrap-v1","target_id":"peer","channel_id":"invite","channel_kind":"admin"})"));
    assert(!preauth_service_open_payload(
        R"({"proto":"service.v1","service":"bootstrap-v1","host":"127.0.0.1","port":22})"));
    assert(!preauth_service_open_payload(
        R"({"proto":"service.v1","service":""})"));
    assert(!preauth_service_open_payload(
        R"({"proto":"tcp","proto":"service.v1","service":"bootstrap-v1"})"));
    assert(!preauth_service_open_payload(
        R"({"proto":"service.v1","proto":"tcp","service":"bootstrap-v1"})"));
    assert(!preauth_service_open_payload(
        R"({"proto":"service.v1","service":"blocked","service":"bootstrap-v1"})"));
    assert(!preauth_service_open_payload(
        R"({"proto":"service.v1","service":"bootstrap-v1","service":"blocked"})"));
    assert(!preauth_service_open_payload("not-json"));
}

void test_authorized_and_unauthenticated_tiers() {
    using yume::server::authorization::post_auth_frame_allowed;
    assert(post_auth_frame_allowed(SessionTier::Authorized,
                                   yume::protocol::CONTROL));
    assert(post_auth_frame_allowed(SessionTier::Authorized,
                                   yume::protocol::RLISTEN));
    assert(!post_auth_frame_allowed(SessionTier::Authorized,
                                    yume::protocol::AUTH));
    assert(!post_auth_frame_allowed(SessionTier::Unauthenticated,
                                    yume::protocol::PING));
}

void test_admin_directional_policy_quadrants() {
    using yume::server::authorization::admin_attach_allowed;
    assert(admin_attach_allowed(true, true, true));
    assert(!admin_attach_allowed(true, false, true));
    assert(!admin_attach_allowed(true, true, false));
    assert(!admin_attach_allowed(true, false, false));
    assert(!admin_attach_allowed(false, true, true));
}

void test_admin_claim_requires_an_authorized_visitor() {
    using yume::server::authorization::admin_claim_eligible;
    assert(admin_claim_eligible(true, true));
    assert(!admin_claim_eligible(false, true));
    assert(!admin_claim_eligible(true, false));
    assert(!admin_claim_eligible(false, false));
}

}  // namespace

int main() {
    test_preauth_service_only_frame_families();
    test_preauth_service_open_payload_is_unambiguous();
    test_authorized_and_unauthenticated_tiers();
    test_admin_directional_policy_quadrants();
    test_admin_claim_requires_an_authorized_visitor();
    std::puts("authorization_test: all cases passed");
    return 0;
}
