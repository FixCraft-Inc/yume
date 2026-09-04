/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * libFuzzer entry for the server-side HTTP/2 carrier probe decoder. This is
 * the first parser an unauthenticated peer reaches: Session::on_h2_probe_read
 * feeds it raw bytes off the TLS stream before any admission check runs.
 *
 * The decoder's contract is that it never throws -- a throw would unwind into
 * the Asio worker rather than the session -- so a caught exception is a
 * finding, not a rejection.
 */

#include "core/stealth/obfs_h2.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data,
                                      std::size_t size) {
    // Split the input so the fuzzer also explores the streamed case: the
    // decoder must reach the same verdict whether bytes arrive at once or in
    // pieces, and its retained buffer must stay bounded across feeds.
    const std::size_t split = size == 0 ? 0 : (data[0] % (size + 1));

    for (int streamed = 0; streamed < 2; ++streamed) {
        for (int server_side = 0; server_side < 2; ++server_side) {
            yume::obfs::H2InboundDecoder decoder(server_side != 0);
            try {
                if (streamed == 0) {
                    decoder.feed(data, size);
                } else {
                    decoder.feed(data, split);
                    decoder.feed(data + split, size - split);
                }
                // Exercise the accessors a caller reaches on a decoded probe.
                (void)decoder.extracted_path();
                (void)decoder.extracted_authority();
                (void)decoder.decoded_headers();
                (void)decoder.header_value("content-type");
                (void)decoder.is_carrier_accept_response();
                (void)decoder.inbound_buffered();
                (void)decoder.take_outbound_replies();
            } catch (const std::exception&) {
                __builtin_trap();  // must reject, never throw
            }
        }
    }
    return 0;
}
