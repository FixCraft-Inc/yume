/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 *
 * TransportCore outbound write path: frame queueing, encode + obfs padding, priority-ordered batched dispatch.
 * Extracted verbatim from client/transport/core.cpp. Same
 * yume::client::TransportCore class, no behavior change. Shared helpers
 * via client/transport/internal.hpp.
 */

#include "client/transport/core.hpp"
#include "client/transport/internal.hpp"

#include <algorithm>
#include <cstdio>
#include <thread>

#include "core/security/inner_crypto.hpp"

namespace yume::client {

using namespace detail;

void TransportCore::queue_frame(protocol::Frame frame, WriteCompletion handler) {
    bool dispatch = false;
    {
        std::lock_guard<std::mutex> state_lock(state_mu_);
        if (stopped_) {
            if (handler) {
                handler(false, 0, "transport stopped");
            }
            return;
        }
    }
    {
        std::lock_guard<std::mutex> write_lock(write_mu_);
        write_queue_.push_back({std::move(frame), std::move(handler)});
        if (!write_in_flight_) {
            write_in_flight_ = true;
            dispatch = true;
        }
    }
    if (dispatch) {
        dispatch_next_write();
    }
}

std::shared_ptr<TransportCore::Bytes> TransportCore::encode_outgoing_frame(const protocol::Frame& frame) {
    // Avoid copying the payload on the no-inner path: encode_frame and
    // encrypt_inner_payload both take const&, so the source frame's payload
    // can be passed through directly. Only the inner-encrypted path needs a
    // separate buffer to hold the AEAD output.
    const Bytes* eff_payload = &frame.payload;
    Bytes encrypted;
    if ((frame.header.flags & protocol::kFlagInnerEncrypted) != 0) {
        encrypted = encrypt_inner_payload(frame.header.type, frame.header.stream_id, frame.payload);
        eff_payload = &encrypted;
    }
    std::uint16_t pad_multiple = 0;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        pad_multiple = obfs_pad_multiple_;
    }
    return std::make_shared<Bytes>(protocol::encode_frame(
        static_cast<protocol::FrameType>(frame.header.type),
        frame.header.stream_id,
        frame.header.flags,
        *eff_payload,
        pad_multiple));
}

void TransportCore::dispatch_next_write() {
    std::vector<PendingWrite> batch;
    WriteHandler writer;
    {
        std::lock_guard<std::mutex> state_lock(state_mu_);
        if (stopped_) {
            return;
        }
        writer = write_handler_;
    }
    if (!writer) {
        request_transport_close("transport writer unavailable");
        return;
    }

    {
        std::lock_guard<std::mutex> write_lock(write_mu_);
        if (write_queue_.empty()) {
            write_in_flight_ = false;
            return;
        }
        std::size_t total_bytes = 0;
        std::unordered_set<uint8_t> batch_streams;
        while (!write_queue_.empty() && batch.size() < kMaxWriteBatchFrames) {
            auto it = select_next_write_locked(total_bytes, batch_streams);
            if (it == write_queue_.end()) {
                break;
            }
            const auto stream_id = it->frame.header.stream_id;
            total_bytes += it->frame.payload.size() + 8U;
            batch_streams.insert(stream_id);
            batch.push_back(std::move(*it));
            write_queue_.erase(it);
        }
    }

    std::shared_ptr<Bytes> encoded;
    std::vector<std::size_t> encoded_sizes;
    try {
        encoded_sizes.reserve(batch.size());
        if (batch.size() == 1) {
            encoded = encode_outgoing_frame(batch.front().frame);
            encoded_sizes.push_back(encoded->size());
        } else {
            encoded = std::make_shared<Bytes>();
            encoded->reserve(kMaxWriteBatchBytes);
            for (const auto& item : batch) {
                auto part = encode_outgoing_frame(item.frame);
                encoded_sizes.push_back(part->size());
                encoded->insert(encoded->end(), part->begin(), part->end());
            }
        }
    } catch (const std::exception& ex) {
        for (auto& item : batch) {
            if (item.handler) {
                item.handler(false, 0, ex.what());
            }
        }
        request_transport_close("frame encode failed: " + std::string(ex.what()));
        return;
    } catch (...) {
        for (auto& item : batch) {
            if (item.handler) {
                item.handler(false, 0, "unknown error");
            }
        }
        request_transport_close("frame encode failed: unknown error");
        return;
    }

    writer(encoded, [this, batch = std::move(batch), encoded_sizes = std::move(encoded_sizes)](
                        bool ok,
                        std::size_t bytes,
                        const std::string& error) mutable {
        bool dispatch = false;
        const bool stopped = is_stopped();
        {
            std::lock_guard<std::mutex> write_lock(write_mu_);
            if (!ok || stopped || write_queue_.empty()) {
                write_in_flight_ = false;
            } else {
                write_in_flight_ = true;
                dispatch = true;
            }
        }
        for (std::size_t i = 0; i < batch.size(); ++i) {
            auto& item = batch[i];
            if (item.handler) {
                const std::size_t item_bytes = ok && i < encoded_sizes.size() ? encoded_sizes[i] : bytes;
                item.handler(ok, item_bytes, error);
            }
        }
        if (!ok) {
            request_transport_close("write failed: " + error);
            return;
        }
        if (dispatch) {
            dispatch_next_write();
        }
    });
}

}  // namespace yume::client
