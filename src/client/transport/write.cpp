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

void TransportCore::queue_frame(protocol::Frame frame, WriteCompletion handler,
                                bool already_protected) {
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
        write_queue_.push_back(
            {std::move(frame), std::move(handler), already_protected});
        if (!write_in_flight_) {
            write_in_flight_ = true;
            dispatch = true;
        }
    }
    if (dispatch) {
        dispatch_next_write();
    }
}

std::shared_ptr<TransportCore::Bytes> TransportCore::encode_outgoing_frame(
    const protocol::Frame& frame, bool already_protected) {
    // Avoid copying the payload on the no-inner path: encode_frame and
    // encrypt_inner_payload both take const&, so the source frame's payload
    // can be passed through directly. Only the inner-encrypted path needs a
    // separate buffer to hold the AEAD output.
    protocol::Frame protected_frame;
    const protocol::Frame* effective_frame = &frame;
    bool use_legacy_inner = false;
    {
        std::lock_guard<std::mutex> lock(state_mu_);
        if (ratchet_ && !already_protected) {
            protected_frame = ratchet_->Seal(
                frame, std::chrono::steady_clock::now());
            effective_frame = &protected_frame;
        } else if (!ratchet_) {
            use_legacy_inner =
                (frame.header.flags & protocol::kFlagInnerEncrypted) != 0;
        }
    }
    const Bytes* eff_payload = &effective_frame->payload;
    Bytes encrypted;
    if (use_legacy_inner) {
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
        effective_frame->header.flags,
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

    std::string selection_error;
    {
        std::lock_guard<std::mutex> state_lock(state_mu_);
        std::lock_guard<std::mutex> write_lock(write_mu_);
        if (write_queue_.empty()) {
            write_in_flight_ = false;
            return;
        }
        try {
            const bool ratchet_active = ratchet_ != nullptr;
            const bool rekey_blocked =
                ratchet_active && ratchet_->outbound_rekey_pending();
            std::size_t total_bytes = 0;
            std::unordered_set<uint8_t> batch_streams;
            auto it = select_next_write_locked(total_bytes, batch_streams,
                                               rekey_blocked);
            if (it == write_queue_.end()) {
                write_in_flight_ = false;
                return;
            }
            if (ratchet_active && !it->already_protected &&
                ratchet_->ShouldStartRekey(
                    it->frame, std::chrono::steady_clock::now())) {
                protocol::Frame rekey = ratchet_->BeginOutboundRekey(
                    std::chrono::steady_clock::now());
                batch.push_back({std::move(rekey), {}, true});
            } else if (ratchet_active) {
                batch.push_back(std::move(*it));
                write_queue_.erase(it);
            } else {
                while (it != write_queue_.end() &&
                       batch.size() < kMaxWriteBatchFrames) {
                    const auto stream_id = it->frame.header.stream_id;
                    total_bytes += it->frame.payload.size() + 8U;
                    batch_streams.insert(stream_id);
                    batch.push_back(std::move(*it));
                    write_queue_.erase(it);
                    it = select_next_write_locked(total_bytes, batch_streams,
                                                  false);
                }
            }
        } catch (const std::exception& ex) {
            selection_error = ex.what();
            write_in_flight_ = false;
        }
    }
    if (!selection_error.empty()) {
        request_transport_close("rekey start failed: " + selection_error);
        return;
    }

    std::shared_ptr<Bytes> encoded;
    std::vector<std::size_t> encoded_sizes;
    try {
        encoded_sizes.reserve(batch.size());
        if (batch.size() == 1) {
            encoded = encode_outgoing_frame(batch.front().frame,
                                            batch.front().already_protected);
            encoded_sizes.push_back(encoded->size());
        } else {
            encoded = std::make_shared<Bytes>();
            encoded->reserve(kMaxWriteBatchBytes);
            for (const auto& item : batch) {
                auto part = encode_outgoing_frame(item.frame,
                                                  item.already_protected);
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

void TransportCore::resume_writes_after_rekey() {
    bool dispatch = false;
    {
        std::lock_guard<std::mutex> lock(write_mu_);
        if (!write_in_flight_ && !write_queue_.empty()) {
            write_in_flight_ = true;
            dispatch = true;
        }
    }
    if (dispatch) dispatch_next_write();
}

}  // namespace yume::client
