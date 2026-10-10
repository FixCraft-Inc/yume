/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/h2_duplex_carrier.hpp"
#include "providers/ytp1_h2_admission.hpp"

#include <openssl/crypto.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <limits>
#include <new>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "engine/buffer.hpp"

namespace yume::providers {
namespace {

using engine::Buffer;
using engine::CancellationRegistration;
using engine::CancellationToken;
using engine::Carrier;
using engine::CarrierCredit;
using engine::EndpointRole;
using engine::ExecutorAffinity;
using engine::ProviderDescriptor;
using engine::ProviderKind;
using engine::ReceivedRecord;
using engine::Result;
using engine::SecureChannel;
using engine::Status;
using engine::StatusCode;

constexpr std::array<std::uint8_t, 4> kCarrierMagic{'Y', 'C', 'R', 0};
constexpr std::uint8_t kCarrierEnvelopeVersion = 1U;

// Diagnostics are best effort; the typed error and completion must survive OOM.
template <typename T>
decltype(auto) completion_argument(T&& value) noexcept {
    if constexpr (std::is_same_v<std::remove_cvref_t<T>, Status>) {
        return Status::diagnostic(value.code(), value.message());
    } else {
        return std::forward<T>(value);
    }
}

template <typename Callback, typename... Args>
void invoke_noexcept(Callback& callback, Args&&... args) noexcept {
    if (!callback) {
        return;
    }
    try {
        auto owned = std::move(callback);
        owned(completion_argument(std::forward<Args>(args))...);
    } catch (...) {
        // Provider callbacks are containment boundaries. State is settled
        // before invocation, so application exceptions cannot corrupt it.
    }
}

Status validate_limits(const H2DuplexCarrierLimits& limits) {
    const std::size_t window = limits.admitted_receive_window_bytes;
    const bool window_fits = window >= obfs::kAdmittedH2ReceiveWindowBytes &&
                             window <= obfs::kMaxAdmittedH2ReceiveWindowBytes;
    const bool framed_record_fits =
        window_fits &&
        limits.max_record_bytes <= window - kH2DuplexEnvelopeBytes;
    const bool retained_record_fits =
        limits.max_record_bytes <=
            std::numeric_limits<std::size_t>::max() - kH2DuplexEnvelopeBytes &&
        limits.max_retained_receive_bytes >=
            limits.max_record_bytes + kH2DuplexEnvelopeBytes &&
        limits.max_retained_receive_bytes >= window;
    if (limits.max_record_bytes == 0U ||
        limits.max_record_bytes > engine::kAbsoluteMaxBufferBytes ||
        !framed_record_fits || limits.max_buffered_records == 0U ||
        !retained_record_fits ||
        limits.max_retained_receive_bytes >
            obfs::kMaxAdmittedH2ReceiveWindowBytes ||
        limits.max_pending_secure_write_bytes == 0U ||
        limits.max_pending_secure_write_bytes > 32U * 1024U * 1024U ||
        limits.secure_read_bytes == 0U ||
        limits.secure_read_bytes > engine::kAbsoluteMaxBufferBytes) {
        return Status::diagnostic(
            StatusCode::InvalidArgument,
            "H2 carrier limits are zero, inconsistent, or exceed hard bounds");
    }
    if (limits.max_record_bytes >
        std::numeric_limits<std::uint32_t>::max()) {
        return Status::diagnostic(
            StatusCode::InvalidArgument,
            "H2 carrier record limit exceeds its wire field");
    }
    return Status::success();
}

Result<ProviderDescriptor> make_descriptor() {
    return ProviderDescriptor::create(
        std::string(kH2DuplexCarrierProviderId), ProviderKind::Carrier,
        kH2DuplexCarrierProviderApiVersion,
        engine::mandatory_capabilities(ProviderKind::Carrier));
}

std::uint32_t read_be32(const std::uint8_t* input) noexcept {
    return (static_cast<std::uint32_t>(input[0]) << 24U) |
           (static_cast<std::uint32_t>(input[1]) << 16U) |
           (static_cast<std::uint32_t>(input[2]) << 8U) |
           static_cast<std::uint32_t>(input[3]);
}

void write_be32(std::uint8_t* output, std::uint32_t value) noexcept {
    output[0] = static_cast<std::uint8_t>((value >> 24U) & 0xffU);
    output[1] = static_cast<std::uint8_t>((value >> 16U) & 0xffU);
    output[2] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
    output[3] = static_cast<std::uint8_t>(value & 0xffU);
}

class H2DuplexCarrierState;

class H2DuplexCarrier final : public Carrier {
public:
    explicit H2DuplexCarrier(
        std::shared_ptr<H2DuplexCarrierState> state) noexcept
        : state_(std::move(state)) {}
    ~H2DuplexCarrier() noexcept override;

    const ProviderDescriptor& descriptor() const noexcept override;
    ExecutorAffinity executor_affinity() const noexcept override;
    std::size_t max_record_size() const noexcept override;
    SecureChannel& secure_channel() noexcept override;
    const SecureChannel& secure_channel() const noexcept override;
    void async_receive(CancellationToken cancellation,
                       ReceiveCompletion completion) override;
    void async_send(Buffer record,
                    CancellationToken cancellation,
                    SendCompletion completion) override;
    void cancel() noexcept override;
    void close() noexcept override;

private:
    std::shared_ptr<H2DuplexCarrierState> state_;
};

class H2DuplexCarrierState final
    : public std::enable_shared_from_this<H2DuplexCarrierState> {
public:
    H2DuplexCarrierState(
        ProviderDescriptor descriptor,
        ExecutorAffinity affinity,
        H2Dispatch post,
        H2DuplexCarrierLimits limits,
        std::unique_ptr<SecureChannel> channel,
        std::unique_ptr<obfs::H2Carrier> h2,
        std::shared_ptr<H2CoverHandler> cover = {})
        : descriptor_(std::move(descriptor)),
          affinity_(affinity),
          dispatch_(std::move(post)),
          limits_(limits),
          channel_(std::move(channel)),
          h2_(std::move(h2)), cover_(std::move(cover)) {}

    const ProviderDescriptor& descriptor() const noexcept {
        return descriptor_;
    }
    ExecutorAffinity affinity() const noexcept { return affinity_; }
    std::size_t max_record_size() const noexcept {
        return limits_.max_record_bytes;
    }
    SecureChannel& channel() noexcept { return *channel_; }
    const SecureChannel& channel() const noexcept { return *channel_; }

    template <typename Task>
    StatusCode post(Task&& task) noexcept {
        try {
            dispatch_.post(std::forward<Task>(task));
            return StatusCode::Ok;
        } catch (const std::bad_alloc&) {
            return StatusCode::ResourceExhausted;
        } catch (...) {
            return StatusCode::Internal;
        }
    }

    void start_client(std::string authority,
                      std::string carrier_path,
                      CancellationToken cancellation,
                      engine::CarrierProvider::Completion completion) {
        if (terminal_) {
            complete_create(completion,
                            Status::diagnostic(StatusCode::Closed,
                                               "H2 carrier is already closed"));
            return;
        }
        opening_ = true;
        authority_ = std::move(authority);
        carrier_path_ = std::move(carrier_path);
        create_completion_ = std::move(completion);

        try {
            const std::weak_ptr<H2DuplexCarrierState> weak = weak_from_this();
            create_token_ = cancellation;
            auto registration = cancellation.register_callback([weak] {
                if (auto self = weak.lock()) self->notify_control();
            });
            if (!registration.ok()) {
                fail(registration.status());
                return;
            }
            create_cancellation_ = std::move(registration).take_value();
            if (cancellation.is_cancelled()) {
                fail(Status::diagnostic(StatusCode::Cancelled,
                                        "H2 carrier creation was cancelled"));
                return;
            }

            if (!h2_->StartClient(authority_)) {
                fail(h2_failure("start HTTP/2 client"));
                return;
            }
            pump();
        } catch (const std::bad_alloc&) {
            fail(Status::diagnostic(StatusCode::ResourceExhausted,
                                    "H2 carrier creation allocation failed"));
        } catch (...) {
            fail(Status::diagnostic(StatusCode::Internal,
                                    "H2 carrier creation threw"));
        }
    }

    void start_admitted_server() {
        if (terminal_) {
            return;
        }
        try {
            drain_tunnel_bytes();
            pump();
        } catch (const std::bad_alloc&) {
            fail(Status::diagnostic(StatusCode::ResourceExhausted,
                                    "admitted H2 carrier allocation failed"));
        } catch (...) {
            fail(Status::diagnostic(StatusCode::Internal,
                                    "admitted H2 carrier startup threw"));
        }
    }

    void async_receive(CancellationToken cancellation,
                       Carrier::ReceiveCompletion completion) {
        const auto self = shared_from_this();
        std::shared_ptr<Carrier::ReceiveCompletion> completion_holder;
        try {
            completion_holder =
                std::make_shared<Carrier::ReceiveCompletion>(
                    std::move(completion));
        } catch (const std::bad_alloc&) {
            Result<ReceivedRecord> result(
                Status::diagnostic(StatusCode::ResourceExhausted,
                                   "H2 receive-dispatch allocation failed"));
            invoke_noexcept(completion, std::move(result));
            return;
        }
        const auto dispatched = post([self, cancellation = std::move(cancellation),
                   completion_holder]() mutable {
                self->begin_receive(std::move(cancellation),
                                    std::move(*completion_holder));
            });
        if (dispatched != StatusCode::Ok) {
            Result<ReceivedRecord> result(Status::diagnostic(
                dispatched, "H2 carrier executor rejected receive"));
            invoke_noexcept(*completion_holder, std::move(result));
        }
    }

    void async_send(Buffer record,
                    CancellationToken cancellation,
                    Carrier::SendCompletion completion) {
        const auto self = shared_from_this();
        std::shared_ptr<std::optional<Buffer>> owned_record;
        std::shared_ptr<Carrier::SendCompletion> completion_holder;
        try {
            owned_record = std::make_shared<std::optional<Buffer>>(
                std::move(record));
            completion_holder = std::make_shared<Carrier::SendCompletion>(
                std::move(completion));
        } catch (const std::bad_alloc&) {
            invoke_noexcept(completion_holder ? *completion_holder : completion,
                            Status::diagnostic(
                                StatusCode::ResourceExhausted,
                                "H2 carrier send-dispatch allocation failed"),
                            0U);
            return;
        }
        const auto dispatched = post([self, owned_record,
                   cancellation = std::move(cancellation),
                   completion_holder]() mutable {
                self->begin_send(
                    std::move(**owned_record), std::move(cancellation),
                    std::move(*completion_holder));
                owned_record->reset();
            });
        if (dispatched != StatusCode::Ok) {
            invoke_noexcept(
                *completion_holder,
                Status::diagnostic(dispatched,
                                   "H2 carrier executor rejected send"),
                0U);
        }
    }

    void notify_control() noexcept {
        // submit never invokes inline. Keep publication inside the lock so a
        // completed failure cannot be followed by retaining control work.
        std::lock_guard lock(control_mutex_);
        if (!control_closed_ && requested_terminal_ == StatusCode::Ok)
            dispatch_.submit(control_, shared_from_this());
    }

    void request_terminal(StatusCode code) noexcept {
        std::lock_guard lock(control_mutex_);
        if (control_closed_ || requested_terminal_ != StatusCode::Ok) return;
        requested_terminal_ = code;
        dispatch_.submit(control_, shared_from_this());
    }
    void request_cancel() noexcept { request_terminal(StatusCode::Cancelled); }
    void request_close() noexcept { request_terminal(StatusCode::Closed); }

    static void on_control(void* pointer) noexcept {
        auto& self = *static_cast<H2DuplexCarrierState*>(pointer);
        try { self.settle_control();
        } catch (const std::bad_alloc&) {
            self.fail(Status::diagnostic(StatusCode::ResourceExhausted));
        } catch (...) {
            self.fail(Status::diagnostic(StatusCode::Internal));
        }
    }

    void settle_control() {
        StatusCode requested;
        std::size_t credit;
        {
            std::lock_guard lock(control_mutex_);
            requested = requested_terminal_;
            credit = std::exchange(returned_credit_, 0U);
        }
        if (terminal_ || closing_) return;
        if (requested != StatusCode::Ok) {
            if (!begin_graceful_close()) fail(Status::diagnostic(requested));
            return;
        }
        if (opening_ && create_token_.is_cancelled()) {
            fail(Status::diagnostic(StatusCode::Cancelled));
            return;
        }
        if (pending_send_ && pending_send_->token.is_cancelled()) {
            cancel_send(pending_send_->id); return;
        }
        if (pending_receive_ && pending_receive_->token.is_cancelled())
            cancel_receive(pending_receive_->id);
        if (credit) return_credit(credit);
    }

    void request_credit(std::size_t bytes) noexcept {
        {
            std::lock_guard lock(control_mutex_);
            if (control_closed_ || requested_terminal_ != StatusCode::Ok) return;
            // Credits are move-owned and bounded by max_retained_receive_bytes.
            returned_credit_ += bytes;
        }
        notify_control();
    }

private:
    struct QueuedRecord {
        Buffer payload;
        std::size_t credit_bytes{0U};
    };

    struct PendingReceive {
        std::uint64_t id{0U};
        Carrier::ReceiveCompletion completion;
        CancellationRegistration cancellation;
        CancellationToken token;
    };

    struct PendingSend {
        std::uint64_t id{0U};
        std::size_t record_bytes{0U};
        Carrier::SendCompletion completion;
        CancellationRegistration cancellation;
        CancellationToken token;
    };

    Status h2_failure(std::string_view operation) const noexcept {
        try {
            std::string message(operation);
            if (!h2_->error().empty()) {
                message += ": ";
                message += h2_->error();
            }
            return Status::diagnostic(StatusCode::FailedPrecondition, message);
        } catch (...) {
            return Status::diagnostic(StatusCode::FailedPrecondition);
        }
    }

    static void complete_create(engine::CarrierProvider::Completion& completion,
                                const Status& status) noexcept {
        Result<std::unique_ptr<Carrier>> result(
            Status::diagnostic(status.code(), status.message()));
        invoke_noexcept(completion, std::move(result));
    }

    void finish_client_opening();

    void maybe_advance_client_opening() {
        if (!opening_ || terminal_) {
            return;
        }
        if (h2_->failed()) {
            fail(h2_failure("HTTP/2 opening failed"));
            return;
        }
        if (!connect_submitted_ && h2_->priming_complete()) {
            if (!h2_->peer_extended_connect_enabled() ||
                !h2_->SubmitExtendedConnect(carrier_path_)) {
                fail(h2_failure("submit HTTP/2 extended CONNECT"));
                return;
            }
            connect_submitted_ = true;
            collect_h2_output();
        }
        if (connect_submitted_ && h2_->carrier_active()) {
            finish_client_opening();
        } else if (h2_->carrier_closed()) {
            fail(Status::diagnostic(StatusCode::FailedPrecondition,
                                    "HTTP/2 peer rejected the carrier stream"));
        }
    }

    void begin_receive(CancellationToken cancellation,
                       Carrier::ReceiveCompletion completion) {
        try {
            if (!completion) {
                return;
            }
            if (terminal_) {
                Result<ReceivedRecord> result(Status::diagnostic(
                    terminal_status_.code(), terminal_status_.message()));
                invoke_noexcept(completion, std::move(result));
                return;
            }
            if (closing_) {
                Result<ReceivedRecord> result(Status::diagnostic(
                    StatusCode::Closed, "H2 carrier is closing"));
                invoke_noexcept(completion, std::move(result));
                return;
            }
            if (pending_receive_.has_value()) {
                Result<ReceivedRecord> result(Status::diagnostic(
                    StatusCode::AlreadyExists,
                    "H2 carrier already has a pending receive"));
                invoke_noexcept(completion, std::move(result));
                return;
            }
            if (cancellation.is_cancelled()) {
                Result<ReceivedRecord> result(Status::diagnostic(
                    StatusCode::Cancelled, "H2 carrier receive was cancelled"));
                invoke_noexcept(completion, std::move(result));
                return;
            }
            if (!records_.empty()) {
                deliver_record(std::move(completion));
                pump();
                return;
            }
            if (peer_closed_) {
                Result<ReceivedRecord> result(Status::diagnostic(
                    StatusCode::Closed, "HTTP/2 carrier peer closed"));
                invoke_noexcept(completion, std::move(result));
                return;
            }
            if (next_operation_id_ == std::numeric_limits<std::uint64_t>::max()) {
                fail(Status::diagnostic(
                    StatusCode::ResourceExhausted,
                    "H2 carrier operation IDs are exhausted"));
                Result<ReceivedRecord> result(Status::diagnostic(
                    terminal_status_.code(), terminal_status_.message()));
                invoke_noexcept(completion, std::move(result));
                return;
            }
            const std::uint64_t id = next_operation_id_++;
            // As for sends: the handlers below must not complete it again.
            pending_receive_.emplace(PendingReceive{
                id, std::exchange(completion, nullptr), {}, cancellation});
            const std::weak_ptr<H2DuplexCarrierState> weak = weak_from_this();
            auto registration = cancellation.register_callback([weak] {
                if (auto self = weak.lock()) self->notify_control();
            });
            if (!registration.ok()) {
                Carrier::ReceiveCompletion failed =
                    std::move(pending_receive_->completion);
                pending_receive_.reset();
                Result<ReceivedRecord> result(
                    Status::diagnostic(registration.status().code(),
                                       registration.status().message()));
                invoke_noexcept(failed, std::move(result));
                return;
            }
            if (pending_receive_.has_value() && pending_receive_->id == id) {
                pending_receive_->cancellation =
                    std::move(registration).take_value();
            }
            pump();
        } catch (const std::bad_alloc&) {
            fail(Status::diagnostic(StatusCode::ResourceExhausted));
            Result<ReceivedRecord> result(
                Status::diagnostic(StatusCode::ResourceExhausted));
            invoke_noexcept(completion, std::move(result));
        } catch (...) {
            fail(Status::diagnostic(StatusCode::Internal));
            Result<ReceivedRecord> result(
                Status::diagnostic(StatusCode::Internal));
            invoke_noexcept(completion, std::move(result));
        }
    }

    void cancel_receive(std::uint64_t id) noexcept {
        if (!pending_receive_.has_value() || pending_receive_->id != id) {
            return;
        }
        Carrier::ReceiveCompletion completion =
            std::move(pending_receive_->completion);
        pending_receive_.reset();
        Result<ReceivedRecord> result(Status::diagnostic(
            StatusCode::Cancelled, "H2 carrier receive was cancelled"));
        invoke_noexcept(completion, std::move(result));
    }

    void begin_send(Buffer record,
                    CancellationToken cancellation,
                    Carrier::SendCompletion completion) {
        try {
            if (!completion) {
                return;
            }
            if (terminal_) {
                invoke_noexcept(completion, terminal_status_, 0U);
                return;
            }
            if (closing_ || peer_closed_ || !h2_->carrier_active()) {
                invoke_noexcept(
                    completion,
                    Status::diagnostic(StatusCode::Closed,
                                       "HTTP/2 carrier is not active"),
                    0U);
                return;
            }
            if (pending_send_.has_value()) {
                invoke_noexcept(
                    completion,
                    Status::diagnostic(StatusCode::AlreadyExists,
                                       "H2 carrier already has a pending send"),
                    0U);
                return;
            }
            if (record.empty() || record.size() > limits_.max_record_bytes) {
                invoke_noexcept(
                    completion,
                    Status::diagnostic(
                        StatusCode::ResourceExhausted,
                        "H2 carrier record is empty or exceeds its bound"),
                    0U);
                return;
            }
            if (cancellation.is_cancelled()) {
                invoke_noexcept(
                    completion,
                    Status::diagnostic(StatusCode::Cancelled,
                                       "H2 carrier send was cancelled"),
                    0U);
                return;
            }
            if (next_operation_id_ == std::numeric_limits<std::uint64_t>::max()) {
                fail(Status::diagnostic(
                    StatusCode::ResourceExhausted,
                    "H2 carrier operation IDs are exhausted"));
                invoke_noexcept(completion, terminal_status_, 0U);
                return;
            }

            const std::uint64_t id = next_operation_id_++;
            const std::size_t record_bytes = record.size();
            // Empty the parameter as the pending send takes it: the handlers
            // below complete through it, and a moved-from std::function need
            // not be empty (libc++ leaves a small target in place).
            pending_send_.emplace(
                PendingSend{id,
                            record_bytes,
                            std::exchange(completion, nullptr),
                            {},
                            cancellation});
            const std::weak_ptr<H2DuplexCarrierState> weak = weak_from_this();
            auto registration = cancellation.register_callback([weak] {
                if (auto self = weak.lock()) self->notify_control();
            });
            if (!registration.ok()) {
                Carrier::SendCompletion failed =
                    std::move(pending_send_->completion);
                pending_send_.reset();
                invoke_noexcept(failed, registration.status(), 0U);
                return;
            }
            if (pending_send_.has_value() && pending_send_->id == id) {
                pending_send_->cancellation =
                    std::move(registration).take_value();
            }

            // The envelope and the record go to the carrier as two parts,
            // which it frames without joining them first.
            std::array<std::uint8_t, kH2DuplexEnvelopeBytes> envelope{};
            std::copy(kCarrierMagic.begin(), kCarrierMagic.end(),
                      envelope.begin());
            envelope[4] = kCarrierEnvelopeVersion;
            write_be32(envelope.data() + 8,
                       static_cast<std::uint32_t>(record_bytes));
            if (!h2_->SendBinary(envelope,
                                 {reinterpret_cast<const std::uint8_t*>(
                                      record.bytes().data()),
                                  record_bytes})) {
                fail(h2_failure("queue H2 carrier record"));
                return;
            }
            pump();
        } catch (const std::bad_alloc&) {
            fail(Status::diagnostic(StatusCode::ResourceExhausted));
            invoke_noexcept(completion,
                            Status::diagnostic(StatusCode::ResourceExhausted),
                            0U);
        } catch (...) {
            fail(Status::diagnostic(StatusCode::Internal));
            invoke_noexcept(completion,
                            Status::diagnostic(StatusCode::Internal), 0U);
        }
    }

    void cancel_send(std::uint64_t id) noexcept {
        if (!pending_send_.has_value() || pending_send_->id != id) {
            return;
        }
        // A record may already be partly serialized or written. Continuing
        // would let the next record inherit an ambiguous byte stream, so send
        // cancellation is terminal for this carrier.
        fail(Status::diagnostic(StatusCode::Cancelled,
                                "H2 carrier send was cancelled"));
    }

    void deliver_record(Carrier::ReceiveCompletion completion) {
        try {
            if (records_.empty()) {
                return;
            }
            QueuedRecord record = std::move(records_.front());
            records_.pop_front();
            queued_record_bytes_ -= record.payload.size();
            const std::size_t credit_bytes = record.credit_bytes;
            const std::weak_ptr<H2DuplexCarrierState> weak = weak_from_this();
            CarrierCredit credit(
                credit_bytes,
                [weak](std::size_t bytes) {
                    if (auto self = weak.lock()) self->request_credit(bytes);
                });
            Result<ReceivedRecord> result(ReceivedRecord(
                std::move(record.payload), std::move(credit)));
            invoke_noexcept(completion, std::move(result));
        } catch (const std::bad_alloc&) {
            fail(Status::diagnostic(StatusCode::ResourceExhausted));
            Result<ReceivedRecord> result(
                Status::diagnostic(StatusCode::ResourceExhausted));
            invoke_noexcept(completion, std::move(result));
        } catch (...) {
            fail(Status::diagnostic(StatusCode::Internal));
            Result<ReceivedRecord> result(
                Status::diagnostic(StatusCode::Internal));
            invoke_noexcept(completion, std::move(result));
        }
    }

    void maybe_deliver_pending_receive() {
        if (!pending_receive_.has_value() || records_.empty()) {
            return;
        }
        Carrier::ReceiveCompletion completion =
            std::move(pending_receive_->completion);
        pending_receive_.reset();
        deliver_record(std::move(completion));
    }

    void return_credit(std::size_t bytes) {
        if (terminal_) {
            return;
        }
        if (bytes == 0U || bytes > owned_credit_bytes_) {
            fail(Status::diagnostic(StatusCode::Internal,
                                    "H2 carrier credit ledger underflow"));
            return;
        }
        if (!h2_->ConsumeTunnelBytes(bytes)) {
            fail(h2_failure("return HTTP/2 carrier credit"));
            return;
        }
        owned_credit_bytes_ -= bytes;
        pump();
    }

    std::span<const std::uint8_t> retained_input() const noexcept {
        return std::span<const std::uint8_t>(input_).subspan(input_offset_);
    }

    void compact_input() {
        if (input_offset_ == 0U) {
            return;
        }
        if (input_offset_ == input_.size()) {
            input_.clear();
            input_offset_ = 0U;
            return;
        }
        if (input_offset_ >= input_.size() / 2U) {
            input_.erase(
                input_.begin(),
                input_.begin() + static_cast<std::ptrdiff_t>(input_offset_));
            input_offset_ = 0U;
        }
    }

    bool parse_record_header(std::span<const std::uint8_t> header) {
        if (header.size() != kH2DuplexEnvelopeBytes ||
            !std::equal(kCarrierMagic.begin(), kCarrierMagic.end(),
                        header.begin()) ||
            header[4] != kCarrierEnvelopeVersion || header[5] != 0U ||
            header[6] != 0U || header[7] != 0U) {
            fail(Status::diagnostic(
                StatusCode::InvalidArgument,
                "malformed H2-duplex carrier record envelope"));
            return false;
        }
        const std::uint32_t payload_length = read_be32(header.data() + 8);
        if (payload_length == 0U ||
            payload_length > limits_.max_record_bytes) {
            fail(Status::diagnostic(
                StatusCode::ResourceExhausted,
                "H2-duplex carrier record length exceeds its bound"));
            return false;
        }
        expected_payload_bytes_ = payload_length;
        if (!h2_->ConsumeTunnelBytes(kH2DuplexEnvelopeBytes)) {
            fail(h2_failure("retire H2 carrier envelope credit"));
            return false;
        }
        if (owned_credit_bytes_ < kH2DuplexEnvelopeBytes) {
            fail(Status::diagnostic(
                StatusCode::Internal,
                "H2 carrier envelope credit ledger underflow"));
            return false;
        }
        owned_credit_bytes_ -= kH2DuplexEnvelopeBytes;
        input_offset_ += kH2DuplexEnvelopeBytes;
        return true;
    }

    void parse_records() {
        while (!terminal_) {
            compact_input();
            std::span<const std::uint8_t> available = retained_input();
            if (!expected_payload_bytes_.has_value()) {
                if (records_.size() >= limits_.max_buffered_records ||
                    available.size() < kH2DuplexEnvelopeBytes) {
                    return;
                }
                if (!parse_record_header(
                        available.first(kH2DuplexEnvelopeBytes))) {
                    return;
                }
                compact_input();
                available = retained_input();
            }
            const std::size_t payload_bytes = *expected_payload_bytes_;
            if (available.size() < payload_bytes ||
                records_.size() >= limits_.max_buffered_records) {
                return;
            }
            if (queued_record_bytes_ > limits_.max_retained_receive_bytes ||
                payload_bytes > limits_.max_retained_receive_bytes -
                                    queued_record_bytes_) {
                fail(Status::diagnostic(
                    StatusCode::ResourceExhausted,
                    "H2 carrier receive queue exceeded its byte bound"));
                return;
            }
            auto copied = Buffer::copy_from(
                std::as_bytes(available.first(payload_bytes)),
                limits_.max_record_bytes);
            if (!copied.ok()) {
                fail(copied.status());
                return;
            }
            records_.push_back(QueuedRecord{
                std::move(copied).take_value(), payload_bytes});
            queued_record_bytes_ += payload_bytes;
            input_offset_ += payload_bytes;
            expected_payload_bytes_.reset();
            maybe_deliver_pending_receive();
        }
    }

    void drain_tunnel_bytes() {
        obfs::H2Bytes decoded = h2_->TakeTunnelBytes();
        if (decoded.empty()) {
            return;
        }
        if (closing_) {
            // Nothing reads records any more. Retire their credit at once so
            // a peer still sending can reach its close.
            if (!h2_->ConsumeTunnelBytes(decoded.size())) {
                fail(h2_failure("retire HTTP/2 credit while closing"));
            }
            return;
        }
        if (owned_credit_bytes_ > limits_.max_retained_receive_bytes ||
            decoded.size() > limits_.max_retained_receive_bytes -
                                 owned_credit_bytes_) {
            fail(Status::diagnostic(
                StatusCode::ResourceExhausted,
                "H2 carrier retained receive credit exceeded its bound"));
            return;
        }
        compact_input();
        const std::size_t retained = input_.size() - input_offset_;
        if (decoded.size() > limits_.max_retained_receive_bytes - retained) {
            fail(Status::diagnostic(
                StatusCode::ResourceExhausted,
                "H2 carrier input accumulation exceeded its bound"));
            return;
        }
        input_.insert(input_.end(), decoded.begin(), decoded.end());
        owned_credit_bytes_ += decoded.size();
        parse_records();
    }

    bool can_read() const noexcept {
        if (terminal_ || read_in_flight_) return false;
        if (closing_) return true;
        return !peer_closed_ &&
               records_.size() < limits_.max_buffered_records &&
               owned_credit_bytes_ < limits_.max_retained_receive_bytes;
    }

    void start_read() {
        if (!can_read()) {
            return;
        }
        const std::size_t channel_limit = channel_->max_read_size();
        const std::size_t max_bytes =
            std::min(limits_.secure_read_bytes, channel_limit);
        if (max_bytes == 0U) {
            fail(Status::diagnostic(
                StatusCode::ProviderMismatch,
                "secure channel declares a zero read bound"));
            return;
        }
        read_in_flight_ = true;
        const auto self = shared_from_this();
        try {
            channel_->async_read(
                max_bytes, transport_cancellation_.token(),
                [self](Result<Buffer> result) noexcept {
                    try {
                        self->on_read(std::move(result));
                    } catch (const std::bad_alloc&) {
                        self->fail(Status::diagnostic(
                            StatusCode::ResourceExhausted,
                            "H2 carrier read allocation failed"));
                    } catch (...) {
                        self->fail(Status::diagnostic(
                            StatusCode::Internal,
                            "H2 carrier read callback threw"));
                    }
                });
        } catch (const std::bad_alloc&) {
            read_in_flight_ = false;
            fail(Status::diagnostic(StatusCode::ResourceExhausted));
        } catch (...) {
            read_in_flight_ = false;
            fail(Status::diagnostic(
                StatusCode::Internal,
                "secure channel threw while starting a read"));
        }
    }

    void on_read(Result<Buffer> result) {
        if (!read_in_flight_) {
            return;
        }
        read_in_flight_ = false;
        if (terminal_) {
            return;
        }
        if (!result.ok() || result.value().empty()) {
            if (closing_) {
                // The peer ended the connection. That completes a server's
                // wait, and a client's once the echo has arrived.
                finish_graceful_close(!close_initiated_ ||
                                      h2_->websocket_close_received());
                return;
            }
            fail(!result.ok() ? result.status()
                              : Status::diagnostic(
                                    StatusCode::Closed,
                                    "secure channel returned an empty read"));
            return;
        }
        Buffer plaintext = std::move(result).take_value();
        const auto bytes = plaintext.bytes();
        h2_->Feed(reinterpret_cast<const std::uint8_t*>(bytes.data()),
                  bytes.size());
        if (h2_->failed()) {
            fail(h2_failure("parse HTTP/2 plaintext"));
            return;
        }
        if (h2_->role() == obfs::H2CarrierRole::Server) {
            for (const auto& event : h2_->TakeStreamCloses()) {
                if (cover_) cover_->stream_closed(event.stream_id);
            }
            for (const auto& request : h2_->TakeRequests()) {
                if (!cover_ || !cover_->respond(*h2_, request)) {
                    fail(Status::diagnostic(StatusCode::ResourceExhausted));
                    return;
                }
                for (const auto& event : h2_->TakeStreamCloses()) {
                    cover_->stream_closed(event.stream_id);
                }
            }
            for (const auto& event : h2_->TakeStreamCloses()) {
                if (cover_) cover_->stream_closed(event.stream_id);
            }
        }
        drain_tunnel_bytes();
        if (terminal_) {
            return;
        }
        collect_h2_output();
        maybe_advance_client_opening();
        if (terminal_) {
            return;
        }
        if (h2_->carrier_closed()) {
            handle_peer_close();
            return;
        }
        pump();
    }

    void collect_h2_output() {
        if (terminal_) {
            return;
        }
        // Each part the H2 carrier hands over stays a write of its own, so
        // the TLS records follow the profiled browser's write boundaries.
        std::vector<obfs::H2Bytes> writes = h2_->TakeOutboundWrites();
        if (h2_->failed()) {
            fail(h2_failure("serialize HTTP/2 output"));
            return;
        }
        std::size_t total = 0U;
        for (const auto& write : writes) total += write.size();
        if (total == 0U) {
            return;
        }
        if (pending_secure_write_bytes_ >
                limits_.max_pending_secure_write_bytes ||
            total > limits_.max_pending_secure_write_bytes -
                        pending_secure_write_bytes_) {
            fail(Status::diagnostic(
                StatusCode::ResourceExhausted,
                "H2 secure-write queue exceeded its byte bound"));
            return;
        }
        const std::size_t channel_limit = channel_->max_write_size();
        if (channel_limit == 0U) {
            fail(Status::diagnostic(
                StatusCode::ProviderMismatch,
                "secure channel declares a zero write bound"));
            return;
        }
        std::deque<Buffer> admitted;
        for (const auto& wire : writes) {
            std::size_t offset = 0U;
            while (offset < wire.size()) {
                const std::size_t count =
                    std::min(channel_limit, wire.size() - offset);
                auto copy = Buffer::copy_from(
                    std::as_bytes(std::span<const std::uint8_t>(
                        wire.data() + offset, count)),
                    channel_limit);
                if (!copy.ok()) {
                    fail(copy.status());
                    return;
                }
                admitted.push_back(std::move(copy).take_value());
                offset += count;
            }
        }
        while (!admitted.empty()) {
            secure_writes_.push_back(std::move(admitted.front()));
            admitted.pop_front();
        }
        pending_secure_write_bytes_ += total;
    }

    void start_write() {
        if (terminal_ || write_in_flight_ || secure_writes_.empty()) {
            return;
        }
        Buffer output = std::move(secure_writes_.front());
        secure_writes_.pop_front();
        active_write_bytes_ = output.size();
        write_in_flight_ = true;
        const auto self = shared_from_this();
        try {
            channel_->async_write(
                std::move(output), transport_cancellation_.token(),
                [self](Status status, std::size_t transferred) noexcept {
                    try {
                        self->on_write(std::move(status), transferred);
                    } catch (const std::bad_alloc&) {
                        self->fail(
                            Status::diagnostic(StatusCode::ResourceExhausted));
                    } catch (...) {
                        self->fail(Status::diagnostic(
                            StatusCode::Internal,
                            "H2 carrier write callback threw"));
                    }
                });
        } catch (const std::bad_alloc&) {
            write_in_flight_ = false;
            fail(Status::diagnostic(StatusCode::ResourceExhausted));
        } catch (...) {
            write_in_flight_ = false;
            fail(Status::diagnostic(
                StatusCode::Internal,
                "secure channel threw while starting a write"));
        }
    }

    void on_write(Status status, std::size_t transferred) {
        if (!write_in_flight_) {
            return;
        }
        const std::size_t expected = active_write_bytes_;
        write_in_flight_ = false;
        active_write_bytes_ = 0U;
        if (terminal_) {
            return;
        }
        if (!status.ok()) {
            fail(status);
            return;
        }
        if (transferred != expected ||
            expected > pending_secure_write_bytes_) {
            fail(Status::diagnostic(
                StatusCode::Internal,
                "secure channel reported a partial H2 write"));
            return;
        }
        pending_secure_write_bytes_ -= expected;
        pump();
    }

    void maybe_complete_send() {
        if (!pending_send_.has_value() || terminal_ || write_in_flight_ ||
            pending_secure_write_bytes_ != 0U ||
            h2_->queued_output_bytes() != 0U) {
            return;
        }
        const std::size_t bytes = pending_send_->record_bytes;
        Carrier::SendCompletion completion =
            std::move(pending_send_->completion);
        pending_send_.reset();
        invoke_noexcept(completion, Status::success(), bytes);
    }

    void pump() {
        if (terminal_) {
            return;
        }
        if (!closing_) parse_records();
        if (terminal_) {
            return;
        }
        collect_h2_output();
        if (terminal_) {
            return;
        }
        maybe_deliver_pending_receive();
        start_write();
        maybe_complete_send();
        start_read();
        maybe_finish_graceful_close();
    }

    void handle_peer_close() {
        if (terminal_ || peer_closed_) {
            return;
        }
        if (closing_) {
            peer_closed_ = true;
            pump();
            return;
        }
        compact_input();
        if (expected_payload_bytes_.has_value() || !retained_input().empty()) {
            fail(Status::diagnostic(
                StatusCode::InvalidArgument,
                "HTTP/2 carrier closed with a truncated record"));
            return;
        }
        peer_closed_ = true;
        if (pending_send_.has_value()) {
            Carrier::SendCompletion completion =
                std::move(pending_send_->completion);
            pending_send_.reset();
            invoke_noexcept(completion,
                            Status::diagnostic(StatusCode::Closed,
                                               "HTTP/2 carrier peer closed"),
                            0U);
        }
        maybe_deliver_pending_receive();
        if (pending_receive_.has_value() && records_.empty()) {
            Carrier::ReceiveCompletion completion =
                std::move(pending_receive_->completion);
            pending_receive_.reset();
            Result<ReceivedRecord> result(Status::diagnostic(
                StatusCode::Closed, "HTTP/2 carrier peer closed"));
            invoke_noexcept(completion, std::move(result));
        }
        // The connection stays open so queued output, such as the echo of the
        // peer's WebSocket CLOSE, still reaches it. The session's close ends
        // it.
        pump();
    }

    // Starts the close described at H2DuplexCarrierProvider. False means this
    // carrier cannot close gracefully and must end the connection at once.
    bool begin_graceful_close() {
        if (terminal_ || opening_ || closing_ || !dispatch_.defer ||
            h2_->failed()) {
            return false;
        }
        const bool client = h2_->role() == obfs::H2CarrierRole::Client;
        const bool initiate = client && !peer_closed_;
        if (initiate ? !h2_->carrier_active() || h2_->carrier_closed()
                     : !peer_closed_) {
            return false;
        }
        closing_ = true;
        close_initiated_ = initiate;
        create_cancellation_.unregister();
        Carrier::ReceiveCompletion receive;
        Carrier::SendCompletion send;
        if (pending_receive_.has_value()) {
            receive = std::move(pending_receive_->completion);
            pending_receive_.reset();
        }
        if (pending_send_.has_value()) {
            send = std::move(pending_send_->completion);
            pending_send_.reset();
        }
        records_.clear();
        queued_record_bytes_ = 0U;
        input_.clear();
        input_offset_ = 0U;
        expected_payload_bytes_.reset();
        const Status closed =
            Status::diagnostic(StatusCode::Closed, "H2 carrier is closing");
        if (receive) {
            Result<ReceivedRecord> result(closed);
            invoke_noexcept(receive, std::move(result));
        }
        if (send) invoke_noexcept(send, closed, 0U);
        if (terminal_) return true;
        // Credit the session still holds returns no more. Retire it now so
        // the peer's window cannot hold back its close.
        if (owned_credit_bytes_ != 0U) {
            if (!h2_->ConsumeTunnelBytes(owned_credit_bytes_)) {
                fail(h2_failure("retire HTTP/2 credit for close"));
                return true;
            }
            owned_credit_bytes_ = 0U;
        }
        if (initiate && !h2_->GracefulClose()) {
            fail(h2_failure("queue HTTP/2 carrier close"));
            return true;
        }
        try {
            const std::weak_ptr<H2DuplexCarrierState> weak = weak_from_this();
            close_deadline_ = dispatch_.defer(kH2GracefulCloseDeadline, [weak] {
                if (auto self = weak.lock()) self->finish_graceful_close(false);
            });
        } catch (...) {
            close_deadline_.reset();
        }
        if (!close_deadline_) {
            fail(Status::diagnostic(StatusCode::ResourceExhausted,
                                    "H2 carrier close deadline unavailable"));
            return true;
        }
        pump();
        return true;
    }

    void maybe_finish_graceful_close() {
        if (!closing_ || terminal_ || write_in_flight_ ||
            !secure_writes_.empty() || h2_->queued_output_bytes() != 0U) {
            return;
        }
        // A client ends the connection once its CLOSE is answered, as the
        // captured browser did. A server leaves that to its client.
        if (close_initiated_ && h2_->websocket_close_received()) {
            finish_graceful_close(true);
        } else if (!close_initiated_ &&
                   h2_->role() == obfs::H2CarrierRole::Client) {
            finish_graceful_close(true);
        }
    }

    void finish_graceful_close(bool completed) noexcept {
        if (!closing_ || terminal_) return;
        close_completed_ = completed;
        fail(Status::diagnostic(StatusCode::Closed, "HTTP/2 carrier closed"));
    }

    void fail(const Status& status) noexcept {
        if (terminal_) {
            return;
        }
        terminal_ = true;
        if (closing_) h2_->RecordCloseWireResult(close_completed_);
        close_deadline_.reset();
        {
            std::lock_guard lock(control_mutex_);
            control_closed_ = true;
            returned_credit_ = 0U;
        }
        terminal_status_ =
            status.ok() ? Status::diagnostic(
                              StatusCode::Internal,
                              "H2 carrier failed without an error status")
                        : Status::diagnostic(status.code(), status.message());
        create_cancellation_.unregister();

        // Empty the member, which a move need not do (libc++ leaves a small
        // target in place), so the creation completes once.
        engine::CarrierProvider::Completion create =
            std::exchange(create_completion_, nullptr);
        Carrier::ReceiveCompletion receive;
        Carrier::SendCompletion send;
        if (pending_receive_.has_value()) {
            receive = std::move(pending_receive_->completion);
            pending_receive_.reset();
        }
        if (pending_send_.has_value()) {
            send = std::move(pending_send_->completion);
            pending_send_.reset();
        }

        records_.clear();
        secure_writes_.clear();
        input_.clear();
        owned_credit_bytes_ = 0U;
        queued_record_bytes_ = 0U;
        pending_secure_write_bytes_ = 0U;
        transport_cancellation_.cancel();

        try {
            channel_->cancel();
            channel_->close();
        } catch (...) {
            // Transport cleanup must not prevent completion settlement.
        }
        if (create) {
            complete_create(create, terminal_status_);
        }
        if (receive) {
            Result<ReceivedRecord> result(Status::diagnostic(
                terminal_status_.code(), terminal_status_.message()));
            invoke_noexcept(receive, std::move(result));
        }
        if (send) {
            invoke_noexcept(send, terminal_status_, 0U);
        }
    }

    ProviderDescriptor descriptor_;
    ExecutorAffinity affinity_;
    H2Dispatch dispatch_;
    H2DuplexCarrierLimits limits_;
    std::unique_ptr<SecureChannel> channel_;
    std::unique_ptr<obfs::H2Carrier> h2_;
    std::shared_ptr<H2CoverHandler> cover_;
    engine::CancellationSource transport_cancellation_;

    engine::CarrierProvider::Completion create_completion_;
    CancellationRegistration create_cancellation_;
    std::optional<PendingReceive> pending_receive_;
    std::optional<PendingSend> pending_send_;

    std::deque<QueuedRecord> records_;
    std::deque<Buffer> secure_writes_;
    std::vector<std::uint8_t> input_;
    std::optional<std::size_t> expected_payload_bytes_;
    std::string authority_;
    std::string carrier_path_;
    Status terminal_status_{StatusCode::Closed};
    ControlTask control_{&H2DuplexCarrierState::on_control};
    std::mutex control_mutex_;
    StatusCode requested_terminal_{StatusCode::Ok};
    std::size_t returned_credit_{0U};
    bool control_closed_{false};
    CancellationToken create_token_;

    std::size_t input_offset_{0U};
    std::size_t queued_record_bytes_{0U};
    std::size_t owned_credit_bytes_{0U};
    std::size_t pending_secure_write_bytes_{0U};
    std::size_t active_write_bytes_{0U};
    std::uint64_t next_operation_id_{1U};
    bool opening_{false};
    bool connect_submitted_{false};
    bool read_in_flight_{false};
    bool write_in_flight_{false};
    bool peer_closed_{false};
    bool terminal_{false};
    bool closing_{false};
    bool close_initiated_{false};
    bool close_completed_{false};
    std::shared_ptr<void> close_deadline_;
};

H2DuplexCarrier::~H2DuplexCarrier() noexcept {
    state_->request_close();
}

const ProviderDescriptor& H2DuplexCarrier::descriptor() const noexcept {
    return state_->descriptor();
}

ExecutorAffinity H2DuplexCarrier::executor_affinity() const noexcept {
    return state_->affinity();
}

std::size_t H2DuplexCarrier::max_record_size() const noexcept {
    return state_->max_record_size();
}

SecureChannel& H2DuplexCarrier::secure_channel() noexcept {
    return state_->channel();
}

const SecureChannel& H2DuplexCarrier::secure_channel() const noexcept {
    return state_->channel();
}

void H2DuplexCarrier::async_receive(CancellationToken cancellation,
                                  ReceiveCompletion completion) {
    state_->async_receive(std::move(cancellation), std::move(completion));
}

void H2DuplexCarrier::async_send(Buffer record,
                               CancellationToken cancellation,
                               SendCompletion completion) {
    state_->async_send(std::move(record), std::move(cancellation),
                       std::move(completion));
}

void H2DuplexCarrier::cancel() noexcept {
    state_->request_cancel();
}

void H2DuplexCarrier::close() noexcept {
    state_->request_close();
}

void H2DuplexCarrierState::finish_client_opening() {
    if (!opening_ || terminal_) {
        return;
    }
    // Chrome's captured initial stream window is smaller than the maximum YTP
    // carrier record. The secure channel has authenticated the peer and the
    // peer has accepted the extended CONNECT, so admit bounded receive credit
    // before the YTP session handshake starts. This is carrier admission, not
    // YTP session authentication.
    if (!h2_->EnableAdmittedReceiveWindow(
            limits_.admitted_receive_window_bytes)) {
        fail(h2_failure("expand admitted client receive credit"));
        return;
    }
    opening_ = false;
    create_cancellation_.unregister();
    // fail() below settles create_completion_ again, so it must be empty.
    engine::CarrierProvider::Completion completion =
        std::exchange(create_completion_, nullptr);
    try {
        std::unique_ptr<Carrier> carrier =
            std::make_unique<H2DuplexCarrier>(shared_from_this());
        Result<std::unique_ptr<Carrier>> result(std::move(carrier));
        invoke_noexcept(completion, std::move(result));
    } catch (const std::bad_alloc&) {
        const Status failure =
            Status::diagnostic(StatusCode::ResourceExhausted,
                               "H2 carrier object allocation failed");
        complete_create(completion, failure);
        fail(failure);
    } catch (...) {
        const Status failure = Status::diagnostic(
            StatusCode::Internal, "H2 carrier object construction threw");
        complete_create(completion, failure);
        fail(failure);
    }
}

}  // namespace

struct H2DuplexCarrierProvider::AdmissionKey final {
    explicit AdmissionKey(std::span<const std::byte> key) noexcept {
        std::copy(key.begin(), key.end(), bytes.begin());
    }
    AdmissionKey(const AdmissionKey&) = delete;
    AdmissionKey& operator=(const AdmissionKey&) = delete;
    ~AdmissionKey() noexcept { OPENSSL_cleanse(bytes.data(), bytes.size()); }

    std::array<std::byte, kYtp1H2AdmissionKeyBytes> bytes{};
};

H2DuplexCarrierProvider::H2DuplexCarrierProvider(
    ProviderDescriptor descriptor,
    ExecutorAffinity executor_affinity,
    H2Dispatch post,
    H2DuplexClientConfig config,
    std::shared_ptr<const AdmissionKey> admission_key) noexcept
    : descriptor_(std::move(descriptor)),
      executor_affinity_(executor_affinity),
      dispatch_(std::move(post)),
      config_(std::move(config)),
      admission_key_(std::move(admission_key)) {}

Result<std::shared_ptr<H2DuplexCarrierProvider>>
H2DuplexCarrierProvider::create(
    ExecutorAffinity executor_affinity,
    H2Dispatch post,
    H2DuplexClientConfig config,
    std::span<const std::byte> admission_key) {
    if (!executor_affinity.valid() || !post) {
        return Result<std::shared_ptr<H2DuplexCarrierProvider>>(
            Status::diagnostic(
                StatusCode::InvalidArgument,
                "H2 carrier provider requires an executor and valid affinity"));
    }
    if (admission_key.size() != kYtp1H2AdmissionKeyBytes ||
        config.server_port == 0U) {
        return Result<std::shared_ptr<H2DuplexCarrierProvider>>(
            Status::diagnostic(StatusCode::InvalidArgument,
                               "H2 carrier requires an exact 32-byte admission "
                               "key and nonzero port"));
    }
    const Status limits_status = validate_limits(config.limits);
    if (!limits_status.ok()) {
        return Result<std::shared_ptr<H2DuplexCarrierProvider>>(
            Status::diagnostic(limits_status.code(), limits_status.message()));
    }
    try {
        auto descriptor = make_descriptor();
        if (!descriptor.ok()) {
            return Result<std::shared_ptr<H2DuplexCarrierProvider>>(
                descriptor.status());
        }
        auto normalized = canonicalize_ytp1_h2_server_name(config.server_name);
        if (!normalized.has_value()) {
            return Result<std::shared_ptr<H2DuplexCarrierProvider>>(
                Status::diagnostic(
                    StatusCode::InvalidArgument,
                    "H2 carrier intended TLS server name is invalid"));
        }
        config.server_name = std::move(*normalized);
        auto owned_key = std::make_shared<AdmissionKey>(admission_key);
        return Result<std::shared_ptr<H2DuplexCarrierProvider>>(
            std::shared_ptr<H2DuplexCarrierProvider>(
                new H2DuplexCarrierProvider(
                    std::move(descriptor).take_value(), executor_affinity,
                    std::move(post), std::move(config), std::move(owned_key))));
    } catch (const std::bad_alloc&) {
        return Result<std::shared_ptr<H2DuplexCarrierProvider>>(
            Status::diagnostic(StatusCode::ResourceExhausted,
                               "H2 carrier provider allocation failed"));
    }
}

const ProviderDescriptor&
H2DuplexCarrierProvider::descriptor() const noexcept {
    return descriptor_;
}

void H2DuplexCarrierProvider::async_create(
    std::unique_ptr<SecureChannel> channel,
    EndpointRole local_role,
    CancellationToken cancellation,
    Completion completion) {
    std::shared_ptr<std::unique_ptr<SecureChannel>> owned_channel;
    std::shared_ptr<Completion> completion_holder;
    try {
        owned_channel = std::make_shared<std::unique_ptr<SecureChannel>>(
            std::move(channel));
        completion_holder =
            std::make_shared<Completion>(std::move(completion));
        const ProviderDescriptor descriptor = descriptor_;
        const ExecutorAffinity executor_affinity = executor_affinity_;
        const H2Dispatch post = dispatch_;
        H2DuplexClientConfig config = config_;
        if (trace_claimed_.exchange(true, std::memory_order_acq_rel)) {
            config.outer_trace.reset();
        }
        const auto admission_key = admission_key_;
        dispatch_.post([descriptor, executor_affinity, post, config, admission_key, owned_channel,
               local_role,
               cancellation = std::move(cancellation),
               completion_holder]() mutable {
            if (!*completion_holder) {
                if (*owned_channel) {
                    (*owned_channel)->close();
                }
                return;
            }
            if (local_role != EndpointRole::Client || !*owned_channel) {
                if (*owned_channel) {
                    (*owned_channel)->close();
                }
                Result<std::unique_ptr<Carrier>> result(Status::diagnostic(
                    StatusCode::InvalidArgument,
                    "H2 carrier provider creates client carriers only"));
                invoke_noexcept(*completion_holder, std::move(result));
                return;
            }
            if ((*owned_channel)->executor_affinity() !=
                executor_affinity) {
                (*owned_channel)->close();
                Result<std::unique_ptr<Carrier>> result(Status::diagnostic(
                    StatusCode::ProviderMismatch,
                    "H2 carrier and secure channel affinities differ"));
                invoke_noexcept(*completion_holder, std::move(result));
                return;
            }
            try {
                const auto reject = [&](Status failure) {
                    (*owned_channel)->close();
                    Result<std::unique_ptr<Carrier>> result(std::move(failure));
                    invoke_noexcept(*completion_holder, std::move(result));
                };
                if (cancellation.is_cancelled()) {
                    reject(Status::diagnostic(
                        StatusCode::Cancelled,
                        "H2 carrier creation was cancelled"));
                    return;
                }
                const auto& peer = (*owned_channel)->peer_evidence();
                if (!(*owned_channel)->descriptor().capabilities().contains(
                        engine::Capability::Tls13) ||
                    !peer.authenticated() || peer.peer_role() != EndpointRole::Server ||
                    canonicalize_ytp1_h2_server_name(peer.identity()) !=
                        std::optional<std::string>(config.server_name)) {
                    reject(Status::diagnostic(StatusCode::ProviderMismatch,
                                              "H2 carrier TLS evidence does "
                                              "not match the intended server"));
                    return;
                }
                auto exported = (*owned_channel)->export_keying_material(
                    kYtp1H2AdmissionExporterLabel, {}, kYtp1H2AdmissionExporterBytes);
                if (!exported.ok()) {
                    reject(exported.status());
                    return;
                }
                Buffer exporter = std::move(exported).take_value();
                struct ExporterWiper final {
                    Buffer& buffer;
                    ~ExporterWiper() noexcept {
                        OPENSSL_cleanse(buffer.mutable_bytes().data(), buffer.size());
                    }
                } exporter_wiper{exporter};
                if (exporter.size() != kYtp1H2AdmissionExporterBytes) {
                    reject(Status::diagnostic(
                        StatusCode::ProviderMismatch,
                        "H2 admission exporter returned an invalid length"));
                    return;
                }
                if (cancellation.is_cancelled()) {
                    reject(Status::diagnostic(
                        StatusCode::Cancelled,
                        "H2 carrier creation was cancelled"));
                    return;
                }
                const auto nonce = admission::random_nonce();
                if (!nonce.has_value()) {
                    reject(Status::diagnostic(
                        StatusCode::FailedPrecondition,
                        "H2 admission nonce generation failed"));
                    return;
                }
                auto path = build_ytp1_h2_admission_path(
                    admission_key->bytes, config.server_name, exporter.bytes(), *nonce);
                if (!path.has_value()) {
                    reject(Status::diagnostic(
                        StatusCode::FailedPrecondition,
                        "H2 admission proof generation failed"));
                    return;
                }
                if (cancellation.is_cancelled()) {
                    reject(Status::diagnostic(
                        StatusCode::Cancelled,
                        "H2 carrier creation was cancelled"));
                    return;
                }
                std::string authority = config.server_name;
                if (config.server_port != 443U) {
                    authority += ":" + std::to_string(config.server_port);
                }
                // The client TLS provider publishes a channel only after it
                // negotiated exactly h2.
                if (config.outer_trace) config.outer_trace->SetTlsAlpn("h2");
                auto h2 = std::make_unique<obfs::H2Carrier>(
                    obfs::H2CarrierRole::Client, config.outer_trace);
                auto state = std::make_shared<H2DuplexCarrierState>(
                    descriptor, executor_affinity, post, config.limits,
                    std::move(*owned_channel), std::move(h2));
                state->start_client(
                    std::move(authority), std::move(*path),
                    std::move(cancellation),
                    std::move(*completion_holder));
            } catch (const std::bad_alloc&) {
                if (*owned_channel) {
                    (*owned_channel)->close();
                }
                Result<std::unique_ptr<Carrier>> result(Status::diagnostic(
                    StatusCode::ResourceExhausted,
                    "H2 carrier creation allocation failed"));
                invoke_noexcept(*completion_holder, std::move(result));
            } catch (...) {
                if (*owned_channel) {
                    (*owned_channel)->close();
                }
                Result<std::unique_ptr<Carrier>> result(Status::diagnostic(
                    StatusCode::Internal, "H2 carrier creation threw"));
                invoke_noexcept(*completion_holder, std::move(result));
            }
        });
    } catch (const std::bad_alloc&) {
        if (owned_channel && *owned_channel) {
            (*owned_channel)->close();
        } else if (channel) {
            channel->close();
        }
        Result<std::unique_ptr<Carrier>> result(Status::diagnostic(
            StatusCode::ResourceExhausted,
            "H2 carrier creation dispatch allocation failed"));
        if (completion_holder) {
            invoke_noexcept(*completion_holder, std::move(result));
        } else {
            invoke_noexcept(completion, std::move(result));
        }
    } catch (...) {
        if (owned_channel && *owned_channel) {
            (*owned_channel)->close();
        } else if (channel) {
            channel->close();
        }
        Result<std::unique_ptr<Carrier>> result(Status::diagnostic(
            StatusCode::Internal, "H2 carrier executor rejected creation"));
        if (completion_holder) {
            invoke_noexcept(*completion_holder, std::move(result));
        } else {
            invoke_noexcept(completion, std::move(result));
        }
    }
}

ExecutorAffinity
H2DuplexCarrierProvider::executor_affinity() const noexcept {
    return executor_affinity_;
}

Result<std::unique_ptr<Carrier>> make_admitted_h2_duplex_server_carrier(
    std::unique_ptr<SecureChannel> channel,
    std::unique_ptr<obfs::H2Carrier> admitted_h2,
    ExecutorAffinity executor_affinity,
    H2Dispatch post,
    H2DuplexCarrierLimits limits,
    std::shared_ptr<H2CoverHandler> cover) {
    try {
        const Status limits_status = validate_limits(limits);
        if (!limits_status.ok()) {
            return Result<std::unique_ptr<Carrier>>(Status::diagnostic(
                limits_status.code(), limits_status.message()));
        }
        if (!channel || !admitted_h2 || !executor_affinity.valid() || !post) {
            return Result<std::unique_ptr<Carrier>>(
                Status::diagnostic(StatusCode::InvalidArgument,
                                   "admitted H2 carrier requires live typed "
                                   "state and an executor"));
        }
        if (channel->executor_affinity() != executor_affinity ||
            admitted_h2->role() != obfs::H2CarrierRole::Server ||
            !admitted_h2->carrier_active() || admitted_h2->carrier_closed() ||
            admitted_h2->failed()) {
            channel->close();
            return Result<std::unique_ptr<Carrier>>(Status::diagnostic(
                StatusCode::ProviderMismatch,
                "server H2 state is not a live admitted carrier"));
        }
        // YTP application records may exceed HTTP/2's 65,535-byte initial
        // per-stream window. Promotion expands the already-admitted carrier to
        // the configured receive window, at least 8 MiB. Otherwise a record
        // larger than the initial window could never reach ReceivedRecord and
        // its move-owned credit could never be released.
        if (!admitted_h2->EnableAdmittedReceiveWindow(
                limits.admitted_receive_window_bytes)) {
            channel->close();
            return Result<std::unique_ptr<Carrier>>(Status::diagnostic(
                StatusCode::FailedPrecondition,
                "failed to enable bounded admitted H2 receive credit"));
        }
        auto descriptor = make_descriptor();
        if (!descriptor.ok()) {
            channel->close();
            return Result<std::unique_ptr<Carrier>>(descriptor.status());
        }
        auto state = std::make_shared<H2DuplexCarrierState>(
            std::move(descriptor).take_value(), executor_affinity, post,
            limits, std::move(channel), std::move(admitted_h2), std::move(cover));
        std::unique_ptr<Carrier> carrier =
            std::make_unique<H2DuplexCarrier>(state);
        const auto dispatched = state->post([state] { state->start_admitted_server(); });
        if (dispatched != StatusCode::Ok) {
            state->request_close();
            return Result<std::unique_ptr<Carrier>>(Status::diagnostic(
                dispatched, "H2 carrier executor rejected admitted startup"));
        }
        return Result<std::unique_ptr<Carrier>>(std::move(carrier));
    } catch (const std::bad_alloc&) {
        if (channel) {
            channel->close();
        }
        return Result<std::unique_ptr<Carrier>>(
            Status::diagnostic(StatusCode::ResourceExhausted,
                               "admitted H2 carrier allocation failed"));
    }
}

Status validate_h2_duplex_carrier_limits(const H2DuplexCarrierLimits& limits) {
    return validate_limits(limits);
}

H2DuplexCarrierLimits h2_duplex_limits_for_budget(
    std::size_t session_budget_bytes) noexcept {
    H2DuplexCarrierLimits limits;
    const std::size_t window = std::max(
        2U * std::min(session_budget_bytes, kMaxH2DuplexSessionBudgetBytes),
        obfs::kAdmittedH2ReceiveWindowBytes);
    limits.admitted_receive_window_bytes = window;
    limits.max_retained_receive_bytes =
        std::max(limits.max_retained_receive_bytes, window);
    return limits;
}

}  // namespace yume::providers
