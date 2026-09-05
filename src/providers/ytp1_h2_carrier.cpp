/*
 * YUME - Yume Universal Multiprotocol Engine
 * Copyright (C) 2026  FixCraft Inc.
 * Licensed under the GNU Affero General Public License v3.0 or later.
 */

#include "providers/ytp1_h2_carrier.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <limits>
#include <new>
#include <optional>
#include <span>
#include <string>
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
constexpr std::size_t kMaxAuthorityBytes = 253U;
constexpr std::size_t kMaxCarrierPathBytes = 2048U;

template <typename Callback, typename... Args>
void invoke_noexcept(Callback& callback, Args&&... args) noexcept {
    if (!callback) {
        return;
    }
    try {
        callback(std::forward<Args>(args)...);
    } catch (...) {
        // Provider callbacks are containment boundaries. State is settled
        // before invocation, so application exceptions cannot corrupt it.
    }
}

bool valid_visible_text(std::string_view value,
                        std::size_t max_size) noexcept {
    return !value.empty() && value.size() <= max_size &&
        std::all_of(value.begin(), value.end(), [](unsigned char byte) {
            return byte >= 0x21U && byte <= 0x7eU;
        });
}

Status validate_limits(const Ytp1H2CarrierLimits& limits) {
    const bool framed_record_fits =
        limits.max_record_bytes <=
        obfs::kAdmittedH2ReceiveWindowBytes -
            kYtp1H2CarrierEnvelopeBytes;
    const bool retained_record_fits =
        limits.max_record_bytes <=
        std::numeric_limits<std::size_t>::max() -
            kYtp1H2CarrierEnvelopeBytes &&
        limits.max_retained_receive_bytes >=
            limits.max_record_bytes + kYtp1H2CarrierEnvelopeBytes;
    if (limits.max_record_bytes == 0U ||
        limits.max_record_bytes > engine::kAbsoluteMaxBufferBytes ||
        !framed_record_fits ||
        limits.max_buffered_records == 0U ||
        !retained_record_fits ||
        limits.max_retained_receive_bytes > 32U * 1024U * 1024U ||
        limits.max_pending_secure_write_bytes == 0U ||
        limits.max_pending_secure_write_bytes > 32U * 1024U * 1024U ||
        limits.secure_read_bytes == 0U ||
        limits.secure_read_bytes > engine::kAbsoluteMaxBufferBytes) {
        return Status(
            StatusCode::InvalidArgument,
            "H2 carrier limits are zero, inconsistent, or exceed hard bounds");
    }
    if (limits.max_record_bytes >
        std::numeric_limits<std::uint32_t>::max()) {
        return Status(StatusCode::InvalidArgument,
                      "H2 carrier record limit exceeds its wire field");
    }
    return Status::success();
}

Result<ProviderDescriptor> make_descriptor() {
    return ProviderDescriptor::create(
        std::string(kYtp1H2CarrierProviderId), ProviderKind::Carrier,
        kYtp1H2CarrierProviderApiVersion,
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

class Ytp1H2CarrierState;

class Ytp1H2Carrier final : public Carrier {
public:
    explicit Ytp1H2Carrier(
        std::shared_ptr<Ytp1H2CarrierState> state) noexcept
        : state_(std::move(state)) {}
    ~Ytp1H2Carrier() noexcept override;

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
    std::shared_ptr<Ytp1H2CarrierState> state_;
};

class Ytp1H2CarrierState final
    : public std::enable_shared_from_this<Ytp1H2CarrierState> {
public:
    Ytp1H2CarrierState(
        ProviderDescriptor descriptor,
        ExecutorAffinity affinity,
        Ytp1H2PostHandler post,
        Ytp1H2CarrierLimits limits,
        std::unique_ptr<SecureChannel> channel,
        std::unique_ptr<obfs::H2Carrier> h2) noexcept
        : descriptor_(std::move(descriptor)),
          affinity_(affinity),
          post_(std::move(post)),
          limits_(limits),
          channel_(std::move(channel)),
          h2_(std::move(h2)) {}

    const ProviderDescriptor& descriptor() const noexcept {
        return descriptor_;
    }
    ExecutorAffinity affinity() const noexcept { return affinity_; }
    std::size_t max_record_size() const noexcept {
        return limits_.max_record_bytes;
    }
    SecureChannel& channel() noexcept { return *channel_; }
    const SecureChannel& channel() const noexcept { return *channel_; }

    bool post(std::function<void()> task) noexcept {
        try {
            post_(std::move(task));
            return true;
        } catch (...) {
            return false;
        }
    }

    void start_client(std::string authority,
                      std::string carrier_path,
                      CancellationToken cancellation,
                      engine::CarrierProvider::Completion completion) {
        if (terminal_) {
            complete_create(
                completion,
                Status(StatusCode::Closed, "H2 carrier is already closed"));
            return;
        }
        opening_ = true;
        authority_ = std::move(authority);
        carrier_path_ = std::move(carrier_path);
        create_completion_ = std::move(completion);

        const std::weak_ptr<Ytp1H2CarrierState> weak = weak_from_this();
        auto registration = cancellation.register_callback([weak] {
            if (auto self = weak.lock()) {
                self->post([weak] {
                    if (auto current = weak.lock()) {
                        current->fail(Status(
                            StatusCode::Cancelled,
                            "H2 carrier creation was cancelled"));
                    }
                });
            }
        });
        if (!registration.ok()) {
            fail(registration.status());
            return;
        }
        create_cancellation_ = std::move(registration).take_value();
        if (cancellation.is_cancelled()) {
            fail(Status(StatusCode::Cancelled,
                        "H2 carrier creation was cancelled"));
            return;
        }

        try {
            if (!h2_->StartClient(authority_)) {
                fail(h2_failure("start HTTP/2 client"));
                return;
            }
            pump();
        } catch (const std::bad_alloc&) {
            fail(Status(StatusCode::ResourceExhausted,
                        "H2 carrier creation allocation failed"));
        } catch (...) {
            fail(Status(StatusCode::Internal,
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
            fail(Status(StatusCode::ResourceExhausted,
                        "admitted H2 carrier allocation failed"));
        } catch (...) {
            fail(Status(StatusCode::Internal,
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
            Result<ReceivedRecord> result(Status(
                StatusCode::ResourceExhausted,
                "H2 receive-dispatch allocation failed"));
            invoke_noexcept(completion, std::move(result));
            return;
        }
        if (!post([self, cancellation = std::move(cancellation),
                   completion_holder]() mutable {
                self->begin_receive(std::move(cancellation),
                                    std::move(*completion_holder));
            })) {
            Result<ReceivedRecord> result(Status(
                StatusCode::Internal, "H2 carrier executor rejected receive"));
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
            invoke_noexcept(
                completion_holder ? *completion_holder : completion,
                Status(StatusCode::ResourceExhausted,
                       "H2 carrier send-dispatch allocation failed"),
                0U);
            return;
        }
        if (!post([self, owned_record,
                   cancellation = std::move(cancellation),
                   completion_holder]() mutable {
                self->begin_send(
                    std::move(**owned_record), std::move(cancellation),
                    std::move(*completion_holder));
                owned_record->reset();
            })) {
            invoke_noexcept(
                *completion_holder,
                Status(StatusCode::Internal,
                       "H2 carrier executor rejected send"),
                0U);
        }
    }

    void request_cancel() noexcept {
        const auto self = shared_from_this();
        // State is executor-confined, so there is no safe inline fallback.
        // The public post-handler contract requires accepted carrier lifetime
        // work to be serialized and never rejected or silently discarded.
        (void)post([self] {
            self->fail(Status(StatusCode::Cancelled,
                              "H2 carrier was cancelled"));
        });
    }

    void request_close() noexcept {
        const auto self = shared_from_this();
        // See request_cancel(): an off-affinity close would race carrier state,
        // and rejecting lifetime work already violates the provider contract.
        (void)post([self] {
            self->fail(Status(StatusCode::Closed,
                              "H2 carrier was closed"));
        });
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
    };

    struct PendingSend {
        std::uint64_t id{0U};
        std::size_t record_bytes{0U};
        Carrier::SendCompletion completion;
        CancellationRegistration cancellation;
    };

    Status h2_failure(std::string_view operation) const {
        std::string message(operation);
        if (!h2_->error().empty()) {
            message += ": ";
            message += h2_->error();
        }
        return Status(StatusCode::FailedPrecondition, message);
    }

    static void complete_create(engine::CarrierProvider::Completion& completion,
                                Status status) noexcept {
        Result<std::unique_ptr<Carrier>> result(std::move(status));
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
            fail(Status(StatusCode::FailedPrecondition,
                        "HTTP/2 peer rejected the carrier stream"));
        }
    }

    void begin_receive(CancellationToken cancellation,
                       Carrier::ReceiveCompletion completion) {
        if (!completion) {
            return;
        }
        if (terminal_) {
            Result<ReceivedRecord> result(terminal_status_);
            invoke_noexcept(completion, std::move(result));
            return;
        }
        if (pending_receive_.has_value()) {
            Result<ReceivedRecord> result(Status(
                StatusCode::AlreadyExists,
                "H2 carrier already has a pending receive"));
            invoke_noexcept(completion, std::move(result));
            return;
        }
        if (cancellation.is_cancelled()) {
            Result<ReceivedRecord> result(Status(
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
            Result<ReceivedRecord> result(Status(
                StatusCode::Closed, "HTTP/2 carrier peer closed"));
            invoke_noexcept(completion, std::move(result));
            return;
        }
        if (next_operation_id_ == std::numeric_limits<std::uint64_t>::max()) {
            fail(Status(StatusCode::ResourceExhausted,
                        "H2 carrier operation IDs are exhausted"));
            Result<ReceivedRecord> result(terminal_status_);
            invoke_noexcept(completion, std::move(result));
            return;
        }
        const std::uint64_t id = next_operation_id_++;
        pending_receive_.emplace(
            PendingReceive{id, std::move(completion), {}});
        const std::weak_ptr<Ytp1H2CarrierState> weak = weak_from_this();
        auto registration = cancellation.register_callback([weak, id] {
            if (auto self = weak.lock()) {
                self->post([weak, id] {
                    if (auto current = weak.lock()) {
                        current->cancel_receive(id);
                    }
                });
            }
        });
        if (!registration.ok()) {
            Carrier::ReceiveCompletion failed =
                std::move(pending_receive_->completion);
            pending_receive_.reset();
            Result<ReceivedRecord> result(registration.status());
            invoke_noexcept(failed, std::move(result));
            return;
        }
        if (pending_receive_.has_value() && pending_receive_->id == id) {
            pending_receive_->cancellation =
                std::move(registration).take_value();
        }
        pump();
    }

    void cancel_receive(std::uint64_t id) noexcept {
        if (!pending_receive_.has_value() || pending_receive_->id != id) {
            return;
        }
        Carrier::ReceiveCompletion completion =
            std::move(pending_receive_->completion);
        pending_receive_.reset();
        Result<ReceivedRecord> result(Status(
            StatusCode::Cancelled, "H2 carrier receive was cancelled"));
        invoke_noexcept(completion, std::move(result));
    }

    void begin_send(Buffer record,
                    CancellationToken cancellation,
                    Carrier::SendCompletion completion) {
        if (!completion) {
            return;
        }
        if (terminal_) {
            invoke_noexcept(completion, terminal_status_, 0U);
            return;
        }
        if (peer_closed_ || !h2_->carrier_active()) {
            invoke_noexcept(
                completion,
                Status(StatusCode::Closed, "HTTP/2 carrier is not active"),
                0U);
            return;
        }
        if (pending_send_.has_value()) {
            invoke_noexcept(
                completion,
                Status(StatusCode::AlreadyExists,
                       "H2 carrier already has a pending send"),
                0U);
            return;
        }
        if (record.empty() || record.size() > limits_.max_record_bytes) {
            invoke_noexcept(
                completion,
                Status(StatusCode::ResourceExhausted,
                       "H2 carrier record is empty or exceeds its bound"),
                0U);
            return;
        }
        if (cancellation.is_cancelled()) {
            invoke_noexcept(
                completion,
                Status(StatusCode::Cancelled,
                       "H2 carrier send was cancelled"),
                0U);
            return;
        }
        if (next_operation_id_ == std::numeric_limits<std::uint64_t>::max()) {
            fail(Status(StatusCode::ResourceExhausted,
                        "H2 carrier operation IDs are exhausted"));
            invoke_noexcept(completion, terminal_status_, 0U);
            return;
        }

        const std::uint64_t id = next_operation_id_++;
        const std::size_t record_bytes = record.size();
        pending_send_.emplace(
            PendingSend{id, record_bytes, std::move(completion), {}});
        const std::weak_ptr<Ytp1H2CarrierState> weak = weak_from_this();
        auto registration = cancellation.register_callback([weak, id] {
            if (auto self = weak.lock()) {
                self->post([weak, id] {
                    if (auto current = weak.lock()) {
                        current->cancel_send(id);
                    }
                });
            }
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

        try {
            std::vector<std::uint8_t> framed(
                kYtp1H2CarrierEnvelopeBytes + record_bytes);
            std::copy(kCarrierMagic.begin(), kCarrierMagic.end(),
                      framed.begin());
            framed[4] = kCarrierEnvelopeVersion;
            framed[5] = 0U;
            framed[6] = 0U;
            framed[7] = 0U;
            write_be32(framed.data() + 8,
                       static_cast<std::uint32_t>(record_bytes));
            std::memcpy(framed.data() + kYtp1H2CarrierEnvelopeBytes,
                        record.bytes().data(), record_bytes);
            if (!h2_->SendBinary(framed)) {
                fail(h2_failure("queue H2 carrier record"));
                return;
            }
            pump();
        } catch (const std::bad_alloc&) {
            fail(Status(StatusCode::ResourceExhausted,
                        "H2 carrier send allocation failed"));
        } catch (...) {
            fail(Status(StatusCode::Internal, "H2 carrier send threw"));
        }
    }

    void cancel_send(std::uint64_t id) noexcept {
        if (!pending_send_.has_value() || pending_send_->id != id) {
            return;
        }
        // A record may already be partly serialized or written. Continuing
        // would let the next record inherit an ambiguous byte stream, so send
        // cancellation is terminal for this carrier.
        fail(Status(StatusCode::Cancelled,
                    "H2 carrier send was cancelled"));
    }

    void deliver_record(Carrier::ReceiveCompletion completion) {
        if (records_.empty()) {
            return;
        }
        QueuedRecord record = std::move(records_.front());
        records_.pop_front();
        queued_record_bytes_ -= record.payload.size();
        const std::size_t credit_bytes = record.credit_bytes;
        const std::weak_ptr<Ytp1H2CarrierState> weak = weak_from_this();
        CarrierCredit credit(
            credit_bytes,
            [weak](std::size_t bytes) {
                if (auto self = weak.lock()) {
                    self->post([weak, bytes] {
                        if (auto current = weak.lock()) {
                            current->return_credit(bytes);
                        }
                    });
                }
            });
        Result<ReceivedRecord> result(ReceivedRecord(
            std::move(record.payload), std::move(credit)));
        invoke_noexcept(completion, std::move(result));
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
            fail(Status(StatusCode::Internal,
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
        if (header.size() != kYtp1H2CarrierEnvelopeBytes ||
            !std::equal(kCarrierMagic.begin(), kCarrierMagic.end(),
                        header.begin()) ||
            header[4] != kCarrierEnvelopeVersion || header[5] != 0U ||
            header[6] != 0U || header[7] != 0U) {
            fail(Status(StatusCode::InvalidArgument,
                        "malformed H2-duplex carrier record envelope"));
            return false;
        }
        const std::uint32_t payload_length = read_be32(header.data() + 8);
        if (payload_length == 0U ||
            payload_length > limits_.max_record_bytes) {
            fail(Status(StatusCode::ResourceExhausted,
                        "H2-duplex carrier record length exceeds its bound"));
            return false;
        }
        expected_payload_bytes_ = payload_length;
        if (!h2_->ConsumeTunnelBytes(kYtp1H2CarrierEnvelopeBytes)) {
            fail(h2_failure("retire H2 carrier envelope credit"));
            return false;
        }
        if (owned_credit_bytes_ < kYtp1H2CarrierEnvelopeBytes) {
            fail(Status(StatusCode::Internal,
                        "H2 carrier envelope credit ledger underflow"));
            return false;
        }
        owned_credit_bytes_ -= kYtp1H2CarrierEnvelopeBytes;
        input_offset_ += kYtp1H2CarrierEnvelopeBytes;
        return true;
    }

    void parse_records() {
        while (!terminal_) {
            compact_input();
            std::span<const std::uint8_t> available = retained_input();
            if (!expected_payload_bytes_.has_value()) {
                if (records_.size() >= limits_.max_buffered_records ||
                    available.size() < kYtp1H2CarrierEnvelopeBytes) {
                    return;
                }
                if (!parse_record_header(
                        available.first(kYtp1H2CarrierEnvelopeBytes))) {
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
                fail(Status(StatusCode::ResourceExhausted,
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
        if (owned_credit_bytes_ > limits_.max_retained_receive_bytes ||
            decoded.size() > limits_.max_retained_receive_bytes -
                                 owned_credit_bytes_) {
            fail(Status(StatusCode::ResourceExhausted,
                        "H2 carrier retained receive credit exceeded its bound"));
            return;
        }
        compact_input();
        const std::size_t retained = input_.size() - input_offset_;
        if (decoded.size() > limits_.max_retained_receive_bytes - retained) {
            fail(Status(StatusCode::ResourceExhausted,
                        "H2 carrier input accumulation exceeded its bound"));
            return;
        }
        input_.insert(input_.end(), decoded.begin(), decoded.end());
        owned_credit_bytes_ += decoded.size();
        parse_records();
    }

    bool can_read() const noexcept {
        return !terminal_ && !peer_closed_ && !read_in_flight_ &&
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
            fail(Status(StatusCode::ProviderMismatch,
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
                        self->fail(Status(
                            StatusCode::ResourceExhausted,
                            "H2 carrier read allocation failed"));
                    } catch (...) {
                        self->fail(Status(StatusCode::Internal,
                                          "H2 carrier read callback threw"));
                    }
                });
        } catch (...) {
            read_in_flight_ = false;
            fail(Status(StatusCode::Internal,
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
        if (!result.ok()) {
            fail(result.status());
            return;
        }
        Buffer plaintext = std::move(result).take_value();
        if (plaintext.empty()) {
            fail(Status(StatusCode::Closed,
                        "secure channel returned an empty read"));
            return;
        }
        const auto bytes = plaintext.bytes();
        h2_->Feed(reinterpret_cast<const std::uint8_t*>(bytes.data()),
                  bytes.size());
        if (h2_->failed()) {
            fail(h2_failure("parse HTTP/2 plaintext"));
            return;
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
        obfs::H2Bytes wire = h2_->TakeOutbound();
        if (h2_->failed()) {
            fail(h2_failure("serialize HTTP/2 output"));
            return;
        }
        if (wire.empty()) {
            return;
        }
        if (pending_secure_write_bytes_ >
                limits_.max_pending_secure_write_bytes ||
            wire.size() > limits_.max_pending_secure_write_bytes -
                              pending_secure_write_bytes_) {
            fail(Status(StatusCode::ResourceExhausted,
                        "H2 secure-write queue exceeded its byte bound"));
            return;
        }
        const std::size_t channel_limit = channel_->max_write_size();
        if (channel_limit == 0U) {
            fail(Status(StatusCode::ProviderMismatch,
                        "secure channel declares a zero write bound"));
            return;
        }
        std::deque<Buffer> admitted;
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
        while (!admitted.empty()) {
            secure_writes_.push_back(std::move(admitted.front()));
            admitted.pop_front();
        }
        pending_secure_write_bytes_ += wire.size();
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
                    } catch (...) {
                        self->fail(Status(StatusCode::Internal,
                                          "H2 carrier write callback threw"));
                    }
                });
        } catch (...) {
            write_in_flight_ = false;
            fail(Status(StatusCode::Internal,
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
            fail(Status(StatusCode::Internal,
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
        parse_records();
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
    }

    void handle_peer_close() {
        if (terminal_ || peer_closed_) {
            return;
        }
        compact_input();
        if (expected_payload_bytes_.has_value() || !retained_input().empty()) {
            fail(Status(StatusCode::InvalidArgument,
                        "HTTP/2 carrier closed with a truncated record"));
            return;
        }
        peer_closed_ = true;
        if (pending_send_.has_value()) {
            Carrier::SendCompletion completion =
                std::move(pending_send_->completion);
            pending_send_.reset();
            invoke_noexcept(
                completion,
                Status(StatusCode::Closed, "HTTP/2 carrier peer closed"),
                0U);
        }
        maybe_deliver_pending_receive();
        if (pending_receive_.has_value() && records_.empty()) {
            Carrier::ReceiveCompletion completion =
                std::move(pending_receive_->completion);
            pending_receive_.reset();
            Result<ReceivedRecord> result(Status(
                StatusCode::Closed, "HTTP/2 carrier peer closed"));
            invoke_noexcept(completion, std::move(result));
        }
        channel_->close();
    }

    void fail(Status status) noexcept {
        if (terminal_) {
            return;
        }
        terminal_ = true;
        terminal_status_ = status.ok()
            ? Status(StatusCode::Internal,
                     "H2 carrier failed without an error status")
            : std::move(status);
        transport_cancellation_.cancel();
        create_cancellation_.unregister();

        engine::CarrierProvider::Completion create =
            std::move(create_completion_);
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
            Result<ReceivedRecord> result(terminal_status_);
            invoke_noexcept(receive, std::move(result));
        }
        if (send) {
            invoke_noexcept(send, terminal_status_, 0U);
        }
    }

    ProviderDescriptor descriptor_;
    ExecutorAffinity affinity_;
    Ytp1H2PostHandler post_;
    Ytp1H2CarrierLimits limits_;
    std::unique_ptr<SecureChannel> channel_;
    std::unique_ptr<obfs::H2Carrier> h2_;
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
    Status terminal_status_{StatusCode::Closed, "H2 carrier is closed"};

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
};

Ytp1H2Carrier::~Ytp1H2Carrier() noexcept {
    state_->request_close();
}

const ProviderDescriptor& Ytp1H2Carrier::descriptor() const noexcept {
    return state_->descriptor();
}

ExecutorAffinity Ytp1H2Carrier::executor_affinity() const noexcept {
    return state_->affinity();
}

std::size_t Ytp1H2Carrier::max_record_size() const noexcept {
    return state_->max_record_size();
}

SecureChannel& Ytp1H2Carrier::secure_channel() noexcept {
    return state_->channel();
}

const SecureChannel& Ytp1H2Carrier::secure_channel() const noexcept {
    return state_->channel();
}

void Ytp1H2Carrier::async_receive(CancellationToken cancellation,
                                  ReceiveCompletion completion) {
    state_->async_receive(std::move(cancellation), std::move(completion));
}

void Ytp1H2Carrier::async_send(Buffer record,
                               CancellationToken cancellation,
                               SendCompletion completion) {
    state_->async_send(std::move(record), std::move(cancellation),
                       std::move(completion));
}

void Ytp1H2Carrier::cancel() noexcept {
    state_->request_cancel();
}

void Ytp1H2Carrier::close() noexcept {
    state_->request_close();
}

void Ytp1H2CarrierState::finish_client_opening() {
    if (!opening_ || terminal_) {
        return;
    }
    // Chrome's captured initial stream window is smaller than the maximum YTP
    // carrier record. The secure channel has authenticated the peer and the
    // peer has accepted the extended CONNECT, so admit bounded receive credit
    // before the YTP session handshake starts. This is carrier admission, not
    // YTP session authentication.
    if (!h2_->EnableAdmittedReceiveWindow()) {
        fail(h2_failure("expand admitted client receive credit"));
        return;
    }
    opening_ = false;
    create_cancellation_.unregister();
    engine::CarrierProvider::Completion completion =
        std::move(create_completion_);
    try {
        std::unique_ptr<Carrier> carrier =
            std::make_unique<Ytp1H2Carrier>(shared_from_this());
        Result<std::unique_ptr<Carrier>> result(std::move(carrier));
        invoke_noexcept(completion, std::move(result));
    } catch (const std::bad_alloc&) {
        const Status failure(StatusCode::ResourceExhausted,
                             "H2 carrier object allocation failed");
        complete_create(completion, failure);
        fail(failure);
    } catch (...) {
        const Status failure(StatusCode::Internal,
                             "H2 carrier object construction threw");
        complete_create(completion, failure);
        fail(failure);
    }
}

}  // namespace

Ytp1H2CarrierProvider::Ytp1H2CarrierProvider(
    ProviderDescriptor descriptor,
    ExecutorAffinity executor_affinity,
    Ytp1H2PostHandler post,
    Ytp1H2ClientConfig config) noexcept
    : descriptor_(std::move(descriptor)),
      executor_affinity_(executor_affinity),
      post_(std::move(post)),
      config_(std::move(config)) {}

Result<std::shared_ptr<Ytp1H2CarrierProvider>>
Ytp1H2CarrierProvider::create(
    ExecutorAffinity executor_affinity,
    Ytp1H2PostHandler post,
    Ytp1H2ClientConfig config) {
    if (!executor_affinity.valid() || !post) {
        return Result<std::shared_ptr<Ytp1H2CarrierProvider>>(Status(
            StatusCode::InvalidArgument,
            "H2 carrier provider requires an executor and valid affinity"));
    }
    if (!valid_visible_text(config.authority, kMaxAuthorityBytes) ||
        config.authority.find('/') != std::string::npos ||
        !valid_visible_text(config.carrier_path, kMaxCarrierPathBytes) ||
        config.carrier_path.front() != '/') {
        return Result<std::shared_ptr<Ytp1H2CarrierProvider>>(Status(
            StatusCode::InvalidArgument,
            "H2 carrier authority or path is invalid"));
    }
    const Status limits_status = validate_limits(config.limits);
    if (!limits_status.ok()) {
        return Result<std::shared_ptr<Ytp1H2CarrierProvider>>(limits_status);
    }
    auto descriptor = make_descriptor();
    if (!descriptor.ok()) {
        return Result<std::shared_ptr<Ytp1H2CarrierProvider>>(
            descriptor.status());
    }
    try {
        return Result<std::shared_ptr<Ytp1H2CarrierProvider>>(
            std::shared_ptr<Ytp1H2CarrierProvider>(
                new Ytp1H2CarrierProvider(
                    std::move(descriptor).take_value(), executor_affinity,
                    std::move(post), std::move(config))));
    } catch (const std::bad_alloc&) {
        return Result<std::shared_ptr<Ytp1H2CarrierProvider>>(Status(
            StatusCode::ResourceExhausted,
            "H2 carrier provider allocation failed"));
    }
}

const ProviderDescriptor&
Ytp1H2CarrierProvider::descriptor() const noexcept {
    return descriptor_;
}

void Ytp1H2CarrierProvider::async_create(
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
        const Ytp1H2PostHandler post = post_;
        const Ytp1H2ClientConfig config = config_;
        post_([descriptor, executor_affinity, post, config, owned_channel,
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
                Result<std::unique_ptr<Carrier>> result(Status(
                    StatusCode::InvalidArgument,
                    "H2 carrier provider creates client carriers only"));
                invoke_noexcept(*completion_holder, std::move(result));
                return;
            }
            if ((*owned_channel)->executor_affinity() !=
                executor_affinity) {
                (*owned_channel)->close();
                Result<std::unique_ptr<Carrier>> result(Status(
                    StatusCode::ProviderMismatch,
                    "H2 carrier and secure channel affinities differ"));
                invoke_noexcept(*completion_holder, std::move(result));
                return;
            }
            try {
                auto h2 = std::make_unique<obfs::H2Carrier>(
                    obfs::H2CarrierRole::Client);
                auto state = std::make_shared<Ytp1H2CarrierState>(
                    descriptor, executor_affinity, post, config.limits,
                    std::move(*owned_channel), std::move(h2));
                state->start_client(
                    config.authority, config.carrier_path,
                    std::move(cancellation),
                    std::move(*completion_holder));
            } catch (const std::bad_alloc&) {
                if (*owned_channel) {
                    (*owned_channel)->close();
                }
                Result<std::unique_ptr<Carrier>> result(Status(
                    StatusCode::ResourceExhausted,
                    "H2 carrier creation allocation failed"));
                invoke_noexcept(*completion_holder, std::move(result));
            } catch (...) {
                if (*owned_channel) {
                    (*owned_channel)->close();
                }
                Result<std::unique_ptr<Carrier>> result(Status(
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
        Result<std::unique_ptr<Carrier>> result(Status(
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
        Result<std::unique_ptr<Carrier>> result(Status(
            StatusCode::Internal, "H2 carrier executor rejected creation"));
        if (completion_holder) {
            invoke_noexcept(*completion_holder, std::move(result));
        } else {
            invoke_noexcept(completion, std::move(result));
        }
    }
}

ExecutorAffinity
Ytp1H2CarrierProvider::executor_affinity() const noexcept {
    return executor_affinity_;
}

const Ytp1H2ClientConfig&
Ytp1H2CarrierProvider::config() const noexcept {
    return config_;
}

Result<std::unique_ptr<Carrier>> make_ytp1_h2_admitted_server_carrier(
    std::unique_ptr<SecureChannel> channel,
    std::unique_ptr<obfs::H2Carrier> admitted_h2,
    ExecutorAffinity executor_affinity,
    Ytp1H2PostHandler post,
    Ytp1H2CarrierLimits limits) {
    const Status limits_status = validate_limits(limits);
    if (!limits_status.ok()) {
        return Result<std::unique_ptr<Carrier>>(limits_status);
    }
    if (!channel || !admitted_h2 || !executor_affinity.valid() || !post) {
        return Result<std::unique_ptr<Carrier>>(Status(
            StatusCode::InvalidArgument,
            "admitted H2 carrier requires live typed state and an executor"));
    }
    if (channel->executor_affinity() != executor_affinity ||
        admitted_h2->role() != obfs::H2CarrierRole::Server ||
        !admitted_h2->carrier_active() || admitted_h2->carrier_closed() ||
        admitted_h2->failed()) {
        channel->close();
        return Result<std::unique_ptr<Carrier>>(Status(
            StatusCode::ProviderMismatch,
            "server H2 state is not a live admitted carrier"));
    }
    // YTP application records may exceed HTTP/2's 65,535-byte initial
    // per-stream window. Promotion expands the already-admitted carrier to the
    // transport-v2 provider's fixed 8-MiB receive window; otherwise a record
    // larger than the initial window could never reach ReceivedRecord and its
    // move-owned credit could never be released.
    if (!admitted_h2->EnableAdmittedReceiveWindow()) {
        channel->close();
        return Result<std::unique_ptr<Carrier>>(Status(
            StatusCode::FailedPrecondition,
            "failed to enable bounded admitted H2 receive credit"));
    }
    auto descriptor = make_descriptor();
    if (!descriptor.ok()) {
        channel->close();
        return Result<std::unique_ptr<Carrier>>(descriptor.status());
    }
    try {
        auto state = std::make_shared<Ytp1H2CarrierState>(
            std::move(descriptor).take_value(), executor_affinity, post,
            limits, std::move(channel), std::move(admitted_h2));
        std::unique_ptr<Carrier> carrier =
            std::make_unique<Ytp1H2Carrier>(state);
        if (!state->post([state] { state->start_admitted_server(); })) {
            state->request_close();
            return Result<std::unique_ptr<Carrier>>(Status(
                StatusCode::Internal,
                "H2 carrier executor rejected admitted startup"));
        }
        return Result<std::unique_ptr<Carrier>>(std::move(carrier));
    } catch (const std::bad_alloc&) {
        if (channel) {
            channel->close();
        }
        return Result<std::unique_ptr<Carrier>>(Status(
            StatusCode::ResourceExhausted,
            "admitted H2 carrier allocation failed"));
    }
}

}  // namespace yume::providers
