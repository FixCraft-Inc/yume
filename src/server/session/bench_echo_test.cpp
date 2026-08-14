#include "server/session/bench_echo.hpp"

#include <cassert>
#include <cstdint>
#include <vector>

namespace {

using yume::server::BenchEchoTransaction;

void ExactAdmissionIsRequired() {
    assert(BenchEchoTransaction::Create(
        BenchEchoTransaction::kRequiredBytes,
        BenchEchoTransaction::kRequiredMessageBytes));
    assert(!BenchEchoTransaction::Create(
        BenchEchoTransaction::kRequiredBytes - 1,
        BenchEchoTransaction::kRequiredMessageBytes));
    assert(!BenchEchoTransaction::Create(
        BenchEchoTransaction::kRequiredBytes,
        BenchEchoTransaction::kRequiredMessageBytes - 1));
}

void MessagesEchoInOrderAndCompleteExactly() {
    auto transaction = BenchEchoTransaction::Create(
        BenchEchoTransaction::kRequiredBytes,
        BenchEchoTransaction::kRequiredMessageBytes);
    assert(transaction);
    BenchEchoTransaction::Bytes reply;
    for (std::size_t message = 0; message < 64; ++message) {
        BenchEchoTransaction::Bytes payload(
            BenchEchoTransaction::kRequiredMessageBytes);
        for (std::size_t index = 0; index < payload.size(); ++index) {
            payload[index] = static_cast<std::uint8_t>(message + index);
        }
        assert(transaction->Accept(payload, &reply));
        assert(reply == payload);
        assert(transaction->complete() == (message == 63));
    }
    assert(transaction->received_bytes() ==
           BenchEchoTransaction::kRequiredBytes);
    assert(!transaction->Accept({0x01}, &reply));
}

void MalformedMessagesFailClosed() {
    BenchEchoTransaction::Bytes reply;
    auto empty = BenchEchoTransaction::Create(
        BenchEchoTransaction::kRequiredBytes,
        BenchEchoTransaction::kRequiredMessageBytes);
    assert(empty && !empty->Accept({}, &reply));

    auto oversized = BenchEchoTransaction::Create(
        BenchEchoTransaction::kRequiredBytes,
        BenchEchoTransaction::kRequiredMessageBytes);
    assert(oversized);
    assert(!oversized->Accept(
        BenchEchoTransaction::Bytes(
            BenchEchoTransaction::kRequiredMessageBytes + 1),
        &reply));

    auto undersized = BenchEchoTransaction::Create(
        BenchEchoTransaction::kRequiredBytes,
        BenchEchoTransaction::kRequiredMessageBytes);
    assert(undersized);
    assert(!undersized->Accept(
        BenchEchoTransaction::Bytes(
            BenchEchoTransaction::kRequiredMessageBytes - 1),
        &reply));
}

}  // namespace

int main() {
    ExactAdmissionIsRequired();
    MessagesEchoInOrderAndCompleteExactly();
    MalformedMessagesFailClosed();
    return 0;
}
