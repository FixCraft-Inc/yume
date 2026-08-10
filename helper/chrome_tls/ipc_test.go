// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"
)

type oneByteReader struct {
	reader io.Reader
}

func (r oneByteReader) Read(buffer []byte) (int, error) {
	if len(buffer) > 1 {
		buffer = buffer[:1]
	}
	return r.reader.Read(buffer)
}

type chunkWriter struct {
	buffer bytes.Buffer
	chunk  int
}

func (w *chunkWriter) Write(data []byte) (int, error) {
	if w.chunk == 0 {
		return 0, nil
	}
	if len(data) > w.chunk {
		data = data[:w.chunk]
	}
	return w.buffer.Write(data)
}

func encodedRequest(t *testing.T, mutate func(*messageHeader, *[]byte)) []byte {
	t.Helper()
	payload, err := appendString16(nil, buildID)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ = appendString16(payload, "localhost")
	payload, _ = appendString16(payload, "")
	payload = append(payload, 0)
	payload = binary.BigEndian.AppendUint32(payload, 12000)
	header := messageHeader{
		Magic: protocolMagic, Version: protocolVersion, Type: messageRequest,
		PayloadBytes: uint32(len(payload)),
	}
	if mutate != nil {
		mutate(&header, &payload)
		header.PayloadBytes = uint32(len(payload))
	}
	var wire bytes.Buffer
	if err := binary.Write(&wire, binary.BigEndian, header); err != nil {
		t.Fatal(err)
	}
	wire.Write(payload)
	return wire.Bytes()
}

func TestReadRequest(t *testing.T) {
	_, request, err := readRequest(bytes.NewReader(encodedRequest(t, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if request.ExpectedBuildID != buildID || request.ServerName != "localhost" ||
		request.TimeoutMillis != 12000 {
		t.Fatalf("unexpected request: %#v", request)
	}
}

func TestReadRequestHandlesPartialReads(t *testing.T) {
	wire := encodedRequest(t, nil)
	_, request, err := readRequest(oneByteReader{reader: bytes.NewReader(wire)})
	if err != nil {
		t.Fatal(err)
	}
	if request.ExpectedBuildID != buildID || request.ServerName != "localhost" {
		t.Fatalf("unexpected request: %#v", request)
	}
}

func TestReadRequestRejectsEveryTruncatedPrefix(t *testing.T) {
	wire := encodedRequest(t, nil)
	for size := 0; size < len(wire); size++ {
		_, _, err := readRequest(bytes.NewReader(wire[:size]))
		if err == nil {
			t.Fatalf("accepted truncated request of %d/%d bytes", size, len(wire))
		}
	}
}

func TestReadRequestRejectsTrailingBytes(t *testing.T) {
	wire := encodedRequest(t, func(_ *messageHeader, payload *[]byte) {
		*payload = append(*payload, 0)
	})
	_, _, err := readRequest(bytes.NewReader(wire))
	if err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("expected trailing-byte error, got %v", err)
	}
}

func TestReadRequestRejectsOversizeHeaderBeforeAllocation(t *testing.T) {
	wire := encodedRequest(t, nil)
	binary.BigEndian.PutUint32(wire[12:16], maxPayloadBytes+1)
	_, _, err := readRequest(bytes.NewReader(wire))
	if err == nil || !strings.Contains(err.Error(), "exceeds cap") {
		t.Fatalf("expected payload cap error, got %v", err)
	}
}

func TestReadRequestRejectsInvalidHeaderFields(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func([]byte)
		expected string
	}{
		{
			name: "magic",
			mutate: func(wire []byte) {
				wire[0] ^= 1
			},
			expected: "magic",
		},
		{
			name: "version",
			mutate: func(wire []byte) {
				binary.BigEndian.PutUint16(wire[8:10], protocolVersion+1)
			},
			expected: "unsupported",
		},
		{
			name: "type",
			mutate: func(wire []byte) {
				binary.BigEndian.PutUint16(wire[10:12], messageReady)
			},
			expected: "message type",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wire := append([]byte(nil), encodedRequest(t, nil)...)
			test.mutate(wire)
			_, _, err := readRequest(bytes.NewReader(wire))
			if err == nil || !strings.Contains(err.Error(), test.expected) {
				t.Fatalf("expected %q error, got %v", test.expected, err)
			}
		})
	}
}

func TestReadRequestRejectsInvalidSemanticFields(t *testing.T) {
	t.Run("empty server name", func(t *testing.T) {
		wire := encodedRequest(t, nil)
		serverLengthOffset := 32 + 2 + len(buildID)
		binary.BigEndian.PutUint16(wire[serverLengthOffset:serverLengthOffset+2], 0)
		_, _, err := readRequest(bytes.NewReader(wire))
		if err == nil || !strings.Contains(err.Error(), "server name is empty") {
			t.Fatalf("expected empty-server-name error, got %v", err)
		}
	})

	t.Run("invalid leaf pin length", func(t *testing.T) {
		wire := encodedRequest(t, nil)
		pinLengthOffset := 32 + 2 + len(buildID) + 2 + len("localhost") + 2
		wire[pinLengthOffset] = 31
		_, _, err := readRequest(bytes.NewReader(wire))
		if err == nil || !strings.Contains(err.Error(), "leaf pin") {
			t.Fatalf("expected leaf-pin error, got %v", err)
		}
	})

	for _, timeout := range []uint32{999, 120001} {
		t.Run("invalid timeout", func(t *testing.T) {
			wire := encodedRequest(t, nil)
			binary.BigEndian.PutUint32(wire[len(wire)-4:], timeout)
			_, _, err := readRequest(bytes.NewReader(wire))
			if err == nil || !strings.Contains(err.Error(), "timeout") {
				t.Fatalf("expected timeout error, got %v", err)
			}
		})
	}
}

func TestWriteMessageHandlesPartialWrites(t *testing.T) {
	connectionID := [16]byte{0x42}
	payload := []byte("payload")
	writer := &chunkWriter{chunk: 1}
	if err := writeMessage(writer, messageReady, connectionID, payload); err != nil {
		t.Fatal(err)
	}
	header, err := readHeader(&writer.buffer)
	if err != nil {
		t.Fatal(err)
	}
	if header.Type != messageReady || header.ConnectionID != connectionID ||
		header.PayloadBytes != uint32(len(payload)) {
		t.Fatalf("unexpected header: %#v", header)
	}
	encodedPayload, err := io.ReadAll(&writer.buffer)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encodedPayload, payload) {
		t.Fatalf("payload mismatch: %q", encodedPayload)
	}
}

func TestWriteMessageRejectsZeroLengthWrite(t *testing.T) {
	writer := &chunkWriter{}
	err := writeMessage(writer, messageReady, [16]byte{}, []byte("payload"))
	if err == nil || !strings.Contains(err.Error(), io.ErrShortWrite.Error()) {
		t.Fatalf("expected short-write error, got %v", err)
	}
}

func TestWriteMessageRejectsOversizedPayload(t *testing.T) {
	err := writeMessage(io.Discard, messageReady, [16]byte{},
		make([]byte, maxPayloadBytes+1))
	if err == nil || !strings.Contains(err.Error(), "exceeds cap") {
		t.Fatalf("expected payload-cap error, got %v", err)
	}
}

func TestWriteErrorBoundsMessage(t *testing.T) {
	writer := &chunkWriter{chunk: 3}
	if err := writeError(writer, [16]byte{0x42}, 9, strings.Repeat("x", 2048)); err != nil {
		t.Fatal(err)
	}
	header, err := readHeader(&writer.buffer)
	if err != nil {
		t.Fatal(err)
	}
	if header.Type != messageError {
		t.Fatalf("unexpected response type: %d", header.Type)
	}
	payload := make([]byte, header.PayloadBytes)
	if _, err := io.ReadFull(&writer.buffer, payload); err != nil {
		t.Fatal(err)
	}
	decoder := decoder{data: payload}
	code, err := decoder.u16()
	if err != nil {
		t.Fatal(err)
	}
	message, err := decoder.string16(1024)
	if err != nil {
		t.Fatal(err)
	}
	if code != 9 || len(message) != 1024 || decoder.off != len(payload) {
		t.Fatalf("unexpected bounded error: code=%d length=%d", code, len(message))
	}
}

func TestValidServerName(t *testing.T) {
	tests := []struct {
		name  string
		valid bool
	}{
		{name: "localhost", valid: true},
		{name: "example.com.", valid: true},
		{name: "127.0.0.1", valid: true},
		{name: "::1", valid: true},
		{name: "", valid: false},
		{name: ".", valid: false},
		{name: "-example.com", valid: false},
		{name: "example-.com", valid: false},
		{name: "example..com", valid: false},
		{name: "example_com", valid: false},
		{name: strings.Repeat("a", 64) + ".com", valid: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validServerName(test.name); got != test.valid {
				t.Fatalf("validServerName(%q)=%v, want %v", test.name, got, test.valid)
			}
		})
	}
}
