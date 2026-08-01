// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

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
