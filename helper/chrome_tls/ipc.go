// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	protocolVersion = uint16(1)
	messageRequest  = uint16(1)
	messageReady    = uint16(2)
	messageError    = uint16(3)
	maxPayloadBytes = 64 * 1024
	maxServerName   = 253
	maxCAPath       = 4096
)

var protocolMagic = [8]byte{'Y', 'U', 'M', 'E', 'T', 'L', 'S', 0}

type messageHeader struct {
	Magic        [8]byte
	Version      uint16
	Type         uint16
	PayloadBytes uint32
	ConnectionID [16]byte
}

type request struct {
	ExpectedBuildID string
	ServerName      string
	CAPath          string
	LeafPin         []byte
	TimeoutMillis   uint32
}

type decoder struct {
	data []byte
	off  int
}

func (d *decoder) take(size int) ([]byte, error) {
	if size < 0 || d.off > len(d.data) || size > len(d.data)-d.off {
		return nil, io.ErrUnexpectedEOF
	}
	value := d.data[d.off : d.off+size]
	d.off += size
	return value, nil
}

func (d *decoder) u8() (byte, error) {
	value, err := d.take(1)
	if err != nil {
		return 0, err
	}
	return value[0], nil
}

func (d *decoder) u16() (uint16, error) {
	value, err := d.take(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(value), nil
}

func (d *decoder) u32() (uint32, error) {
	value, err := d.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(value), nil
}

func (d *decoder) string16(maximum int) (string, error) {
	size, err := d.u16()
	if err != nil {
		return "", err
	}
	if int(size) > maximum {
		return "", fmt.Errorf("string length %d exceeds cap %d", size, maximum)
	}
	value, err := d.take(int(size))
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func readHeader(reader io.Reader) (messageHeader, error) {
	var header messageHeader
	if err := binary.Read(reader, binary.BigEndian, &header); err != nil {
		return header, err
	}
	if header.Magic != protocolMagic {
		return header, errors.New("invalid helper IPC magic")
	}
	if header.Version != protocolVersion {
		return header, fmt.Errorf("helper IPC version %d is unsupported", header.Version)
	}
	if header.PayloadBytes > maxPayloadBytes {
		return header, fmt.Errorf("helper IPC payload %d exceeds cap", header.PayloadBytes)
	}
	return header, nil
}

func readRequest(reader io.Reader) (messageHeader, request, error) {
	header, err := readHeader(reader)
	if err != nil {
		return header, request{}, err
	}
	if header.Type != messageRequest {
		return header, request{}, fmt.Errorf("unexpected helper IPC message type %d", header.Type)
	}
	payload := make([]byte, header.PayloadBytes)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return header, request{}, err
	}
	d := decoder{data: payload}
	buildID, err := d.string16(256)
	if err != nil {
		return header, request{}, fmt.Errorf("invalid expected build ID: %w", err)
	}
	serverName, err := d.string16(maxServerName)
	if err != nil {
		return header, request{}, fmt.Errorf("invalid server name: %w", err)
	}
	if serverName == "" {
		return header, request{}, errors.New("server name is empty")
	}
	caPath, err := d.string16(maxCAPath)
	if err != nil {
		return header, request{}, fmt.Errorf("invalid CA path: %w", err)
	}
	pinLength, err := d.u8()
	if err != nil {
		return header, request{}, err
	}
	if pinLength != 0 && pinLength != 32 {
		return header, request{}, errors.New("leaf pin must be empty or 32 bytes")
	}
	leafPin, err := d.take(int(pinLength))
	if err != nil {
		return header, request{}, err
	}
	timeoutMillis, err := d.u32()
	if err != nil {
		return header, request{}, err
	}
	if timeoutMillis < 1000 || timeoutMillis > 120000 {
		return header, request{}, errors.New("handshake timeout must be in 1000..120000 ms")
	}
	if d.off != len(d.data) {
		return header, request{}, errors.New("trailing request payload bytes")
	}
	return header, request{
		ExpectedBuildID: buildID,
		ServerName:      serverName,
		CAPath:          caPath,
		LeafPin:         append([]byte(nil), leafPin...),
		TimeoutMillis:   timeoutMillis,
	}, nil
}

func appendString16(output []byte, value string) ([]byte, error) {
	if len(value) > 65535 {
		return nil, errors.New("helper IPC string exceeds uint16")
	}
	output = binary.BigEndian.AppendUint16(output, uint16(len(value)))
	return append(output, value...), nil
}

func writeMessage(writer io.Writer, kind uint16, connectionID [16]byte,
	payload []byte) error {
	if len(payload) > maxPayloadBytes {
		return errors.New("helper IPC response exceeds cap")
	}
	header := messageHeader{
		Magic:        protocolMagic,
		Version:      protocolVersion,
		Type:         kind,
		PayloadBytes: uint32(len(payload)),
		ConnectionID: connectionID,
	}
	var wire bytes.Buffer
	if err := binary.Write(&wire, binary.BigEndian, header); err != nil {
		return err
	}
	wire.Write(payload)
	defer func() {
		encoded := wire.Bytes()
		for index := range encoded {
			encoded[index] = 0
		}
	}()
	remaining := wire.Bytes()
	for len(remaining) != 0 {
		written, err := writer.Write(remaining)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(remaining) {
			return io.ErrShortWrite
		}
		remaining = remaining[written:]
	}
	return nil
}

func writeError(writer io.Writer, connectionID [16]byte, code uint16,
	message string) error {
	if len(message) > 1024 {
		message = message[:1024]
	}
	payload := binary.BigEndian.AppendUint16(nil, code)
	var err error
	payload, err = appendString16(payload, message)
	if err != nil {
		return err
	}
	return writeMessage(writer, messageError, connectionID, payload)
}
