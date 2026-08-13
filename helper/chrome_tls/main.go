// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/sys/unix"
)

const (
	exporterLabel = "EXPORTER-yume/2.0/auth-channel-binding/v1"
	exporterBytes = 32
	maxCABytes    = 4 * 1024 * 1024
	connectedFD   = 3
	ipcFD         = 4
)

type exporterFunc func(utls.ConnectionState) ([]byte, error)

func exportChannelBinding(state utls.ConnectionState) ([]byte, error) {
	return state.ExportKeyingMaterial(exporterLabel, nil, exporterBytes)
}

func connectionFromFD(fd uintptr, name string) (net.Conn, error) {
	file := os.NewFile(fd, name)
	if file == nil {
		return nil, fmt.Errorf("invalid %s descriptor", name)
	}
	defer file.Close()
	connection, err := net.FileConn(file)
	if err != nil {
		return nil, fmt.Errorf("adopt %s descriptor: %w", name, err)
	}
	return connection, nil
}

func loadRootCAs(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open custom CA: %w", err)
	}
	defer file.Close()
	pemBytes, err := io.ReadAll(io.LimitReader(file, maxCABytes+1))
	if err != nil {
		return nil, fmt.Errorf("read custom CA: %w", err)
	}
	if len(pemBytes) > maxCABytes {
		return nil, errors.New("custom CA exceeds 4 MiB cap")
	}
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(pemBytes) {
		return nil, errors.New("custom CA contains no certificates")
	}
	return roots, nil
}

func validServerName(name string) bool {
	if net.ParseIP(name) != nil {
		return true
	}
	name = strings.TrimSuffix(name, ".")
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') &&
				(character < 'A' || character > 'Z') &&
				(character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

func readyPayload(buildID string, alpn string, leafHash [32]byte, exporter []byte) ([]byte, error) {
	payload, err := appendString16(nil, buildID)
	if err != nil {
		return nil, err
	}
	payload, err = appendString16(payload, alpn)
	if err != nil {
		return nil, err
	}
	payload = append(payload, leafHash[:]...)
	payload = append(payload, exporter...)
	return payload, nil
}

func proxyPlaintext(ipc net.Conn, tlsConnection *utls.UConn) error {
	type copyResult struct {
		direction string
		err       error
	}
	results := make(chan copyResult, 2)
	copyOne := func(destination io.Writer, source io.Reader, direction string) {
		buffer := make([]byte, 64*1024)
		_, err := io.CopyBuffer(destination, source, buffer)
		for index := range buffer {
			buffer[index] = 0
		}
		results <- copyResult{direction: direction, err: err}
	}
	go copyOne(tlsConnection, ipc, "parent-to-tls")
	go copyOne(ipc, tlsConnection, "tls-to-parent")
	first := <-results
	_ = tlsConnection.Close()
	_ = ipc.Close()
	second := <-results
	isExpectedClose := func(err error) bool {
		return err == nil || errors.Is(err, net.ErrClosed) ||
			errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) ||
			errors.Is(err, unix.EPIPE) ||
			errors.Is(err, unix.ECONNRESET)
	}
	if !isExpectedClose(first.err) {
		return fmt.Errorf("%s proxy: %w", first.direction, first.err)
	}
	if !isExpectedClose(second.err) {
		return fmt.Errorf("%s proxy: %w", second.direction, second.err)
	}
	return nil
}

func runWithConnectionsAndExporter(connected net.Conn, ipc net.Conn,
	exportExporter exporterFunc) error {
	_ = ipc.SetDeadline(time.Now().Add(15 * time.Second))
	header, request, err := readRequest(ipc)
	if err != nil {
		return err
	}
	profile, found := profileForBuildID(request.ExpectedBuildID)
	if !found {
		_ = writeError(ipc, header.ConnectionID, 1, "helper build identity mismatch")
		return errors.New("helper build identity mismatch")
	}
	if !validServerName(request.ServerName) {
		_ = writeError(ipc, header.ConnectionID, 2, "invalid TLS server name")
		return errors.New("invalid TLS server name")
	}
	roots, err := loadRootCAs(request.CAPath)
	if err != nil {
		_ = writeError(ipc, header.ConnectionID, 3, "custom CA load failed")
		return err
	}
	config := &utls.Config{
		ServerName: request.ServerName,
		RootCAs:    roots,
		MinVersion: utls.VersionTLS13,
		MaxVersion: utls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
	}
	tlsConnection := utls.UClient(connected, config, utls.HelloCustom)
	spec, err := profile.buildSpec()
	if err != nil {
		_ = writeError(ipc, header.ConnectionID, 4, "TLS profile failed")
		return err
	}
	if err := tlsConnection.ApplyPreset(spec); err != nil {
		_ = writeError(ipc, header.ConnectionID, 4, "apply TLS profile failed")
		return fmt.Errorf("apply %s profile: %w", profile.displayName, err)
	}
	timeout := time.Duration(request.TimeoutMillis) * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		_ = writeError(ipc, header.ConnectionID, 5, "TLS handshake or verification failed")
		return fmt.Errorf("TLS handshake: %w", err)
	}
	state := tlsConnection.ConnectionState()
	if state.Version != utls.VersionTLS13 {
		_ = writeError(ipc, header.ConnectionID, 6, "TLS 1.3 was not negotiated")
		return errors.New("TLS 1.3 was not negotiated")
	}
	if state.NegotiatedProtocol != "h2" {
		_ = writeError(ipc, header.ConnectionID, 7, "h2 ALPN was not negotiated")
		return fmt.Errorf("unexpected ALPN %q", state.NegotiatedProtocol)
	}
	if len(state.PeerCertificates) == 0 {
		_ = writeError(ipc, header.ConnectionID, 8, "peer sent no certificate")
		return errors.New("peer sent no certificate")
	}
	leafHash := sha256.Sum256(state.PeerCertificates[0].Raw)
	if len(request.LeafPin) != 0 && !bytes.Equal(request.LeafPin, leafHash[:]) {
		_ = writeError(ipc, header.ConnectionID, 9, "TLS leaf pin mismatch")
		return errors.New("TLS leaf pin mismatch")
	}
	exporter, err := exportExporter(state)
	if err != nil {
		_ = writeError(ipc, header.ConnectionID, 10, "TLS exporter failed")
		return fmt.Errorf("TLS exporter: %w", err)
	}
	defer func() {
		for index := range exporter {
			exporter[index] = 0
		}
	}()
	if len(exporter) != exporterBytes {
		_ = writeError(ipc, header.ConnectionID, 10, "TLS exporter failed")
		return fmt.Errorf("TLS exporter returned %d bytes", len(exporter))
	}
	payload, err := readyPayload(profile.buildID, state.NegotiatedProtocol, leafHash, exporter)
	if err != nil {
		return err
	}
	writeErr := writeMessage(ipc, messageReady, header.ConnectionID, payload)
	for index := range payload {
		payload[index] = 0
	}
	if writeErr != nil {
		return fmt.Errorf("send helper ready: %w", writeErr)
	}
	_ = ipc.SetDeadline(time.Time{})
	_ = connected.SetDeadline(time.Time{})
	return proxyPlaintext(ipc, tlsConnection)
}

func runWithConnections(connected net.Conn, ipc net.Conn) error {
	return runWithConnectionsAndExporter(connected, ipc, exportChannelBinding)
}

func run() error {
	if runtime.GOOS != "linux" {
		return errors.New("Chrome TLS helper supports Linux only")
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}
	connected, err := connectionFromFD(connectedFD, "connected TCP")
	if err != nil {
		return err
	}
	defer connected.Close()
	ipc, err := connectionFromFD(ipcFD, "private IPC")
	if err != nil {
		return err
	}
	defer ipc.Close()
	return runWithConnections(connected, ipc)
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		fmt.Printf("%s protocol=%d go=%s\n", buildID, protocolVersion, runtime.Version())
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: yume-chrome-tls-helper [--version]")
		os.Exit(2)
	}
	if err := run(); err != nil {
		// No detailed TLS verification error crosses IPC; stderr is inherited by
		// the parent for local diagnostics and contains no key material.
		fmt.Fprintln(os.Stderr, "yume-chrome-tls-helper:", err)
		os.Exit(1)
	}
}
