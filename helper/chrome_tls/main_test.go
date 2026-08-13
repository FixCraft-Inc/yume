// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

type testPKI struct {
	certificate tls.Certificate
	rootPEM     []byte
	leafHash    [32]byte
}

func newTestPKI(t *testing.T, serverName string) testPKI {
	t.Helper()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "YUME helper test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(
		rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serverName},
		DNSNames:     []string{serverName},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(
		rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	return testPKI{
		certificate: tls.Certificate{
			Certificate: [][]byte{leafDER},
			PrivateKey:  leafKey,
		},
		rootPEM: pem.EncodeToMemory(&pem.Block{
			Type: "CERTIFICATE", Bytes: rootDER,
		}),
		leafHash: sha256.Sum256(leafDER),
	}
}

func writeTestCA(t *testing.T, name string, certificate []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func startTLSServer(t *testing.T, pki testPKI, alpn string,
	handler func(*tls.Conn) error) (net.Conn, <-chan error) {
	t.Helper()
	helperSide, serverSide := net.Pipe()
	done := make(chan error, 1)
	go func() {
		defer serverSide.Close()
		connection := tls.Server(serverSide, &tls.Config{
			Certificates: []tls.Certificate{pki.certificate},
			MinVersion:   tls.VersionTLS13,
			MaxVersion:   tls.VersionTLS13,
			NextProtos:   []string{alpn},
		})
		if err := connection.Handshake(); err != nil {
			done <- err
			return
		}
		if handler != nil {
			done <- handler(connection)
			return
		}
		_, err := io.Copy(io.Discard, connection)
		done <- err
	}()
	return helperSide, done
}

func encodeLiveRequest(t *testing.T, connectionID [16]byte,
	serverName, caPath string, leafPin []byte) []byte {
	t.Helper()
	payload, err := appendString16(nil, buildID)
	if err != nil {
		t.Fatal(err)
	}
	payload, err = appendString16(payload, serverName)
	if err != nil {
		t.Fatal(err)
	}
	payload, err = appendString16(payload, caPath)
	if err != nil {
		t.Fatal(err)
	}
	payload = append(payload, byte(len(leafPin)))
	payload = append(payload, leafPin...)
	payload = append(payload, 0, 0, 0x13, 0x88) // 5,000 ms
	var wire bytes.Buffer
	if err := writeMessage(&wire, messageRequest, connectionID, payload); err != nil {
		t.Fatal(err)
	}
	return wire.Bytes()
}

func readLiveResponse(t *testing.T, connection net.Conn) (messageHeader, []byte) {
	t.Helper()
	if err := connection.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	header, err := readHeader(connection)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, header.PayloadBytes)
	if _, err := io.ReadFull(connection, payload); err != nil {
		t.Fatal(err)
	}
	return header, payload
}

func decodeLiveError(t *testing.T, payload []byte) (uint16, string) {
	t.Helper()
	decoder := decoder{data: payload}
	code, err := decoder.u16()
	if err != nil {
		t.Fatal(err)
	}
	message, err := decoder.string16(1024)
	if err != nil {
		t.Fatal(err)
	}
	if decoder.off != len(payload) {
		t.Fatal("trailing helper error payload")
	}
	return code, message
}

func waitTestResult(t *testing.T, name string, result <-chan error) error {
	t.Helper()
	select {
	case err := <-result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not terminate", name)
		return nil
	}
}

func TestRunWithConnectionsRealTLS(t *testing.T) {
	pki := newTestPKI(t, "localhost")
	caPath := writeTestCA(t, "root.pem", pki.rootPEM)
	connected, serverDone := startTLSServer(t, pki, "h2", func(connection *tls.Conn) error {
		request := make([]byte, 4)
		if _, err := io.ReadFull(connection, request); err != nil {
			return err
		}
		if string(request) != "ping" {
			return errors.New("unexpected proxied request")
		}
		_, err := connection.Write([]byte("pong"))
		return err
	})
	parentIPC, helperIPC := net.Pipe()
	helperDone := make(chan error, 1)
	go func() {
		defer connected.Close()
		defer helperIPC.Close()
		helperDone <- runWithConnections(connected, helperIPC)
	}()
	connectionID := [16]byte{0x41}
	if _, err := parentIPC.Write(encodeLiveRequest(
		t, connectionID, "localhost", caPath, pki.leafHash[:])); err != nil {
		t.Fatal(err)
	}
	header, payload := readLiveResponse(t, parentIPC)
	if header.Type != messageReady || header.ConnectionID != connectionID {
		helperErr := waitTestResult(t, "helper", helperDone)
		serverErr := waitTestResult(t, "TLS server", serverDone)
		t.Fatalf("unexpected ready header: %#v; helper=%v; server=%v",
			header, helperErr, serverErr)
	}
	response := decoder{data: payload}
	responseBuildID, err := response.string16(256)
	if err != nil {
		t.Fatal(err)
	}
	responseALPN, err := response.string16(16)
	if err != nil {
		t.Fatal(err)
	}
	leafHash, err := response.take(sha256.Size)
	if err != nil {
		t.Fatal(err)
	}
	exporter, err := response.take(exporterBytes)
	if err != nil {
		t.Fatal(err)
	}
	if responseBuildID != buildID || responseALPN != "h2" ||
		!bytes.Equal(leafHash, pki.leafHash[:]) || len(exporter) != exporterBytes ||
		response.off != len(payload) {
		t.Fatalf("unexpected ready payload: build=%q alpn=%q", responseBuildID, responseALPN)
	}
	if _, err := parentIPC.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(parentIPC, reply); err != nil {
		t.Fatal(err)
	}
	if string(reply) != "pong" {
		t.Fatalf("unexpected proxied response %q", reply)
	}
	_ = parentIPC.Close()
	if err := waitTestResult(t, "TLS server", serverDone); err != nil {
		t.Fatal(err)
	}
	if err := waitTestResult(t, "helper", helperDone); err != nil {
		t.Fatal(err)
	}
}

func TestRunWithConnectionsTLSFailuresAreGeneric(t *testing.T) {
	pki := newTestPKI(t, "localhost")
	wrongPKI := newTestPKI(t, "localhost")
	caPath := writeTestCA(t, "root.pem", pki.rootPEM)
	wrongCAPath := writeTestCA(t, "wrong-root.pem", wrongPKI.rootPEM)
	tests := []struct {
		name       string
		serverName string
		caPath     string
		leafPin    []byte
		alpn       string
		exporter   exporterFunc
		code       uint16
		message    string
	}{
		{
			name: "wrong CA", serverName: "localhost", caPath: wrongCAPath,
			alpn: "h2", code: 5, message: "TLS handshake or verification failed",
		},
		{
			name: "wrong hostname", serverName: "not-localhost.example", caPath: caPath,
			alpn: "h2", code: 5, message: "TLS handshake or verification failed",
		},
		{
			name: "wrong leaf pin", serverName: "localhost", caPath: caPath,
			leafPin: make([]byte, sha256.Size), alpn: "h2",
			code: 9, message: "TLS leaf pin mismatch",
		},
		{
			name: "wrong ALPN", serverName: "localhost", caPath: caPath,
			alpn: "http/1.1", code: 7, message: "h2 ALPN was not negotiated",
		},
		{
			name: "exporter failure", serverName: "localhost", caPath: caPath,
			alpn: "h2", code: 10, message: "TLS exporter failed",
			exporter: func(utls.ConnectionState) ([]byte, error) {
				return nil, errors.New("injected private exporter detail")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connected, serverDone := startTLSServer(t, pki, test.alpn, nil)
			parentIPC, helperIPC := net.Pipe()
			helperDone := make(chan error, 1)
			exporter := test.exporter
			if exporter == nil {
				exporter = exportChannelBinding
			}
			go func() {
				defer connected.Close()
				defer helperIPC.Close()
				helperDone <- runWithConnectionsAndExporter(
					connected, helperIPC, exporter)
			}()
			connectionID := [16]byte{0x52}
			if _, err := parentIPC.Write(encodeLiveRequest(
				t, connectionID, test.serverName, test.caPath, test.leafPin)); err != nil {
				t.Fatal(err)
			}
			header, payload := readLiveResponse(t, parentIPC)
			if header.Type != messageError || header.ConnectionID != connectionID {
				t.Fatalf("unexpected error header: %#v", header)
			}
			code, message := decodeLiveError(t, payload)
			if code != test.code || message != test.message || len(message) > 64 {
				t.Fatalf("unexpected public helper error: code=%d message=%q", code, message)
			}
			_ = parentIPC.Close()
			if err := waitTestResult(t, "helper", helperDone); err == nil {
				t.Fatal("helper unexpectedly accepted invalid TLS session")
			}
			_ = waitTestResult(t, "TLS server", serverDone)
		})
	}
}
