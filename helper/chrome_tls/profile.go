// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

package main

import (
	"fmt"

	utls "github.com/refraction-networking/utls"
)

type clientHelloProfile struct {
	profileID   string
	buildID     string
	displayName string
	buildSpec   func() (*utls.ClientHelloSpec, error)
}

// buildID is retained as the single-profile binary identity used by existing
// packaging and tests. Connection setup resolves through the registry below,
// so another reviewed profile does not require branches in the TLS lifecycle.
const buildID = activeHelperBuildID

func profileForBuildID(expected string) (*clientHelloProfile, bool) {
	var selected *clientHelloProfile
	for index := range clientHelloProfiles {
		if clientHelloProfiles[index].buildID == expected {
			if selected != nil {
				return nil, false
			}
			selected = &clientHelloProfiles[index]
		}
	}
	return selected, selected != nil
}

func chrome151Spec() (*utls.ClientHelloSpec, error) {
	// Chrome 151 retains the Chrome 133 cipher/group/key-share/ALPS/ECH
	// geometry represented by uTLS v1.8.2, but advertises three additional
	// post-quantum signature schemes. Start from the reviewed upstream spec so
	// GREASE ECH sizing and Chrome's cryptographic extension shuffle stay in
	// one maintained implementation, then replace the measured field.
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
	if err != nil {
		return nil, fmt.Errorf("load base Chrome spec: %w", err)
	}
	foundSignatures := false
	foundRenegotiation := false
	for _, extension := range spec.Extensions {
		switch typed := extension.(type) {
		case *utls.SignatureAlgorithmsExtension:
			if foundSignatures {
				return nil, fmt.Errorf("base Chrome spec has duplicate signature extensions")
			}
			foundSignatures = true
			typed.SupportedSignatureAlgorithms = []utls.SignatureScheme{
				utls.SignatureScheme(0x0904),
				utls.SignatureScheme(0x0905),
				utls.SignatureScheme(0x0906),
				utls.ECDSAWithP256AndSHA256,
				utls.PSSWithSHA256,
				utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384,
				utls.PSSWithSHA384,
				utls.PKCS1WithSHA384,
				utls.PSSWithSHA512,
				utls.PKCS1WithSHA512,
			}
		case *utls.RenegotiationInfoExtension:
			if foundRenegotiation {
				return nil, fmt.Errorf("base Chrome spec has duplicate renegotiation extensions")
			}
			foundRenegotiation = true
			// Keep Chrome's empty renegotiation_info extension on the wire,
			// but never enable TLS 1.2 renegotiation in the uTLS state. uTLS
			// otherwise disables RFC 8446 exporters even after a TLS 1.3
			// handshake, which would break YUME's mandatory channel binding.
			typed.Renegotiation = utls.RenegotiateNever
		}
	}
	if !foundSignatures {
		return nil, fmt.Errorf("base Chrome spec has no signature extension")
	}
	if !foundRenegotiation {
		return nil, fmt.Errorf("base Chrome spec has no renegotiation extension")
	}
	return &spec, nil
}
