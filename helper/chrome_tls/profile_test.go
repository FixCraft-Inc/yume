// YUME - Yume Universal Multiprotocol Engine
// Copyright (C) 2026 FixCraft Inc.
// Licensed under the GNU Affero General Public License v3.0 or later.

package main

import (
	"testing"

	utls "github.com/refraction-networking/utls"
)

func TestProfileForBuildIDRejectsAmbiguity(t *testing.T) {
	original := clientHelloProfiles
	clientHelloProfiles = append(
		append([]clientHelloProfile(nil), original...), original[0])
	t.Cleanup(func() { clientHelloProfiles = original })
	if profile, ok := profileForBuildID(original[0].buildID); ok || profile != nil {
		t.Fatal("ambiguous helper build ID was accepted")
	}
}

func TestChrome151SpecKeepsExporterAvailable(t *testing.T) {
	spec, err := chrome151Spec()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, extension := range spec.Extensions {
		renegotiation, ok := extension.(*utls.RenegotiationInfoExtension)
		if !ok {
			continue
		}
		found = true
		if renegotiation.Renegotiation != utls.RenegotiateNever {
			t.Fatalf("renegotiation enabled: %v", renegotiation.Renegotiation)
		}
		if renegotiation.Len() != 5 {
			t.Fatalf("unexpected on-wire extension length: %d", renegotiation.Len())
		}
	}
	if !found {
		t.Fatal("Chrome spec has no renegotiation_info extension")
	}
}
