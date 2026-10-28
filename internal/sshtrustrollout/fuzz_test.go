// SPDX-License-Identifier: BUSL-1.1

package sshtrustrollout

import (
	"bytes"
	"encoding/json"
	"testing"
)

func FuzzSSHTrustCommand(f *testing.F) {
	valid, err := json.Marshal(reviewedCommand(f))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{"confirmed":true,"mode":"remove"}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		command, err := DecodeCommand(bytes.NewReader(raw))
		if err != nil {
			return
		}
		if err := command.Validate(); err != nil {
			t.Fatalf("decoder accepted an invalid command: %v", err)
		}
	})
}
func FuzzSSHTrustPublicCA(f *testing.F) {
	f.Add([]byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPexCbv5HmN6JhIN7b1GaDxkyWFY3uSrHBvKdlQYHONt comment@example.test"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		canonical, fingerprint, err := CanonicalPublicCAKey(raw)
		if err != nil {
			return
		}
		again, second, err := CanonicalPublicCAKey(canonical)
		if err != nil || second != fingerprint || !bytes.Equal(canonical, again) {
			t.Fatalf("public key normalization was not stable: %v", err)
		}
	})
}
func FuzzSSHTrustReceipt(f *testing.F) {
	f.Add([]byte(`{"state":"verified"}`))
	f.Add([]byte(`{} {}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		report, err := DecodeReport(raw)
		if err != nil {
			return
		}
		canonical, _, err := report.Encode()
		if err != nil || len(canonical) > MaxReportBytes {
			return
		}
		again, err := DecodeReport(canonical)
		if err != nil {
			t.Fatal(err)
		}
		second, _, err := again.Encode()
		if err != nil || !bytes.Equal(canonical, second) {
			t.Fatalf("unstable canonical receipt: %v", err)
		}
	})
}
