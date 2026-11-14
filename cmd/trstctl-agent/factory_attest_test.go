// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/deviceattest"
	"trstctl.com/trstctl/internal/crypto/deviceattesttest"
)

// P12-L1: a batch that pins device attestation roots has the station check
// each device's TPM attestation of its own key before it signs. An attested
// device gets its birth certificate and the journal carries the attestation
// with the CSR; no attestation, another device's, or one for a key the TPM
// could release gets nothing, and the journal is untouched.
func TestFactoryStationChecksTheDeviceAttestationP12L1(t *testing.T) {
	dir, opts := factoryStationFixture(t, 4)
	now := time.Now().UTC()
	device, err := deviceattesttest.NewTPMIdentity(now)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(opts.factoryManifest)
	if err != nil {
		t.Fatal(err)
	}
	var manifest factoryManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.DeviceAttestationRootsPEM = []string{string(device.RootPEM())}
	raw, _ = json.Marshal(manifest)
	if err := os.WriteFile(opts.factoryManifest, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	attested := func(device *deviceattesttest.TPMIdentity, name, segmentDevice string, releasable bool) (csrPath, credentialPath string) {
		t.Helper()
		csrDER, err := device.CSRDERFor(name)
		if err != nil {
			t.Fatal(err)
		}
		challenge := crypto.EdgeAttestationChallenge(manifest.TenantID, deviceattest.FactoryAttestationSegment(manifest.BatchID, segmentDevice), csrDER)
		credential, err := device.CredentialJSON(challenge)
		if releasable {
			credential, err = device.DuplicableCredentialJSON(challenge)
		}
		if err != nil {
			t.Fatal(err)
		}
		return write(name+".csr", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), write(name+".attestation.json", credential)
	}
	issue := func(name, csrPath, credentialPath string) error {
		o := opts
		o.factoryDevice, o.factoryCSR, o.factoryAttestation, o.certOut = name, csrPath, credentialPath, filepath.Join(dir, name+".crt")
		return runFactoryIssue(o, "line-1")
	}
	journal := func() factoryJournal {
		t.Helper()
		var j factoryJournal
		if raw, err := os.ReadFile(opts.factoryJournal); err == nil {
			if err := json.Unmarshal(raw, &j); err != nil {
				t.Fatal(err)
			}
		}
		return j
	}

	const name = "sn-0001.devices.example.test"
	csrPath, credentialPath := attested(device, name, name, false)
	if err := issue(name, csrPath, credentialPath); err != nil {
		t.Fatalf("an attested device: %v", err)
	}
	j := journal()
	if len(j.CertificatesPEM) != 1 || len(j.Attestations) != 1 {
		t.Fatalf("journal = %+v; want the birth certificate and its attestation", j)
	}
	block, _ := pem.Decode([]byte(j.CertificatesPEM[0]))
	if j.Attestations[0].CertificateSHA256 != crypto.SHA256Hex(block.Bytes) || !strings.Contains(j.Attestations[0].CSRPEM, "CERTIFICATE REQUEST") ||
		!json.Valid(j.Attestations[0].Credential) {
		t.Fatalf("journal attestation = %+v", j.Attestations[0])
	}

	const second = "sn-0002.devices.example.test"
	refusals := map[string]func() error{
		"no attestation": func() error { csr, _ := attested(device, second, second, false); return issue(second, csr, "") },
		"another device's attestation": func() error {
			csr, credential := attested(device, second, name, false)
			return issue(second, csr, credential)
		},
		"a key the TPM could release": func() error {
			csr, credential := attested(device, second, second, true)
			return issue(second, csr, credential)
		},
	}
	for what, run := range refusals {
		if err := run(); err == nil {
			t.Fatalf("%s: the station signed", what)
		}
		if j := journal(); len(j.CertificatesPEM) != 1 {
			t.Fatalf("%s: the journal grew to %d", what, len(j.CertificatesPEM))
		}
	}
}
