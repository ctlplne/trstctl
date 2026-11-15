// SPDX-License-Identifier: BUSL-1.1

package relay_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/kms/tpm"
)

// softwareHostKeyTPM stands in for the host's TPM in a unit test: it makes a
// software P-256 key per host key file and signs with it. It never certifies;
// the test injects the attestation, and the swtpm journey runs the real one.
type softwareHostKeyTPM struct {
	mu      sync.Mutex
	keys    map[string]*crypto.LockedSigner
	created int
}

func (d *softwareHostKeyTPM) CreateHostKey() ([]byte, []byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		return nil, nil, err
	}
	d.created++
	file, err := tpm.EncodeTSS2PrivateKey(tpm.HostSRKHandle, []byte("public-area-"+strconv.Itoa(d.created)), []byte("wrapped-private"))
	if err != nil {
		return nil, nil, err
	}
	if d.keys == nil {
		d.keys = map[string]*crypto.LockedSigner{}
	}
	d.keys[string(file)] = signer
	return file, append([]byte(nil), signer.Public().DER...), nil
}

func (d *softwareHostKeyTPM) key(file []byte) (*crypto.LockedSigner, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	signer, ok := d.keys[string(file)]
	if !ok {
		return nil, errors.New("software TPM: no such host key file")
	}
	return signer, nil
}

func (d *softwareHostKeyTPM) SignWithHostKey(file, digest []byte) ([]byte, error) {
	signer, err := d.key(file)
	if err != nil {
		return nil, err
	}
	return signer.SignDigest(digest, crypto.SignOptions{Hash: crypto.SHA256})
}

func (d *softwareHostKeyTPM) CertifyHostKey([]byte, string, []byte, []byte) (crypto.EdgeTPMCertification, error) {
	return crypto.EdgeTPMCertification{}, errors.New("software TPM: certification is injected by the test")
}

func (d *softwareHostKeyTPM) HostKeyPublicDER(file []byte) ([]byte, error) {
	signer, err := d.key(file)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), signer.Public().DER...), nil
}

// attestedRenewChannel is a renewChannel that also takes the TPM's
// attestation with the CSR.
type attestedRenewChannel struct {
	renewChannel
	attestations [][]byte
}

func (r *attestedRenewChannel) SignJobCSRWithKeyAttestation(ctx context.Context, jobID int64, attempt int, csrDER, attestation []byte) ([]byte, []byte, string, error) {
	r.attestations = append(r.attestations, append([]byte(nil), attestation...))
	return r.SignJobCSR(ctx, jobID, attempt, csrDER)
}

func tpmRenewProfile(t *testing.T, dir string, withTPM bool) connector.LocalOpsConfig {
	t.Helper()
	nginx := filepath.Join(dir, "nginx")
	if err := os.WriteFile(nginx, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil { // #nosec G306 -- the fixture IS an executable (CWE-276)
		t.Fatal(err)
	}
	profile := connector.LocalOpsConfig{AllowedRoots: []string{dir},
		Actions: []connector.LocalAction{{LogicalName: "nginx", Command: nginx, PassArgs: true}}}
	if withTPM {
		profile.HostKeyTPM = &connector.HostKeyTPMConfig{AttestationKey: filepath.Join(dir, "ak.json"), AttestationCertChain: filepath.Join(dir, "ak.pem")}
	}
	return profile
}

func tpmRenewIntent(t *testing.T, dir, connectorName string) relay.DeployIntent {
	t.Helper()
	return relay.DeployIntent{
		Connector: connectorName, Target: "web01", TargetID: "t-web01",
		KeyCustody:        relay.HostKeyCustodyTPM,
		SubjectCommonName: "web.example.test", SubjectDNSNames: []string{"web.example.test"},
		TargetConfig: renewTargetConfig(t, filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")),
	}
}

// TestTPMHostRenewalMakesTheKeyInTheTPMAndSendsItsAttestationTPMO1: a renewal
// whose profile requires a TPM-held key has the TPM make the key and sign the
// CSR, sends the TPM's attestation of that key for this job with the CSR, and
// installs the TPM's key file: no software private key exists on the host or
// in the request, and the receipt claims a device-origin, device-bound,
// non-exportable key.
func TestTPMHostRenewalMakesTheKeyInTheTPMAndSendsItsAttestationTPMO1(t *testing.T) {
	dev := &softwareHostKeyTPM{}
	var attested []string
	restore := relay.SetHostKeyTPMForTest(dev, func(jobID int64, file, csrDER []byte) ([]byte, error) {
		attested = append(attested, strconv.FormatInt(jobID, 10))
		if !bytes.Contains(file, []byte("BEGIN TSS2 PRIVATE KEY")) {
			t.Errorf("the attestation was asked for a key that is not a TPM key file:\n%s", file)
		}
		return []byte("tpm-attestation-for-job-" + strconv.FormatInt(jobID, 10)), nil
	})
	defer restore()
	dir := t.TempDir()
	ch := &attestedRenewChannel{renewChannel: renewChannel{certPEM: []byte("ISSUED-LEAF\n"), chainPEM: []byte("ISSUER\n"), fpr: "sha256:issued"}}
	ch.jobs = []relay.Job{renewJob(t, tpmRenewIntent(t, dir, "nginx"))}

	if _, err := relay.RunOnceWithHost(context.Background(), ch, http.DefaultClient, tpmRenewProfile(t, dir, true), 4, 60); err != nil {
		t.Fatalf("RunOnceWithHost: %v", err)
	}
	if len(ch.reports) != 1 || ch.reports[0].outcome == relay.OutcomeFailed {
		t.Fatalf("reports = %+v", ch.reports)
	}
	if dev.created != 1 || len(ch.signed) != 1 || len(ch.attestations) != 1 ||
		string(ch.attestations[0]) != "tpm-attestation-for-job-77" || strings.Join(attested, ",") != "77" {
		t.Fatalf("created %d keys, signed %d CSRs with attestations %q (asked for jobs %v)", dev.created, len(ch.signed), ch.attestations, attested)
	}
	csr, err := crypto.InspectCSR(ch.signed[0])
	if err != nil || csr.KeyAlgorithm != "ECDSA" || csr.KeyBits != 256 {
		t.Fatalf("CSR %+v: %v", csr, err)
	}
	var tpmPublic []byte
	for _, signer := range dev.keys {
		tpmPublic = signer.Public().DER
	}
	if !bytes.Contains(ch.signed[0], tpmPublic) {
		t.Fatal("the CSR does not carry the TPM's key")
	}
	installed, err := os.ReadFile(filepath.Join(dir, "key.pem")) // #nosec G304 -- the test's own temp directory (CWE-22)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(installed, []byte("-----BEGIN TSS2 PRIVATE KEY-----")) ||
		bytes.Contains(installed, []byte("BEGIN PRIVATE KEY")) || bytes.Contains(installed, []byte("BEGIN EC PRIVATE KEY")) {
		t.Fatalf("the installed key is not the TPM's key file:\n%s", installed)
	}
	if len(ch.custody) != 1 || ch.custody[0].Origin != custody.OriginDevice ||
		ch.custody[0].Storage != custody.StorageDeviceBound || ch.custody[0].Exportable != custody.NonExportable {
		t.Fatalf("custody = %+v, want device, device_bound, non_exportable", ch.custody)
	}
}

// TestTPMHostRenewalIsRefusedBeforeAnyKeyWhenTheHostCannotHoldItTPMO1: a
// renewal that requires a TPM-held key, on a host whose profile names no TPM,
// for a connector that cannot install one, for a key the TPM cannot hold, or
// through a channel that cannot send an attestation, or that names a custody
// no agent provides, is refused with its reason before the TPM makes a key
// and before anything is signed or written.
func TestTPMHostRenewalIsRefusedBeforeAnyKeyWhenTheHostCannotHoldItTPMO1(t *testing.T) {
	dev := &softwareHostKeyTPM{}
	restore := relay.SetHostKeyTPMForTest(dev, func(int64, []byte, []byte) ([]byte, error) {
		t.Error("an attestation was asked for")
		return nil, errors.New("unexpected")
	})
	defer restore()
	for _, tc := range []struct {
		name     string
		withTPM  bool
		plain    bool
		mutate   func(*relay.DeployIntent)
		wantText string
	}{
		{"no TPM in the host profile", false, false, nil, "names no host_key_tpm"},
		{"a connector that converts the key", true, false, func(i *relay.DeployIntent) { i.Connector = "apache" }, "installed only for nginx"},
		{"a key the TPM cannot hold", true, false, func(i *relay.DeployIntent) { i.SubjectKeyAlgorithm = "RSA-2048" }, "ECDSA P-256"},
		{"a channel that cannot send an attestation", true, true, nil, "cannot send a TPM key attestation"},
		{"a custody no agent provides", true, false, func(i *relay.DeployIntent) { i.KeyCustody = "hsm" }, "which this agent does not provide"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			intent := tpmRenewIntent(t, dir, "nginx")
			if tc.mutate != nil {
				tc.mutate(&intent)
			}
			var ch relay.Channel
			var signCalls func() int
			var reports func() []report
			if tc.plain {
				plain := &renewChannel{certPEM: []byte("ISSUED-LEAF\n"), fpr: "sha256:issued"}
				plain.jobs = []relay.Job{renewJob(t, intent)}
				ch, signCalls, reports = plain, func() int { return plain.signCalls }, func() []report { return plain.reports }
			} else {
				attested := &attestedRenewChannel{renewChannel: renewChannel{certPEM: []byte("ISSUED-LEAF\n"), fpr: "sha256:issued"}}
				attested.jobs = []relay.Job{renewJob(t, intent)}
				ch, signCalls, reports = attested, func() int { return attested.signCalls }, func() []report { return attested.reports }
			}
			before := dev.created
			if _, err := relay.RunOnceWithHost(context.Background(), ch, http.DefaultClient, tpmRenewProfile(t, dir, tc.withTPM), 4, 60); err != nil {
				t.Fatalf("RunOnceWithHost: %v", err)
			}
			got := reports()
			if len(got) != 1 || got[0].outcome != relay.OutcomeFailed || !strings.Contains(got[0].detail, tc.wantText) {
				t.Fatalf("reports = %+v, want a failure naming %q", got, tc.wantText)
			}
			if dev.created != before || signCalls() != 0 {
				t.Fatalf("the TPM made %d keys and %d CSRs were signed before the refusal", dev.created-before, signCalls())
			}
			if _, err := os.Stat(filepath.Join(dir, "key.pem")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a key file was written: %v", err)
			}
		})
	}
}

// TestTPMHostKeyCustodyIsDeviceBoundTPMO1: the receipt a TPM-held key's
// renewal sends, and the control plane expects, names a key generated on a
// device that will not export it (device origin, device-bound,
// non-exportable); a custody the agent does not know is an error.
func TestTPMHostKeyCustodyIsDeviceBoundTPMO1(t *testing.T) {
	record, err := relay.HostRenewCustody("nginx", relay.HostKeyCustodyTPM, "host-agent-7")
	if err != nil || !record.Complete() || record.Origin != custody.OriginDevice || record.Storage != custody.StorageDeviceBound ||
		record.Exportable != custody.NonExportable || record.GeneratedBy != "host-agent-7" {
		t.Fatalf("TPM custody = %+v: %v", record, err)
	}
	if _, err := relay.HostRenewCustody("nginx", "hsm", "host-agent-7"); err == nil {
		t.Fatal("an unknown host key custody was classified")
	}
}

// TestHostKeyTPMProfileNeedsItsAttestationFilesTPMO1: the host profile's
// host_key_tpm names the attestation key's handle and chain by absolute path,
// beside the roots its key files are written in.
func TestHostKeyTPMProfileNeedsItsAttestationFilesTPMO1(t *testing.T) {
	dir := t.TempDir()
	write := func(profile map[string]any) string {
		raw, err := json.Marshal(profile)
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "profile.json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	good := map[string]any{"tpm_path": "/dev/tpmrm0", "attestation_key": "/etc/trstctl/ak.json", "attestation_cert_chain": "/etc/trstctl/ak.pem"}
	loaded, err := relay.LoadHostProfile(write(map[string]any{"allowed_roots": []string{dir}, "host_key_tpm": good}))
	if err != nil || loaded.HostKeyTPM == nil || loaded.HostKeyTPM.AttestationKey != "/etc/trstctl/ak.json" || loaded.HostKeyTPM.Path != "/dev/tpmrm0" {
		t.Fatalf("loaded %+v: %v", loaded.HostKeyTPM, err)
	}
	for _, tc := range []struct {
		name    string
		profile map[string]any
		want    string
	}{
		{"no attestation chain", map[string]any{"allowed_roots": []string{dir}, "host_key_tpm": map[string]any{"attestation_key": "/etc/trstctl/ak.json"}}, "needs attestation_key and attestation_cert_chain"},
		{"a relative path", map[string]any{"allowed_roots": []string{dir}, "host_key_tpm": map[string]any{"attestation_key": "ak.json", "attestation_cert_chain": "/etc/trstctl/ak.pem"}}, "is not absolute"},
		{"no roots", map[string]any{"kubernetes_secrets": map[string]any{"namespaces": []string{"web"}}, "host_key_tpm": good}, "must name the allowed roots"},
	} {
		if _, err := relay.LoadHostProfile(write(tc.profile)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
	}
}
