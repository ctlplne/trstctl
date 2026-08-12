// SPDX-License-Identifier: LicenseRef-trstctl-EE

package governance

import (
	"bytes"
	"encoding/json"
	"testing"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/graph"
)

func TestSignedGovernanceReportCountsCustodyAndNamesEveryGapAUD25(t *testing.T) {
	t.Parallel()
	g := graph.New()
	g.AddNode(graph.Node{ID: "credential:cert:complete", Kind: graph.KindCredential, Name: "complete.example.test", Attrs: map[string]string{
		"credential_kind": "certificate", "certificate_id": "complete", "fingerprint": "sha256:complete",
		"subject": "complete.example.test", "key_origin": "host_agent", "key_storage": "file",
		"key_exportable": "exportable", "key_generated_by": "host-agent-7",
	}})
	g.AddNode(graph.Node{ID: "credential:cert:missing", Kind: graph.KindCredential, Name: "missing.example.test", Attrs: map[string]string{
		"credential_kind": "certificate", "certificate_id": "missing", "fingerprint": "sha256:missing",
		"subject": "missing.example.test", "key_origin": "host_agent",
	}})
	// A non-certificate credential must not inflate the certificate estate.
	g.AddNode(graph.Node{ID: "credential:ssh:key", Kind: graph.KindCredential, Attrs: map[string]string{"credential_kind": "ssh"}})

	signer, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(signer.Destroy)
	reporter := New("t1", signer)
	report, err := reporter.Generate(SOC2, auditFixture(), g, testEvidenceWindow())
	if err != nil {
		t.Fatal(err)
	}
	if report.Custody.Total != 2 || report.Custody.Recorded != 1 || report.Custody.Unrecorded != 1 {
		t.Fatalf("custody counts = %+v, want total=2 recorded=1 unrecorded=1", report.Custody)
	}
	if report.Custody.Origins.HostAgent != 2 || report.Custody.Storage.File != 1 || report.Custody.Exportability.Exportable != 1 {
		t.Fatalf("custody vocabulary counts = %+v", report.Custody)
	}
	if len(report.Custody.UnrecordedCertificates) != 1 {
		t.Fatalf("unrecorded rows = %+v, want one explicit row", report.Custody.UnrecordedCertificates)
	}
	gap := report.Custody.UnrecordedCertificates[0]
	if gap.ID != "missing" || gap.Fingerprint != "sha256:missing" ||
		!containsAll(gap.MissingFields, "key_storage", "key_exportable", "key_generated_by") {
		t.Fatalf("explicit unrecorded row = %+v", gap)
	}

	signed, err := reporter.Export(report)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := Verify(signed, signer.Public().DER)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(manifest, []byte(`"custody"`)) || !bytes.Contains(manifest, []byte(`"unrecorded_certificates"`)) {
		t.Fatalf("signed manifest omits custody evidence: %s", manifest)
	}

	var env signedEnvelope
	if err := json.Unmarshal(signed, &env); err != nil {
		t.Fatal(err)
	}
	env.Manifest = bytes.Replace(env.Manifest, []byte(`"unrecorded":1`), []byte(`"unrecorded":0`), 1)
	tampered, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(tampered, signer.Public().DER); err == nil {
		t.Fatal("altered custody counts retained a valid evidence-pack signature")
	}
}

func containsAll(got []string, wants ...string) bool {
	set := make(map[string]bool, len(got))
	for _, value := range got {
		set[value] = true
	}
	for _, want := range wants {
		if !set[want] {
			return false
		}
	}
	return true
}
