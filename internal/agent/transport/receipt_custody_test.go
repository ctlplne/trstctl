// SPDX-License-Identifier: MPL-2.0

package transport_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/custody"
)

func TestHostRenewalReceiptCanonicalFormBindsCompleteCustodyAUD25(t *testing.T) {
	t.Parallel()
	statement := transport.JobReceiptStatement{ // #nosec G101 -- the credential fingerprint is public fixture metadata, not a credential (CWE-798).
		TenantID: "11111111-1111-1111-1111-111111111111", AgentCommonName: "host-agent-7",
		JobID: 42, Attempt: 3, Outcome: transport.JobOutcomeVerified,
		CredentialFingerprint: "sha256:leaf-42",
		Custody: custody.Record{
			Origin: custody.OriginHostAgent, Storage: custody.StorageFile,
			Exportable: custody.Exportable, GeneratedBy: "host-agent-7",
		},
		IssuedAtUnix: 1_786_460_400,
	}
	if err := statement.Validate(); err != nil {
		t.Fatalf("complete custody statement rejected: %v", err)
	}
	canonical := string(statement.Canonical())
	for _, want := range []string{
		"trstctl-agent-job-receipt/v2\n",
		"credential_fingerprint=sha256:leaf-42\n",
		"key_origin=host_agent\n",
		"key_storage=file\n",
		"key_exportable=exportable\n",
		"key_generated_by=host-agent-7\n",
	} {
		if !strings.Contains(canonical, want) {
			t.Errorf("canonical custody receipt missing %q:\n%s", want, canonical)
		}
	}

	tampered := statement
	tampered.Custody.Storage = custody.StorageOSStore
	if string(tampered.Canonical()) == canonical {
		t.Fatal("changing the custody storage locus did not change the signed bytes")
	}

	partial := statement
	partial.Custody.Storage = custody.StorageUnrecorded
	if err := partial.Validate(); err == nil {
		t.Fatal("a partial custody attestation was canonicalized as complete evidence")
	}
}

func TestOrdinaryReceiptRetainsVersionOneCompatibilityAUD25(t *testing.T) {
	t.Parallel()
	statement := transport.JobReceiptStatement{
		TenantID: "11111111-1111-1111-1111-111111111111", AgentCommonName: "relay-1",
		JobID: 7, Attempt: 1, Outcome: transport.JobOutcomeExecuted, IssuedAtUnix: 1_786_460_400,
	}
	if err := statement.Validate(); err != nil {
		t.Fatal(err)
	}
	if got := string(statement.Canonical()); !strings.HasPrefix(got, "trstctl-agent-job-receipt/v1\n") {
		t.Fatalf("non-custody receipt wire version changed:\n%s", got)
	}
}
