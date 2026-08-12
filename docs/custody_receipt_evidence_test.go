// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"strings"
	"testing"
)

// AUD-25 crossed seven package boundaries. This guard pins the joins, because
// a green receipt library or a green report renderer alone cannot prove the
// custody fact survives from the host to the signed export.
func TestCustodyReceiptAndEvidencePackStayEndToEndAUD25(t *testing.T) {
	t.Parallel()
	checks := []struct {
		file  string
		wants []string
	}{
		{"../internal/agent/transport/receipt.go", []string{
			"trstctl-agent-job-receipt/v2", "credential_fingerprint", "key_origin", "key_storage", "key_exportable", "key_generated_by",
		}},
		{"../internal/agent/relay/hostrenew.go", []string{
			"HostRenewCustody", "reportWithEvidenceAndCustody", "StorageOSStore", "StorageService", "StorageFile",
		}},
		{"../internal/server/agent_jobs.go", []string{
			"validateCertificateCustodyReceipt", "recordCertificateCustodyFromJob", "AttestCertificateCustody",
		}},
		{"../internal/projections/projections.go", []string{
			"certificate.custody.attested", "ApplyCertificateCustodyAttestedTx",
		}},
		{"../internal/graph/build.go", []string{
			`"credential_kind"`, `"certificate"`, `"key_origin"`, `"key_storage"`, `"key_exportable"`, `"key_generated_by"`,
		}},
		{"../ee/governance/governance.go", []string{"Custody", "custodyPosture", "SummarizeCertificates"}},
		{"../internal/api/compliance.go", []string{"trstctl.compliance.evidence-pack.v4", "custody.CertificateSummary"}},
		{"../web/src/components/ComplianceEvidencePackPanel.tsx", []string{
			"custody.unrecorded_certificates", "missing_fields", "policy.compliance.custodyGaps",
		}},
		{"custody.md", []string{"certificate.custody.attested", "counts by the closed custody vocabulary", "incomplete certificate"}},
		{"compliance.md", []string{"signed_export.manifest.custody", "unrecorded_certificates", "missing_fields"}},
	}
	for _, check := range checks {
		body := read(t, check.file)
		for _, want := range check.wants {
			if !strings.Contains(body, want) {
				t.Errorf("%s no longer contains %q; the signed custody evidence chain is incomplete", check.file, want)
			}
		}
	}
}
