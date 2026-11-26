// SPDX-License-Identifier: BUSL-1.1
package transport_test

import (
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/custody"
)

func TestJobReceiptRejectsUnboundedSignedFieldsN0010(t *testing.T) {
	base := transport.JobReceiptStatement{TenantID: "tenant", AgentCommonName: "host-agent", JobID: 4, Attempt: 1, Outcome: transport.JobOutcomeFailed, IssuedAtUnix: 1}
	for _, tc := range []struct {
		name string
		edit func(*transport.JobReceiptStatement)
	}{
		{"evidence", func(s *transport.JobReceiptStatement) { s.EvidenceDigest = strings.Repeat("e", 33<<10) }},
		{"detail", func(s *transport.JobReceiptStatement) { s.DetailDigest = strings.Repeat("d", 33<<10) }},
		{"fingerprint", func(s *transport.JobReceiptStatement) { s.CredentialFingerprint = strings.Repeat("f", 33<<10) }},
		{"generated_by", func(s *transport.JobReceiptStatement) {
			s.CredentialFingerprint = strings.Repeat("a", 64)
			s.Custody = custody.Record{Origin: custody.OriginHostAgent, Storage: custody.StorageFile, Exportable: custody.Exportable, GeneratedBy: strings.Repeat("g", 33<<10)}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := base
			tc.edit(&s)
			if err := s.Validate(); err == nil {
				t.Fatal("oversized signed receipt was accepted")
			}
		})
	}
}
