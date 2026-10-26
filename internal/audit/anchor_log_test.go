// SPDX-License-Identifier: BUSL-1.1

package audit_test

import (
	"errors"
	"testing"

	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/crypto/jose"
)

// A148: the audit service signs anchor log heads with the audit export key and
// nothing else through this path; an export bundle signed here would let any
// caller mint evidence.
func TestAuditServiceSignsOnlyAnchorLogHeads(t *testing.T) {
	svc := newService(t, openLog(t))
	signed, err := svc.SignArtifact(jose.ArtifactAuditAnchorLog, []byte(`{"tree_size":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.VerificationKeys().VerifyArtifact(signed, jose.ArtifactAuditAnchorLog); err != nil {
		t.Fatalf("anchor log head does not verify: %v", err)
	}
	if _, err := svc.SignArtifact(jose.ArtifactAuditExport, []byte(`{}`)); !errors.Is(err, audit.ErrUnsupportedArtifact) {
		t.Fatalf("an export bundle was signed through the anchor log path: %v", err)
	}
	if _, err := audit.NewService(openLog(t), nil).SignArtifact(jose.ArtifactAuditAnchorLog, nil); !errors.Is(err, audit.ErrMissingSigner) {
		t.Fatalf("no signer = %v", err)
	}
}
