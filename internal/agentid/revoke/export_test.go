// SPDX-License-Identifier: BUSL-1.1

package revoke

import "context"

// export_test.go exposes narrow, test-only seams into the unexported cascade
// internals so the external revoke_test integration tests can drive a single job
// directly (replay/idempotency) and observe the ledger head (follow-on watermark)
// without widening the production API. Compiled solely into the package test binary.

// BuildJobPayloadForTest builds and encodes a job payload the way EnqueueDirective
// does, so a test can hand the executor a Message identical to one the cascade
// enqueued (to replay a single job N times).
func BuildJobPayloadForTest(tenantID, directiveID, credentialID string, reason ReasonClass, publishDownstream bool) ([]byte, error) {
	return JobPayload{
		TenantID:          tenantID,
		DirectiveID:       directiveID,
		CredentialID:      credentialID,
		Reason:            reason,
		PublishDownstream: publishDownstream,
	}.encode()
}

// LedgerHeadForTest exposes the cascade's ledger-head read so a follow-on test can
// assert a late seed advanced the ledger beyond the recorded watermark.
func (c *Cascade) LedgerHeadForTest(ctx context.Context) (uint64, error) {
	return c.ledgerHead(ctx)
}
