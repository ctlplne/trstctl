package breakglass

import (
	"context"
	"fmt"
	"time"

	"trustctl.io/trustctl/internal/auditsink"
)

// Reconcile replays emergency bundles into the control plane's audit log on
// recovery (AN-2). Each verified bundle becomes an audited "breakglass.issued"
// event; a bundle that fails verification is rejected and stops the batch, so a
// tampered emergency credential cannot be silently absorbed into the record.
func Reconcile(ctx context.Context, tenantID string, bundles []Bundle, caCertDER, breakglassPubDER []byte, audit auditsink.Auditor) (reconciled int, err error) {
	if audit == nil {
		audit = auditsink.Nop{}
	}
	for _, b := range bundles {
		if verr := Verify(b, caCertDER, breakglassPubDER); verr != nil {
			return reconciled, fmt.Errorf("breakglass: reconcile rejected bundle %q: %w", b.RequestID, verr)
		}
		data := []byte(fmt.Sprintf(`{"request_id":%q,"subject":%q,"reason":%q,"issued_at":%q,"approvals":%d}`,
			b.RequestID, b.Subject, b.Reason, b.IssuedAt.Format(time.RFC3339), len(b.Approvals)))
		if aerr := audit.Audit(ctx, "breakglass.issued", tenantID, data); aerr != nil {
			return reconciled, aerr
		}
		reconciled++
	}
	return reconciled, nil
}
