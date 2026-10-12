// SPDX-License-Identifier: BUSL-1.1

package breakglass

import "fmt"

// VerifyBatch checks every bundle before a caller starts reconciliation. Event
// writes belong to the server's durable, tenant-scoped request-ID fence; a
// generic audit sink cannot prevent a second import after a retry or restart.
func VerifyBatch(bundles []Bundle, caCertDER, breakglassPubDER []byte) error {
	for _, b := range bundles {
		if err := Verify(b, caCertDER, breakglassPubDER); err != nil {
			return fmt.Errorf("breakglass: reconcile rejected bundle %q: %w", b.RequestID, err)
		}
	}
	return nil
}
