// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"strings"

	"trstctl.com/trstctl/internal/observ"
)

// managedKeyProvidersCheck reports, in /readyz, a managed-key provider whose
// workload identity token exchange has not succeeded since the signer started
// (A169-L2): degraded — readiness still passes, because CA signing and every
// other provider keep working — naming each such provider and the closed
// reason the signer recorded. An unreachable signer is the signer check's to
// report.
func managedKeyProvidersCheck(signer SignerProvider) observ.Check {
	return observ.Check{Name: "managed_key_providers", Probe: func(ctx context.Context) error {
		if signer == nil {
			return nil
		}
		client := signer.Client()
		if client == nil {
			return nil
		}
		providers, err := client.ManagedKeyProviderReadiness(ctx)
		if err != nil {
			return nil
		}
		var waiting []string
		for _, p := range providers {
			if !p.Ready {
				waiting = append(waiting, p.Provider+" ("+p.Reason+")")
			}
		}
		if len(waiting) > 0 {
			return observ.Degraded("managed-key provider workload identity not ready: " + strings.Join(waiting, ", "))
		}
		return nil
	}}
}
