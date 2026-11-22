// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"testing"
)

// An old row can reach the worker without passing through today's API. It
// must fail before provider construction or any credential resolution.
func TestCR049WorkerRejectsLegacyMisCasedSecretSource(t *testing.T) {
	raw := json.RawMessage(`{"providers":[{"provider":"hashicorp-vault","vault_url":"https://example.com","Token_Ref":"env:SECRET","Allow_Private_Endpoint":true}]}`)
	providers, unbuilt, err := cloudSecretProviders(context.Background(), raw)
	if err == nil || len(providers) != 0 || len(unbuilt) != 0 {
		t.Fatalf("worker accepted legacy mis-cased source: providers=%d unbuilt=%d err=%v", len(providers), len(unbuilt), err)
	}
}
