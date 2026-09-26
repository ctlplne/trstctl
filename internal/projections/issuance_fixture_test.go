// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"trstctl.com/trstctl/internal/crypto/kek"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/server"
)

// Generated subject keys must be durably sealed before the CA is called. Supply
// the same credential-sealing dependency as the binary, using a disposable key;
// never bypass that custody requirement to make an issuance fixture succeed.
func issuanceTestKEK(t *testing.T) *seal.LocalKEK {
	t.Helper()
	key, err := kek.LoadOrCreate(filepath.Join(t.TempDir(), "credential.kek"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	return key
}

func oneIssuedCertificate(t *testing.T, ts *httptest.Server, token string) map[string]any {
	t.Helper()
	items := list(t, ts, token, "/api/v1/certificates")
	if len(items) != 1 {
		t.Fatalf("issuance produced %d inventory certificates, want exactly one before testing revocation", len(items))
	}
	return items[0]
}

func TestGeneratedSubjectIssuanceRequiresCredentialSealing(t *testing.T) {
	if testing.Short() {
		t.Skip("assembles real PostgreSQL, NATS and a signer child")
	}
	for _, configured := range []bool{false, true} {
		name := "missing sealing refuses"
		if configured {
			name = "configured sealing issues"
		}
		t.Run(name, func(t *testing.T) {
			st := newStore(t)
			log := openRegisteredTenantLog(t)
			prov, stop := startSignerChild(t)
			defer stop()
			deps := server.Deps{Store: st, Log: log, Signer: prov}
			if configured {
				deps.KEK = issuanceTestKEK(t)
			}
			asm, err := server.Build(context.Background(), deps)
			if err != nil {
				t.Fatal(err)
			}
			ts := httptest.NewServer(asm.Handler())
			defer ts.Close()
			token := mintToken(t, st, "owners:write", "identities:write", "identities:read", "certs:read", "certs:issue")
			owner := created(t, ts, token, "/api/v1/owners", `{"kind":"workload","name":"sealing-control"}`)
			id := created(t, ts, token, "/api/v1/identities", `{"kind":"x509_certificate","name":"sealing.test","owner_id":"`+owner+`"}`)
			transition(t, ts, token, id, "issued")
			if attempted, err := asm.DispatchIssuanceOnce(context.Background()); err != nil || !attempted {
				t.Fatalf("dispatch one issuance: attempted=%v error=%v", attempted, err)
			}
			items := list(t, ts, token, "/api/v1/certificates")
			pending, err := orchestrator.NewOutbox(st).Pending(context.Background(), tenantA)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range pending {
				t.Logf("outbox destination=%s status=%s attempts=%d error=%s", entry.Destination, entry.Status, entry.Attempts, entry.LastError)
			}
			if configured {
				if len(items) != 1 || items[0]["fingerprint"] == "" || len(pending) != 0 {
					t.Fatalf("configured sealing: certificates=%d pending=%d", len(items), len(pending))
				}
			} else {
				if len(items) != 0 || len(pending) != 1 || pending[0].Destination != "ca.issue" || pending[0].Attempts != 1 || pending[0].LastError == "" {
					t.Fatalf("missing sealing must refuse durably before inventory: certificates=%d pending=%d", len(items), len(pending))
				}
			}
			if code, _ := req(t, ts, http.MethodGet, "/healthz", "", ""); code != http.StatusOK {
				t.Fatalf("issuance dependency refusal made the process unhealthy: %d", code)
			}
		})
	}
}
