// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/certtest"
	"trstctl.com/trstctl/internal/store"
)

// B11-8 follow-up (owner finding): the compromised-key check once read and
// parsed every keyCompromise-revoked certificate of the tenant on every
// issuance and refused all issuance beyond 10,000, so a mass key-compromise
// revocation stopped the replacement issuance it exists to protect. A tenant
// with more than 10,000 recorded keyCompromise revocations — 10,000 left by an
// older build and backfilled, one more recorded by the revocation projection —
// still issues for a fresh key and still refuses a recorded one.
func TestServedCompromisedKeyCheckScalesPastTenThousandRevocations(t *testing.T) {
	const bulk = 10000
	h := newOperatingServedHarness(t, config.Protocols{})
	ctx := t.Context()
	ders, err := certtest.DistinctLeaves(bulk, "mass-compromise")
	if err != nil {
		t.Fatal(err)
	}
	fingerprints := make([]string, len(ders))
	jobs := make(chan int)
	errs := make(chan error, 8)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				info, err := certinfo.Inspect(ders[i])
				if err == nil {
					fingerprints[i] = info.SHA256Fingerprint
					_, err = h.store.UpsertCertificate(ctx, store.Certificate{TenantID: h.tenant, Subject: info.Subject,
						Fingerprint: info.SHA256Fingerprint, CertificateDER: ders[i], Source: "import"})
				}
				if err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	for i := range ders {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	close(errs)
	if err := <-errs; err != nil {
		t.Fatalf("seed certificates: %v", err)
	}
	// The revocations an older build projected: certificate rows marked
	// keyCompromise, with no recorded subject keys.
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE certificates SET status = 'revoked', revocation_reason = 'keyCompromise', revoked_at = now()
			WHERE tenant_id = $1 AND fingerprint = ANY($2)`, h.tenant, fingerprints)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	recorded, unreadable, err := h.store.BackfillCompromisedSubjectKeys(ctx)
	if err != nil || recorded < bulk || unreadable != 0 {
		t.Fatalf("backfill recorded=%d unreadable=%d err=%v; want at least %d", recorded, unreadable, err, bulk)
	}
	if again, _, err := h.store.BackfillCompromisedSubjectKeys(ctx); err != nil || again != 0 {
		t.Fatalf("a second backfill recorded %d keys (err=%v); want none", again, err)
	}
	compromised := compromisedSubjectSigner(t, h.store, h.tenant)
	var keys int
	if err := h.store.SystemPool().QueryRow(ctx, `SELECT count(*) FROM compromised_subject_keys WHERE tenant_id = $1`, h.tenant).Scan(&keys); err != nil || keys <= bulk {
		t.Fatalf("recorded compromised keys = %d (err=%v); want more than %d", keys, err, bulk)
	}

	// The check is one lookup on the (tenant, SPKI hash) index, not a scan of
	// the tenant's revocations.
	if _, err := h.store.SystemPool().Exec(ctx, `ANALYZE compromised_subject_keys`); err != nil {
		t.Fatal(err)
	}
	var plan strings.Builder
	if err := h.store.WithTenant(ctx, h.tenant, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `EXPLAIN (FORMAT TEXT) SELECT certificate_fingerprint FROM compromised_subject_keys
			WHERE tenant_id = $1 AND spki_sha256 = $2 ORDER BY revoked_at, certificate_fingerprint LIMIT 1`,
			h.tenant, strings.Repeat("a", 64))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var line string
			if err := rows.Scan(&line); err != nil {
				return err
			}
			plan.WriteString(line + "\n")
		}
		return rows.Err()
	}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.String(), "compromised_subject_keys_spki_idx") {
		t.Fatalf("the compromised-key lookup does not use the (tenant, SPKI hash) index:\n%s", plan.String())
	}

	tok := seedScopedToken(t, h.store, h.tenant, "owners:read", "owners:write", "identities:read", "identities:write", "certs:read", "certs:issue")
	owner, err := h.store.CreateOwner(ctx, store.Owner{TenantID: h.tenant, Kind: store.OwnerWorkload, Name: "replacement"})
	if err != nil {
		t.Fatal(err)
	}
	issue := func(name string, key *crypto.LockedSigner) (int, []byte) {
		t.Helper()
		status, body := secretsReq(t, h, http.MethodPost, "/api/v1/identities", tok, map[string]any{"owner_id": owner.ID, "kind": "x509", "name": name})
		var ident struct {
			ID string `json:"id"`
		}
		if status != http.StatusCreated || json.Unmarshal(body, &ident) != nil {
			t.Fatalf("create identity %s = %d: %s", name, status, body)
		}
		csr := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: badSubjectCSR(t, key,
			crypto.CertificateRequestTemplate{CommonName: name, DNSNames: []string{name}})})
		start := time.Now()
		status, body = secretsReq(t, h, http.MethodPost, "/api/v1/identities/"+ident.ID+"/transitions", tok, map[string]any{
			"to": "issued", "reason": "replacement after mass compromise", "subject_csr_pem": string(csr),
		})
		t.Logf("issue %s: %d in %s", name, status, time.Since(start))
		return status, body
	}
	fresh, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(fresh.Destroy)
	if status, body := issue("replacement.example.test", fresh); status != http.StatusOK {
		t.Fatalf("issuance for a fresh key after %d keyCompromise revocations = %d: %s", keys, status, body)
	}
	status, body := issue("reused.example.test", compromised)
	if status != http.StatusBadRequest {
		t.Fatalf("issuance for a recorded compromised key = %d, want 400: %s", status, body)
	}
	assertRefusalNames(t, "REST transition at scale", badSubjectKeys[1], body)
}
