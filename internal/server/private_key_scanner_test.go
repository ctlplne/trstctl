// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// Proving a negative: no private key bytes control-plane side (epic B2).
//
// Every other test in this repo proves that something works. This one proves
// that something is ABSENT, which is a different and harder claim, and the
// existing "no canary" helpers do not make it:
//
//   - assertNoCanaryInJobRows selects outbox.last_error and required_agent_role.
//     It never reads outbox.payload — which is exactly where a sealed deploy
//     keeps its key bytes.
//   - assertNoCanaryInEvents looks for a PLAINTEXT canary in the event log. A
//     sealed side_effect.payload never contains plaintext, so that assertion
//     passes over a row full of encrypted key material without noticing.
//
// Both were written for a different question ("did this string leak into an
// error message") and answer it well. B2's criterion is stronger: encrypted key
// bytes are still key bytes, because "we encrypted it" is not the same claim as
// "we never had it".

// pemPrivateKeyMarkers are the PEM preambles a private key can arrive under.
//
// Structural rather than a fixed canary string: the point is to catch key
// material this test did not plant, including material a future change starts
// storing. A canary only finds what the test already knows about.
var pemPrivateKeyMarkers = [][]byte{
	[]byte("-----BEGIN PRIVATE KEY-----"),
	[]byte("-----BEGIN RSA PRIVATE KEY-----"),
	[]byte("-----BEGIN EC PRIVATE KEY-----"),
	[]byte("-----BEGIN ENCRYPTED PRIVATE KEY-----"),
	[]byte("-----BEGIN OPENSSH PRIVATE KEY-----"),
	// The JSON field a connector deploy payload uses. Present in an UNSEALED
	// payload only — a sealed one is ciphertext — which is precisely why this
	// scanner also has to assert the sealing invariant separately.
	[]byte(`"key_pem"`),
}

// scanForPrivateKeyMaterial reports every column value carrying a private-key
// marker, with enough context to identify the row.
type keyMaterialFinding struct {
	Table  string
	Column string
	Marker string
	RowRef string
}

// assertNoPrivateKeyMaterial walks the control-plane tables that could hold a
// deploy payload and fails on any private-key marker.
//
// SCOPE, stated honestly, in three parts:
//
//  1. It proves no PLAINTEXT private key rests in these tables. It cannot prove
//     the absence of SEALED key bytes, because sealed bytes are
//     indistinguishable from any other ciphertext — that property is
//     established by the executor parity gate refusing to build such a payload
//     in the first place.
//  2. It covers POSTGRES only. The append-only event log is NATS JetStream, not
//     a table, so no SQL scan reaches it. What protects the log is upstream: the
//     renewal path never constructs a payload with key bytes, so there is
//     nothing for an event to carry.
//  3. It scans one tenant's rows. That is the right scope — it runs inside a
//     tenant-scoped test — but it is not an estate-wide audit.
func assertNoPrivateKeyMaterial(t *testing.T, ctx context.Context, store interface {
	WithTenant(context.Context, string, func(pgx.Tx) error) error
}, tenantID string) []keyMaterialFinding {
	t.Helper()
	var findings []keyMaterialFinding

	// Every table that can hold a payload, an event, or a receipt. Listed
	// explicitly rather than discovered, so adding a table that can carry a
	// payload is a deliberate act that updates this list.
	scans := []struct{ table, column, ref string }{
		{"outbox", "payload", "id"},
		{"outbox", "last_error", "id"},
		{"connector_delivery_receipts", "detail", "id"},
		{"connector_delivery_receipts", "reason", "id"},
		{"connector_delivery_receipts", "rollback_ref", "id"},
		{"lifecycle_rotation_runs", "error", "id"},
		// The agent's own signed words. The statement is what the agent said and
		// the signature commits to it, so a relay that echoed key material into
		// its report would land here verbatim.
		{"agent_job_receipts", "statement", "job_id"},
		{"agent_job_receipts", "reason", "job_id"},
		{"certificates", "certificate_der", "id"},
		{"endpoint_verifications", "detail", "endpoint_id"},
	}

	// Resolve which of the listed columns actually exist BEFORE scanning.
	//
	// The previous shape ran each scan and swallowed the error, which was wrong
	// twice over: a failed query aborts its transaction so the commit failed
	// anyway, and — worse — a scanner that silently skips what it cannot read
	// reports "no key material found" for a table it never opened. That is the
	// precise failure this whole workstream exists to remove, and it would have
	// been sitting inside the test that proves the absence.
	present := map[string]bool{}
	if err := store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			//trstctl:system-query — test-only schema probe; reads no tenant rows.
			`SELECT table_name, column_name FROM information_schema.columns
			  WHERE table_schema = current_schema()`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var table, column string
			if err := rows.Scan(&table, &column); err != nil {
				return err
			}
			present[table+"."+column] = true
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("resolve scannable columns: %v", err)
	}

	scanned := 0
	for _, scan := range scans {
		scan := scan
		// A table absent from this schema is not a finding. A table that is
		// present but missing the named column IS one: the list has drifted and
		// the scanner would be quietly checking less than it claims.
		if !present[scan.table+"."+scan.ref] || !present[scan.table+"."+scan.column] {
			if present[scan.table+".tenant_id"] {
				t.Errorf("the key scanner names %s.%s, which this schema does not have; the "+
					"scan list has drifted and is checking less than it says",
					scan.table, scan.column)
			}
			continue
		}
		err := store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx,
				//trstctl:system-query — test-only scan of this tenant's own rows for key material.
				`SELECT `+scan.ref+`::text, coalesce(`+scan.column+`::text, '') FROM `+scan.table+
					` WHERE tenant_id = $1`, tenantID)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var ref, value string
				if err := rows.Scan(&ref, &value); err != nil {
					return err
				}
				for _, marker := range pemPrivateKeyMarkers {
					if bytes.Contains([]byte(value), marker) {
						findings = append(findings, keyMaterialFinding{
							Table: scan.table, Column: scan.column,
							Marker: string(marker), RowRef: ref,
						})
					}
				}
			}
			return rows.Err()
		})
		if err != nil {
			t.Fatalf("scan %s.%s: %v", scan.table, scan.column, err)
		}
		scanned++
	}
	// A scan that opened nothing proves nothing, and would report a clean estate.
	if scanned == 0 {
		t.Fatal("the key scanner opened no tables at all, so its clean result means nothing")
	}
	return findings
}

// The scanner must actually find planted material, or it proves nothing.
//
// A scanner that cannot fail is worse than no scanner: it converts an unchecked
// property into a checked-looking one, and every later change is measured
// against a test that was always going to pass.
func TestThePrivateKeyScannerDetectsPlantedMaterial(t *testing.T) {
	t.Parallel()
	planted := []string{
		`{"key_pem":"-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----"}`,
		"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----",
		"-----BEGIN EC PRIVATE KEY-----\nMHc\n-----END EC PRIVATE KEY-----",
		"-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIF\n-----END ENCRYPTED PRIVATE KEY-----",
	}
	for _, value := range planted {
		found := false
		for _, marker := range pemPrivateKeyMarkers {
			if bytes.Contains([]byte(value), marker) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("the scanner would not detect planted key material: %.60s", value)
		}
	}

	// And it must not fire on material that is NOT a private key. A scanner
	// that flags certificates would be turned off within a week.
	safe := []string{
		"-----BEGIN CERTIFICATE-----\nMIID\n-----END CERTIFICATE-----",
		"-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----",
		"-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----",
		`{"cert_pem":"-----BEGIN CERTIFICATE-----"}`,
	}
	for _, value := range safe {
		for _, marker := range pemPrivateKeyMarkers {
			if bytes.Contains([]byte(value), marker) {
				t.Errorf("the scanner fires on non-key material %.40s (marker %q); a scanner that "+
					"flags certificates gets switched off", value, marker)
			}
		}
	}
}
