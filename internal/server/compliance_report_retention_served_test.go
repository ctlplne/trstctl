// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/objectstore/s3test"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// a206Retention is a served deployment with the report retention on and count
// completed evidence-pack runs the real scheduler produced, their reports in
// the archive directory or, with objects, in that object store.
type a206Retention struct {
	h        *servedHarness
	runs     []store.ComplianceReportRun
	archive  string
	writer   string
	auditor  string
	schedule []string
	due      time.Time
}

func newA206Retention(t *testing.T, objects objectstore.Store, retention time.Duration, count int) *a206Retention {
	t.Helper()
	key, err := crypto.GenerateLockedKey(crypto.ECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	signer := evidencePackReportSigner{&reportWorkerSigner{key: key}}
	r := &a206Retention{archive: filepath.Join(t.TempDir(), "archive"), due: time.Now().UTC().Add(-time.Hour)}
	if err := os.Mkdir(r.archive, 0o700); err != nil {
		t.Fatal(err)
	}
	r.h = newOperatingServedHarness(t, config.Protocols{}, func(d *Deps) {
		if objects != nil {
			d.ArchiveObjectStore = objects
		} else {
			d.AuditArchiveDir = r.archive
		}
		d.ComplianceReportRetention = retention
		d.APIOptions = append(d.APIOptions, api.WithComplianceEvidence(signer))
	})
	ctx := t.Context()
	for i := 0; i < count; i++ {
		scheduleID := fmt.Sprintf("a2060000-0000-4000-8000-%012x", 0xd00+i)
		r.schedule = append(r.schedule, scheduleID)
		r.upsertSchedule(t, scheduleID, i, true)
	}
	if processed, err := r.h.srv.RunComplianceReportsOnce(ctx); err != nil || processed != count {
		t.Fatalf("due sweep = %d, %v", processed, err)
	}
	for _, scheduleID := range r.schedule {
		run, err := r.h.store.GetComplianceReportRunByDue(ctx, r.h.tenant, scheduleID, r.due)
		if err != nil || run.Status != "completed" {
			t.Fatalf("evidence-pack run = %+v, %v", run, err)
		}
		r.runs = append(r.runs, run)
	}
	r.writer = seedScopedToken(t, r.h.store, r.h.tenant, "audit:write")
	r.auditor = seedScopedToken(t, r.h.store, r.h.tenant, "audit:read")
	return r
}

func (r *a206Retention) upsertSchedule(t *testing.T, scheduleID string, i int, enabled bool) {
	t.Helper()
	ctx := t.Context()
	seed, err := r.h.log.Append(ctx, events.Event{
		TenantID: r.h.tenant, Type: projections.EventComplianceReportScheduleUpserted,
		Time: r.due.Add(-7 * 24 * time.Hour), SchemaVersion: 1,
		Data: []byte(fmt.Sprintf(`{"id":%q,"framework":"soc2","name":"retention pack %d","report_type":"framework_evidence_pack","interval_seconds":604800,"enabled":%t,"delivery":"audit_export"}`,
			scheduleID, i, enabled)),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(r.h.store).Apply(ctx, seed); err != nil {
		t.Fatal(err)
	}
}

// expire runs the retention sweep as of after (a time past the window) and
// returns how many removals it queued.
func (r *a206Retention) expire(t *testing.T, after time.Duration) int {
	t.Helper()
	queued, err := r.h.srv.expireComplianceReportsOnce(t.Context(), time.Now().UTC().Add(after))
	if err != nil {
		t.Fatalf("retention sweep: %v", err)
	}
	return queued
}

func (r *a206Retention) drain(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	if err := r.h.srv.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
}

func (r *a206Retention) run(t *testing.T, id string) store.ComplianceReportRun {
	t.Helper()
	run, err := r.h.store.GetComplianceReportRun(t.Context(), r.h.tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func (r *a206Retention) hold(t *testing.T, id, reason string) (int, []byte) {
	t.Helper()
	return secretsReq(t, r.h, http.MethodPost, "/api/v1/compliance/report-runs/"+id+"/legal-hold", r.writer, map[string]string{"reason": reason})
}

func (r *a206Retention) release(t *testing.T, id string) (int, []byte) {
	t.Helper()
	return secretsReq(t, r.h, http.MethodDelete, "/api/v1/compliance/report-runs/"+id+"/legal-hold", r.writer, nil)
}

func (r *a206Retention) download(t *testing.T, id string) (int, []byte) {
	t.Helper()
	return secretsReq(t, r.h, http.MethodGet, "/api/v1/compliance/report-runs/"+id+"/artifact", r.auditor, nil)
}

// expiryRows lists the outbox rows that remove the run's report.
func (r *a206Retention) expiryRows(t *testing.T, id string) []string {
	t.Helper()
	var rows []string
	if err := r.h.store.WithTenant(t.Context(), r.h.tenant, func(tx pgx.Tx) error {
		result, err := tx.Query(t.Context(), `SELECT idempotency_key || ' ' || status || ' ' || coalesce(last_error, '')
			FROM outbox WHERE tenant_id = $1 AND destination = $2 AND idempotency_key LIKE $3 ORDER BY id`,
			r.h.tenant, store.ComplianceReportArtifactExpiryDestination, "report-expiry:"+id+":%")
		if err != nil {
			return err
		}
		defer result.Close()
		for result.Next() {
			var row string
			if err := result.Scan(&row); err != nil {
				return err
			}
			rows = append(rows, row)
		}
		return result.Err()
	}); err != nil {
		t.Fatal(err)
	}
	return rows
}

// A206: with audit.report_retention, the sweep queues the removal of every
// completed report older than the window that no person holds; the outbox
// removes it where the run's reference says, confirms it is gone, and only
// then records it expired, after which the download answers 410. A held
// report outlives the window, a release returns it to the retention, and a
// rebuild from the log reaches the same state.
func TestServedReportRetentionRemovesUnheldReportsAndKeepsHeldOnes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		objects func(t *testing.T) (objectstore.Store, func(ref string) bool)
	}{
		{"archive directory", nil},
		{"object store", func(t *testing.T) (objectstore.Store, func(string) bool) {
			srv := s3test.NewServer(t)
			return srv.Open(t), func(ref string) bool { _, found := srv.Object(ref); return found }
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var objects objectstore.Store
			var inObjects func(string) bool
			if tc.objects != nil {
				objects, inObjects = tc.objects(t)
			}
			r := newA206Retention(t, objects, 24*time.Hour, 2)
			present := func(run store.ComplianceReportRun) bool {
				if inObjects != nil {
					return inObjects(run.ArtifactRef)
				}
				_, err := os.Stat(filepath.Join(r.archive, filepath.FromSlash(run.ArtifactRef)))
				return err == nil
			}
			held, unheld := r.runs[0], r.runs[1]

			status, body := r.hold(t, held.ID, "  litigation hold 2026-117  ")
			if status != http.StatusOK {
				t.Fatalf("hold = %d %s", status, body)
			}
			var got struct {
				LegalHold *struct {
					Reason string    `json:"reason"`
					By     string    `json:"by"`
					At     time.Time `json:"at"`
				} `json:"legal_hold"`
				ArtifactExpiredAt *time.Time `json:"artifact_expired_at"`
			}
			if err := json.Unmarshal(body, &got); err != nil || got.LegalHold == nil ||
				got.LegalHold.Reason != "litigation hold 2026-117" || got.LegalHold.By == "" || got.LegalHold.At.IsZero() {
				t.Fatalf("held run = %s (%v)", body, err)
			}
			if status, body := r.hold(t, held.ID, "again"); status != http.StatusConflict {
				t.Fatalf("a second hold = %d %s", status, body)
			}
			if status, body := r.hold(t, unheld.ID, " "); status != http.StatusBadRequest {
				t.Fatalf("a hold with no reason = %d %s", status, body)
			}
			if status, body := r.hold(t, unheld.ID, strings.Repeat("r", 513)); status != http.StatusBadRequest {
				t.Fatalf("a hold with a 513-character reason = %d %s", status, body)
			}
			if status, body := secretsReq(t, r.h, http.MethodPost, "/api/v1/compliance/report-runs/"+unheld.ID+"/legal-hold", r.auditor,
				map[string]string{"reason": "read-only"}); status != http.StatusForbidden {
				t.Fatalf("a hold with audit:read = %d %s", status, body)
			}
			if status, body := r.release(t, unheld.ID); status != http.StatusConflict {
				t.Fatalf("a release of an unheld run = %d %s", status, body)
			}
			if status, body := r.hold(t, "a2060000-0000-4000-8000-00000000ffff", "missing"); status != http.StatusNotFound {
				t.Fatalf("a hold on a missing run = %d %s", status, body)
			}

			// Inside the window nothing is queued; past it only the unheld
			// report is, once.
			if n := r.expire(t, 0); n != 0 {
				t.Fatalf("inside the window the sweep queued %d", n)
			}
			if n := r.expire(t, 25*time.Hour); n != 1 {
				t.Fatalf("past the window the sweep queued %d, want the unheld report", n)
			}
			if n := r.expire(t, 25*time.Hour); n != 0 {
				t.Fatalf("a second sweep queued %d again", n)
			}
			if !present(unheld) {
				t.Fatal("the report went before the outbox delivered its removal")
			}
			r.drain(t)
			if present(unheld) {
				t.Fatal("the unheld report is still in the archive")
			}
			gone := r.run(t, unheld.ID)
			if gone.Retention.ArtifactExpiredAt == nil {
				t.Fatalf("the removed run reads %+v", gone.Retention)
			}
			if rows := r.expiryRows(t, unheld.ID); len(rows) != 1 || !strings.Contains(rows[0], " delivered") {
				t.Fatalf("removal rows = %q", rows)
			}
			status, body = secretsReq(t, r.h, http.MethodGet, "/api/v1/compliance/report-runs/"+unheld.ID, r.auditor, nil)
			if status != http.StatusOK || !bytes.Contains(body, []byte(`"artifact_expired_at"`)) {
				t.Fatalf("expired run = %d %s", status, body)
			}
			if status, body := r.download(t, unheld.ID); status != http.StatusGone || !bytes.Contains(body, []byte("report retention removed")) {
				t.Fatalf("download of the removed report = %d %s", status, body)
			}
			if status, body := r.hold(t, unheld.ID, "too late"); status != http.StatusConflict {
				t.Fatalf("a hold on the removed report = %d %s", status, body)
			}
			if !present(held) {
				t.Fatal("the held report was removed")
			}
			if status, body := r.download(t, held.ID); status != http.StatusOK || r.h.srv.api.VerifyScheduledComplianceArtifact(body, held) != nil {
				t.Fatalf("download of the held report = %d (%d bytes)", status, len(body))
			}

			// The release returns the run to the retention.
			status, body = r.release(t, held.ID)
			if status != http.StatusOK || bytes.Contains(body, []byte(`"legal_hold"`)) {
				t.Fatalf("release = %d %s", status, body)
			}
			if n := r.expire(t, 25*time.Hour); n != 1 {
				t.Fatalf("after the release the sweep queued %d", n)
			}
			r.drain(t)
			if present(held) || r.run(t, held.ID).Retention.ArtifactExpiredAt == nil {
				t.Fatal("the released report was not removed")
			}

			// A rebuild from the log converges on the same holds and removals.
			if err := r.h.srv.proj.Rebuild(t.Context(), r.h.log); err != nil {
				t.Fatalf("rebuild: %v", err)
			}
			for _, run := range r.runs {
				rebuilt := r.run(t, run.ID)
				if rebuilt.Retention.ArtifactExpiredAt == nil || rebuilt.Retention.Held() {
					t.Fatalf("rebuilt run %s reads %+v", run.ID, rebuilt.Retention)
				}
				if rows := r.expiryRows(t, run.ID); len(rows) != 1 {
					t.Fatalf("the rebuild queued removal rows again: %q", rows)
				}
			}
		})
	}
}

// A hold placed after the removal was queued cancels it: the delivery leaves
// the report, and only a release queues the removal again, as a new row.
func TestServedReportLegalHoldCancelsAQueuedRemoval(t *testing.T) {
	r := newA206Retention(t, nil, 24*time.Hour, 1)
	run := r.runs[0]
	if n := r.expire(t, 25*time.Hour); n != 1 {
		t.Fatalf("sweep queued %d", n)
	}
	if status, body := r.hold(t, run.ID, "regulator request 44"); status != http.StatusOK {
		t.Fatalf("hold = %d %s", status, body)
	}
	if got := r.run(t, run.ID).Retention; got.ExpiryRequestedAt != nil || !got.Held() {
		t.Fatalf("held run reads %+v", got)
	}
	r.drain(t)
	if status, _ := r.download(t, run.ID); status != http.StatusOK {
		t.Fatalf("download after the cancelled removal = %d", status)
	}
	if got := r.run(t, run.ID).Retention; got.ArtifactExpiredAt != nil {
		t.Fatalf("the held run was recorded expired: %+v", got)
	}
	if n := r.expire(t, 25*time.Hour); n != 0 {
		t.Fatalf("the sweep queued %d for a held run", n)
	}
	if status, body := r.release(t, run.ID); status != http.StatusOK {
		t.Fatalf("release = %d %s", status, body)
	}
	if n := r.expire(t, 25*time.Hour); n != 1 {
		t.Fatalf("after the release the sweep queued %d", n)
	}
	r.drain(t)
	if status, _ := r.download(t, run.ID); status != http.StatusGone {
		t.Fatalf("download after the second removal = %d", status)
	}
	if rows := r.expiryRows(t, run.ID); len(rows) != 2 || rows[0] == rows[1] {
		t.Fatalf("removal rows = %q, want one per request", rows)
	}
}

// keepingObjectStore can acknowledge a delete without applying it, as a store
// that answers a delete it did not perform would.
type keepingObjectStore struct {
	objectstore.Store
	keep atomic.Bool
}

func (s *keepingObjectStore) Delete(ctx context.Context, name string) error {
	if s.keep.Load() {
		return nil
	}
	return s.Store.Delete(ctx, name)
}

// The run is recorded expired only after an independent read finds the
// report gone: a delete the store acknowledged but did not apply leaves the
// run unexpired, its report downloadable and the removal retrying.
func TestServedReportRetentionNeverRecordsARemovalItCannotConfirm(t *testing.T) {
	srv := s3test.NewServer(t)
	objects := &keepingObjectStore{Store: srv.Open(t)}
	objects.keep.Store(true)
	r := newA206Retention(t, objects, 24*time.Hour, 1)
	run := r.runs[0]
	if n := r.expire(t, 25*time.Hour); n != 1 {
		t.Fatalf("sweep queued %d", n)
	}
	r.drain(t)
	if got := r.run(t, run.ID).Retention; got.ArtifactExpiredAt != nil {
		t.Fatalf("an unconfirmed removal was recorded: %+v", got)
	}
	if _, found := srv.Object(run.ArtifactRef); !found {
		t.Fatal("the object went")
	}
	if status, _ := r.download(t, run.ID); status != http.StatusOK {
		t.Fatalf("download while the removal retries = %d", status)
	}
	// The outbox keeps the row pending under its failure class and retries.
	rows := r.expiryRows(t, run.ID)
	if len(rows) != 1 || !strings.Contains(rows[0], " pending external_delivery_failed") {
		t.Fatalf("removal rows = %q, want one retrying", rows)
	}
	objects.keep.Store(false)
	if err := r.h.store.WithTenant(t.Context(), r.h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `UPDATE outbox SET next_attempt_at = now() WHERE tenant_id = $1 AND destination = $2 AND status = 'pending'`,
			r.h.tenant, store.ComplianceReportArtifactExpiryDestination)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	r.drain(t)
	if got := r.run(t, run.ID).Retention; got.ArtifactExpiredAt == nil {
		t.Fatalf("the confirmed removal was not recorded: %+v", got)
	}
	if _, found := srv.Object(run.ArtifactRef); found {
		t.Fatal("the object is still in the store")
	}
}

// A hold that meets a removal in flight is refused with a retry rather than
// recorded after the report is gone; once the removal lands, the run reads
// expired and cannot be held.
func TestServedReportLegalHoldWaitsForARemovalInFlight(t *testing.T) {
	srv := s3test.NewServer(t)
	r := newA206Retention(t, srv.Open(t), 24*time.Hour, 1)
	run := r.runs[0]
	if n := r.expire(t, 25*time.Hour); n != 1 {
		t.Fatalf("sweep queued %d", n)
	}
	release := srv.Stall(http.MethodDelete)
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		done <- r.h.srv.Drain(ctx)
	}()
	deadline := time.Now().Add(15 * time.Second)
	for !a206Requested(srv.Requests(), "DELETE "+run.ArtifactRef) {
		if time.Now().After(deadline) {
			release()
			t.Fatalf("the removal never reached the store: %q", srv.Requests())
		}
		time.Sleep(20 * time.Millisecond)
	}
	status, body := r.hold(t, run.ID, "late hold")
	release()
	if status != http.StatusConflict || !bytes.Contains(body, []byte("retry")) {
		t.Fatalf("a hold during the removal = %d %s", status, body)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := r.run(t, run.ID).Retention; got.ArtifactExpiredAt == nil || got.Held() {
		t.Fatalf("after the removal the run reads %+v", got)
	}
	if status, _ := r.hold(t, run.ID, "late hold"); status != http.StatusConflict {
		t.Fatalf("a hold after the removal = %d", status)
	}
}

func a206Requested(requests []string, want string) bool {
	for _, request := range requests {
		if request == want {
			return true
		}
	}
	return false
}

// The retention rides the report sweep even when every schedule is paused.
func TestServedReportRetentionRunsWithEverySchedulePaused(t *testing.T) {
	r := newA206Retention(t, nil, time.Millisecond, 1)
	r.upsertSchedule(t, r.schedule[0], 0, false)
	time.Sleep(5 * time.Millisecond)
	if processed, err := r.h.srv.RunComplianceReportsOnce(t.Context()); err != nil || processed != 0 {
		t.Fatalf("sweep with every schedule paused = %d, %v", processed, err)
	}
	if got := r.run(t, r.runs[0].ID).Retention; got.ExpiryRequestedAt == nil {
		t.Fatalf("the paused schedule's report was not queued for removal: %+v", got)
	}
}
