// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/objectstore/s3test"
	"trstctl.com/trstctl/internal/store"
)

// failingRemovalStore fails a report's removal the three ways an archive can:
// it refuses the delete, acknowledges it without applying it, or cannot be
// read to confirm the report is gone.
type failingRemovalStore struct {
	objectstore.Store
	refuse, keep, unreadable atomic.Bool
}

func (s *failingRemovalStore) Delete(ctx context.Context, name string) error {
	switch {
	case s.refuse.Load():
		return errors.New("AccessDenied: the credential may not delete " + name)
	case s.keep.Load():
		return nil
	}
	return s.Store.Delete(ctx, name)
}

func (s *failingRemovalStore) Head(ctx context.Context, name string) (objectstore.Object, error) {
	if s.unreadable.Load() {
		return objectstore.Object{}, errors.New("read tcp: connection reset by peer")
	}
	return s.Store.Head(ctx, name)
}

// removalFailureRun is one run under the report retention whose archive
// fails its removal as the test says.
type removalFailureRun struct {
	r       *a206Retention
	srv     *s3test.Server
	objects *failingRemovalStore
	run     store.ComplianceReportRun
}

type removalFailure struct {
	Reason        string     `json:"reason"`
	Attempts      int        `json:"attempts"`
	Retrying      bool       `json:"retrying"`
	NextAttemptAt *time.Time `json:"next_attempt_at"`
}

func newRemovalFailureRun(t *testing.T) *removalFailureRun {
	t.Helper()
	srv := s3test.NewServer(t)
	objects := &failingRemovalStore{Store: srv.Open(t)}
	r := newA206Retention(t, objects, 24*time.Hour, 1)
	return &removalFailureRun{r: r, srv: srv, objects: objects, run: r.runs[0]}
}

// read is the run as the API answers it.
func (f *removalFailureRun) read(t *testing.T) (*removalFailure, *time.Time) {
	t.Helper()
	status, body := secretsReq(t, f.r.h, http.MethodGet, "/api/v1/compliance/report-runs/"+f.run.ID, f.r.auditor, nil)
	if status != http.StatusOK {
		t.Fatalf("read run = %d %s", status, body)
	}
	var got struct {
		Failure   *removalFailure `json:"artifact_removal_failure"`
		ExpiredAt *time.Time      `json:"artifact_expired_at"`
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	return got.Failure, got.ExpiredAt
}

// retry makes the pending removal due and delivers it.
func (f *removalFailureRun) retry(t *testing.T) {
	t.Helper()
	if err := f.r.h.store.WithTenant(t.Context(), f.r.h.tenant, func(tx pgx.Tx) error {
		_, err := tx.Exec(t.Context(), `UPDATE outbox SET next_attempt_at = now() WHERE tenant_id = $1 AND destination = $2 AND status = 'pending'`,
			f.r.h.tenant, store.ComplianceReportArtifactExpiryDestination)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	f.r.drain(t)
}

// failed checks the run shows the reason and the row keeps only the class.
func (f *removalFailureRun) failed(t *testing.T, reason, class string, attempts int) {
	t.Helper()
	got, expired := f.read(t)
	if expired != nil || got == nil || got.Reason != reason || got.Attempts != attempts || !got.Retrying ||
		got.NextAttemptAt == nil || !got.NextAttemptAt.After(time.Now().Add(-time.Minute)) {
		t.Fatalf("run after a %s removal: failure %+v, expired %v; want %s after %d attempts, retrying", reason, got, expired, reason, attempts)
	}
	rows := f.r.expiryRows(t, f.run.ID)
	if len(rows) != 1 || !strings.HasSuffix(rows[0], " pending "+class) {
		t.Fatalf("removal rows = %q, want one pending under %s", rows, class)
	}
	if strings.Contains(rows[0], "AccessDenied") || strings.Contains(rows[0], "connection reset") {
		t.Fatalf("the store's own words reached the outbox: %q", rows)
	}
}

// A206-L1: a report removal that keeps failing says why, on the run itself.
// The outbox keeps a closed class on the removal's row, never the store's
// words, and the run's API answer shows the reason (refused, kept or
// unconfirmed), the attempts so far and the next one while it retries. Once a
// removal is confirmed the run reads expired and no failure is shown.
func TestServedReportRemovalFailureSaysWhyA206L1(t *testing.T) {
	t.Run("refused, then kept, then confirmed", func(t *testing.T) {
		f := newRemovalFailureRun(t)
		if got, _ := f.read(t); got != nil {
			t.Fatalf("a run with no removal shows a failure: %+v", got)
		}
		f.objects.refuse.Store(true)
		if n := f.r.expire(t, 25*time.Hour); n != 1 {
			t.Fatalf("sweep queued %d", n)
		}
		f.r.drain(t)
		f.failed(t, "refused", "report_removal_refused", 1)

		f.objects.refuse.Store(false)
		f.objects.keep.Store(true)
		f.retry(t)
		f.failed(t, "kept", "report_removal_kept", 2)

		f.objects.keep.Store(false)
		f.retry(t)
		if got, expired := f.read(t); got != nil || expired == nil {
			t.Fatalf("after a confirmed removal the run reads failure %+v, expired %v", got, expired)
		}
	})
	// The outbox opens a destination's circuit after three failures in a
	// row, so the third reason has a deployment of its own.
	t.Run("unconfirmed", func(t *testing.T) {
		f := newRemovalFailureRun(t)
		f.objects.unreadable.Store(true)
		if n := f.r.expire(t, 25*time.Hour); n != 1 {
			t.Fatalf("sweep queued %d", n)
		}
		f.r.drain(t)
		f.failed(t, "unconfirmed", "report_removal_unconfirmed", 1)
		if _, found := f.srv.Object(f.run.ArtifactRef); found {
			t.Fatal("the delete was applied, yet the report is still in the store")
		}
		f.objects.unreadable.Store(false)
		f.retry(t)
		if got, expired := f.read(t); got != nil || expired == nil {
			t.Fatalf("after a confirmed removal the run reads failure %+v, expired %v", got, expired)
		}
	})
}
