// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/objectstore/s3test"
)

type a208Hold struct {
	ID           string `json:"id"`
	Object       string `json:"object"`
	ReportRunID  string `json:"report_run_id"`
	PlacedBy     string `json:"placed_by"`
	Status       string `json:"status"`
	StatusDetail string `json:"status_detail"`
}

func a208DecodeHold(t *testing.T, body []byte) a208Hold {
	t.Helper()
	var h a208Hold
	if err := json.Unmarshal(body, &h); err != nil {
		t.Fatalf("decode hold %s: %v", body, err)
	}
	return h
}

func (r *a206Retention) holds(t *testing.T) []a208Hold {
	t.Helper()
	status, body := secretsReq(t, r.h, http.MethodGet, "/api/v1/archives/legal-holds", r.auditor, nil)
	if status != http.StatusOK {
		t.Fatalf("list holds = %d %s", status, body)
	}
	var list struct {
		Items []a208Hold `json:"items"`
	}
	if err := json.Unmarshal(body, &list); err != nil {
		t.Fatal(err)
	}
	return list.Items
}

func (r *a206Retention) hold208(t *testing.T, id string) a208Hold {
	t.Helper()
	for _, h := range r.holds(t) {
		if h.ID == id {
			return h
		}
	}
	t.Fatalf("hold %s is not listed", id)
	return a208Hold{}
}

// A208: a person holds one archive object under the tenant's prefix. The hold
// reads pending until the outbox has set it in the bucket and read it back,
// then applied; a release reads released only once the bucket reads it
// cleared. Objects outside the tenant's prefix, missing objects and a second
// hold on one object are refused; a bucket that acknowledges a change without
// applying it leaves the hold pending and retrying, and one without Object
// Lock fails the hold with the reason.
func TestServedArchiveLegalHoldIsSetInTheBucketAndReadBack(t *testing.T) {
	srv := s3test.NewServer(t)
	objects := &lockingObjectStore{Store: srv.Open(t), until: map[string]time.Time{}, holds: map[string]bool{}}
	r := newA206Retention(t, objects, 24*time.Hour, 2)
	object := r.runs[0].ArtifactRef
	place := func(object, reason string) (int, []byte) {
		return secretsReq(t, r.h, http.MethodPost, "/api/v1/archives/legal-holds", r.writer, map[string]string{"object": object, "reason": reason})
	}

	for name, tc := range map[string]struct {
		object string
		want   int
	}{
		"another tenant's prefix": {"tenant/a2080000-0000-4000-8000-0000000000ff/reports/x/" + strings.Repeat("a", 64) + ".json", http.StatusBadRequest},
		"climbing out":            {"tenant/" + r.h.tenant + "/../x", http.StatusBadRequest},
		"missing object":          {"tenant/" + r.h.tenant + "/reports/missing.json", http.StatusNotFound},
	} {
		if status, body := place(tc.object, "litigation"); status != tc.want {
			t.Fatalf("%s: hold = %d %s, want %d", name, status, body, tc.want)
		}
	}
	if status, body := place(object, ""); status != http.StatusBadRequest {
		t.Fatalf("a hold without a reason = %d %s", status, body)
	}
	if status, body := secretsReq(t, r.h, http.MethodPost, "/api/v1/archives/legal-holds", r.auditor, map[string]string{"object": object, "reason": "x"}); status != http.StatusForbidden {
		t.Fatalf("a hold with audit:read = %d %s", status, body)
	}

	status, body := place(object, "regulator request 208")
	if status != http.StatusCreated {
		t.Fatalf("hold = %d %s", status, body)
	}
	hold := a208DecodeHold(t, body)
	if hold.Status != "pending" || hold.PlacedBy == "" || objects.held(object) {
		t.Fatalf("a new hold reads %+v (bucket held %v)", hold, objects.held(object))
	}
	if status, body := place(object, "again"); status != http.StatusConflict {
		t.Fatalf("a second hold on one object = %d %s", status, body)
	}
	r.drain(t)
	if got := r.hold208(t, hold.ID); got.Status != "applied" || !objects.held(object) {
		t.Fatalf("after delivery the hold reads %+v (bucket held %v)", got, objects.held(object))
	}

	status, body = secretsReq(t, r.h, http.MethodDelete, "/api/v1/archives/legal-holds/"+hold.ID, r.writer, nil)
	if status != http.StatusOK || a208DecodeHold(t, body).Status != "release_pending" {
		t.Fatalf("release = %d %s", status, body)
	}
	r.drain(t)
	if got := r.hold208(t, hold.ID); got.Status != "released" || objects.held(object) {
		t.Fatalf("after the release the hold reads %+v (bucket held %v)", got, objects.held(object))
	}

	// A bucket that acknowledges without applying: the hold stays pending.
	objects.mu.Lock()
	objects.ignore = true
	objects.mu.Unlock()
	status, body = place(r.runs[1].ArtifactRef, "acknowledged but not applied")
	if status != http.StatusCreated {
		t.Fatalf("hold = %d %s", status, body)
	}
	ignored := a208DecodeHold(t, body)
	r.drain(t)
	if got := r.hold208(t, ignored.ID); got.Status != "pending" {
		t.Fatalf("an unapplied hold reads %+v", got)
	}

	// A bucket without Object Lock: the hold fails with the reason.
	objects.mu.Lock()
	objects.ignore, objects.noLock = false, true
	objects.mu.Unlock()
	segment := "tenant/" + r.h.tenant + "/audit/audit-1.jws"
	srv.Seed(segment, []byte("a208 segment"))
	status, body = place(segment, "audit records under review")
	if status != http.StatusCreated {
		t.Fatalf("hold = %d %s", status, body)
	}
	failed := a208DecodeHold(t, body)
	r.drain(t)
	if got := r.hold208(t, failed.ID); got.Status != "failed" || !strings.Contains(got.StatusDetail, "Object Lock") {
		t.Fatalf("a hold on a bucket without Object Lock reads %+v", got)
	}
}

// A208: when the archive writes under S3 Object Lock, a report legal hold
// also holds the report's object in the bucket, in the same event; the run
// shows that storage hold's state, its release releases it, and the storage
// hold cannot be released on its own.
func TestServedReportLegalHoldAlsoHoldsItsObjectInTheBucket(t *testing.T) {
	srv := s3test.NewServer(t)
	objects := &lockingObjectStore{Store: srv.Open(t), until: map[string]time.Time{}, holds: map[string]bool{}, configured: true}
	r := newA206Retention(t, objects, 24*time.Hour, 1)
	run := r.runs[0]
	status, body := r.hold(t, run.ID, "litigation hold 2026-208")
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"storage":{"id"`)) || !bytes.Contains(body, []byte(`"status":"pending"`)) {
		t.Fatalf("report hold = %d %s", status, body)
	}
	r.drain(t)
	if !objects.held(run.ArtifactRef) {
		t.Fatal("the report's object is not held in the bucket")
	}
	status, body = secretsReq(t, r.h, http.MethodGet, "/api/v1/compliance/report-runs/"+run.ID, r.auditor, nil)
	if status != http.StatusOK || !bytes.Contains(body, []byte(`"status":"applied"`)) {
		t.Fatalf("held run = %d %s", status, body)
	}
	// The tenant's other holds may be listed too; find this run's.
	var linked a208Hold
	for _, h := range r.holds(t) {
		if h.ReportRunID == run.ID {
			linked = h
		}
	}
	if linked.ID == "" || linked.Object != run.ArtifactRef || linked.Status != "applied" {
		t.Fatalf("the run's storage hold = %+v", linked)
	}
	if status, body := secretsReq(t, r.h, http.MethodDelete, "/api/v1/archives/legal-holds/"+linked.ID, r.writer, nil); status != http.StatusConflict {
		t.Fatalf("releasing a report's storage hold on its own = %d %s", status, body)
	}
	if status, body := r.release(t, run.ID); status != http.StatusOK {
		t.Fatalf("report release = %d %s", status, body)
	}
	r.drain(t)
	if objects.held(run.ArtifactRef) || r.hold208(t, linked.ID).Status != "released" {
		t.Fatalf("after the report's release the bucket hold is %v, hold %+v", objects.held(run.ArtifactRef), r.hold208(t, linked.ID))
	}
}
