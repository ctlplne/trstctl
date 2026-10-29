// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/objectstore/s3test"
)

// Actual API/outbox/bucket-readback recovery. The bucket is a local protocol
// fixture; this does not qualify a vendor S3 implementation or crypto-shred.
func TestServedFailedArchiveHoldReleaseCanBeRetriedWithoutLosingReportHold(t *testing.T) {
	for _, test := range []struct {
		name              string
		linked, competing bool
	}{{name: "archive"}, {name: "report", linked: true}, {name: "competing-archive", competing: true}} {
		t.Run(test.name, func(t *testing.T) {
			linked := test.linked
			srv := s3test.NewServer(t)
			objects := &lockingObjectStore{Store: srv.Open(t), until: map[string]time.Time{}, holds: map[string]bool{}, configured: true}
			r := newA206Retention(t, objects, 24*time.Hour, 1)
			run := r.runs[0]
			var id string
			if linked {
				if status, body := r.hold(t, run.ID, "release recovery"); status != http.StatusOK {
					t.Fatalf("report hold: %d %s", status, body)
				}
			} else {
				status, body := secretsReq(t, r.h, http.MethodPost, "/api/v1/archives/legal-holds", r.writer, map[string]string{"object": run.ArtifactRef, "reason": "release recovery"})
				if status != http.StatusCreated {
					t.Fatalf("archive hold: %d %s", status, body)
				}
				id = a208DecodeHold(t, body).ID
			}
			r.drain(t)
			if linked {
				for _, hold := range r.holds(t) {
					if hold.ReportRunID == run.ID {
						id = hold.ID
					}
				}
			}
			if id == "" || !objects.held(run.ArtifactRef) || r.hold208(t, id).Status != "applied" {
				t.Fatal("hold never reached independent bucket state")
			}
			if linked {
				if status, body := secretsReq(t, r.h, http.MethodDelete, "/api/v1/archives/legal-holds/"+id, r.writer, nil); status != http.StatusConflict {
					t.Fatalf("active report protection bypassed: %d %s", status, body)
				}
			}
			objects.mu.Lock()
			objects.noLock = true
			objects.mu.Unlock()
			var status int
			var body []byte
			if linked {
				status, body = r.release(t, run.ID)
			} else {
				status, body = secretsReq(t, r.h, http.MethodDelete, "/api/v1/archives/legal-holds/"+id, r.writer, nil)
			}
			if status != http.StatusOK {
				t.Fatalf("first release: %d %s", status, body)
			}
			r.drain(t)
			if got := r.hold208(t, id); got.Status != "failed" || !objects.held(run.ArtifactRef) {
				t.Fatalf("failed release falsely cleared hold: %+v", got)
			}
			objects.mu.Lock()
			objects.noLock = false
			objects.mu.Unlock()
			if test.competing {
				status, body = secretsReq(t, r.h, http.MethodPost, "/api/v1/archives/legal-holds", r.writer, map[string]string{"object": run.ArtifactRef, "reason": "a separate current hold"})
				if status != http.StatusCreated {
					t.Fatalf("separate hold: %d %s", status, body)
				}
				other := a208DecodeHold(t, body)
				r.drain(t)
				if r.hold208(t, other.ID).Status != "applied" || !objects.held(run.ArtifactRef) {
					t.Fatal("separate hold not independently applied")
				}
				if status, body := secretsReq(t, r.h, http.MethodDelete, "/api/v1/archives/legal-holds/"+id, r.writer, nil); status != http.StatusConflict {
					t.Fatalf("failed older hold could clear a separate active hold: %d %s", status, body)
				}
				if !objects.held(run.ArtifactRef) {
					t.Fatal("refusal changed the current bucket hold")
				}
				if status, body := secretsReq(t, r.h, http.MethodDelete, "/api/v1/archives/legal-holds/"+other.ID, r.writer, nil); status != http.StatusOK {
					t.Fatalf("release separate hold: %d %s", status, body)
				}
				r.drain(t)
			}
			status, body = secretsReq(t, r.h, http.MethodDelete, "/api/v1/archives/legal-holds/"+id, r.writer, nil)
			if status != http.StatusOK || a208DecodeHold(t, body).Status != "release_pending" {
				t.Fatalf("failed hold has no supported release recovery: %d %s", status, body)
			}
			r.drain(t)
			if got := r.hold208(t, id); got.Status != "released" || objects.held(run.ArtifactRef) {
				t.Fatalf("retry did not clear and read back bucket hold: %+v", got)
			}
		})
	}
}

func TestServedFailedArchiveHoldCanReleaseAfterVerifiedObjectAbsence(t *testing.T) {
	srv := s3test.NewServer(t)
	objects := &lockingObjectStore{Store: srv.Open(t), until: map[string]time.Time{}, holds: map[string]bool{}, configured: true}
	r := newA206Retention(t, objects, 24*time.Hour, 1)
	object := r.runs[0].ArtifactRef
	objects.mu.Lock()
	objects.noLock = true
	objects.mu.Unlock()
	status, body := secretsReq(t, r.h, http.MethodPost, "/api/v1/archives/legal-holds", r.writer, map[string]string{"object": object, "reason": "placement failed before the object disappeared"})
	if status != http.StatusCreated {
		t.Fatalf("place hold: %d %s", status, body)
	}
	hold := a208DecodeHold(t, body)
	r.drain(t)
	if got := r.hold208(t, hold.ID); got.Status != "failed" || objects.held(object) {
		t.Fatalf("fixture did not fail before applying the hold: %+v", got)
	}
	// This object was never held. Remove only the test-created object, then
	// require the receiver's separate readback to prove current absence.
	if err := objects.Delete(t.Context(), object); err != nil {
		t.Fatal(err)
	}
	status, body = secretsReq(t, r.h, http.MethodDelete, "/api/v1/archives/legal-holds/"+hold.ID, r.writer, nil)
	if status != http.StatusOK {
		t.Fatalf("missing-object release recovery: %d %s", status, body)
	}
	r.drain(t)
	if got := r.hold208(t, hold.ID); got.Status != "released" || got.StatusDetail != "object_absence_verified" {
		t.Fatalf("independently absent object left an unrecoverable hold: %+v", got)
	}
}
