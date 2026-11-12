// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// OD-11 (A233-L5): an offboarded tenant chose a one-second retention window,
// but the operator's audit retention floor keeps its key (and so its audit
// archives, history and backups readable) until the floor has passed since
// the offboard. Waiting for the floor spends none of the destruction's retry
// budget, the key is destroyed once the floor ends, and the public hold
// clearance written before the removal records what kept it and until when.
func TestServedEventKeyDestructionWaitsForTheAuditRetentionFloorOD11(t *testing.T) {
	stack := newDoneWhenStack(t)
	const floorSeconds = 6
	stack.cfg.Privacy.EventProtection.AuditRetentionFloor = "6s"
	const tenant = "8c4e3fbd-5a6b-4d0c-8f9e-4b7a1d3c2e65"
	srv, log, runtime, key := stack.open(t)
	registered, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: []byte(`{"name":"retention floor"}`)})
	if err != nil {
		t.Fatal(err)
	}
	if err := projections.New(stack.st, runtime.projectionOptions()...).Apply(t.Context(), registered); err != nil {
		t.Fatal(err)
	}
	token := seedServedAPIToken(t, t.Context(), stack.st, tenant, "operator-floor@example.invalid",
		[]string{string(authz.PrivacyRead), string(authz.PrivacyWrite)})
	call := doneWhenCaller(srv)
	body := `{"registration_identity":"` + registered.ID + `","retention":"1s"}`
	if code, out := call(http.MethodPost, "/api/v1/privacy/event-protection", token, body, "floor-opt-in"); code != http.StatusAccepted {
		t.Fatalf("enable HTTP=%d %s", code, out)
	}
	if err := srv.Drain(t.Context()); err != nil {
		t.Fatal(err)
	}
	if code, out := call(http.MethodGet, "/api/v1/privacy/event-protection", token, "", ""); code != http.StatusOK || !bytes.Contains(out, []byte(`"state":"active"`)) {
		t.Fatalf("not active after the worker: HTTP=%d %s", code, out)
	}
	keyRef := doneWhenKeyRef(t, runtime, tenant)

	offboard, err := srv.orch.OffboardTenant(t.Context(), orchestrator.TenantOffboardCommand{TenantID: tenant, RegistrationIdentity: registered.ID})
	if err != nil {
		t.Fatal(err)
	}
	floorEnds := offboard.Time.Add(floorSeconds * time.Second)

	// Past the tenant's one-second window, inside the floor: the key stays.
	for time.Now().Before(offboard.Time.Add(3 * time.Second)) {
		if err := srv.Drain(t.Context()); err != nil {
			t.Fatal(err)
		}
		if _, erased, err := runtime.custody.DestructionReceipt(t.Context(), keyRef); err != nil || erased {
			t.Fatalf("inside the operator's floor: erased=%v err=%v", erased, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	var attempts int
	var status string
	if err := stack.st.SystemPool().QueryRow(t.Context(), `SELECT attempts, status FROM outbox WHERE tenant_id = $1 AND destination = $2`,
		tenant, store.EventKeyDestructionDestination).Scan(&attempts, &status); err != nil {
		t.Fatal(err)
	}
	if attempts != 0 || status == "dead" {
		t.Fatalf("waiting for the floor spent the retry budget: attempts=%d status=%s", attempts, status)
	}

	receipt := ""
	for deadline := floorEnds.Add(45 * time.Second); receipt == ""; {
		if err := srv.Drain(t.Context()); err != nil {
			t.Fatal(err)
		}
		got, erased, err := runtime.custody.DestructionReceipt(t.Context(), keyRef)
		if err != nil {
			t.Fatal(err)
		}
		if erased {
			receipt = got
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the key was not destroyed after the operator's floor ended")
		}
		time.Sleep(250 * time.Millisecond)
	}
	claims, err := eventprotect.VerifyDestructionReceipt(key.JWKS(), receipt)
	if err != nil || claims.Request.Ref != keyRef {
		t.Fatalf("destruction record: %+v %v", claims, err)
	}
	if claims.RemovedAt.Before(floorEnds) || !claims.Request.NotBefore.Before(floorEnds) {
		t.Fatalf("removed at %s, tenant window ends %s, floor ends %s", claims.RemovedAt, claims.Request.NotBefore, floorEnds)
	}

	// The public clearance records what kept the key and until when.
	clearance, found, err := log.EventByID(t.Context(), eventprivacy.HoldClearanceEventID(claims.Request))
	if err != nil || !found {
		t.Fatalf("hold clearance: found=%v err=%v", found, err)
	}
	recorded, err := eventprivacy.ParseHoldClearance(clearance)
	if err != nil || recorded.RetentionFloorSeconds != floorSeconds || recorded.RetentionFloorUntil == nil ||
		!recorded.RetentionFloorUntil.Equal(claims.Request.OffboardedAt.Add(floorSeconds*time.Second)) || clearance.Time.Before(*recorded.RetentionFloorUntil) {
		t.Fatalf("the clearance does not record the floor: %+v %v (at %s)", recorded, err, clearance.Time)
	}
	stack.close(t, srv, log, runtime)
}
