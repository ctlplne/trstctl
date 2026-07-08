// SPDX-License-Identifier: LicenseRef-trstctl-EE

package reprotect

import (
	"context"
	"reflect"
	"testing"

	"trstctl.com/trstctl/ee/decommission/depstate"
	"trstctl.com/trstctl/internal/eventspec"
)

func TestDepState_ReprotectionJobsGeneratedFromState(t *testing.T) {
	const (
		tenantID = "tenant-a"
		keyID    = "key://tenant-a/issuer"
	)
	ciphertext := depstate.Dependent{Class: depstate.DependentCiphertext, ID: "ciphertext:bucket-a/object-1"}
	wrapped := depstate.Dependent{Class: depstate.DependentWrappedKey, ID: "wrapped-key:dek-7"}
	credential := depstate.Dependent{Class: depstate.DependentCredential, ID: "credential:serial-99"}
	lease := depstate.Dependent{Class: depstate.DependentLeasedSecret, ID: "lease:db-creds-1"}
	dataSet := depstate.Dependent{Class: depstate.DependentDataSet, ID: "dataset:active-report"}
	alreadyComplete := depstate.Dependent{Class: depstate.DependentCiphertext, ID: "ciphertext:already-complete"}
	released := depstate.Dependent{Class: depstate.DependentCredential, ID: "credential:expired"}
	erased := depstate.Dependent{Class: depstate.DependentDataSet, ID: "dataset:erased"}
	unregistered := depstate.Dependent{Class: depstate.DependentWrappedKey, ID: "wrapped-key:unregistered"}

	seq := []eventspec.Event{
		mustDepEvent(t, depstate.DependencyRegisteredV1{TenantID: tenantID, KeyID: keyID, Dependent: ciphertext}),
		mustDepEvent(t, depstate.DependencyRegisteredV1{TenantID: tenantID, KeyID: keyID, Dependent: wrapped}),
		mustDepEvent(t, depstate.DependencyRegisteredV1{TenantID: tenantID, KeyID: keyID, Dependent: credential}),
		mustDepEvent(t, depstate.DependencyRegisteredV1{TenantID: tenantID, KeyID: keyID, Dependent: lease}),
		mustDepEvent(t, depstate.DependencyRegisteredV1{TenantID: tenantID, KeyID: keyID, Dependent: dataSet}),
		mustDepEvent(t, depstate.DependencyRegisteredV1{TenantID: tenantID, KeyID: keyID, Dependent: alreadyComplete}),
		mustDepEvent(t, depstate.DependencyRegisteredV1{TenantID: tenantID, KeyID: keyID, Dependent: released}),
		mustDepEvent(t, depstate.DependencyRegisteredV1{TenantID: tenantID, KeyID: keyID, Dependent: erased}),
		mustDepEvent(t, depstate.ReprotectionCompletedV1{TenantID: tenantID, KeyID: keyID, JobID: "job-already-complete", Dependent: alreadyComplete, SuccessorKeyID: "key://tenant-a/successor"}),
		mustDepEvent(t, depstate.DependencyReleasedV1{TenantID: tenantID, KeyID: keyID, Dependent: released, Reason: "expired"}),
		mustDepEvent(t, depstate.DependencyErasureDesignatedV1{TenantID: tenantID, KeyID: keyID, Dependent: erased, DesignationRef: "erase-1"}),
		mustDepEvent(t, depstate.ReprotectionCompletedV1{TenantID: tenantID, KeyID: keyID, JobID: "job-unregistered", Dependent: unregistered, SuccessorKeyID: "key://tenant-a/successor"}),
	}
	for i := range seq {
		seq[i].Sequence = uint64(i + 1)
	}
	proj, err := depstate.Fold(seq)
	if err != nil {
		t.Fatalf("Fold: %v", err)
	}
	state, ok := proj.Lookup(tenantID, keyID)
	if !ok {
		t.Fatalf("projection missing %s/%s", tenantID, keyID)
	}

	jobs, err := PlanFromState(state)
	if err != nil {
		t.Fatalf("PlanFromState: %v", err)
	}
	got := jobKindsByDependent(jobs)
	want := map[depstate.Dependent]JobKind{
		ciphertext: JobKindReEncrypt,
		wrapped:    JobKindReWrap,
		credential: JobKindReIssue,
		lease:      JobKindRevokeLease,
		dataSet:    JobKindReDerive,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("planned jobs mismatch:\n got %#v\nwant %#v", got, want)
	}
	for _, job := range jobs {
		if job.TenantID != tenantID || job.KeyID != keyID {
			t.Fatalf("job escaped projected state: %#v", job)
		}
		if job.ID == "" || job.IdempotencyKey == "" {
			t.Fatalf("job lacks stable identifiers: %#v", job)
		}
	}

	advanced := state
	advanced.LedgerPosition++
	advancedJobs, err := PlanFromState(advanced)
	if err != nil {
		t.Fatalf("PlanFromState advanced: %v", err)
	}
	if len(advancedJobs) != len(jobs) {
		t.Fatalf("advanced job count = %d, want %d", len(advancedJobs), len(jobs))
	}
	for i := range jobs {
		if advancedJobs[i].ID != jobs[i].ID || advancedJobs[i].IdempotencyKey != jobs[i].IdempotencyKey {
			t.Fatalf("job identity changed with unrelated ledger advancement:\n before %#v\n after  %#v", jobs[i], advancedJobs[i])
		}
	}
}

func TestReprotect_IdempotentAtMostOneCompletion(t *testing.T) {
	const (
		tenantID = "tenant-a"
		keyID    = "key://tenant-a/issuer"
	)
	state := depstate.KeyState{
		TenantID:       tenantID,
		KeyID:          keyID,
		LedgerPosition: 42,
		Registered: []depstate.Dependent{
			{Class: depstate.DependentCiphertext, ID: "ciphertext:object-1"},
			{Class: depstate.DependentWrappedKey, ID: "wrapped-key:dek-2"},
		},
	}
	jobs, err := PlanFromState(state)
	if err != nil {
		t.Fatalf("PlanFromState: %v", err)
	}
	if len(jobs) != 2 {
		t.Fatalf("len(jobs) = %d, want 2", len(jobs))
	}

	sink := &recordingCompletionSink{}
	recorder := NewCompletionRecorder(sink)
	if _, err := recorder.RecordCompletion(context.Background(), jobs[0], ""); err == nil {
		t.Fatal("RecordCompletion accepted an empty successor key id")
	}
	for i := 0; i < 3; i++ {
		got, err := recorder.RecordCompletion(context.Background(), jobs[0], "key://tenant-a/successor")
		if err != nil {
			t.Fatalf("RecordCompletion redelivery %d: %v", i, err)
		}
		if got.Recorded != (i == 0) {
			t.Fatalf("redelivery %d Recorded = %t, want %t", i, got.Recorded, i == 0)
		}
	}
	if got := len(sink.events); got != 1 {
		t.Fatalf("completion events after redelivery = %d, want 1", got)
	}
	if sink.events[0].Dependent != jobs[0].Dependent || sink.events[0].JobID != jobs[0].ID {
		t.Fatalf("completion event mismatch: %#v for job %#v", sink.events[0], jobs[0])
	}

	secondDependent := jobs[1]
	secondDependent.IdempotencyKey = jobs[0].IdempotencyKey
	again, err := recorder.RecordCompletion(context.Background(), secondDependent, "key://tenant-a/successor")
	if err != nil {
		t.Fatalf("RecordCompletion second dependent: %v", err)
	}
	if !again.Recorded {
		t.Fatal("same idempotency domain must not suppress a different dependent")
	}
	if got := len(sink.events); got != 2 {
		t.Fatalf("completion events after second dependent = %d, want 2", got)
	}
}

func mustDepEvent(t *testing.T, p depstate.Payload) eventspec.Event {
	t.Helper()
	e, err := depstate.Encode(p)
	if err != nil {
		t.Fatalf("Encode(%T): %v", p, err)
	}
	return e
}

func jobKindsByDependent(jobs []Job) map[depstate.Dependent]JobKind {
	out := make(map[depstate.Dependent]JobKind, len(jobs))
	for _, job := range jobs {
		if _, ok := out[job.Dependent]; ok {
			out[job.Dependent] = JobKind("duplicate:" + string(job.Kind))
			continue
		}
		out[job.Dependent] = job.Kind
	}
	return out
}

type recordingCompletionSink struct {
	events []depstate.ReprotectionCompletedV1
}

func (s *recordingCompletionSink) AppendReprotectionCompleted(_ context.Context, event depstate.ReprotectionCompletedV1) error {
	s.events = append(s.events, event)
	return nil
}
