// SPDX-License-Identifier: BUSL-1.1

package reprotect

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"runtime"
	"testing"

	"trstctl.com/trstctl/internal/decommission/depstate"
	"trstctl.com/trstctl/internal/transit"
)

// Guard for VDEC-claim-5.
func TestReprotect_ReencryptInCryptoBoundaryNoKeyBytes(t *testing.T) {
	assertBoundaryReturnsNoBytes(t)

	ctx := context.Background()
	const (
		tenantID = "tenant-a"
		keyName  = "app-data"
	)
	svc := transit.NewService(nil)
	if _, err := svc.CreateKey(ctx, tenantID, keyName, transit.KindAEAD); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	plaintext := []byte("classified object bytes")
	aad := []byte("bucket/object")
	ct1, err := svc.Encrypt(ctx, tenantID, keyName, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := svc.Rotate(ctx, tenantID, keyName); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	boundary, err := NewTransitBoundary(svc)
	if err != nil {
		t.Fatalf("NewTransitBoundary: %v", err)
	}
	sink := &recordingCompletionSink{}
	exec, err := NewCiphertextExecutor(boundary, NewCompletionRecorder(sink))
	if err != nil {
		t.Fatalf("NewCiphertextExecutor: %v", err)
	}
	job := ciphertextJob(tenantID, "key://tenant-a/root", JobKindReEncrypt)

	res, err := exec.Execute(ctx, CiphertextRequest{
		Job:            job,
		TransitKeyName: keyName,
		Ciphertext:     ct1,
		AAD:            aad,
		SuccessorKeyID: "key://tenant-a/root@v2",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.Ciphertext == "" || res.Ciphertext == ct1 {
		t.Fatalf("rewrap did not return a successor ciphertext: %q", res.Ciphertext)
	}
	version, err := transit.CiphertextVersion(res.Ciphertext)
	if err != nil {
		t.Fatalf("CiphertextVersion: %v", err)
	}
	if version != 2 {
		t.Fatalf("rewrapped ciphertext version = %d, want 2", version)
	}
	got, err := svc.Decrypt(ctx, tenantID, keyName, res.Ciphertext, aad)
	if err != nil {
		t.Fatalf("Decrypt rewrapped: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch after rewrap:\n got %q\nwant %q", got, plaintext)
	}
	if len(sink.events) != 1 || sink.events[0].JobID != job.ID || sink.events[0].SuccessorKeyID != "key://tenant-a/root@v2" {
		t.Fatalf("completion evidence mismatch: %#v", sink.events)
	}
	if !res.Completion.Recorded {
		t.Fatalf("first successful execution did not record completion: %#v", res.Completion)
	}
}

func TestReprotect_PlaintextZeroizedAfter(t *testing.T) {
	ctx := context.Background()
	job := ciphertextJob("tenant-a", "key://tenant-a/root", JobKindReEncrypt)

	successBoundary := &instrumentedBoundary{plaintext: []byte("wipe-me-success"), ciphertext: "rewrapped"}
	successSink := &recordingCompletionSink{}
	successExec, err := NewCiphertextExecutor(successBoundary, NewCompletionRecorder(successSink))
	if err != nil {
		t.Fatalf("NewCiphertextExecutor success: %v", err)
	}
	if _, err := successExec.Execute(ctx, CiphertextRequest{
		Job:            job,
		TransitKeyName: "app-data",
		Ciphertext:     "ciphertext",
		SuccessorKeyID: "key://tenant-a/root@v2",
	}); err != nil {
		t.Fatalf("Execute success: %v", err)
	}
	if !allZeroBytes(successBoundary.residue) {
		t.Fatalf("success path plaintext residue not wiped: %x", successBoundary.residue)
	}
	if len(successSink.events) != 1 {
		t.Fatalf("success completion events = %d, want 1", len(successSink.events))
	}

	wrappedBoundary := &instrumentedBoundary{plaintext: []byte("wipe-me-wrapped-key"), ciphertext: "rewrapped-dek"}
	wrappedSink := &recordingCompletionSink{}
	wrappedExec, err := NewCiphertextExecutor(wrappedBoundary, NewCompletionRecorder(wrappedSink))
	if err != nil {
		t.Fatalf("NewCiphertextExecutor wrapped: %v", err)
	}
	if _, err := wrappedExec.Execute(ctx, CiphertextRequest{
		Job:            ciphertextJob("tenant-a", "key://tenant-a/root", JobKindReWrap),
		TransitKeyName: "dek-wrap",
		Ciphertext:     "wrapped-key",
		SuccessorKeyID: "key://tenant-a/root@v2",
	}); err != nil {
		t.Fatalf("Execute wrapped-key: %v", err)
	}
	if !allZeroBytes(wrappedBoundary.residue) {
		t.Fatalf("wrapped-key plaintext residue not wiped: %x", wrappedBoundary.residue)
	}
	if len(wrappedSink.events) != 1 {
		t.Fatalf("wrapped-key completion events = %d, want 1", len(wrappedSink.events))
	}

	failureBoundary := &instrumentedBoundary{plaintext: []byte("wipe-me-failure"), err: errors.New("boundary failed")}
	failureSink := &recordingCompletionSink{}
	failureExec, err := NewCiphertextExecutor(failureBoundary, NewCompletionRecorder(failureSink))
	if err != nil {
		t.Fatalf("NewCiphertextExecutor failure: %v", err)
	}
	if _, err := failureExec.Execute(ctx, CiphertextRequest{
		Job:            job,
		TransitKeyName: "app-data",
		Ciphertext:     "ciphertext",
		SuccessorKeyID: "key://tenant-a/root@v2",
	}); !errors.Is(err, failureBoundary.err) {
		t.Fatalf("Execute failure err = %v, want %v", err, failureBoundary.err)
	}
	if !allZeroBytes(failureBoundary.residue) {
		t.Fatalf("failure path plaintext residue not wiped: %x", failureBoundary.residue)
	}
	if len(failureSink.events) != 0 {
		t.Fatalf("failure recorded completion events: %#v", failureSink.events)
	}
}

func assertBoundaryReturnsNoBytes(t *testing.T) {
	t.Helper()
	method, ok := reflect.TypeOf((*RewrapBoundary)(nil)).Elem().MethodByName("Rewrap")
	if !ok {
		t.Fatal("RewrapBoundary has no Rewrap method")
	}
	for i := 0; i < method.Type.NumOut(); i++ {
		if method.Type.Out(i).Kind() == reflect.Slice && method.Type.Out(i).Elem().Kind() == reflect.Uint8 {
			t.Fatalf("RewrapBoundary returns []byte at output %d: %s", i, method.Type.Out(i))
		}
	}
}

type instrumentedBoundary struct {
	plaintext  []byte
	ciphertext string
	err        error
	residue    []byte
}

func (b *instrumentedBoundary) Rewrap(context.Context, string, string, string, []byte) (string, error) {
	pt := append([]byte(nil), b.plaintext...)
	defer func() { b.residue = append([]byte(nil), pt...) }()
	defer wipeTestPlaintext(pt)
	if b.err != nil {
		return "", b.err
	}
	return b.ciphertext, nil
}

func wipeTestPlaintext(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func ciphertextJob(tenantID, keyID string, kind JobKind) Job {
	dep := depstate.Dependent{Class: depstate.DependentCiphertext, ID: "ciphertext:object-1"}
	if kind == JobKindReWrap {
		dep = depstate.Dependent{Class: depstate.DependentWrappedKey, ID: "wrapped-key:dek-1"}
	}
	return Job{
		ID:             "job-" + string(kind),
		TenantID:       tenantID,
		KeyID:          keyID,
		LedgerPosition: 7,
		Kind:           kind,
		Dependent:      dep,
		IdempotencyKey: "idem-" + string(kind),
	}
}

func allZeroBytes(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
