// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package winservice

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

func TestHandlerReportsLoopErrorAsServiceFailure(t *testing.T) {
	statuses := make(chan svc.Status, 4)
	requests := make(chan svc.ChangeRequest)
	result := make(chan uint32, 1)
	h := &handler{loop: func(context.Context) error { return errors.New("control plane unavailable") }}

	go func() {
		_, code := h.Execute(nil, requests, statuses)
		result <- code
	}()

	if got := <-statuses; got.State != svc.StartPending {
		t.Fatalf("first status = %v, want StartPending", got.State)
	}
	if got := <-statuses; got.State != svc.Running {
		t.Fatalf("second status = %v, want Running", got.State)
	}
	if got := <-statuses; got.State != svc.StopPending {
		t.Fatalf("third status = %v, want StopPending", got.State)
	}
	if code := <-result; code == 0 {
		t.Fatal("loop error reported a successful service exit; SCM recovery would not run")
	}
}

func TestHandlerReportsOperatorStopAsCleanExit(t *testing.T) {
	statuses := make(chan svc.Status, 4)
	requests := make(chan svc.ChangeRequest, 1)
	result := make(chan uint32, 1)
	h := &handler{loop: func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	}}

	go func() {
		_, code := h.Execute(nil, requests, statuses)
		result <- code
	}()

	<-statuses // StartPending
	if got := <-statuses; got.State != svc.Running {
		t.Fatalf("second status = %v, want Running", got.State)
	}
	requests <- svc.ChangeRequest{Cmd: svc.Stop}
	if got := <-statuses; got.State != svc.StopPending {
		t.Fatalf("stop status = %v, want StopPending", got.State)
	}
	select {
	case code := <-result:
		if code != 0 {
			t.Fatalf("operator stop exit code = %d, want 0", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not finish after operator stop")
	}
}
