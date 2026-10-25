// SPDX-License-Identifier: BUSL-1.1

package spiffe

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// WithX509KeygenCheck is asked before every X.509-SVID key the socket would
// generate, including a re-send on a long stream, and its refusal is the
// workload's error.
func TestX509KeygenCheckRefusesBeforeTheKeyExists(t *testing.T) {
	api, stream, cancel := newX509StreamProbe(t, 3*time.Second)
	defer cancel()
	var refuse atomic.Bool
	refuse.Store(true)
	api.x509KeygenCheck = func(context.Context) error {
		if refuse.Load() {
			return errors.New("control-plane key generation is off for this tenant: fetch the SVID from the host agent's Workload API socket (trstctl-agent --workload-api-socket)")
		}
		return nil
	}
	err := api.FetchX509SVID(nil, stream)
	if st, _ := status.FromError(err); err == nil || st.Code() != codes.PermissionDenied || !strings.Contains(st.Message(), "--workload-api-socket") {
		t.Fatalf("FetchX509SVID with the check refusing = %v, want PermissionDenied with its reason", err)
	}
	select {
	case <-stream.responses:
		t.Fatal("an SVID was sent although the check refused")
	default:
	}

	// Allowed, the stream issues; refused before the re-send, it stops there.
	refuse.Store(false)
	done := make(chan error, 1)
	go func() { done <- api.FetchX509SVID(nil, stream) }()
	select {
	case <-stream.responses:
	case err := <-done:
		t.Fatalf("stream ended before its first SVID: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("no SVID while the check allowed it")
	}
	refuse.Store(true)
	select {
	case err := <-done:
		if st, _ := status.FromError(err); st.Code() != codes.PermissionDenied {
			t.Fatalf("re-send after the check turned refusing = %v, want PermissionDenied", err)
		}
	case <-stream.responses:
		t.Fatal("a re-send generated another key although the check refused")
	case <-time.After(10 * time.Second):
		t.Fatal("the stream neither re-sent nor refused")
	}
}
