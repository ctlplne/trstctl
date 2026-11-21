//go:build trstctl_dodprojectiontest

// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// This fake queue checks only the polling helper. Run it with both
// trstctl_dodproof and trstctl_dodprojectiontest; its separate tag keeps
// httptest out of the thirteen production-assembly runtime proof files.
func TestDODPendingManagedKeyApprovalWaitsForProjection(t *testing.T) {
	var reads atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/api/v1/approval-requests" || req.URL.Query().Get("status") != "pending" || req.Header.Get("Authorization") != "Bearer test-token" {
			t.Error("approval queue request lost its tenant auth or pending filter")
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		if reads.Add(1) < 3 {
			_, _ = io.WriteString(w, `{"items":[]}`)
			return
		}
		_, _ = io.WriteString(w, `{"items":[{"id":"approval-1","intent_digest":"digest-1","resource_id":"aws-key-2","resource_kind":"managed_key","action":"managedkey:zeroize","requester":"dod-hsm-operator","approval_count":0,"required_approvals":2,"status":"pending"}]}`)
	}))
	defer server.Close()
	port := server.Listener.Addr().(*net.TCPAddr).Port
	runtime := &dodManagedKeyRuntime{t: t, token: "test-token", serverPort: port}
	authority := runtime.pendingManagedKeyApproval("aws-key-2", "zeroize", "approval-1")
	if authority.ID != "approval-1" || reads.Load() < 3 {
		t.Fatalf("eventual approval = %+v after %d reads", authority, reads.Load())
	}
}
