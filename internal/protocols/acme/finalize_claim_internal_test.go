// SPDX-License-Identifier: BUSL-1.1

package acme

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"trstctl.com/trstctl/internal/crypto/jose"
)

// claimProbeWriter inspects the order's status AT THE MOMENT the handler
// writes its response. Under the pre-fix ordering the non-owner's request had
// already claimed the order (statusReady -> statusProcessing) when the
// ownership 404 was written — the deferred release ran only after the handler
// returned — which is exactly the window a concurrent owner finalize died in.
type claimProbeWriter struct {
	http.ResponseWriter
	s                  *Server
	o                  *order
	observedProcessing bool
}

func (w *claimProbeWriter) Write(p []byte) (int, error) {
	w.s.mu.Lock()
	if w.o.status == statusProcessing {
		w.observedProcessing = true
	}
	w.s.mu.Unlock()
	return w.ResponseWriter.Write(p)
}

func (w *claimProbeWriter) WriteHeader(code int) {
	w.s.mu.Lock()
	if w.o.status == statusProcessing {
		w.observedProcessing = true
	}
	w.s.mu.Unlock()
	w.ResponseWriter.WriteHeader(code)
}

// TestNonOwnerFinalizeNeverClaimsTheOrder is the deterministic regression
// guard for AUD-201 follow-up G1/V15: a non-owner's finalize must be rejected
// WITHOUT ever flipping the victim's ready order into processing. The probe
// reads the order's status at response-write time, which is inside the old
// code's claim window and outside the new code's.
func TestNonOwnerFinalizeNeverClaimsTheOrder(t *testing.T) {
	s := New(nil, AcceptAll{})
	o := &order{id: "7", accountURL: "https://acme.test/acct/victim", status: statusReady}
	s.orders["7"] = o

	req := httptest.NewRequest(http.MethodPost, "/acme/order/7/finalize", nil)
	req.SetPathValue("id", "7")
	probe := &claimProbeWriter{ResponseWriter: httptest.NewRecorder(), s: s, o: o}

	s.finalize(probe, req, &jose.ACMEMessage{}, &account{url: "https://acme.test/acct/attacker"})

	if probe.observedProcessing {
		t.Fatal("a NON-OWNER's finalize claimed the order before the ownership check; " +
			"a concurrent owner finalize in that window is refused with 403 orderNotReady (cross-account DoS)")
	}
	s.mu.Lock()
	final := o.status
	s.mu.Unlock()
	if final != statusReady {
		t.Fatalf("order status after a non-owner finalize = %q, want ready", final)
	}
	if rec := probe.ResponseWriter.(*httptest.ResponseRecorder); rec.Code != http.StatusNotFound {
		t.Fatalf("non-owner finalize = %d, want 404 indistinguishable from no-such-order", rec.Code)
	}
}
