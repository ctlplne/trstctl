// SPDX-License-Identifier: MPL-2.0

package cloudhttp

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newReq(t *testing.T, ctx context.Context, method, url string, body string) *http.Request {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, r)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// TestJSONDecodesSuccess: a 2xx JSON body decodes into out.
func TestJSONDecodesSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer t" {
			t.Errorf("auth header not forwarded: %q", got)
		}
		_, _ = w.Write([]byte(`{"value":"ok"}`))
	}))
	defer srv.Close()

	req := newReq(t, context.Background(), http.MethodGet, srv.URL, "")
	req.Header.Set("Authorization", "Bearer t")
	var out struct {
		Value string `json:"value"`
	}
	if err := JSON(http.DefaultClient, req, &out); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if out.Value != "ok" {
		t.Errorf("decoded %q, want ok", out.Value)
	}
}

// TestJSONNilOutDiscardsBody: out == nil succeeds and discards the body.
func TestJSONNilOutDiscardsBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ignored":true}`))
	}))
	defer srv.Close()
	req := newReq(t, context.Background(), http.MethodDelete, srv.URL, "")
	if err := JSON(http.DefaultClient, req, nil); err != nil {
		t.Fatalf("JSON nil-out: %v", err)
	}
}

// TestJSONNon2xxIsStatusError: a non-2xx response becomes a *StatusError carrying the
// status and a bounded body snippet.
func TestJSONNon2xxIsStatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("  denied: bad scope  "))
	}))
	defer srv.Close()
	req := newReq(t, context.Background(), http.MethodGet, srv.URL, "")
	err := JSON(http.DefaultClient, req, nil)
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("expected *StatusError, got %v", err)
	}
	if se.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want 403", se.StatusCode)
	}
	if se.Body != "denied: bad scope" {
		t.Errorf("body = %q, want trimmed 'denied: bad scope'", se.Body)
	}
}

// TestJSONBoundsErrorBody: a giant error body is truncated to MaxErrorBytes.
func TestJSONBoundsErrorBody(t *testing.T) {
	big := strings.Repeat("x", MaxErrorBytes*4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(big))
	}))
	defer srv.Close()
	req := newReq(t, context.Background(), http.MethodGet, srv.URL, "")
	err := JSON(http.DefaultClient, req, nil)
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("expected *StatusError, got %v", err)
	}
	if len(se.Body) > MaxErrorBytes {
		t.Errorf("error body not bounded: %d bytes (cap %d)", len(se.Body), MaxErrorBytes)
	}
}

// TestJSONTimeoutFloorAppliesWhenNoDeadline: with timeout > 0 and a context that has
// no deadline, a wedged endpoint fails fast rather than hanging — this is the single
// shared timeout knob CODE-006 wants (change it here, every importer inherits it).
func TestJSONTimeoutFloorAppliesWhenNoDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // never respond until the client gives up
	}))
	defer srv.Close()
	req := newReq(t, context.Background(), http.MethodGet, srv.URL, "")
	start := time.Now()
	err := JSON(http.DefaultClient, req, nil, WithTimeout(50*time.Millisecond))
	if err == nil {
		t.Fatal("expected a timeout error from the shared floor")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("timeout floor did not bound the call: took %v", elapsed)
	}
}

// TestJSONRespectsCallerDeadline: when the caller's context already has a deadline,
// the floor does not override it (the deadline path the ContextSigner uses).
func TestJSONRespectsCallerDeadline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	req := newReq(t, ctx, http.MethodGet, srv.URL, "")
	start := time.Now()
	// A long floor must not extend the caller's short deadline.
	if err := JSON(http.DefaultClient, req, nil, WithTimeout(time.Hour)); err == nil {
		t.Fatal("expected the caller's deadline to fire")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("caller deadline not respected: took %v", elapsed)
	}
}

// errDoer is a Doer that always errors, proving transport errors propagate.
type errDoer struct{}

func (errDoer) Do(*http.Request) (*http.Response, error) { return nil, errors.New("dial fail") }

func TestJSONPropagatesTransportError(t *testing.T) {
	req := newReq(t, context.Background(), http.MethodGet, "http://example.invalid", "")
	if err := JSON(errDoer{}, req, nil); err == nil || !strings.Contains(err.Error(), "dial fail") {
		t.Fatalf("expected transport error to propagate, got %v", err)
	}
}

// TestJSONSignerRunsBeforeSendOverBody proves the WithSigner seam: the signer is
// invoked with the request and the exact body bytes (via SetBody) before the request
// is sent, and the headers it sets reach the server. This is the AWS-SigV4 / Akamai-
// EdgeGrid attachment point — the providers compute their keyed MAC over the body and
// stamp an Authorization header here, sharing the bounded-read / timeout core.
func TestJSONSignerRunsBeforeSendOverBody(t *testing.T) {
	body := []byte(`{"k":"v"}`)
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	req := newReq(t, context.Background(), http.MethodPost, srv.URL, string(body))
	req = SetBody(req, body)
	signer := func(r *http.Request, b []byte) error {
		// The signer sees exactly the bytes that will be sent.
		if string(b) != string(body) {
			t.Errorf("signer body = %q, want %q", b, body)
		}
		r.Header.Set("Authorization", "SIG over "+string(b))
		return nil
	}
	if err := JSON(http.DefaultClient, req, nil, WithSigner(signer)); err != nil {
		t.Fatalf("JSON with signer: %v", err)
	}
	if want := "SIG over " + string(body); gotSig != want {
		t.Errorf("server saw Authorization %q, want %q", gotSig, want)
	}
}

// TestJSONSignerErrorAbortsBeforeSend: a signer that fails stops the call before any
// request reaches the doer (a credential-derivation failure must never send an
// unauthenticated request).
func TestJSONSignerErrorAbortsBeforeSend(t *testing.T) {
	var sent bool
	doer := doerFunc(func(*http.Request) (*http.Response, error) {
		sent = true
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{}"))}, nil
	})
	req := newReq(t, context.Background(), http.MethodPost, "http://example.invalid", "{}")
	failSign := func(*http.Request, []byte) error { return errors.New("sign failed") }
	err := JSON(doer, req, nil, WithSigner(failSign))
	if err == nil || !strings.Contains(err.Error(), "sign failed") {
		t.Fatalf("expected signer error, got %v", err)
	}
	if sent {
		t.Fatal("request was sent despite a signer failure")
	}
}

// doerFunc adapts a function to the Doer seam.
type doerFunc func(*http.Request) (*http.Response, error)

func (f doerFunc) Do(r *http.Request) (*http.Response, error) { return f(r) }
