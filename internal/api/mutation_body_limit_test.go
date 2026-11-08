// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"trstctl.com/trstctl/internal/orchestrator"
)

// largeMutationBody is a JSON body past the shared 1 MiB REST limit.
func largeMutationBody(fill byte, last string) string {
	return `{"export":"` + strings.Repeat(string(fill), defaultRESTJSONBodyLimit+64) + last + `"}`
}

// A route whose own limit is larger than the shared one accepts its
// documented size: the binding digests the whole body, so a replay of the
// same body replays, a body that differs only past the first MiB is a
// different command, and a body over the route's limit is refused before the
// key is claimed.
func TestMutateWithBodyLimitBindsTheWholeLargeBody(t *testing.T) {
	a := New(nil, orchestrator.NewMemoryIdempotency(), nil)
	const limit = 4 << 20
	body := largeMutationBody('a', "z")
	request := func(body string) *http.Request {
		return mutationBindingRequestWithBody("operator-a", http.MethodPost, "/test/mutations/imports", body)
	}

	shared := httptest.NewRecorder()
	a.mutate(shared, request(body), "shared-limit", func(context.Context, string) (int, any, error) {
		t.Fatal("the shared wrapper ran a body past its limit")
		return 0, nil, nil
	})
	if shared.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("shared wrapper = %d, want 413", shared.Code)
	}

	calls := 0
	first := httptest.NewRecorder()
	firstRequest := request(body)
	a.mutateWithBodyLimit(first, firstRequest, "large-import", limit, func(context.Context, string) (int, any, error) {
		calls++
		raw, err := io.ReadAll(firstRequest.Body)
		if err != nil {
			t.Fatal(err)
		}
		if string(raw) != body {
			t.Fatalf("handler read %d bytes, want the whole %d-byte body restored", len(raw), len(body))
		}
		return http.StatusCreated, map[string]string{"import": "recorded"}, nil
	})
	if first.Code != http.StatusCreated || calls != 1 {
		t.Fatalf("large body = %d/%s calls %d, want 201 once", first.Code, first.Body.String(), calls)
	}

	invoke := func(key, body string) *httptest.ResponseRecorder {
		t.Helper()
		recorder := httptest.NewRecorder()
		a.mutateWithBodyLimit(recorder, request(body), key, limit, func(context.Context, string) (int, any, error) {
			calls++
			return http.StatusCreated, map[string]string{"import": "again"}, nil
		})
		return recorder
	}
	if replay := invoke("large-import", body); replay.Code != first.Code || replay.Body.String() != first.Body.String() || calls != 1 {
		t.Fatalf("exact replay = %d/%s calls %d; first %d/%s", replay.Code, replay.Body.String(), calls, first.Code, first.Body.String())
	}
	if changed := invoke("large-import", largeMutationBody('a', "y")); changed.Code != http.StatusConflict || calls != 1 {
		t.Fatalf("a body changed past its first MiB = %d/%s calls %d, want 409 without the callback", changed.Code, changed.Body.String(), calls)
	}
	if over := invoke("over-limit", `{"export":"`+strings.Repeat("a", limit)+`"}`); over.Code != http.StatusRequestEntityTooLarge || calls != 1 {
		t.Fatalf("a body over the route's limit = %d/%s calls %d, want 413 before the claim", over.Code, over.Body.String(), calls)
	}
	if retry := invoke("over-limit", body); retry.Code != http.StatusCreated || calls != 2 {
		t.Fatalf("a valid retry after the refused body = %d/%s calls %d, want an unclaimed key", retry.Code, retry.Body.String(), calls)
	}
}

// A response recorded under mutate replays under mutateWithBodyLimit: a body
// within the shared limit binds the same way under both, so moving a route
// to the larger limit keeps its cached results.
func TestMutateWithBodyLimitReplaysWhatMutateRecorded(t *testing.T) {
	a := New(nil, orchestrator.NewMemoryIdempotency(), nil)
	const body = `{"name":"estate","export":"fingerprint_sha256\nab"}`
	request := func() *http.Request {
		return mutationBindingRequestWithBody("operator-a", http.MethodPost, "/test/mutations/imports", body)
	}
	first := httptest.NewRecorder()
	a.mutate(first, request(), "recorded-before", func(context.Context, string) (int, any, error) {
		return http.StatusCreated, map[string]string{"id": "import-1"}, nil
	})
	replay := httptest.NewRecorder()
	a.mutateWithBodyLimit(replay, request(), "recorded-before", 40<<20, func(context.Context, string) (int, any, error) {
		t.Fatal("a response recorded under mutate ran again")
		return 0, nil, nil
	})
	if first.Code != http.StatusCreated || replay.Code != first.Code || replay.Body.String() != first.Body.String() {
		t.Fatalf("replay = %d/%s, first = %d/%s", replay.Code, replay.Body.String(), first.Code, first.Body.String())
	}
}

// The three routes with a documented body above 1 MiB reach their own
// handlers with such a body: before, the shared binding refused anything
// over 1 MiB, so a switching export of more than about 2,500 rows, a KRL
// over 1 MiB or an ownership CSV over 1 MiB could not be applied at all.
func TestLargeBodyMutationRoutesReachTheirHandlers(t *testing.T) {
	a := New(nil, orchestrator.NewMemoryIdempotency(), nil)
	pad := strings.Repeat("a", 2<<20)
	switching, err := json.Marshal(map[string]string{"name": "", "export": pad})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		path    string
		body    string
		handler func(http.ResponseWriter, *http.Request)
		status  int
		detail  string
	}{
		{"switching import apply", "/api/v1/switching/imports", string(switching), a.applySwitchingImport, http.StatusBadRequest, "name is required"},
		{"ssh krl adoption", "/api/v1/ssh/krl/adoptions", pad, a.adoptSSHKRL, http.StatusServiceUnavailable, "ssh workflow"},
		{"ownership csv import", "/api/v1/owners/import", "team\n" + pad, a.importOwnership, http.StatusBadRequest, "naming the owner each row is about"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := mutationBindingRequestWithBody("operator-a", http.MethodPost, tc.path, tc.body)
			req.Header.Set("Idempotency-Key", "large-"+strings.ReplaceAll(tc.name, " ", "-"))
			rec := httptest.NewRecorder()
			tc.handler(rec, req)
			if rec.Code != tc.status || !strings.Contains(rec.Body.String(), tc.detail) {
				t.Fatalf("%d-byte body = %d %s, want the handler's own %d (%q)", len(tc.body), rec.Code, rec.Body.String(), tc.status, tc.detail)
			}
		})
	}
}
