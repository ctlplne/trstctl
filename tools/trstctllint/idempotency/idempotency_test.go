// SPDX-License-Identifier: MPL-2.0

package idempotency_test

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"trstctl.com/trstctl/tools/trstctllint/idempotency"
)

// TestIdempotency exercises AN-5: a served mutation handler must thread an
// idempotency key into a real dedupe sink (orchestrator.Idempotency.Do or a
// key-accepting forwarding call such as API.mutate). Merely naming the key,
// passing it to a logger, or declaring an unused idempotency parameter does not
// satisfy the rule (ARCH-002). Coverage comes from both the //trstctl:mutation
// marker and the route registry's mutation: true entries (ARCH-003). Unmarked,
// read-only functions are ignored. The fixture lives under the real module path
// so it can import the orchestrator stub for type-resolved sink detection.
func TestIdempotency(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), idempotency.Analyzer,
		"trstctl.com/trstctl/internal/api",
		"trstctl.com/trstctl/internal/app")
}

func TestIdempotencyRejectsUnapprovedKeyProvenance(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "src/trstctl.com/trstctl/internal/orchestrator/idempotency.go", `package orchestrator

type Idempotency struct{}

func (i *Idempotency) Do(ctx any, tenantID, key string, fn func(any) ([]byte, error)) ([]byte, error) {
	return fn(ctx)
}
`)
	writeFixture(t, dir, "src/trstctl.com/trstctl/internal/api/handlers.go", `package api

import (
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
)

type uuidFactory struct{}

var uuid uuidFactory

func (uuidFactory) NewString() string { return "generated-uuid" }

type API struct {
	idem *orchestrator.Idempotency
}

type route struct {
	handler  http.HandlerFunc
	mutation bool
}

func (a *API) routes() []route {
	return []route{
		{handler: a.goodHeader, mutation: true},
		{handler: a.goodVaultCompat, mutation: true},
		{handler: a.goodVaultMutationHelper, mutation: true},
		{handler: a.goodSCIMCompat, mutation: true},
		{handler: a.badFixedString, mutation: true},
		{handler: a.badUUIDGenerated, mutation: true},
		{handler: a.badTimeGenerated, mutation: true},
		{handler: a.badWrongHeader, mutation: true},
	}
}

func (a *API) goodHeader(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, nil)
}

func (a *API) goodVaultCompat(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := vaultIdempotencyKey(r, nil)
	a.mutate(w, r, idempotencyKey, nil)
}

func (a *API) goodVaultMutationHelper(w http.ResponseWriter, r *http.Request) {
	idempotencyKey, ok := vaultMutationKey(w, r)
	if !ok { return }
	a.mutate(w, r, idempotencyKey, nil)
}

func (a *API) goodSCIMCompat(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := scimIdempotencyKey(r, nil)
	a.mutate(w, r, idempotencyKey, nil)
}

func (a *API) badFixedString(w http.ResponseWriter, r *http.Request) { // want "mutating handler must thread an approved Idempotency-Key value"
	idempotencyKey := "fixed-key"
	a.mutate(w, r, idempotencyKey, nil)
}

func (a *API) badUUIDGenerated(w http.ResponseWriter, r *http.Request) { // want "mutating handler must thread an approved Idempotency-Key value"
	idempotencyKey := uuid.NewString()
	a.mutate(w, r, idempotencyKey, nil)
}

func (a *API) badTimeGenerated(w http.ResponseWriter, r *http.Request) { // want "mutating handler must thread an approved Idempotency-Key value"
	idempotencyKey := time.Now().UTC().Format(time.RFC3339Nano)
	a.mutate(w, r, idempotencyKey, nil)
}

func (a *API) badWrongHeader(w http.ResponseWriter, r *http.Request) { // want "mutating handler must thread an approved Idempotency-Key value"
	idempotencyKey := r.Header.Get("X-Request-ID")
	a.mutate(w, r, idempotencyKey, nil)
}

func (a *API) mutate(w http.ResponseWriter, r *http.Request, idempotencyKey string, fn any) {
	_, _ = a.idem.Do(r.Context(), "tenant", idempotencyKey, func(ctx any) ([]byte, error) { return nil, nil })
}

func vaultIdempotencyKey(r *http.Request, body []byte) string {
	if key := r.Header.Get("Idempotency-Key"); key != "" {
		return key
	}
	return "vault:documented-compatibility-derivation"
}

func vaultMutationKey(w http.ResponseWriter, r *http.Request) (string, bool) {
	key := r.Header.Get("Idempotency-Key")
	return key, key != ""
}

func scimIdempotencyKey(r *http.Request, body []byte) string {
	if key := r.Header.Get("Idempotency-Key"); key != "" {
		return key
	}
	return "scim:documented-compatibility-derivation"
}
`)
	analysistest.Run(t, dir, idempotency.Analyzer, "trstctl.com/trstctl/internal/api")
}

func writeFixture(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { // #nosec G301 -- fixture tree in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatalf("mkdir fixture %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil { // #nosec G306 -- fixture file in a test tempdir; the mode is part of the fixture (CWE-276)
		t.Fatalf("write fixture %s: %v", rel, err)
	}
}
