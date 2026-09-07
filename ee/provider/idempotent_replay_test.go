// SPDX-License-Identifier: LicenseRef-trstctl-EE

package provider

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/orchestrator"
)

// A provider mutation key binds its first outcome, refusals included. The
// operator must be able to tell a replayed answer from a fresh decision: the
// replay carries Idempotent-Replayed, the first answer does not, and a refusal
// recorded under a key stays that refusal until a new key is used.
func TestProviderReplayedMutationSaysItIsAReplay(t *testing.T) {
	ctx := context.Background()
	st := openProviderStore(t)
	truncateProviderAuthority(t, st)
	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	granted := "replay-granted-" + suffix
	refused := "replay-refused-" + suffix
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir(), SyncAlways: true})
	if err != nil {
		t.Fatalf("events.Open: %v", err)
	}
	t.Cleanup(func() { _ = log.Close() })
	runtime := NewAuthorityRuntime(st, log)
	handler := NewHandler(Config{
		License:       providerLicense(t, 10),
		Store:         NewPGStore(st),
		Mutations:     runtime.Mutations,
		Idempotency:   orchestrator.NewIdempotency(st),
		Authenticator: stubAuth{accept: "Bearer real-credential"},
		Delegations:   fullyDelegated("op-1", CustomerID(granted)),
		Clock:         func() time.Time { return time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC) },
	})
	request := func(key, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/provider/v1/tenants", bytes.NewBufferString(body))
		req.Header.Set("Authorization", "Bearer real-credential")
		req.Header.Set("Idempotency-Key", key)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	first := request("granted-"+suffix, fmt.Sprintf(`{"slug":%q,"name":"Granted"}`, granted))
	if first.Code != http.StatusCreated || first.Header().Get("Idempotent-Replayed") != "" {
		t.Fatalf("first provisioning = %d replayed=%q body=%s, want 201 without a replay marker", first.Code, first.Header().Get("Idempotent-Replayed"), first.Body.String())
	}
	again := request("granted-"+suffix, fmt.Sprintf(`{"slug":%q,"name":"Granted"}`, granted))
	if again.Code != http.StatusCreated || again.Header().Get("Idempotent-Replayed") != "true" || again.Body.String() != first.Body.String() {
		t.Fatalf("replayed provisioning = %d replayed=%q, want the identical 201 marked as a replay", again.Code, again.Header().Get("Idempotent-Replayed"))
	}

	denied := request("refused-"+suffix, fmt.Sprintf(`{"slug":%q,"name":"Refused"}`, refused))
	if denied.Code != http.StatusForbidden || denied.Header().Get("Idempotent-Replayed") != "" {
		t.Fatalf("undelegated provisioning = %d replayed=%q, want a fresh 403", denied.Code, denied.Header().Get("Idempotent-Replayed"))
	}
	deniedAgain := request("refused-"+suffix, fmt.Sprintf(`{"slug":%q,"name":"Refused"}`, refused))
	if deniedAgain.Code != http.StatusForbidden || deniedAgain.Header().Get("Idempotent-Replayed") != "true" {
		t.Fatalf("retried refusal = %d replayed=%q, want the recorded 403 marked as a replay", deniedAgain.Code, deniedAgain.Header().Get("Idempotent-Replayed"))
	}
}
