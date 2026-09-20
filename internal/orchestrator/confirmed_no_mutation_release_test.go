// SPDX-License-Identifier: BUSL-1.1

package orchestrator_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/orchestrator"
)

// A positive protocol proof is not permission to erase an uncertain database
// outcome. If releasing the claim fails, a new process must still refuse replay.
func TestConfirmedNoMutationReleaseFailureStaysFenced(t *testing.T) {
	s := newStore(t)
	const key = "confirmed-no-mutation-release-failure"
	_, err := s.SystemPool().Exec(t.Context(), `CREATE FUNCTION confirmed_release_failure() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF OLD.tenant_id='11111111-1111-1111-1111-111111111111'::uuid AND OLD.key='confirmed-no-mutation-release-failure' THEN
  RAISE EXCEPTION 'owned release failure with private-token-value';
 END IF;
 RETURN OLD;
END $$;
CREATE TRIGGER confirmed_release_failure BEFORE DELETE ON idempotency_keys FOR EACH ROW EXECUTE FUNCTION confirmed_release_failure()`)
	if err != nil {
		t.Fatal(err)
	}
	released := false
	restore := func() {
		if released {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := s.SystemPool().Exec(ctx, `DROP TRIGGER confirmed_release_failure ON idempotency_keys; DROP FUNCTION confirmed_release_failure()`); err != nil {
			t.Error(err)
			return
		}
		released = true
	}
	t.Cleanup(restore)
	calls := 0
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result, err := orchestrator.NewIdempotency(s).DoAtMostOnceEffect(ctx, tenantA, key, func(context.Context) ([]byte, error) {
		calls++
		cancel()
		return nil, orchestrator.ConfirmedNoMutation(context.Canceled)
	})
	if len(result) != 0 || !errors.Is(err, orchestrator.ErrEffectIndeterminate) {
		t.Fatalf("failed release was made replayable: %v", err)
	}
	if strings.Contains(err.Error(), "private-token-value") {
		t.Fatal("cleanup error leaked raw database detail")
	}
	if err := s.WithTenant(t.Context(), tenantA, func(tx pgx.Tx) error {
		var state string
		var hasResult bool
		if err := tx.QueryRow(t.Context(), `SELECT status,result IS NOT NULL FROM idempotency_keys WHERE tenant_id=$1 AND key=$2`, tenantA, key).Scan(&state, &hasResult); err != nil {
			return err
		}
		if state != "pending" || hasResult {
			t.Fatalf("uncertain claim changed: status=%s result=%t", state, hasResult)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	restore()
	// Even after the database is healthy, an independent recorder has no proof
	// that it owns the old attempt. It must not infer permission from age/error.
	_, err = orchestrator.NewIdempotency(s).DoAtMostOnceEffect(t.Context(), tenantA, key, func(context.Context) ([]byte, error) { calls++; return []byte("must-not-run"), nil })
	if !errors.Is(err, orchestrator.ErrEffectIndeterminate) || calls != 1 {
		t.Fatalf("restarted recorder replayed uncertain claim: calls=%d err=%v", calls, err)
	}
}
