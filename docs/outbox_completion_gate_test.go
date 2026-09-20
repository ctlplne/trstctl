// SPDX-License-Identifier: BUSL-1.1

package docs

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ---- AN-6: marking an outbox row delivered belongs to the orchestrator alone ----
//
// AN-6 says an external call's intent is written to the outbox in the same
// transaction as the state change, and a separate worker performs it. What makes
// that safe is the spine's completion path in internal/orchestrator/outbox.go: it
// flips a row to 'delivered' only under the dispatch lease (so two drainers cannot
// both finish the same item) and records the destination's circuit success (so a
// healthy endpoint stops being backed off).
//
// A hand-rolled `UPDATE outbox SET status = 'delivered'` anywhere else silently
// drops both. internal/server/secrets.go carried two of them
// (dynamicSecretOutboxQueue.Done and secretSyncOutboxQueue.Done); each could flip a
// row a dispatch worker was still holding. AN-6 has no linter, so this is the class
// gate: the delivered-completion statement may live in exactly one production file.
//
// Scope note: this gate covers COMPLETION only. Enqueue sites (`INSERT INTO
// outbox`), effect-lane metadata updates, and the notification dead-letter requeue
// to 'pending' are a different class and are deliberately not covered here.

var (
	// sqlStringLiteral matches one Go string literal (raw or interpreted). Scoping
	// the scan to a single literal is what makes the gate whitespace- and
	// case-insensitive without the false positives a fixed byte window produces:
	// `UPDATE outbox SET status = 'pending'` followed 40 lines later by an
	// unrelated `status = 'delivered'` is two literals, not one statement.
	sqlStringLiteral = regexp.MustCompile("(?s)`[^`]*`" + `|"(?:[^"\\\n]|\\.)*"`)
	// updateOutboxTable deliberately ends on a word boundary so
	// outbox_reconciliation_checkpoint is not mistaken for the outbox table.
	updateOutboxTable  = regexp.MustCompile(`(?is)update\s+outbox\b`)
	setClauseKeyword   = regexp.MustCompile(`(?is)\bset\b`)
	whereClauseKeyword = regexp.MustCompile(`(?is)\bwhere\b`)
	setStatusDelivered = regexp.MustCompile(`(?is)status\s*=\s*'delivered'`)
)

// outboxDeliveredCompletions returns every SQL string literal in body that updates
// the outbox table and sets a row's status to 'delivered'. Matching is
// case-insensitive and whitespace-insensitive: `status='delivered'` (the spacing
// internal/projections/outbox_test.go already uses) and a lowercased or reflowed
// statement are all caught.
func outboxDeliveredCompletions(body string) []string {
	var out []string
	for _, literal := range sqlStringLiteral.FindAllString(body, -1) {
		updateAt := updateOutboxTable.FindStringIndex(literal)
		if updateAt == nil {
			continue
		}
		afterUpdate := literal[updateAt[1]:]
		setAt := setClauseKeyword.FindStringIndex(afterUpdate)
		if setAt == nil {
			continue
		}
		setClause := afterUpdate[setAt[1]:]
		if whereAt := whereClauseKeyword.FindStringIndex(setClause); whereAt != nil {
			setClause = setClause[:whereAt[0]]
		}
		if setStatusDelivered.MatchString(setClause) {
			out = append(out, literal)
		}
	}
	return out
}

// outboxCompletionAllowedFiles are the production files permitted to mark an outbox
// row delivered. Keep this at one entry: the orchestrator spine.
var outboxCompletionAllowedFiles = map[string]bool{
	"internal/orchestrator/outbox.go": true,
}

// outboxCompletionSkippedPrefixes is the explicit, commented exclusion list. Every
// other tracked production Go file is scanned by default, so a delivered-completion
// added under a new top-level root is covered without editing this gate.
var outboxCompletionSkippedPrefixes = []string{
	// scripts/perf holds soak/burst harness binaries that fabricate outbox backlog
	// depth directly. They are load fixtures, not a delivery path.
	"scripts/",
}

// outboxCompletionSites returns every tracked, non-test production Go file holding a
// delivered-completion statement, with the statements it holds.
func outboxCompletionSites(t *testing.T) map[string][]string {
	t.Helper()
	sites := map[string][]string{}
	for _, rel := range gitTrackedFiles(t) {
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		if strings.Contains(rel, "/testdata/") || strings.HasPrefix(rel, "testdata/") {
			continue
		}
		if hasAnyPrefix(rel, outboxCompletionSkippedPrefixes) {
			continue
		}
		body, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(rel)))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("AN-6 outbox completion gate: read %s: %v", rel, err)
		}
		if found := outboxDeliveredCompletions(string(body)); len(found) > 0 {
			sites[rel] = found
		}
	}
	return sites
}

func TestOutboxDeliveredCompletionsRouteThroughTheOrchestrator(t *testing.T) {
	sites := outboxCompletionSites(t)
	var offenders []string
	for rel := range sites {
		if !outboxCompletionAllowedFiles[rel] {
			offenders = append(offenders, rel)
		}
	}
	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Errorf("AN-6: %v hand-roll an `UPDATE outbox SET status = 'delivered'`. A completion outside internal/orchestrator skips the dispatch lease predicate (two drainers can complete the same item) and never records the destination's circuit success. Route it through orchestrator.Outbox.CompleteByKey.", offenders)
	}
	if len(sites["internal/orchestrator/outbox.go"]) == 0 {
		t.Fatal("AN-6: internal/orchestrator/outbox.go no longer contains a delivered-completion statement; the outbox completion path moved — re-point this gate")
	}
}

// TestOutboxCompletionGateFlagsAHandRolledCompletion is the planted-fixture
// self-test: a gate that cannot fire on a realistic variant is not evidence. Each
// positive probe is a spelling a future bypass could plausibly use; each negative
// probe is a statement the gate must not mistake for a completion.
func TestOutboxCompletionGateFlagsAHandRolledCompletion(t *testing.T) {
	for _, planted := range []string{
		"_ = `UPDATE outbox SET status = 'delivered' WHERE tenant_id = $1`",
		"_ = `UPDATE outbox SET status='delivered', delivered_at=now() WHERE tenant_id=$1`",
		"_ = \"update outbox set status = 'delivered' where idempotency_key = $1\"",
		"_ = `UPDATE   outbox\n\t    SET   status   =   'delivered'`",
	} {
		if len(outboxDeliveredCompletions(planted)) != 1 {
			t.Errorf("AN-6 gate is blind to a planted hand-rolled completion %q; a reformatted bypass would slip through", planted)
		}
	}
	for _, benign := range []string{
		"_ = `UPDATE outbox SET status = 'pending', worker_id = NULL WHERE id = $1`",
		"_ = `UPDATE outbox SET status = 'processing' WHERE EXISTS (SELECT 1 FROM secret_sync_jobs WHERE status = 'delivered')`",
		"_ = `UPDATE outbox SET effect_lane = $3 WHERE tenant_id = $1 AND id = $2`",
		"_ = `UPDATE outbox_reconciliation_checkpoint SET status = 'delivered' WHERE id = 1`",
		"_ = `UPDATE secret_sync_jobs SET status = 'delivered' WHERE tenant_id = $1`",
	} {
		if len(outboxDeliveredCompletions(benign)) != 0 {
			t.Errorf("AN-6 gate flags %q, which is not an outbox delivery completion; a false positive makes the gate get relaxed", benign)
		}
	}
}

// TestOrchestratorOutboxCompletionKeepsLeaseAndCircuitInvariants pins the three
// properties the class gate above exists to protect, INSIDE the statements that
// carry them. A whole-file Contains check is not enough: finalizeClaim's failure
// branch also spells "AND status = 'processing'" and "AND worker_id = $3", so the
// lease predicate could be deleted from the delivered completion with a file-level
// guard still green.
func TestOrchestratorOutboxCompletionKeepsLeaseAndCircuitInvariants(t *testing.T) {
	body := read(t, "../internal/orchestrator/outbox.go")
	statements := outboxDeliveredCompletions(body)
	if len(statements) != 3 {
		t.Fatalf("AN-6: internal/orchestrator/outbox.go holds %d delivered-completion statements, want exactly 3 (finalizeClaim's dispatcher lease, CompleteAgentJobClaim's exact signed-result claim, and CompleteByKey's non-leaseholder path)", len(statements))
	}
	leaseholder := pickOutboxCompletion(t, statements, "WHERE id = $1")
	agentClaim := pickOutboxCompletion(t, statements, "AND claimed_by_agent_id = $2::uuid")
	nonLeaseholder := pickOutboxCompletion(t, statements, "AND idempotency_key = $3")

	// Tokens are matched against the whitespace-normalized statement, so reflowing
	// the SQL does not fail the guard but removing a predicate does.
	requireOrderedTokens(t, "AN-6 leaseholder completion (finalizeClaim)", normalizeSQL(leaseholder),
		"SET status = 'delivered'", "AND status = 'processing'", "AND worker_id = $3")
	requireOrderedTokens(t, "AN-6 exact signed-result completion (CompleteAgentJobClaim)", normalizeSQL(agentClaim),
		"SET claim_completed_at = $5", "status = 'delivered'", "WHERE tenant_id = $1", "AND id = $3",
		"AND claimed_by_agent_id = $2::uuid", "AND claim_attempts = $4", "AND claim_expires_at >= $5",
		"AND claim_completed_at IS NULL", "AND status = 'pending'", "AND delivered_at IS NULL")
	requireOrderedTokens(t, "AN-6 non-leaseholder completion (Outbox.CompleteByKey)", normalizeSQL(nonLeaseholder),
		"SET status = 'delivered'", "AND status <> 'delivered'",
		"AND (status <> 'processing' OR lease_until IS NULL OR lease_until <= $4)")

	// All three completions must record the destination's circuit success, each on its
	// own path — otherwise a lane stays open against an endpoint that just answered.
	requireOrderedTokens(t, "AN-6 dispatcher completion circuit success", body,
		"func (o *Outbox) finalizeClaim(",
		"o.recordCircuitSuccess(claim.msg, o.clockNow())")
	requireOrderedTokens(t, "AN-6 exact agent-claim completion circuit success", body,
		"func (o *Outbox) CompleteAgentJobClaim(",
		"o.recordCircuitSuccess(msg, at.UTC())")
	requireOrderedTokens(t, "AN-6 non-leaseholder completion circuit success", body,
		"func (o *Outbox) CompleteByKey(",
		"return false, ErrOutboxLeaseHeld",
		"o.recordCircuitSuccess(msg, now)")

	// The in-request drainers must be able to see a live lease, or they perform the
	// external effect a second time before CompleteByKey refuses to complete it.
	requireOrderedTokens(t, "AN-6 lease-aware Pending", body,
		"LeaseHeld bool",
		"func (o *Outbox) Pending(",
		"lease_until IS NOT NULL AND lease_until > $2",
		"&r.LeaseHeld")
}

func pickOutboxCompletion(t *testing.T, statements []string, marker string) string {
	t.Helper()
	for _, stmt := range statements {
		if strings.Contains(normalizeSQL(stmt), marker) {
			return stmt
		}
	}
	t.Fatalf("AN-6: no outbox delivered-completion statement contains %q; the completion paths were restructured — re-point this gate", marker)
	return ""
}

func normalizeSQL(stmt string) string { return strings.Join(strings.Fields(stmt), " ") }
