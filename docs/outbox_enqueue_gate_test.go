// SPDX-License-Identifier: MPL-2.0

package docs

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ---- CODE-108: AN-6 enqueue — every outbox INSERT runs on the caller's tx -------
//
// AN-6 says an external call's intent is written to the outbox in the SAME database
// transaction as the state change it accompanies, and a separate worker performs the
// call. The structural enforcement of "same transaction" is the canonical enqueue's
// signature: `func (o *Outbox) Enqueue(ctx context.Context, tx pgx.Tx, e Entry)` takes
// the caller's transaction handle, so the intent is durable if and only if the state
// change commits. An `INSERT INTO outbox` issued on a `*pgxpool.Pool` (or any other
// non-transactional handle) commits on its own connection: the effect survives a
// rolled-back state change, or the state change survives a failed enqueue. Either way
// the outbox stops being a transactional outbox.
//
// The pre-existing ARCH-007 pin (docs/protect_guards_test.go) only greps
// ../internal/orchestrator/outbox.go for the substring "INSERT INTO outbox". It says
// nothing about the nine other production enqueue sites — seven under internal/store
// and two under ee/ — so any of them could be re-pointed at a pool with every gate
// green. AN-6 has no linter, so this is the class gate for ENQUEUE.
//
// Complementary to CODE-107 (docs/outbox_completion_gate_test.go), deliberately not
// duplicative: that gate covers COMPLETION (`UPDATE outbox SET status = 'delivered'`
// may live in exactly one file). This gate covers ENQUEUE (`INSERT INTO outbox` may
// live anywhere, but only on a pgx.Tx). Neither statement class is a site for the
// other, and the planted-fixture self-test below asserts that separation.

// insertIntoOutboxStatement matches an enqueue statement inside one Go string
// literal. Matching is case- and whitespace-insensitive because the repo already
// uses more than one spacing (`INSERT INTO outbox (tenant_id, destination, payload,
// idempotency_key, effect_lane)` in the orchestrator, a different column order in
// internal/store, and a reflowed `SELECT ... WHERE NOT EXISTS` body in the ee/
// recorders). The trailing word boundary is what keeps
// `INSERT INTO outbox_reconciliation_checkpoint` from being mistaken for the outbox
// table: `_` is a word character, so no boundary exists there.
var insertIntoOutboxStatement = regexp.MustCompile(`(?is)insert\s+into\s+outbox\b`)

// outboxEnqueueExecMethods are the pgx execution methods an enqueue can ride on. A
// statement handed to anything else is reported rather than assumed safe.
var outboxEnqueueExecMethods = map[string]bool{
	"Exec":      true,
	"Query":     true,
	"QueryRow":  true,
	"SendBatch": true,
	"CopyFrom":  true,
}

// outboxEnqueueSkippedPrefixes is the explicit, commented exclusion list. Every other
// tracked production Go file is scanned by default, so an enqueue added under a new
// top-level root is covered without editing this gate.
var outboxEnqueueSkippedPrefixes = []string{
	// scripts/perf holds soak/burst harness binaries that fabricate outbox backlog
	// depth directly against a throwaway database. They are load fixtures, not a
	// delivery path — the same carve-out CODE-107 makes.
	"scripts/",
	// tools/ is the architecture linter and its analysistest fixtures; the fixture
	// trees under tools/trstctllint/*/testdata are deliberately-wrong Go by design.
	"tools/",
}

// outboxEnqueueSite is one `INSERT INTO outbox` statement and the verdict on the
// handle it executes on.
type outboxEnqueueSite struct {
	File     string
	Line     int
	Receiver string
	OnTx     bool
	Why      string
}

func (s outboxEnqueueSite) String() string {
	return fmt.Sprintf("%s:%d (%s): %s", s.File, s.Line, s.Receiver, s.Why)
}

// outboxEnqueueTxParams returns the parameter names a function (declaration or
// literal) binds to type pgx.Tx. Closures matter as much as declarations: both ee/
// enqueues live inside a `WithTenant(ctx, tenantID, func(tx pgx.Tx) error {...})`
// callback, not in a function whose own signature carries the handle.
func outboxEnqueueTxParams(fn ast.Node) map[string]bool {
	names := map[string]bool{}
	var params *ast.FieldList
	switch f := fn.(type) {
	case *ast.FuncDecl:
		params = f.Type.Params
	case *ast.FuncLit:
		params = f.Type.Params
	default:
		return names
	}
	if params == nil {
		return names
	}
	for _, field := range params.List {
		// types.ExprString renders the type syntactically; no type checking, no
		// package loading. `pgx.Tx` is the only spelling the repo uses.
		if types.ExprString(field.Type) != "pgx.Tx" {
			continue
		}
		for _, name := range field.Names {
			names[name.Name] = true
		}
	}
	return names
}

// outboxEnqueueScanSource parses one Go source file and returns every enqueue site it
// holds. A site is judged safe only when the statement is an argument to an
// Exec/Query-family call whose receiver is a plain identifier bound to a `pgx.Tx`
// parameter of an enclosing function or closure. Anything else — a pool receiver, a
// field selector such as `s.pool.Exec`, an unrecognized method, or a statement hoisted
// into a constant and executed elsewhere — is reported, because the guard cannot prove
// it runs inside the caller's transaction.
func outboxEnqueueScanSource(rel string, src []byte) ([]outboxEnqueueSite, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, rel, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}

	var sites []outboxEnqueueSite
	attributed := map[token.Pos]bool{}
	var enclosing []ast.Node

	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			enclosing = enclosing[:len(enclosing)-1]
			return true
		}
		enclosing = append(enclosing, n)

		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, arg := range call.Args {
			lit, ok := arg.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			text, uerr := strconv.Unquote(lit.Value)
			if uerr != nil || !insertIntoOutboxStatement.MatchString(text) {
				continue
			}
			attributed[lit.Pos()] = true
			sites = append(sites, outboxEnqueueJudge(fset, call, lit, rel, enclosing))
		}
		return true
	})

	// A statement the walker never attributed to a call is a bypass shape in its own
	// right: `const q = "INSERT INTO outbox ..."` executed on a pool three functions
	// away would otherwise be invisible. Report it instead of ignoring it.
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING || attributed[lit.Pos()] {
			return true
		}
		text, uerr := strconv.Unquote(lit.Value)
		if uerr != nil || !insertIntoOutboxStatement.MatchString(text) {
			return true
		}
		sites = append(sites, outboxEnqueueSite{
			File:     rel,
			Line:     fset.Position(lit.Pos()).Line,
			Receiver: "<not passed to a call>",
			Why:      "the statement is not an argument to an Exec/Query call, so the guard cannot prove which handle executes it",
		})
		return true
	})

	return sites, nil
}

// outboxEnqueueJudge resolves the handle one enqueue statement executes on.
func outboxEnqueueJudge(fset *token.FileSet, call *ast.CallExpr, lit *ast.BasicLit, rel string, enclosing []ast.Node) outboxEnqueueSite {
	site := outboxEnqueueSite{File: rel, Line: fset.Position(lit.Pos()).Line}

	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		site.Receiver = types.ExprString(call.Fun)
		site.Why = "the statement is executed by a plain function call, not a method on a transaction handle"
		return site
	}
	site.Receiver = types.ExprString(sel.X) + "." + sel.Sel.Name
	if !outboxEnqueueExecMethods[sel.Sel.Name] {
		site.Why = "executed via the unrecognized method " + sel.Sel.Name + "; extend outboxEnqueueExecMethods if this is a real pgx execution path"
		return site
	}
	recv, ok := sel.X.(*ast.Ident)
	if !ok {
		site.Why = "the receiver is a selector, not a transaction parameter — a `*pgxpool.Pool` field commits on its own connection"
		return site
	}
	for i := len(enclosing) - 1; i >= 0; i-- {
		switch enclosing[i].(type) {
		case *ast.FuncDecl, *ast.FuncLit:
			if outboxEnqueueTxParams(enclosing[i])[recv.Name] {
				site.OnTx = true
				return site
			}
		}
	}
	site.Why = "the receiver " + recv.Name + " is not a `pgx.Tx` parameter of any enclosing function or closure"
	return site
}

// outboxEnqueueProductionSites returns every enqueue site in tracked, non-test
// production Go source.
func outboxEnqueueProductionSites(t *testing.T) []outboxEnqueueSite {
	t.Helper()
	var sites []outboxEnqueueSite
	for _, rel := range gitTrackedFiles(t) {
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		if strings.Contains(rel, "/testdata/") || strings.HasPrefix(rel, "testdata/") {
			continue
		}
		if hasAnyPrefix(rel, outboxEnqueueSkippedPrefixes) {
			continue
		}
		body, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(rel)))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("AN-6 outbox enqueue gate: read %s: %v", rel, err)
		}
		// Cheap pre-filter: only files that mention the statement are parsed.
		if !insertIntoOutboxStatement.Match(body) {
			continue
		}
		found, err := outboxEnqueueScanSource(rel, body)
		if err != nil {
			t.Fatalf("AN-6 outbox enqueue gate: parse %s: %v", rel, err)
		}
		sites = append(sites, found...)
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].File != sites[j].File {
			return sites[i].File < sites[j].File
		}
		return sites[i].Line < sites[j].Line
	})
	return sites
}

// TestOutboxEnqueuesExecuteOnATransactionHandle is the class gate: no production
// `INSERT INTO outbox` may run on anything but the caller's transaction.
func TestOutboxEnqueuesExecuteOnATransactionHandle(t *testing.T) {
	var offenders []string
	for _, site := range outboxEnqueueProductionSites(t) {
		if !site.OnTx {
			offenders = append(offenders, site.String())
		}
	}
	if len(offenders) > 0 {
		t.Errorf("AN-6: %d outbox enqueue(s) are not provably on the caller's transaction:\n  %s\n"+
			"An outbox INSERT on a pool commits independently of the state change it accompanies, so a rollback "+
			"leaves the external effect scheduled and a crash can lose it. Take a `pgx.Tx` parameter, or route the "+
			"intent through orchestrator.Outbox.Enqueue / EnqueueIfAbsent, which take one.",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}

// outboxEnqueueExpectedSites pins the enqueue inventory as of this gate's landing. It
// is the sentinel set that keeps a broken walker from passing by finding nothing: a
// regex that stops matching, a parser mode change, or an over-broad skip list turns
// this red instead of silently reporting zero offenders over zero sites.
//
// Files NOT listed here are still scanned and still judged — a new enqueue site does
// not need a row. A row that stops matching means an enqueue path moved: confirm the
// move was intended, then update the row.
var outboxEnqueueExpectedSites = map[string]int{
	"internal/orchestrator/outbox.go":                 2, // canonical Enqueue + EnqueueIfAbsent
	"internal/store/code_signing.go":                  1,
	"internal/store/managed_key.go":                   1,
	"internal/store/notification_delivery.go":         1,
	"internal/store/remediation_playbooks.go":         1,
	"internal/store/secret_integration_outbox.go":     2,
	"internal/store/tenant_key_domain_seal_outbox.go": 1,
	"ee/agentid/delegation/brokerstore/recorder.go":   1,
	"ee/succession/orchestrator/orchestrator.go":      1,
}

// TestOutboxEnqueueInventoryPinsTheKnownSites keeps the class gate honest and pins the
// structural rule it enforces: the canonical enqueues must keep taking a pgx.Tx.
func TestOutboxEnqueueInventoryPinsTheKnownSites(t *testing.T) {
	counts := map[string]int{}
	for _, site := range outboxEnqueueProductionSites(t) {
		counts[site.File]++
	}
	files := make([]string, 0, len(outboxEnqueueExpectedSites))
	for rel := range outboxEnqueueExpectedSites {
		files = append(files, rel)
	}
	sort.Strings(files)
	for _, rel := range files {
		if got := counts[rel]; got != outboxEnqueueExpectedSites[rel] {
			t.Errorf("AN-6: %s holds %d `INSERT INTO outbox` statement(s), want %d; either an enqueue path moved "+
				"(confirm it is still transactional, then update outboxEnqueueExpectedSites) or this gate's walker "+
				"stopped seeing statements it used to see", rel, got, outboxEnqueueExpectedSites[rel])
		}
	}

	// The pgx.Tx parameter on the canonical enqueues IS the AN-6 same-transaction
	// enforcement; ARCH-007 only pins their names as text.
	canonical := "internal/orchestrator/outbox.go"
	body, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(canonical)))
	if err != nil {
		t.Fatalf("AN-6 outbox enqueue gate: read %s: %v", canonical, err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, canonical, body, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("AN-6 outbox enqueue gate: parse %s: %v", canonical, err)
	}
	wantTxParam := map[string]bool{"Enqueue": false, "EnqueueIfAbsent": false}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil {
			continue
		}
		if _, tracked := wantTxParam[fn.Name.Name]; !tracked {
			continue
		}
		if types.ExprString(fn.Recv.List[0].Type) != "*Outbox" {
			continue
		}
		if len(outboxEnqueueTxParams(fn)) > 0 {
			wantTxParam[fn.Name.Name] = true
		}
	}
	for _, name := range []string{"Enqueue", "EnqueueIfAbsent"} {
		if !wantTxParam[name] {
			t.Errorf("AN-6: (*Outbox).%s in %s no longer takes a `pgx.Tx` parameter; the canonical enqueue no "+
				"longer forces the intent to commit with the state change", name, canonical)
		}
	}
}

// outboxEnqueuePlantedHeader is the preamble the planted fixtures share. The fixtures
// are parsed, never compiled, so the imports only need to make the type spellings
// resolvable to a reader.
const outboxEnqueuePlantedHeader = `package planted

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type store struct{ pool *pgxpool.Pool }

`

// TestOutboxEnqueueGateFlagsANonTransactionalInsert is the planted-fixture self-test:
// a gate that cannot fire on a realistic bypass is not evidence. Each positive probe is
// a shape a future non-transactional enqueue could plausibly take; each negative probe
// is a statement the gate must not mistake for one — including the completion and
// checkpoint statements that belong to CODE-107 and to nothing at all.
func TestOutboxEnqueueGateFlagsANonTransactionalInsert(t *testing.T) {
	planted := []struct {
		name      string
		body      string
		wantSites int
		wantBad   int
	}{
		{
			name: "pool field on the store",
			body: "func (s *store) enqueue(ctx context.Context) error {\n" +
				"\t_, err := s.pool.Exec(ctx, `INSERT INTO outbox (tenant_id, destination, payload, idempotency_key)\n" +
				"\t\t VALUES ($1, $2, $3, $4)`)\n\treturn err\n}\n",
			wantSites: 1, wantBad: 1,
		},
		{
			name: "pool parameter, lowercased statement",
			body: "func enqueue(ctx context.Context, pool *pgxpool.Pool) error {\n" +
				"\t_, err := pool.Exec(ctx, \"insert into outbox (tenant_id) values ($1)\")\n\treturn err\n}\n",
			wantSites: 1, wantBad: 1,
		},
		{
			name: "pool parameter, statement reflowed across lines",
			body: "func enqueue(ctx context.Context, pool *pgxpool.Pool) error {\n" +
				"\t_, err := pool.Exec(ctx, `INSERT\n\t   INTO   outbox (tenant_id)\n\t VALUES ($1)`)\n\treturn err\n}\n",
			wantSites: 1, wantBad: 1,
		},
		{
			name: "statement hoisted into a constant",
			body: "const q = `INSERT INTO outbox (tenant_id) VALUES ($1)`\n\n" +
				"func enqueue(ctx context.Context, pool *pgxpool.Pool) error {\n" +
				"\t_, err := pool.Exec(ctx, q)\n\treturn err\n}\n",
			wantSites: 1, wantBad: 1,
		},
		{
			name: "a transaction is in scope but a raw connection executes the statement",
			body: "func enqueue(ctx context.Context, conn *pgx.Conn, tx pgx.Tx) error {\n" +
				"\t_, err := conn.Exec(ctx, `INSERT INTO outbox (tenant_id) VALUES ($1)`)\n\treturn err\n}\n",
			wantSites: 1, wantBad: 1,
		},
		{
			name: "transaction parameter",
			body: "func enqueue(ctx context.Context, tx pgx.Tx) error {\n" +
				"\t_, err := tx.Exec(ctx, `INSERT INTO outbox (tenant_id) VALUES ($1)`)\n\treturn err\n}\n",
			wantSites: 1, wantBad: 0,
		},
		{
			name: "transaction bound by a WithTenant closure, as the ee/ recorders do",
			body: "func (s *store) enqueue(ctx context.Context) error {\n" +
				"\treturn withTenant(ctx, func(tx pgx.Tx) error {\n" +
				"\t\treturn tx.QueryRow(ctx, `INSERT INTO outbox (tenant_id) VALUES ($1) RETURNING id`).Scan(nil)\n" +
				"\t})\n}\n",
			wantSites: 1, wantBad: 0,
		},
		{
			name: "the reconciliation checkpoint table is not the outbox table",
			body: "func enqueue(ctx context.Context, pool *pgxpool.Pool) error {\n" +
				"\t_, err := pool.Exec(ctx, `INSERT INTO outbox_reconciliation_checkpoint (id) VALUES ($1)`)\n\treturn err\n}\n",
			wantSites: 0, wantBad: 0,
		},
		{
			name: "a delivered-completion belongs to CODE-107, not to this gate",
			body: "func complete(ctx context.Context, pool *pgxpool.Pool) error {\n" +
				"\t_, err := pool.Exec(ctx, `UPDATE outbox SET status = 'delivered' WHERE id = $1`)\n\treturn err\n}\n",
			wantSites: 0, wantBad: 0,
		},
	}

	for _, probe := range planted {
		t.Run(probe.name, func(t *testing.T) {
			sites, err := outboxEnqueueScanSource("planted.go", []byte(outboxEnqueuePlantedHeader+probe.body))
			if err != nil {
				t.Fatalf("planted fixture does not parse: %v", err)
			}
			if len(sites) != probe.wantSites {
				t.Fatalf("AN-6 enqueue gate found %d site(s) in the planted fixture, want %d: %v", len(sites), probe.wantSites, sites)
			}
			bad := 0
			for _, site := range sites {
				if !site.OnTx {
					bad++
				}
			}
			if bad != probe.wantBad {
				t.Errorf("AN-6 enqueue gate flagged %d of %d planted site(s), want %d; %v",
					bad, len(sites), probe.wantBad, sites)
			}
		})
	}
}
