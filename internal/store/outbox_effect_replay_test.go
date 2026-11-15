// SPDX-License-Identifier: BUSL-1.1

package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// outboxEffectReplayExemptions lists each store function that inserts into
// the outbox without consulting effectsAlreadyQueued, with why a full rebuild
// does not queue its effect a second time, or the open lead that closes it
// (A237L4-L2). A rebuild re-projects every event the deployment projected
// before; the outbox is not truncated, but a delivered row is reclaimed a day
// after delivery, so a projection that dedupes on its own row queues again.
var outboxEffectReplayExemptions = map[string]string{
	"ApplyRestoreDrillAttestationTx":   "the restore-drill attestation is kept across a rebuild (preserveIndependentAttestationsTx) and its alert is skipped for a preserved attestation (preservedRestoreDrillAttestationTx)",
	"ApplySecretSyncIntentTx":          "open lead A237L4-L4: secret_sync_jobs.outbox_id holds the row's id and the secret-sync outbox trigger admits only a pending row; a retained row is already reattached",
	"ensureConnectorRightSizeOutboxTx": "open lead A237L4-L4: the run's terminal event matches the row's original id, which a re-created row cannot have",
}

var outboxInsertRE = regexp.MustCompile(`INSERT INTO outbox\b`)

// TestEveryProjectionQueuedEffectSkipsARebuildA237L4L2: every function of the
// store that inserts into the outbox consults effectsAlreadyQueued, so a full
// rebuild queues no effect again for an event it projected before, or is
// listed in outboxEffectReplayExemptions with its reason; the list names no
// function that does not insert, or that consults the mark.
func TestEveryProjectionQueuedEffectSkipsARebuildA237L4L2(t *testing.T) {
	functions := outboxInsertingFunctions(t)
	if len(functions) < 20 {
		t.Fatalf("found %d functions inserting into the outbox; the scan is broken: %v", len(functions), functions)
	}
	for name, guarded := range functions {
		reason, exempt := outboxEffectReplayExemptions[name]
		switch {
		case guarded && exempt:
			t.Errorf("%s consults effectsAlreadyQueued and is also exempt (%q); drop the exemption", name, reason)
		case !guarded && !exempt:
			t.Errorf("%s inserts into the outbox without consulting effectsAlreadyQueued: a full rebuild queues its effect "+
				"again once the delivered row is reclaimed. Skip the insert under the mark, or list why it cannot in "+
				"outboxEffectReplayExemptions", name)
		}
	}
	for name := range outboxEffectReplayExemptions {
		if _, ok := functions[name]; !ok {
			t.Errorf("outboxEffectReplayExemptions lists %s, which inserts into no outbox row", name)
		}
	}
}

// outboxInsertingFunctions maps each function of this package (tests aside)
// whose body holds a string with INSERT INTO outbox to whether its body calls
// effectsAlreadyQueued or replayedEffectStatus.
func outboxInsertingFunctions(t *testing.T) map[string]bool {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	out := map[string]bool{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			inserts, guarded := false, false
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.BasicLit:
					if x.Kind == token.STRING && outboxInsertRE.MatchString(x.Value) {
						inserts = true
					}
				case *ast.CallExpr:
					// replayedEffectStatus consults the mark for an effect row
					// whose id its caller keeps (A237L4-L3).
					if id, ok := x.Fun.(*ast.Ident); ok && (id.Name == "effectsAlreadyQueued" || id.Name == "replayedEffectStatus") {
						guarded = true
					}
				}
				return true
			})
			if inserts {
				out[fn.Name.Name] = guarded
			}
		}
	}
	return out
}
