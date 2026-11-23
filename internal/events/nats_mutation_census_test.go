// SPDX-License-Identifier: BUSL-1.1

package events

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// Every direct broker mutation in this package needs a reviewed admission path.
// The function and selector census catches a new write even if it avoids the
// normalized Append/Import path. A new API selector must be added here first.
func TestDirectNATSMutationSitesAreReviewed(t *testing.T) {
	mutation := map[string]bool{
		"Publish": true, "PublishMsg": true,
		"DeleteMsg": true, "SecureDeleteMsg": true,
		"CreateStream": true, "UpdateStream": true, "DeleteStream": true,
		"PurgeStream": true,
	}
	want := map[string]int{
		"backup_history.go:bindBackupRestoreIdentity:UpdateStream":             1,
		"backup_history.go:clearBackupRestoreIdentity:UpdateStream":            1,
		"backup_history.go:freezeLegacyBackupRestoreRoute:UpdateStream":        1,
		"backup_history.go:restoreBackupGap:Publish":                           1,
		"backup_history.go:restoreBackupGap:SecureDeleteMsg":                   1,
		"backup_history.go:restoreBackupHistoryAdmitted:PublishMsg":            1,
		"backup_history.go:restoreBackupGapAtSequence:SecureDeleteMsg":         1,
		"event_id_index.go:deleteEventIDIndexesExcept:DeleteStream":            1,
		"event_id_index.go:eventIDIndexFor:CreateStream":                       1,
		"event_id_index.go:indexEventID:Publish":                               2,
		"event_id_index.go:indexEventIDsThrough:Publish":                       1,
		"events.go:Delete:DeleteMsg":                                           1,
		"events.go:PruneTenantThroughCheckpoint:SecureDeleteMsg":               1,
		"tenant_audit_stream.go:DeleteTenantAuditStream:DeleteStream":          1,
		"tenant_data_rewrite.go:appendRewriteReceipt:Publish":                  1,
		"tenant_data_rewrite.go:clearRewriteMetadata:UpdateStream":             1,
		"tenant_data_rewrite.go:copyRewriteMessage:Publish":                    1,
		"tenant_data_rewrite.go:ensureRewriteGap:Publish":                      1,
		"tenant_data_rewrite.go:ensureRewriteGap:SecureDeleteMsg":              2,
		"tenant_data_rewrite.go:publishToActive:Publish":                       1,
		"tenant_data_rewrite.go:recoverExternallyPreparedRewrite:UpdateStream": 1,
		"tenant_data_rewrite.go:restoreSourceAndDiscardTarget:DeleteStream":    1,
		"tenant_data_rewrite.go:restoreSourceAndDiscardTarget:UpdateStream":    1,
		"tenant_data_rewrite.go:rewriteStoredGeneration:CreateStream":          1,
		"tenant_data_rewrite.go:rewriteStoredGeneration:UpdateStream":          5,
		"tenant_data_rewrite.go:scrubAndDeleteSource:DeleteStream":             1,
		"tenant_data_rewrite.go:scrubAndDeleteSource:SecureDeleteMsg":          1,
		"tenant_index.go:deleteTenantIndexGeneration:DeleteStream":             1,
		"tenant_index.go:indexTenantEventsThrough:Publish":                     2,
		"tenant_index.go:tenantIndexFor:CreateStream":                          1,
	}
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]int)
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if ok && mutation[selector.Sel.Name] {
					got[path+":"+function.Name.Name+":"+selector.Sel.Name]++
				}
				return true
			})
		}
	}
	for site, count := range got {
		if want[site] != count {
			t.Errorf("unreviewed broker mutation %s: got %d, want %d", site, count, want[site])
		}
	}
	for site, count := range want {
		if got[site] != count {
			t.Errorf("reviewed broker mutation %s disappeared or changed: got %d, want %d", site, got[site], count)
		}
	}
}
