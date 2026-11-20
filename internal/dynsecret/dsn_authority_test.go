// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// A raw native open can interpret a DSN before the dial hook exists. Assert
// the boundary at each independent caller without exercising a forbidden
// operation against the host. Connector behavior is tested separately.
func TestDatabaseEntryPointsAvoidRawNativeDSNParsers(t *testing.T) {
	for _, tc := range []struct{ file, function, qualifier, method string }{
		{"credential_account.go", "CredentialAccount", "pgconn", "ParseConfig"},
		{"credential_account.go", "CredentialAccount", "mysql", "ParseDSN"},
		{"drivers.go", "connectPostgresAdmin", "pgx", "Connect"},
		{"signin_read.go", "ReadSignIns", "pgconn", "Connect"},
		{"signin_check.go", "CheckSignIn", "pgconn", "Connect"},
		{"discover_accounts.go", "DiscoverPrivilegedAccounts", "pgconn", "Connect"},
		{"drivers.go", "OpenMySQLExecutor", "sql", "Open"},
		{"drivers.go", "OpenMongoAdmin", "", "ApplyURI"},
		{"drivers.go", "VerifyMongoCredential", "", "ApplyURI"},
		{"oracle.go", "OpenOracleExecutor", "sql", "Open"},
		{"oracle.go", "VerifyCredential", "sql", "Open"},
		{"mssql.go", "OpenMSSQLExecutor", "sql", "Open"},
		{"mssql.go", "VerifyCredential", "sql", "Open"},
		{"hana.go", "OpenHANAExecutor", "sql", "Open"},
		{"hana.go", "VerifyCredential", "sql", "Open"},
	} {
		t.Run(tc.file+"/"+tc.function+"/"+tc.method, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), tc.file, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name.Name != tc.function {
					continue
				}
				found = true
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok || sel.Sel.Name != tc.method {
						return true
					}
					prefix, named := sel.X.(*ast.Ident)
					if tc.qualifier == "" || named && prefix.Name == tc.qualifier {
						t.Errorf("%s still invokes a raw native DSN entry", tc.function)
					}
					return true
				})
			}
			if !found {
				t.Fatal("update the boundary assertion for the renamed entry point")
			}
		})
	}
}
