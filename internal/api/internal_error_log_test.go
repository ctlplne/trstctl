// SPDX-License-Identifier: MPL-2.0

package api

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// The 500 log must let an operator find the cause without ever carrying a row
// value: PostgreSQL's Detail/Hint are dropped, quoted literals are masked, and
// the SQLSTATE, constraint and type chain survive.
func TestRedactQuotedMasksValuesButKeepsStructure(t *testing.T) {
	msg := `duplicate key value violates unique constraint "secret_store_name_key"`
	got := redactQuoted(msg)
	if strings.Contains(got, "secret_store_name_key") || !strings.HasPrefix(got, "duplicate key value violates unique constraint") {
		t.Fatalf("redactQuoted(%q) = %q", msg, got)
	}
	got = redactQuoted(`invalid input syntax for type uuid: "topsecret-name"`)
	if strings.Contains(got, "topsecret") || !strings.Contains(got, "[redacted]") {
		t.Fatalf("value leaked: %q", got)
	}
	got = redactQuoted("owner 'alice@example.test' not found")
	if strings.Contains(got, "alice") {
		t.Fatalf("single-quoted value leaked: %q", got)
	}
}

func TestErrorTypeChainNamesWrappedTypesOnly(t *testing.T) {
	err := fmt.Errorf("record: %w", &pgconn.PgError{Code: "23505", Detail: "Key (name)=(topsecret) already exists."})
	chain := errorTypeChain(err)
	if !strings.Contains(chain, "*pgconn.PgError") || strings.Contains(chain, "topsecret") {
		t.Fatalf("chain = %q", chain)
	}
	if errorTypeChain(errors.New("x")) == "" {
		t.Fatal("plain error must name its type")
	}
}
