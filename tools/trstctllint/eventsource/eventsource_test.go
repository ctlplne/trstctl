// SPDX-License-Identifier: BUSL-1.1

package eventsource_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/tools/trstctllint/eventsource"
)

// TestEventSource exercises AN-2 enforcement: a served mutating handler (marked
// //trstctl:mutation or referenced by a route registry mutation: true entry)
// must not write the relational read model directly through a store mutator or
// raw SQL — it must emit an event and let the projection build the read model. A
// planted direct-to-table write fails the build.
func TestEventSource(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), eventsource.Analyzer, "trstctl.com/trstctl/internal/api")
}

func TestEventSourceDeniesEveryStoreReadModelTableInServedMutation(t *testing.T) {
	dir := t.TempDir()
	var src strings.Builder
	src.WriteString(`package api

func exec(query string) error { _ = query; return nil }

`)
	for i, table := range store.ReadModelTables {
		query := fmt.Sprintf("INSERT INTO %s (tenant_id) VALUES ($1)", table)
		want := fmt.Sprintf("must not write the read model table .%s. with raw SQL", table)
		fmt.Fprintf(&src, `//trstctl:mutation
func RawReadModelWrite%d() error {
	return exec(%q) // want %q
}

`, i, query, want)
	}
	writeFixture(t, dir, "src/trstctl.com/trstctl/internal/api/handlers.go", src.String())
	analysistest.Run(t, dir, eventsource.Analyzer, "trstctl.com/trstctl/internal/api")
}

func TestEventSourceFollowsCrossPackageServiceDelegate(t *testing.T) {
	dir := t.TempDir()
	writeFixture(t, dir, "src/trstctl.com/trstctl/internal/store/store.go", `package store

type Store struct{}

func (s *Store) CreateOwner(name string) (string, error) { return "", nil }
`)
	writeFixture(t, dir, "src/trstctl.com/trstctl/internal/api/handlers.go", `package api

import "trstctl.com/trstctl/internal/store"

type API struct{ service CeremonyService }

type CeremonyService interface {
	StartCeremony(st *store.Store) error // want StartCeremony:"mutation delegate"
}

//trstctl:mutation
func (a *API) CreateCeremony(st *store.Store) error {
	return a.service.StartCeremony(st)
}
`)
	writeFixture(t, dir, "src/trstctl.com/trstctl/internal/server/service.go", `package server

import (
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/store"
)

type ceremonyService struct{}

var _ api.CeremonyService = (*ceremonyService)(nil)

func (s *ceremonyService) StartCeremony(st *store.Store) error {
	return s.createCeremony(st)
}

func (s *ceremonyService) createCeremony(st *store.Store) error {
	_, err := st.CreateOwner("delegated-service") // want "must not write the read model directly"
	return err
}
`)
	analysistest.Run(t, dir, eventsource.Analyzer, "trstctl.com/trstctl/internal/server")
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
