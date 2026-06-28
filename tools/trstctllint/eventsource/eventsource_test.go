package eventsource_test

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"

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
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir fixture %s: %v", rel, err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("write fixture %s: %v", rel, err)
	}
}
