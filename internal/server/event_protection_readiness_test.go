// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/internal/eventprivacy"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
)

// Real retained source, independent files, PostgreSQL watermark and served
// readiness. Explicit activation and signer fixtures do not qualify background
// preparation/destruction or separate-process signing.
func TestEventProtectionReadinessDetectsCurrentCustodyLossAtWarmCheckpoint(t *testing.T) {
	for _, mode := range []string{"live-key-loss", "warm-key-loss", "warm-unconfigured-custody", "warm-key-loss-before-first-private-write"} {
		t.Run(mode, func(t *testing.T) {
			st := newServerTestStore(t)
			cfg := eventProtectionRuntimeConfigFixture(t)
			key := testAuditSigningKey(t)
			log, custody, err := openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = custody.Close() })
			t.Cleanup(func() {
				if log != nil {
					_ = log.Close()
				}
			})
			const tenant = "38ac947a-eb6b-48fc-a198-b01222c10ad6"
			registered, err := log.Append(t.Context(), events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: []byte(`{"name":"custody-readiness fixture"}`)})
			if err != nil {
				t.Fatal(err)
			}
			request, err := eventprivacy.NewRequested(tenant, registered.ID, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			wire, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			requested, err := log.Append(t.Context(), events.Event{ID: eventprivacy.RequestedEventID(request), Type: eventprivacy.EventRequested, TenantID: tenant, Data: wire})
			if err != nil {
				t.Fatal(err)
			}
			ref := eventprotect.KeyRef{TenantID: tenant, ID: request.KeyID}
			if err := custody.custody.Provision(t.Context(), ref); err != nil {
				t.Fatal(err)
			}
			creation, err := custody.custody.CreationEvidence(t.Context(), ref)
			if err != nil {
				t.Fatal(err)
			}
			wire, err = json.Marshal(eventprivacy.Activated{RegistrationIdentity: registered.ID, OperationID: request.KeyID, KeyID: request.KeyID, RetentionNanos: request.RetentionNanos, RequestedEventID: requested.ID, RequestedSequence: requested.Sequence, RequestedAt: requested.Time, Creation: creation})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := log.Append(t.Context(), events.Event{ID: request.KeyID, Type: eventprivacy.EventActivated, TenantID: tenant, Data: wire}); err != nil {
				t.Fatal(err)
			}
			var private events.Event
			if mode != "warm-key-loss-before-first-private-write" {
				wire, err = json.Marshal(projections.OwnerCreated{ID: "a11b2222-3333-4444-8555-666677778888", Kind: "team", Name: "readiness fixture", Email: "private-readiness@example.invalid"})
				if err != nil {
					t.Fatal(err)
				}
				private, err = log.Append(t.Context(), events.Event{Type: projections.EventOwnerCreated, TenantID: tenant, Data: wire})
				if err != nil || private.Protection == nil {
					t.Fatalf("fixture did not protect actual source: %v", err)
				}
			}
			if err := projections.New(st, custody.projectionOptions()...).Rebuild(t.Context(), log); err != nil {
				t.Fatal(err)
			}
			head, err := log.LastSequence(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			checkpoint, err := st.ProjectionCheckpoint(t.Context())
			if err != nil || checkpoint != head {
				t.Fatalf("fixture was not at exact warm checkpoint: got%d head%d err%v", checkpoint, head, err)
			}
			keyFile := filepath.Join(cfg.Privacy.EventProtection.KeyDirectory, tenant, request.KeyID+".key")
			heldFile := keyFile + ".held-by-readiness-fixture"
			moved := false
			move := func() {
				t.Helper()
				if err := os.Rename(keyFile, heldFile); err != nil {
					t.Fatal(err)
				}
				moved = true
			}
			restore := func() {
				t.Helper()
				if moved {
					if err := os.Rename(heldFile, keyFile); err != nil {
						t.Fatal(err)
					}
					moved = false
				}
			}
			t.Cleanup(restore)
			if mode != "live-key-loss" {
				if err := log.Close(); err != nil {
					t.Fatal(err)
				}
				if err := custody.Close(); err != nil {
					t.Fatal(err)
				}
				if mode != "warm-unconfigured-custody" {
					move()
				} else {
					cfg.Privacy.EventProtection.KeyDirectory = ""
				}
				log, custody, err = openConfiguredEventSource(t.Context(), cfg, st, key, true, nil)
				if err != nil {
					if !errors.Is(err, eventprotect.ErrKey) && !errors.Is(err, eventprivacy.ErrSource) {
						t.Fatalf("warm source refused for unrelated cause: %v", err)
					}
					return
				}
			}
			srv, err := Build(t.Context(), Deps{Store: st, Log: log, AuditSigningKey: key, eventProtection: custody})
			if err != nil {
				if mode == "live-key-loss" || (!errors.Is(err, eventprotect.ErrKey) && !errors.Is(err, eventprivacy.ErrSource)) {
					t.Fatalf("server refused for unrelated cause: %v", err)
				}
				return
			}
			defer func() { _ = srv.Shutdown(t.Context()) }()
			if mode == "live-key-loss" {
				code, _ := projectionReadiness(t, srv.Handler())
				if code != http.StatusOK {
					t.Fatal("healthy fixture was not ready before key loss")
				}
				move()
			}
			code, checks := projectionReadiness(t, srv.Handler())
			if code != http.StatusServiceUnavailable || checks["event_key_custody"] == "" || checks["event_key_custody"] == "ok" {
				t.Fatalf("current custody loss hidden by warm SQL/head-only probes: HTTP%d checks%v", code, checks)
			}
			for _, privateCoordinate := range []string{keyFile, tenant, request.KeyID} {
				if strings.Contains(checks["event_key_custody"], privateCoordinate) {
					t.Fatal("public readiness disclosed a custody coordinate")
				}
			}
			if mode != "warm-unconfigured-custody" {
				if _, err := os.Stat(keyFile); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("readiness recreated missing material")
				}
				restore()
				code, checks = projectionReadiness(t, srv.Handler())
				if code != http.StatusOK || checks["event_key_custody"] != "ok" {
					t.Fatalf("restored original custody did not recover readiness: HTTP%d checks%v", code, checks)
				}
				if private.ID != "" {
					actual, found, err := log.EventByID(t.Context(), private.ID)
					if err != nil || !found || actual.SensitiveErased || !bytes.Equal(actual.Data, private.Data) {
						t.Fatalf("recovery changed protected source or invented erasure: %v", err)
					}
				}
				got, err := custody.custody.CreationEvidence(t.Context(), ref)
				if err != nil || got.Digest() != creation.Digest() {
					t.Fatal("recovery changed original key creation identity")
				}
			}
		})
	}
}
