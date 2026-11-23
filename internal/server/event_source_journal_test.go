// SPDX-License-Identifier: BUSL-1.1
package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/journalkey"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

type ingressHistoryBeforeBProbe struct {
	base    events.HistoryRewriteCoordinator
	witness *store.Store
	armed   atomic.Bool
	checked atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func (p *ingressHistoryBeforeBProbe) WithRewriteOperation(ctx context.Context, fn func(context.Context) error) error {
	return p.base.WithRewriteOperation(ctx, fn)
}

func (p *ingressHistoryBeforeBProbe) WithCutover(ctx context.Context, fn func(context.Context) error) error {
	return p.base.WithCutover(ctx, fn)
}

func (p *ingressHistoryBeforeBProbe) WithRead(ctx context.Context, fn func(context.Context) error) error {
	if p.armed.Load() && p.checked.CompareAndSwap(false, true) {
		// This separate PostgreSQL connection tests the global B resource at
		// the exact point history A is requested. B must still be free.
		tx, err := p.witness.SystemPool().Begin(ctx)
		if err != nil {
			return err
		}
		var free bool
		err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock($1)`, int64(0x6b737461746542)).Scan(&free)
		rollbackErr := tx.Rollback(ctx)
		if err != nil {
			return err
		}
		if rollbackErr != nil {
			return rollbackErr
		}
		if !free {
			return errors.New("key-state transaction B preceded history session A")
		}
		close(p.entered)
		select {
		case <-p.release:
		case <-ctx.Done():
			return context.Cause(ctx)
		}
	}
	return p.base.WithRead(ctx, fn)
}

// A direct append on one replica holds key-state A before it asks for history
// A, while B remains free. A second replica's exclusive transition cannot
// cross this admitted write in either scheduling order.
func TestJournalIngressDirectKeyStateHistoryOrderAcrossStoresCR045(t *testing.T) {
	writer, witness := newServerTestStore(t), newServerTestStore(t)
	path := filepath.Join(t.TempDir(), "journal-v1.key")
	if err := journalkey.Provision(path); err != nil {
		t.Fatal(err)
	}
	keys := journalkey.Files{ActiveID: "plain-v1", Paths: map[string]string{"plain-v1": path}}
	probe := &ingressHistoryBeforeBProbe{base: store.NewHistoryRewriteCoordinator(writer),
		witness: witness, entered: make(chan struct{}), release: make(chan struct{})}
	options := []events.OpenOption{events.WithRequiredAppendAdmission(), events.WithHistoryRewriteCoordinator(probe)}
	options = append(options, restoreEventIngressOptionsWithJournal(writer,
		func() tenantseal.Access { return publicJournalIngressAccess{} }, keys)...)
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, options...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	const tenant = "49900000-0000-4000-8000-0000000000f4"
	probe.armed.Store(true)
	appendDone := make(chan error, 1)
	go func() {
		_, err := log.Append(ctx, events.Event{ID: "plain-first-order", Type: "tenant.registered",
			TenantID: tenant, Data: []byte(`{"label":"plain-value"}`)})
		appendDone <- err
	}()
	select {
	case <-probe.entered:
	case err := <-appendDone:
		t.Fatalf("append never reached history A: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	transitionEntered := make(chan struct{})
	transitionDone := make(chan error, 1)
	go func() {
		transitionDone <- witness.WithGlobalKeyStateAdmission(ctx, store.KeyStateExclusive,
			func(admitted context.Context) error {
				close(transitionEntered)
				tx, err := witness.SystemPool().Begin(admitted)
				if err != nil {
					return err
				}
				defer func() { _ = tx.Rollback(context.Background()) }()
				if err := witness.LockGlobalKeyStateCommitTx(admitted, tx, store.KeyStateExclusive); err != nil {
					return err
				}
				return tx.Commit(admitted)
			})
	}()
	select {
	case <-transitionEntered:
		t.Fatal("exclusive transition crossed direct append's key-state A")
	case err := <-transitionDone:
		t.Fatalf("exclusive transition ended before append released A: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	close(probe.release)
	if err := <-appendDone; err != nil {
		t.Fatalf("append after history A release: %v", err)
	}
	if err := <-transitionDone; err != nil {
		t.Fatalf("exclusive transition after append: %v", err)
	}
	// Reverse the schedule: the exclusive writer owns A and B before a new
	// direct append starts. The append must stay outside the broker until both
	// locks are released, then proceed with its original event identity.
	transitionHeld := make(chan struct{})
	releaseTransition := make(chan struct{})
	secondTransitionDone := make(chan error, 1)
	go func() {
		secondTransitionDone <- witness.WithGlobalKeyStateAdmission(ctx, store.KeyStateExclusive,
			func(admitted context.Context) error {
				tx, err := witness.SystemPool().Begin(admitted)
				if err != nil {
					return err
				}
				defer func() { _ = tx.Rollback(context.Background()) }()
				if err := witness.LockGlobalKeyStateCommitTx(admitted, tx, store.KeyStateExclusive); err != nil {
					return err
				}
				close(transitionHeld)
				select {
				case <-releaseTransition:
				case <-admitted.Done():
					return context.Cause(admitted)
				}
				return tx.Commit(admitted)
			})
	}()
	select {
	case <-transitionHeld:
	case err := <-secondTransitionDone:
		t.Fatalf("exclusive transition did not hold A/B: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	secondAppendDone := make(chan error, 1)
	go func() {
		_, err := log.Append(ctx, events.Event{ID: "plain-reverse-order", Type: "tenant.registered",
			TenantID: tenant, Data: []byte(`{"label":"plain-value"}`)})
		secondAppendDone <- err
	}()
	select {
	case err := <-secondAppendDone:
		t.Fatalf("append crossed exclusive key-state A/B: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if head, err := log.LastSequence(ctx); err != nil || head != 1 {
		t.Fatalf("blocked append reached NATS: head=%d err=%v", head, err)
	}
	close(releaseTransition)
	if err := <-secondTransitionDone; err != nil {
		t.Fatalf("reverse exclusive transition: %v", err)
	}
	if err := <-secondAppendDone; err != nil {
		t.Fatalf("append after exclusive transition: %v", err)
	}
}

// An arbitrary transaction owner must not acquire history after B. It can
// publish only when its wrapper already holds the history read wall.
func TestJournalIngressRejectsOwnerWithoutPreheldHistoryCR045(t *testing.T) {
	st := newServerTestStore(t)
	path := filepath.Join(t.TempDir(), "journal-v1.key")
	if err := journalkey.Provision(path); err != nil {
		t.Fatal(err)
	}
	keys := journalkey.Files{ActiveID: "plain-v1", Paths: map[string]string{"plain-v1": path}}
	options := []events.OpenOption{events.WithRequiredAppendAdmission()}
	options = append(options, restoreEventIngressOptionsWithJournal(st,
		func() tenantseal.Access { return publicJournalIngressAccess{} }, keys)...)
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, options...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	const tenant = "49900000-0000-4000-8000-0000000000f3"
	err = st.WithGlobalKeyStateAdmission(t.Context(), store.KeyStateShared, func(admitted context.Context) error {
		return st.WithTenant(admitted, tenant, func(tx pgx.Tx) error {
			owner, err := st.BindKeyStateOwnerTx(admitted, tx, tenant, store.KeyStateShared)
			if err != nil {
				return err
			}
			_, err = log.Append(owner, events.Event{ID: "plain-unordered-owner", Type: "tenant.registered",
				TenantID: tenant, Data: []byte(`{"label":"plain-value"}`)})
			return err
		})
	})
	if err == nil {
		t.Fatal("owner without preheld history published")
	}
	if head, err := log.LastSequence(t.Context()); err != nil || head != 0 {
		t.Fatalf("unordered owner reached NATS: head=%d err=%v", head, err)
	}
}

type publicJournalIngressAccess struct{}

func (publicJournalIngressAccess) WithTenant(context.Context, string, func(tenantseal.Cipher) error) error {
	return errors.New("public journal fixture must not open tenant ciphertext")
}

type journalProtectionLock struct{}

func (journalProtectionLock) WithKeyLock(ctx context.Context, _ eventprotect.KeyRef,
	fn func(context.Context) error,
) error {
	return fn(ctx)
}

type journalProtectionAdmission struct{ ref eventprotect.KeyRef }

func (journalProtectionAdmission) WithTenantEventProtection(ctx context.Context, _ string,
	fn func(context.Context) error,
) error {
	return fn(ctx)
}

func (a journalProtectionAdmission) EventProtectionFor(context.Context, events.Event) (events.EventProtectionDecision, error) {
	return events.EventProtectionDecision{Mode: events.EventProtectionSensitive, Ref: a.ref}, nil
}

// CR-045: an absent configured key refuses a public append before NATS, and
// an explicit key produces durable keyed/wire commitments on the exact token.
func TestStoreBackedIngressStagesProducerAndWireCR045(t *testing.T) {
	st := newServerTestStore(t)
	keyPath := filepath.Join(t.TempDir(), "ingress-journal-v1.key")
	keys := journalkey.Files{ActiveID: "plain-v1", Paths: map[string]string{"plain-v1": keyPath}}
	options := []events.OpenOption{events.WithRequiredAppendAdmission()}
	options = append(options, restoreEventIngressOptionsWithJournal(st,
		func() tenantseal.Access { return publicJournalIngressAccess{} }, keys)...)
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, options...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	const tenant = "49900000-0000-4000-8000-0000000000e1"
	missing := events.Event{ID: "plain-missing-key", Type: "tenant.registered", TenantID: tenant,
		Data: []byte(`{"label":"plain-value"}`)}
	if _, err := log.Append(t.Context(), missing); err == nil {
		t.Fatal("missing configured journal key allowed publication")
	}
	if err := journalkey.Provision(keyPath); err != nil {
		t.Fatal(err)
	}
	event := missing
	event.ID = "plain-staged-event"
	published, err := log.Append(t.Context(), event)
	if err != nil {
		t.Fatal(err)
	}
	if published.Sequence != 1 {
		t.Fatalf("append sequence=%d after refused missing-key attempt", published.Sequence)
	}
	var keyID, phase, attemptedWire, canonicalWire string
	var mac []byte
	if err := st.SystemPool().QueryRow(t.Context(), `SELECT producer_key_id,producer_mac,attempted_wire_sha256,canonical_wire_sha256,phase
		FROM trstctl_recovery.event_ingress_journal WHERE tenant_id=$1 AND event_id=$2`, tenant, event.ID).
		Scan(&keyID, &mac, &attemptedWire, &canonicalWire, &phase); err != nil {
		t.Fatal(err)
	}
	if keyID != "plain-v1" || len(mac) != 32 || len(attemptedWire) != 64 ||
		canonicalWire != attemptedWire || phase != "published_verified" {
		t.Fatalf("ingress journal key=%q mac_length=%d attempted=%q canonical=%q phase=%q",
			keyID, len(mac), attemptedWire, canonicalWire, phase)
	}
	retry := event
	retry.Data = []byte(`{"label":"changed-public-value"}`)
	returned, err := log.Append(t.Context(), retry)
	if err != nil {
		t.Fatal(err)
	}
	if returned.Sequence != published.Sequence || string(returned.Data) != string(event.Data) {
		t.Fatalf("public duplicate did not return canonical event: %+v", returned)
	}
	var duplicatePhase, duplicateCanonical string
	if err := st.SystemPool().QueryRow(t.Context(), `SELECT phase,canonical_wire_sha256
		FROM trstctl_recovery.event_ingress_journal WHERE tenant_id=$1 AND event_id=$2
		AND phase='duplicate_verified'`, tenant, event.ID).Scan(&duplicatePhase, &duplicateCanonical); err != nil {
		t.Fatal(err)
	}
	if duplicatePhase != "duplicate_verified" || duplicateCanonical != canonicalWire {
		t.Fatalf("public duplicate phase=%q canonical=%q, want original=%q",
			duplicatePhase, duplicateCanonical, canonicalWire)
	}
}

// CR-045: protected retries use the original canonical bytes and keyed
// producer view. The early duplicate does not synthesize a second wire body.
func TestStoreBackedIngressProtectedEarlyDuplicateCR045(t *testing.T) {
	const eventType = "cr045.journal.protected"
	if err := events.RegisterPrivacyEventPolicy(eventType, 1, events.PrivacyEventPolicy{
		Rules: []events.PrivacyFieldRule{{Path: "/email", Mode: events.PrivacyFieldIdentityExact}},
		PayloadShape: events.PrivacyPayloadShapeOf[struct {
			Email string `json:"email"`
		}](),
	}); err != nil {
		t.Fatal(err)
	}
	st := newServerTestStore(t)
	base := t.TempDir()
	journalPath := filepath.Join(base, "journal-v1.key")
	if err := journalkey.Provision(journalPath); err != nil {
		t.Fatal(err)
	}
	keys := journalkey.Files{ActiveID: "plain-v1", Paths: map[string]string{"plain-v1": journalPath}}
	protectedKeys, err := eventprotect.NewFileAuthority(eventprotect.FileAuthorityConfig{
		Directory: filepath.Join(base, "privacy-keys"), BackupRoots: []string{filepath.Join(base, "events")},
		Locker: journalProtectionLock{},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = protectedKeys.Close() }()
	ref := eventprotect.KeyRef{TenantID: "49900000-0000-4000-8000-0000000000e2",
		ID: "49900000-0000-4000-8000-0000000000e3"}
	if err := protectedKeys.Provision(t.Context(), ref); err != nil {
		t.Fatal(err)
	}
	options := []events.OpenOption{events.WithRequiredAppendAdmission(), events.WithRequiredPrivacyEventPolicies(),
		events.WithEventProtection(events.EventProtection{Keys: protectedKeys,
			Admission: journalProtectionAdmission{ref: ref}})}
	options = append(options, restoreEventIngressOptionsWithJournal(st,
		func() tenantseal.Access { return publicJournalIngressAccess{} }, keys)...)
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded,
		StoreDir: filepath.Join(base, "events")}, options...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	event := events.Event{ID: "plain-protected-journal", Type: eventType, TenantID: ref.TenantID,
		Data: []byte(`{"email":"plain-value@example.invalid"}`)}
	first, err := log.Append(t.Context(), event)
	if err != nil {
		t.Fatal(err)
	}
	second, err := log.Append(t.Context(), event)
	if err != nil {
		t.Fatal(err)
	}
	if second.Sequence != first.Sequence || second.Protection == nil {
		t.Fatalf("protected retry did not return the original canonical event: %+v", second)
	}
	rows, err := st.SystemPool().Query(t.Context(), `SELECT phase,COALESCE(attempted_wire_sha256,''),canonical_wire_sha256
		FROM trstctl_recovery.event_ingress_journal WHERE tenant_id=$1 AND event_id=$2 ORDER BY started_at`,
		ref.TenantID, event.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var phases, attempted, canonical []string
	for rows.Next() {
		var p, a, c string
		if err := rows.Scan(&p, &a, &c); err != nil {
			t.Fatal(err)
		}
		phases, attempted, canonical = append(phases, p), append(attempted, a), append(canonical, c)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(phases) != 2 || phases[0] != "published_verified" || phases[1] != "duplicate_verified" ||
		len(attempted[0]) != 64 || attempted[1] != "" || canonical[0] != canonical[1] {
		t.Fatalf("protected journal phases=%v attempted=%v canonical=%v", phases, attempted, canonical)
	}
}

// CR-045: a broker write can complete after candidate staging while the key
// needed for canonical readback disappears. Neither the ACK nor a timeout can
// turn that ambiguous journal row terminal without authenticated evidence.
func TestStoreBackedIngressRetainsAmbiguousCandidateAfterKeyLossCR045(t *testing.T) {
	st := newServerTestStore(t)
	path := filepath.Join(t.TempDir(), "journal-v1.key")
	if err := journalkey.Provision(path); err != nil {
		t.Fatal(err)
	}
	keys := journalkey.Files{ActiveID: "plain-v1", Paths: map[string]string{"plain-v1": path}}
	options := []events.OpenOption{events.WithRequiredAppendAdmission()}
	options = append(options, restoreEventIngressOptionsWithJournal(st,
		func() tenantseal.Access { return publicJournalIngressAccess{} }, keys)...)
	options = append(options, events.WithIngressWireStage(func(ctx context.Context, _ events.Event, hash string) error {
		if err := st.StageEventIngressCandidateWire(ctx, hash); err != nil {
			return err
		}
		return os.Remove(path)
	}))
	log, err := events.Open(t.Context(), config.NATS{Mode: config.NATSEmbedded, StoreDir: t.TempDir()}, options...)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = log.Close() }()
	const tenant = "49900000-0000-4000-8000-0000000000e4"
	const eventID = "plain-ambiguous-journal"
	if _, err := log.Append(t.Context(), events.Event{ID: eventID, Type: "tenant.registered",
		TenantID: tenant, Data: []byte(`{"label":"plain-value"}`)}); err == nil {
		t.Fatal("missing canonical key accepted a broker ACK")
	}
	if head, err := log.LastSequence(t.Context()); err != nil || head != 1 {
		t.Fatalf("ambiguous callback did not reach one broker write: head=%d err=%v", head, err)
	}
	var phase string
	if err := st.SystemPool().QueryRow(t.Context(), `SELECT phase FROM trstctl_recovery.event_ingress_journal
		WHERE tenant_id=$1 AND event_id=$2`, tenant, eventID).Scan(&phase); err != nil {
		t.Fatal(err)
	}
	if phase != "candidate_staged" {
		t.Fatalf("ambiguous candidate settled as %q without the key", phase)
	}
}
