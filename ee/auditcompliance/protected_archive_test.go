// SPDX-License-Identifier: LicenseRef-trstctl-EE
package auditcompliance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"trstctl.com/trstctl/ee/auditcompliance"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/eventprotect"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

const protectedArchiveEventType = "a233.protected_archive_fixture"
const protectedArchiveNeighbor = "22222222-2222-2222-2222-222222222222"

type protectedArchivePayload struct {
	Email string `json:"email"`
}

func init() {
	if err := events.RegisterPrivacyEventPolicy(protectedArchiveEventType, 1, events.PrivacyEventPolicy{Rules: []events.PrivacyFieldRule{{Path: "/email", Mode: events.PrivacyFieldIdentityExact}}, PayloadShape: events.PrivacyPayloadShapeOf[protectedArchivePayload]()}); err != nil {
		panic(err)
	}
}

// This intentionally narrow component fixture grants no production authority.
// Only the registered sensitive test event is encrypted; public archive controls
// remain writable after a domain key is removed.
type protectedArchiveAdmission struct {
	refs    map[string]eventprotect.KeyRef
	request eventprotect.DestructionRequest
}

func (f *protectedArchiveAdmission) WithTenantEventProtection(ctx context.Context, _ string, fn func(context.Context) error) error {
	return fn(ctx)
}
func (f *protectedArchiveAdmission) EventProtectionFor(_ context.Context, e events.Event) (events.EventProtectionDecision, error) {
	if e.Type != protectedArchiveEventType {
		return events.EventProtectionDecision{Mode: events.EventProtectionLegacy}, nil
	}
	ref, ok := f.refs[e.TenantID]
	if !ok {
		return events.EventProtectionDecision{}, eventprotect.ErrContext
	}
	return events.EventProtectionDecision{Mode: events.EventProtectionSensitive, Ref: ref}, nil
}
func (f *protectedArchiveAdmission) AuthorizeDestruction(_ context.Context, r eventprotect.DestructionRequest) error {
	if r != f.request {
		return eventprotect.ErrContext
	}
	return nil
}

// Real PostgreSQL, NATS, independently persistent FileAuthority and real MinIO
// Object Lock. Admission/destruction/local artifact signer are explicit component
// fixtures; this is not production offboard/outbox or isolated-signer proof.
func TestProtectedRetentionArchivePreservesLockedCiphertextAfterKeyRemoval(t *testing.T) {
	ctx := t.Context()
	raw, opts := protectedArchiveMinIO(t)
	objects, err := objectstore.Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(objects.Destroy)
	st := newAuditTestStore(t)
	base := t.TempDir()
	signer, err := jose.GenerateRSASigningKey("a233-archive-component")
	if err != nil {
		t.Fatal(err)
	}
	trust := signer.JWKS()
	fixture := &protectedArchiveAdmission{refs: map[string]eventprotect.KeyRef{
		tenantA:                  {TenantID: tenantA, ID: "9a8a5078-d32c-4eb1-9362-88e8c3dde32e"},
		protectedArchiveNeighbor: {TenantID: protectedArchiveNeighbor, ID: "ce0040ac-f1e9-44b8-b117-9fbb66b04245"},
	}}
	keycfg := eventprotect.FileAuthorityConfig{Directory: filepath.Join(base, "keys"), BackupRoots: []string{filepath.Join(base, "events")}, Locker: st, EvidenceKey: signer, DestructionAuthority: fixture}
	keys, err := eventprotect.NewFileAuthority(keycfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = keys.Close() })
	for _, ref := range fixture.refs {
		if err := keys.Provision(ctx, ref); err != nil {
			t.Fatal(err)
		}
	}
	creation, err := keys.CreationEvidence(ctx, fixture.refs[tenantA])
	if err != nil {
		t.Fatal(err)
	}
	log, err := events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(base, "events")}, events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(st)), events.WithEventProtection(events.EventProtection{Admission: fixture, Keys: keys}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	for _, tenant := range []string{tenantA, protectedArchiveNeighbor} {
		if _, err := log.Append(ctx, events.Event{Type: projections.EventTenantRegistered, TenantID: tenant, Data: tenantRegistered("archive fixture")}); err != nil {
			t.Fatal(err)
		}
	}
	if err := projections.New(st).Project(ctx, log); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{tenantA, protectedArchiveNeighbor} {
		payload, _ := json.Marshal(protectedArchivePayload{Email: "archive-private-person@example.invalid"})
		if _, err := log.Append(ctx, events.Event{Type: protectedArchiveEventType, TenantID: tenant, Data: payload, Actor: &events.Actor{Subject: "archive-private-operator@example.invalid"}}); err != nil {
			t.Fatal(err)
		}
	}
	service := audit.NewService(log, signer, audit.WithCheckpoints(st))
	archiver := auditcompliance.ObjectArchiver{Store: objects, Verify: func(s string) (audit.Bundle, error) { return audit.VerifyRetentionBundle(s, trust) }}
	// Nanosecond retention is only this disposable fixture. The actual S3
	// version retains its real 24h lock; no host clock or lock is shortened.
	worker := auditcompliance.NewRetentionWorker(service, log, archiver, st, time.Nanosecond, signer)
	sum, err := worker.RunOnce(ctx)
	if err != nil || sum.TenantsProcessed != 2 || sum.RecordsArchived != 4 {
		t.Fatalf("archive sum=%+v err=%v", sum, err)
	}
	type captured struct {
		name, version, digest string
		wire                  []byte
		bundle                audit.Bundle
		retainUntil           time.Time
	}
	readVersion := func(name, version string) []byte {
		out, err := raw.GetObject(ctx, &s3.GetObjectInput{Bucket: awssdk.String(opts.Bucket), Key: awssdk.String(opts.Prefix + name), VersionId: awssdk.String(version)})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = out.Body.Close() }()
		wire, err := io.ReadAll(io.LimitReader(out.Body, 4<<20))
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	capture := func(tenant string) captured {
		cp, ok, err := st.LatestAuditCheckpoint(ctx, tenant)
		if err != nil || !ok {
			t.Fatalf("checkpoint ok=%v err=%v", ok, err)
		}
		name, err := objects.NameOf(cp.ArchiveURI)
		if err != nil {
			t.Fatal(err)
		}
		versions, err := raw.ListObjectVersions(ctx, &s3.ListObjectVersionsInput{Bucket: awssdk.String(opts.Bucket), Prefix: awssdk.String(opts.Prefix + name)})
		if err != nil || len(versions.Versions) != 1 {
			t.Fatalf("versions=%+v err=%v", versions, err)
		}
		version := awssdk.ToString(versions.Versions[0].VersionId)
		if version == "" {
			t.Fatal("archive lacks version identity")
		}
		wire := readVersion(name, version)
		bundle, err := audit.VerifyRetentionBundle(string(wire), trust)
		if err != nil || bundle.TenantID != tenant || bundle.ChainHead != cp.BoundaryHash {
			t.Fatalf("offline archive verification: %v", err)
		}
		payload, err := trust.VerifyArtifact(string(wire), jose.ArtifactAuditRetention)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(payload, []byte("example.invalid")) {
			t.Fatal("managed archive includes private readable fields")
		}
		state, err := objects.Lock(ctx, name)
		if err != nil || state.Mode != "GOVERNANCE" || !state.Locked(time.Now()) || state.RetainUntil == nil || state.RetainUntil.Before(time.Now().Add(23*time.Hour)) {
			t.Fatalf("archive lock=%+v err=%v", state, err)
		}
		if _, err := raw.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: awssdk.String(opts.Bucket), Key: awssdk.String(opts.Prefix + name), VersionId: awssdk.String(version)}); err == nil {
			t.Fatal("locked archive version deleted")
		}
		return captured{name: name, version: version, digest: crypto.SHA256Hex(wire), wire: wire, bundle: bundle, retainUntil: *state.RetainUntil}
	}
	before := map[string]captured{tenantA: capture(tenantA), protectedArchiveNeighbor: capture(protectedArchiveNeighbor)}
	assertReadable := func(tenant string, wantErased bool) {
		details, err := service.CollectorDetails(ctx, tenant, before[tenant].bundle.Records)
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, detail := range details {
			found++
			if detail.SensitiveErased != wantErased {
				t.Fatal("archive readable state disagrees with current custody")
			}
			if wantErased {
				if len(detail.Data) != 0 || detail.Actor != nil {
					t.Fatal("removed archive key still yielded private fields")
				}
			} else if !bytes.Contains(detail.Data, []byte("archive-private-person@example.invalid")) || detail.Actor == nil {
				t.Fatal("active archive lost private fields")
			}
		}
		if found != 1 {
			t.Fatalf("protected record count=%d", found)
		}
	}
	assertArtifactOpen := func(tenant string, wantErased bool) {
		found := 0
		for _, record := range before[tenant].bundle.Records {
			if record.Type != protectedArchiveEventType {
				continue
			}
			found++
			var core audit.ProtectedSourceRecordData
			if err := json.Unmarshal(record.Data, &core); err != nil {
				t.Fatal(err)
			}
			if core.Protection.KeyID != fixture.refs[tenant].ID {
				t.Fatal("archive changed source-selected key")
			}
			binding := eventprotect.Context{Scope: eventprotect.ScopeEvent, ID: record.ID, Type: record.Type, TenantID: record.TenantID, SchemaVersion: core.SchemaVersion, Time: record.Time}
			err := keys.WithKey(ctx, fixture.refs[tenant], func(key seal.KeyWrapper) error {
				payload, err := eventprotect.Open(key, binding, core.Protection.PolicyDigest, core.Protection)
				if err != nil {
					return err
				}
				defer secret.Wipe(payload.Data)
				if !bytes.Contains(payload.Data, []byte("archive-private-person@example.invalid")) || payload.Actor == nil || payload.Actor.Subject != "archive-private-operator@example.invalid" {
					return fmt.Errorf("archive lost original payload or actor")
				}
				return nil
			})
			if wantErased {
				if !errors.Is(err, eventprotect.ErrDestroyed) {
					t.Fatalf("independent archive opening after removal: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
		}
		if found != 1 {
			t.Fatalf("independent protected archive count=%d", found)
		}
	}
	assertArtifactOpen(tenantA, false)
	assertArtifactOpen(protectedArchiveNeighbor, false)
	assertReadable(tenantA, false)
	assertReadable(protectedArchiveNeighbor, false)
	offboarded := time.Now().UTC()
	fixture.request = eventprotect.DestructionRequest{Ref: fixture.refs[tenantA], OperationID: "f28d6a79-706f-4a27-beb5-a45b6db214f5", RegistrationIdentity: "archive-fixture-registration", ActivationEventID: "archive-fixture-activation", ActivationSequence: 1, CreationDigest: creation.Digest(), OffboardEventID: "archive-fixture-offboard", OffboardSequence: 4, OffboardedAt: offboarded, NotBefore: offboarded.Add(2 * time.Millisecond)}
	time.Sleep(time.Until(fixture.request.NotBefore))
	receipt, err := keys.Destroy(ctx, fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := eventprotect.VerifyDestructionReceipt(trust, receipt); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := keys.Close(); err != nil {
		t.Fatal(err)
	}
	keycfg.EvidenceKey = nil
	keycfg.DestructionAuthority = nil
	keycfg.VerificationKeys = trust
	keys, err = eventprotect.NewFileAuthority(keycfg)
	if err != nil {
		t.Fatal(err)
	}
	log, err = events.Open(ctx, config.NATS{Mode: config.NATSEmbedded, StoreDir: filepath.Join(base, "events")}, events.WithHistoryRewriteCoordinator(store.NewHistoryRewriteCoordinator(st)), events.WithEventProtection(events.EventProtection{Admission: fixture, Keys: keys}))
	if err != nil {
		t.Fatal(err)
	}
	service = audit.NewService(log, signer, audit.WithCheckpoints(st))
	worker = auditcompliance.NewRetentionWorker(service, log, archiver, st, time.Nanosecond, signer)
	if current, removed, err := keys.DestructionReceipt(ctx, fixture.refs[tenantA]); err != nil || !removed || current != receipt {
		t.Fatalf("persistent removal readback: %v", err)
	}
	if retained, err := keys.CreationEvidence(ctx, fixture.refs[tenantA]); err != nil || retained.Digest() != creation.Digest() {
		t.Fatalf("reopened original creation changed: %v", err)
	}
	// Reopening the original receiver with only public trust must still report destruction. Never
	// provision a replacement merely to make an old archive readable.
	if err := keys.WithKey(ctx, fixture.refs[tenantA], func(_ seal.KeyWrapper) error { return fmt.Errorf("unexpected key") }); !errors.Is(err, eventprotect.ErrDestroyed) {
		t.Fatalf("removed key returned %v", err)
	}
	assertArtifactOpen(tenantA, true)
	assertArtifactOpen(protectedArchiveNeighbor, false)
	assertReadable(tenantA, true)
	assertReadable(protectedArchiveNeighbor, false)
	for tenant, saved := range before {
		wire := readVersion(saved.name, saved.version)
		if !bytes.Equal(wire, saved.wire) || crypto.SHA256Hex(wire) != saved.digest {
			t.Fatal("removal rewrote WORM evidence")
		}
		bundle, err := audit.VerifyRetentionBundle(string(wire), trust)
		if err != nil || bundle.ChainHead != saved.bundle.ChainHead {
			t.Fatalf("retained public verification: %v", err)
		}
		after := capture(tenant)
		if after.version != saved.version || after.digest != saved.digest || !after.retainUntil.Equal(saved.retainUntil) {
			t.Fatal("archive identity changed")
		}
	}
	later, err := worker.RunOnce(ctx)
	if err != nil || later.TenantsProcessed != 2 {
		t.Fatalf("later archive sum=%+v err=%v", later, err)
	}
	after := capture(tenantA)
	if after.name == before[tenantA].name || after.bundle.PrevHash != before[tenantA].bundle.ChainHead {
		t.Fatal("later archive did not continue original ciphertext chain")
	}
	assertArtifactOpen(tenantA, true)
	assertArtifactOpen(protectedArchiveNeighbor, false)
	assertReadable(tenantA, true)
	assertReadable(protectedArchiveNeighbor, false)
	for _, saved := range before {
		if wire := readVersion(saved.name, saved.version); !bytes.Equal(wire, saved.wire) {
			t.Fatal("later archive altered original version")
		}
	}
	// Public verification stays usable without the destroyed domain key.
	wrong, err := jose.GenerateRSASigningKey("untrusted-archive-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audit.VerifyRetentionBundle(string(before[tenantA].wire), wrong.JWKS()); err == nil {
		t.Fatal("archive accepted unpinned verification trust")
	}
	wrongcfg := keycfg
	wrongcfg.VerificationKeys = wrong.JWKS()
	untrusted, err := eventprotect.NewFileAuthority(wrongcfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = untrusted.Close() }()
	if _, removed, err := untrusted.DestructionReceipt(ctx, fixture.refs[tenantA]); err == nil || removed {
		t.Fatal("current removal accepted unpinned receipt trust")
	}
	secret.Wipe(opts.SecretAccessKey)
}
