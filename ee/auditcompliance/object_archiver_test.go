// SPDX-License-Identifier: LicenseRef-trstctl-EE

package auditcompliance_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"trstctl.com/trstctl/ee/auditcompliance"
	"trstctl.com/trstctl/internal/audit"
	"trstctl.com/trstctl/internal/auditchain"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/objectstore/s3test"
	"trstctl.com/trstctl/internal/server"
)

// With the object store as the archive target, a due segment is written under
// the tenant's object prefix, read back and verified before the checkpoint
// advances, and its s3:// locator is what the audit.archived event and the
// checkpoint record.
func TestRetentionArchivesSegmentsToTheObjectStoreUnderTheTenantPrefix(t *testing.T) {
	ctx := context.Background()
	log := openTestLog(t)
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	srv := s3test.NewServer(t)
	store := srv.Open(t)
	cp := &memCheckpoints{}
	svc := audit.NewService(log, key, audit.WithCheckpoints(cp))
	archiver := auditcompliance.ObjectArchiver{Store: store, Verify: func(signed string) (audit.Bundle, error) {
		return audit.VerifyRetentionBundle(signed, svc.VerificationKeys())
	}}
	worker := auditcompliance.NewRetentionWorker(svc, log, archiver, cp, 24*time.Hour, key)

	const tenant = "11111111-1111-4111-8111-111111111111"
	old := time.Now().Add(-48 * time.Hour)
	for i := 0; i < 3; i++ {
		if _, err := log.Append(ctx, events.Event{Type: "thing.created", TenantID: tenant,
			Time: old.Add(time.Duration(i) * time.Second), Data: []byte(fmt.Sprintf(`{"old":%d}`, i))}); err != nil {
			t.Fatal(err)
		}
	}
	if sum, err := worker.RunOnce(ctx); err != nil || sum.RecordsArchived != 3 {
		t.Fatalf("RunOnce = %+v %v, want three records archived", sum, err)
	}
	keys := srv.Keys()
	if len(keys) != 1 || !strings.HasPrefix(keys[0], "tenant/"+tenant+"/audit/audit-") || !strings.HasSuffix(keys[0], ".jws") {
		t.Fatalf("stored objects = %v, want one segment under the tenant prefix", keys)
	}
	stored, _ := srv.Object(keys[0])
	if bundle, err := audit.VerifyRetentionBundle(string(stored), svc.VerificationKeys()); err != nil || bundle.Count != 3 {
		t.Fatalf("the stored segment = %+v %v, want a verifiable three-record bundle", bundle, err)
	}
	sealed, ok, err := cp.LatestAuditCheckpoint(ctx, tenant)
	if err != nil || !ok || sealed.ArchiveURI != "s3://"+srv.Bucket+"/"+keys[0] {
		t.Fatalf("checkpoint = %+v ok=%v err=%v, want the object's locator", sealed, ok, err)
	}
	var archived audit.ArchivedEvent
	if err := log.Replay(ctx, 0, func(e events.Event) error {
		if e.Type == audit.EventTypeArchived {
			return json.Unmarshal(e.Data, &archived)
		}
		return nil
	}); err != nil || archived.ArchiveURI != sealed.ArchiveURI {
		t.Fatalf("audit.archived locator = %q (%v), want %q", archived.ArchiveURI, err, sealed.ArchiveURI)
	}
	for _, request := range srv.Requests() {
		if strings.HasPrefix(request, "PUT ") && !strings.HasPrefix(request, "PUT tenant/"+tenant+"/") {
			t.Fatalf("the archive wrote outside the tenant prefix: %s", request)
		}
	}
}

// A retry after a crash between the write and the audit.archived event meets
// the earlier attempt's object. A fresh signature over the same records is
// accepted under the same locator; a different segment at that name, or bytes
// altered in the store, stop the archive so the checkpoint cannot advance.
func TestObjectArchiverRecognizesItsEarlierSegmentAndRefusesAnyOther(t *testing.T) {
	ctx := context.Background()
	key, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	keys := key.JWKS()
	srv := s3test.NewServer(t)
	archiver := auditcompliance.ObjectArchiver{Store: srv.Open(t), Verify: func(signed string) (audit.Bundle, error) {
		return audit.VerifyRetentionBundle(signed, keys)
	}}
	const tenant = "22222222-2222-4222-8222-222222222222"
	// sign seals one real chained record carrying data and signs the segment,
	// stamped with its own generation time as every retry is.
	sign := func(generated time.Time, data string) string {
		t.Helper()
		records := []audit.Record{{Sequence: 1, ID: "evt-1", TenantID: tenant, Type: "thing.created",
			Time: time.Unix(500, 0).UTC(), Data: json.RawMessage(data)}}
		head := auditchain.Seal(records)
		payload, err := json.Marshal(audit.Bundle{
			TenantID: tenant, GeneratedAt: generated, Query: audit.Query{TenantID: tenant}, Count: 1, ChainHead: head,
			Records: records,
		})
		if err != nil {
			t.Fatal(err)
		}
		signed, err := key.SignArtifact(jose.ArtifactAuditRetention, payload)
		if err != nil {
			t.Fatal(err)
		}
		return signed
	}
	first, err := archiver.Archive(ctx, tenant, 7, sign(time.Unix(1000, 0).UTC(), `{"n":1}`))
	if err != nil {
		t.Fatal(err)
	}
	again, err := archiver.Archive(ctx, tenant, 7, sign(time.Unix(2000, 0).UTC(), `{"n":1}`))
	if err != nil || again != first {
		t.Fatalf("re-archiving the same records = %q %v, want the earlier locator %q", again, err, first)
	}
	if _, err := archiver.Archive(ctx, tenant, 7, sign(time.Unix(3000, 0).UTC(), `{"n":2}`)); err == nil || !strings.Contains(err.Error(), "different segment") {
		t.Fatalf("a different segment at the same boundary = %v, want a refusal", err)
	}
	name := strings.TrimPrefix(first, "s3://"+srv.Bucket+"/")
	srv.Replace(name, []byte("altered"))
	if _, err := archiver.Archive(ctx, tenant, 7, sign(time.Unix(4000, 0).UTC(), `{"n":1}`)); err == nil {
		t.Fatal("an altered stored segment was accepted")
	}
	if _, err := archiver.Archive(ctx, "33333333-3333-4333-8333-333333333333", 7, sign(time.Unix(5000, 0).UTC(), `{"n":1}`)); err == nil {
		t.Fatal("a segment was archived under another tenant's prefix")
	}
}

// The licensed assembly picks the object archive when the server is given an
// archive object store: retention driven through the assembled server writes
// the tenant's segment into the store and seals the checkpoint in the real
// store with the object's locator.
func TestAssembledServerArchivesAuditSegmentsToTheObjectStore(t *testing.T) {
	st := newAuditTestStore(t)
	log := openTestLog(t)
	ctx := context.Background()
	auditKey, err := jose.GenerateRSASigningKey("audit-export")
	if err != nil {
		t.Fatal(err)
	}
	srv := s3test.NewServer(t)
	asm, err := server.Build(ctx, server.Deps{
		Store: st, Log: log, AuditSigningKey: auditKey, AuditRetention: 24 * time.Hour,
		ArchiveObjectStore: srv.Open(t), AuditComplianceFactory: auditcompliance.Build,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(func() { _ = asm.Shutdown(context.Background()) })
	const tenant = "44444444-4444-4444-8444-444444444444"
	old := time.Now().Add(-72 * time.Hour)
	for i := 0; i < 2; i++ {
		if _, err := log.Append(ctx, events.Event{Type: "thing.created", TenantID: tenant,
			Time: old.Add(time.Duration(i) * time.Second), Data: []byte(fmt.Sprintf(`{"old":%d}`, i))}); err != nil {
			t.Fatal(err)
		}
	}
	if sum, err := asm.RunRetentionOnce(ctx); err != nil || sum.RecordsArchived != 2 {
		t.Fatalf("RunRetentionOnce = %+v %v", sum, err)
	}
	cp, ok, err := st.LatestAuditCheckpoint(ctx, tenant)
	if err != nil || !ok || !strings.HasPrefix(cp.ArchiveURI, "s3://"+srv.Bucket+"/tenant/"+tenant+"/audit/audit-") {
		t.Fatalf("store checkpoint = %+v ok=%v err=%v, want the tenant's object locator", cp, ok, err)
	}
	stored, found := srv.Object(strings.TrimPrefix(cp.ArchiveURI, "s3://"+srv.Bucket+"/"))
	if !found {
		t.Fatalf("no object at the checkpoint's locator %s", cp.ArchiveURI)
	}
	if bundle, err := audit.VerifyRetentionBundle(string(stored), auditKey.JWKS()); err != nil || bundle.Count != 2 {
		t.Fatalf("stored segment = %+v %v", bundle, err)
	}
}
