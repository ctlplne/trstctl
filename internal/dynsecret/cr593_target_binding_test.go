// SPDX-License-Identifier: BUSL-1.1

package dynsecret

import (
	"strings"
	"testing"
	"time"
)

// CR-593: changing a provider's target must not mark an old lease revoked
// while its principal is still live on the original target.
func TestCR593KafkaRevokeRefusesRepointedBroker(t *testing.T) {
	old := &fakeKafka{scram: map[string]string{}, acls: map[kafkaACLKey]bool{}}
	newTarget := &fakeKafka{scram: map[string]string{}, acls: map[kafkaACLKey]bool{}}
	issuer := newFakeKafkaBackend(t, old)
	ref, _, err := issuer.CreateCredential(t.Context(), GenerateRequest{
		Role: "consumer", LeaseID: "lease-cr593-kafka", PrincipalSuffix: testPrincipalSuffix("lease-cr593-kafka"),
	})
	if err != nil || len(old.scram) != 1 {
		t.Fatalf("issue on original broker: %v, users=%d", err, len(old.scram))
	}
	repointed := newFakeKafkaBackend(t, newTarget)
	repointed.addr = "127.0.0.2:9092"
	if err := repointed.Revoke(t.Context(), ref); err == nil {
		t.Fatal("repointed broker falsely reported revoked while original SCRAM user and ACLs remain live")
	}
	if len(old.scram) != 1 || len(old.acls) == 0 || len(newTarget.calls) != 0 {
		t.Fatalf("wrong-target revoke touched a broker: old users=%d ACLs=%d, new calls=%v", len(old.scram), len(old.acls), newTarget.calls)
	}
	user := ref[strings.LastIndexByte(ref, ':')+1:]
	before := len(old.calls)
	if err := issuer.Revoke(t.Context(), user); err == nil || len(old.calls) != before {
		t.Fatalf("legacy target-unbound ref reached broker: err=%v calls=%v", err, old.calls[before:])
	}
	issuer.prefix = "edited_prefix"
	if err := issuer.Revoke(t.Context(), ref); err != nil || len(old.scram) != 0 || len(old.acls) != 0 {
		t.Fatalf("original broker revoke after prefix edit: err=%v users=%d ACLs=%d", err, len(old.scram), len(old.acls))
	}
}

func TestCR593MilvusRevokeRefusesRepointedEndpoint(t *testing.T) {
	old, oldServer := newMilvusStandIn(t)
	newTarget, newServer := newMilvusStandIn(t)
	issuer := newLabMilvus(t, oldServer, map[string]string{"reader": "orders_reader"})
	ref, _, err := issuer.CreateCredential(t.Context(), GenerateRequest{
		Role: "reader", LeaseID: "lease-cr593-milvus", PrincipalSuffix: testPrincipalSuffix("lease-cr593-milvus"),
	})
	if err != nil || len(old.users) != 1 {
		t.Fatalf("issue on original Milvus: %v, users=%d", err, len(old.users))
	}
	repointed := newLabMilvus(t, newServer, map[string]string{"reader": "orders_reader"})
	if err := repointed.Revoke(t.Context(), ref); err == nil {
		t.Fatal("repointed Milvus falsely reported revoked while original user remains live")
	}
	if len(old.users) != 1 || len(newTarget.calls) != 0 {
		t.Fatalf("wrong-target revoke touched an endpoint: old users=%d, new calls=%v", len(old.users), newTarget.calls)
	}
	user := ref[strings.LastIndexByte(ref, ':')+1:]
	before := len(old.calls)
	if err := issuer.Revoke(t.Context(), user); err == nil || len(old.calls) != before {
		t.Fatalf("legacy target-unbound ref reached Milvus: err=%v calls=%v", err, old.calls[before:])
	}
	issuer.prefix = "edited_prefix"
	if err := issuer.Revoke(t.Context(), ref); err != nil || len(old.users) != 0 {
		t.Fatalf("original Milvus revoke after prefix edit: err=%v users=%d", err, len(old.users))
	}
}

func TestCR593AtlasRevokeRefusesRepointedProjectEndpoint(t *testing.T) {
	old, oldServer := newAtlasStandIn(t)
	newTarget, newServer := newAtlasStandIn(t)
	issuer := newLabAtlas(t, oldServer, time.Now())
	ref, _, err := issuer.CreateCredential(t.Context(), GenerateRequest{
		Role: "reader", LeaseID: "lease-cr593-atlas", PrincipalSuffix: testPrincipalSuffix("lease-cr593-atlas"),
	})
	if err != nil || len(old.users) != 1 {
		t.Fatalf("issue on original Atlas project: %v, users=%d", err, len(old.users))
	}
	repointed := newLabAtlas(t, newServer, time.Now())
	if err := repointed.Revoke(t.Context(), ref); err == nil {
		t.Fatal("repointed Atlas falsely reported revoked while original database user remains live")
	}
	if len(old.users) != 1 || len(newTarget.calls) != 0 {
		t.Fatalf("wrong-target revoke touched an endpoint: old users=%d, new calls=%v", len(old.users), newTarget.calls)
	}
	user := ref[strings.LastIndexByte(ref, ':')+1:]
	before := len(old.calls)
	if err := issuer.Revoke(t.Context(), user); err == nil || len(old.calls) != before {
		t.Fatalf("legacy target-unbound ref reached Atlas: err=%v calls=%v", err, old.calls[before:])
	}
	issuer.prefix = "edited_prefix"
	if err := issuer.Revoke(t.Context(), ref); err != nil || len(old.users) != 0 {
		t.Fatalf("original Atlas revoke after prefix edit: err=%v users=%d", err, len(old.users))
	}
}
