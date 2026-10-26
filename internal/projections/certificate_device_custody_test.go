// SPDX-License-Identifier: BUSL-1.1

package projections_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"trstctl.com/trstctl/internal/custody"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A131: certificate.custody.device_attested refines a key the requester
// presented into the device-bound claim its attestation proves, retaining the
// evidence; an incomplete claim is refused, and a certificate whose custody
// already says something else keeps it.
func TestCertificateDeviceCustodyProjectsTheClaimAndItsEvidence(t *testing.T) {
	s, log := newStore(t), openLog(t)
	ctx := t.Context()
	p := projections.New(s)
	mustAppend(t, log, events.Event{Type: projections.EventTenantRegistered, TenantID: tenantA, Data: tenantRegistered("Device custody")})
	record := func(id, fingerprint string, origin custody.KeyOrigin) {
		t.Helper()
		data, err := json.Marshal(projections.CertificateRecorded{
			ID: id, Subject: "CN=" + fingerprint, Fingerprint: fingerprint, Source: "protocol:acme",
			IssuanceIdempotencyKey: "protocol-issue:acme:" + fingerprint, KeyOrigin: string(origin),
			CertificateDER: []byte("der-" + fingerprint),
		})
		if err != nil {
			t.Fatal(err)
		}
		mustAppend(t, log, events.Event{ID: uuid.NewString(), TenantID: tenantA, Type: projections.EventCertificateRecorded, Data: data})
	}
	deviceID, agentID := uuid.NewString(), uuid.NewString()
	record(deviceID, "fp-device", custody.OriginRequester)
	record(agentID, "fp-agent", custody.OriginHostAgent)
	digest := bytes.Repeat([]byte{0x11}, 32)
	verifiedAt := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	attested := func(fingerprint string) projections.CertificateCustodyDeviceAttested {
		return projections.CertificateCustodyDeviceAttested{
			Fingerprint: fingerprint, Source: projections.CertificateDeviceAttestationSourceACME,
			Format: "tpm-webauthn", KeyGeneratedBy: "tpm-ak:sha256:" + strings.Repeat("22", 32),
			Credential: []byte(`{"type":"public-key"}`), Binding: []byte(`{"csr_key_sha256":"key"}`),
			PublicKeySHA256: digest, AttestationCertificateSHA256: digest, TrustedRootsSHA256: digest,
			VerifiedAt: verifiedAt,
		}
	}
	data, err := json.Marshal(attested("fp-device"))
	if err != nil {
		t.Fatal(err)
	}
	mustAppend(t, log, events.Event{ID: "device-custody-1", TenantID: tenantA, Type: projections.EventCertificateCustodyDeviceAttested, Data: data})
	if err := p.ProjectCatchUp(ctx, log); err != nil {
		t.Fatal(err)
	}
	cert, err := s.GetCertificate(ctx, tenantA, deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if cert.KeyOrigin != string(custody.OriginDevice) || cert.KeyStorage != string(custody.StorageDeviceBound) ||
		cert.KeyExportable != string(custody.NonExportable) || !strings.HasPrefix(cert.KeyGeneratedBy, "tpm-ak:sha256:") {
		t.Fatalf("device-attested custody = %+v", cert)
	}
	evidence, err := s.GetCertificateKeyAttestation(ctx, tenantA, deviceID)
	if err != nil || evidence.EventID != "device-custody-1" || string(evidence.Credential) != `{"type":"public-key"}` ||
		!evidence.VerifiedAt.Equal(verifiedAt) || !bytes.Equal(evidence.PublicKeySHA256, digest) {
		t.Fatalf("retained evidence = %+v err=%v", evidence, err)
	}
	if _, err := s.GetCertificateKeyAttestation(ctx, tenantA, agentID); !errors.Is(err, store.ErrCertificateKeyAttestationNotFound) {
		t.Fatalf("a certificate without a device claim returned evidence: %v", err)
	}

	apply := func(id string, payload projections.CertificateCustodyDeviceAttested) error {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		return p.Apply(ctx, events.Event{
			ID: id, Type: projections.EventCertificateCustodyDeviceAttested, TenantID: tenantA,
			Time: verifiedAt, Sequence: 1000, SchemaVersion: 1, Data: raw,
		})
	}
	if err := apply("device-custody-agent", attested("fp-agent")); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("a device claim overwrote host-agent custody: %v", err)
	}
	incomplete := attested("fp-device")
	incomplete.Credential = nil
	if err := apply("device-custody-incomplete", incomplete); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("a device claim without its evidence was projected: %v", err)
	}
}
