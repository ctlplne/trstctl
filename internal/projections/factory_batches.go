// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// Factory provisioning (P12): a batch created for one edge delegation, each
// birth certificate a station's journal reconciled (over the quota or not),
// and each device's first boot or renewal with the operational certificate
// it was given.
const (
	EventFactoryBatchCreated   = "edge.factory_batch.created"
	EventFactoryBirthRecorded  = "edge.factory_birth.recorded"
	EventFactoryDeviceEnrolled = "edge.factory_device.enrolled"
)

// FactoryBatchCreated is the payload of edge.factory_batch.created.
type FactoryBatchCreated struct {
	ID                 string `json:"id"`
	DelegationID       string `json:"delegation_id"`
	Label              string `json:"label"`
	Quota              int    `json:"quota"`
	BirthTTLSeconds    int    `json:"birth_ttl_seconds"`
	OperationalProfile string `json:"operational_profile,omitempty"`
	CreatedBy          string `json:"created_by"`
}

// FactoryBirthRecorded is the payload of edge.factory_birth.recorded.
type FactoryBirthRecorded struct {
	BatchID        string    `json:"batch_id"`
	Serial         string    `json:"serial"`
	DeviceName     string    `json:"device_name"`
	Fingerprint    string    `json:"fingerprint"`
	CertificateDER []byte    `json:"certificate_der"`
	NotAfter       time.Time `json:"not_after"`
	OverQuota      bool      `json:"over_quota"`
}

// FactoryDeviceEnrolled is the payload of edge.factory_device.enrolled: a first
// boot (renewal false) or a renewal in the field.
type FactoryDeviceEnrolled struct {
	BatchID                string `json:"batch_id"`
	Serial                 string `json:"serial"`
	CSRSHA256              string `json:"csr_sha256,omitempty"`
	OperationalSerial      string `json:"operational_serial"`
	OperationalFingerprint string `json:"operational_fingerprint"`
	OperationalDER         []byte `json:"operational_der"`
	Renewal                bool   `json:"renewal"`
}

// ValidateFactoryBatchCreated checks a batch's closed shape.
func ValidateFactoryBatchCreated(b FactoryBatchCreated) error {
	if b.ID == "" || b.DelegationID == "" || b.Label == "" || b.Quota <= 0 || b.BirthTTLSeconds <= 0 || b.CreatedBy == "" {
		return errors.New("projections: a factory batch needs its id, delegation, label, a positive quota and birth lifetime, and its creator")
	}
	return nil
}

func init() {
	for _, typ := range []string{EventFactoryBatchCreated, EventFactoryBirthRecorded, EventFactoryDeviceEnrolled} {
		knownSchemaVersions[typ] = map[int]bool{1: true}
	}
}

func (p *Projector) applyFactoryTx(ctx context.Context, tx pgx.Tx, e events.Event) (bool, error) {
	switch e.Type {
	case EventFactoryBatchCreated:
		var b FactoryBatchCreated
		if err := json.Unmarshal(e.Data, &b); err != nil {
			return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		if err := ValidateFactoryBatchCreated(b); err != nil {
			return true, err
		}
		return true, p.store.ApplyFactoryBatchCreatedTx(ctx, tx, e.TenantID, store.FactoryBatch{ID: b.ID, DelegationID: b.DelegationID,
			Label: b.Label, Quota: b.Quota, BirthTTLSeconds: b.BirthTTLSeconds, OperationalProfile: b.OperationalProfile,
			CreatedBy: b.CreatedBy, CreatedAt: e.Time}, e.Sequence)
	case EventFactoryBirthRecorded:
		var b FactoryBirthRecorded
		if err := json.Unmarshal(e.Data, &b); err != nil {
			return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		if b.BatchID == "" || b.Serial == "" || b.Fingerprint == "" || len(b.CertificateDER) == 0 {
			return true, errors.New("projections: a factory birth certificate needs its batch, serial, fingerprint and certificate")
		}
		return true, p.store.ApplyFactoryBirthRecordedTx(ctx, tx, e.TenantID, store.FactoryBirth{BatchID: b.BatchID, Serial: b.Serial,
			DeviceName: b.DeviceName, Fingerprint: b.Fingerprint, CertificateDER: b.CertificateDER, NotAfter: b.NotAfter,
			OverQuota: b.OverQuota, RecordedAt: e.Time}, e.Sequence)
	case EventFactoryDeviceEnrolled:
		var d FactoryDeviceEnrolled
		if err := json.Unmarshal(e.Data, &d); err != nil {
			return true, fmt.Errorf("projections: decode %s: %w", e.Type, err)
		}
		if d.BatchID == "" || d.Serial == "" || d.OperationalSerial == "" || d.OperationalFingerprint == "" {
			return true, errors.New("projections: a factory enrollment needs its birth certificate and operational certificate")
		}
		return true, p.store.ApplyFactoryDeviceEnrolledTx(ctx, tx, e.TenantID, d.BatchID, d.Serial, d.CSRSHA256, d.OperationalSerial,
			d.OperationalFingerprint, d.OperationalDER, d.Renewal, e.Time, e.Sequence)
	}
	return false, nil
}

func addFactoryPrivacyPolicies(policies map[privacyEventPolicyKey]events.PrivacyEventPolicy) {
	const (
		exact  = events.PrivacyFieldIdentityExact
		opaque = events.PrivacyFieldOpaqueExact
		clear  = events.PrivacyFieldFreeTextClear
	)
	policies[privacyEventPolicyKey{EventFactoryBatchCreated, 1}] = privacyRules(
		privacyRule("/id", opaque), privacyRule("/delegation_id", opaque), privacyRule("/label", clear),
		privacyRule("/quota", opaque), privacyRule("/birth_ttl_seconds", opaque), privacyRule("/operational_profile", opaque),
		privacyRule("/created_by", exact))
	policies[privacyEventPolicyKey{EventFactoryBirthRecorded, 1}] = privacyRules(
		privacyRule("/batch_id", opaque), privacyRule("/serial", opaque), privacyRule("/device_name", opaque),
		privacyRule("/fingerprint", opaque), privacyRule("/certificate_der", opaque), privacyRule("/not_after", opaque),
		privacyRule("/over_quota", opaque))
	policies[privacyEventPolicyKey{EventFactoryDeviceEnrolled, 1}] = privacyRules(
		privacyRule("/batch_id", opaque), privacyRule("/serial", opaque), privacyRule("/csr_sha256", opaque),
		privacyRule("/operational_serial", opaque), privacyRule("/operational_fingerprint", opaque),
		privacyRule("/operational_der", opaque), privacyRule("/renewal", opaque))
}

func addFactoryPrivacyShapes(shapes map[privacyEventPolicyKey]events.PrivacyPayloadShape) {
	shapes[privacyEventPolicyKey{EventFactoryBatchCreated, 1}] = privacyPayloadShape[FactoryBatchCreated]()
	shapes[privacyEventPolicyKey{EventFactoryBirthRecorded, 1}] = privacyPayloadShape[FactoryBirthRecorded]()
	shapes[privacyEventPolicyKey{EventFactoryDeviceEnrolled, 1}] = privacyPayloadShape[FactoryDeviceEnrolled]()
}
