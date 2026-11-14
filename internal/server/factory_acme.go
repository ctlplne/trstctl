// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/projections"
	acme "trstctl.com/trstctl/internal/protocols/acme"
)

// factoryACMEAuthority is the factory behind first boot over ACME (P12-L2):
// a reconciled birth certificate answers device-attest-01 for its device's
// name under exactly the checks of a first boot over EST, and the order's
// certificate is recorded as the device's first boot.
type factoryACMEAuthority struct{ server *Server }

var _ acme.FactoryBirthAuthority = factoryACMEAuthority{}

// FactoryDevice reports whether a reconciled birth certificate names identifier.
func (a factoryACMEAuthority) FactoryDevice(ctx context.Context, tenantID, identifier string) (bool, error) {
	if a.server == nil || a.server.store == nil {
		return false, nil
	}
	_, found, err := a.server.store.FactoryBirthByDeviceName(ctx, tenantID, strings.TrimSpace(identifier))
	return found, err
}

// VerifyFactoryBirth checks a birth certificate may enroll identifier now.
func (a factoryACMEAuthority) VerifyFactoryBirth(ctx context.Context, tenantID, identifier string, birthDER []byte, csrSHA256 string) (acme.FactoryBirthGrant, error) {
	if a.server == nil || a.server.store == nil {
		return acme.FactoryBirthGrant{}, errors.New("factory first boot is not available")
	}
	birth, found, err := a.server.store.FactoryBirthByFingerprint(ctx, tenantID, crypto.SHA256Hex(birthDER), false)
	if err != nil {
		return acme.FactoryBirthGrant{}, err
	}
	if !found {
		return acme.FactoryBirthGrant{}, errors.New("this birth certificate was never reconciled from a factory batch")
	}
	if !strings.EqualFold(birth.DeviceName, strings.TrimSpace(identifier)) {
		return acme.FactoryBirthGrant{}, errors.New("the birth certificate names another device")
	}
	batch, err := a.server.store.GetFactoryBatch(ctx, tenantID, birth.BatchID)
	if err != nil {
		return acme.FactoryBirthGrant{}, errors.New("the device's batch could not be read")
	}
	if _, err := a.server.factoryFirstBootAllowed(ctx, tenantID, birth, batch, csrSHA256, time.Now()); err != nil {
		return acme.FactoryBirthGrant{}, err
	}
	public, err := crypto.PublicKeyDERFromCert(birth.CertificateDER)
	if err != nil {
		return acme.FactoryBirthGrant{}, err
	}
	return acme.FactoryBirthGrant{BatchID: birth.BatchID, Serial: birth.Serial, PublicKeyDER: public}, nil
}

// RecordFactoryFirstBoot records the order's certificate as the device's first boot.
func (a factoryACMEAuthority) RecordFactoryFirstBoot(ctx context.Context, tenantID string, grant acme.FactoryBirthGrant, csrSHA256 string, operationalPEM []byte) error {
	if a.server == nil || a.server.orch == nil {
		return errors.New("factory first boot is not available")
	}
	info, err := certinfo.Inspect(operationalPEM)
	if err != nil {
		return err
	}
	der, err := firstCertDER(string(operationalPEM))
	if err != nil {
		return err
	}
	return a.server.orch.RecordFactoryDeviceEnrolled(ctx, tenantID, projections.FactoryDeviceEnrolled{BatchID: grant.BatchID, Serial: grant.Serial,
		CSRSHA256: csrSHA256, OperationalSerial: strings.ToLower(info.SerialNumber), OperationalFingerprint: strings.ToLower(info.SHA256Fingerprint),
		OperationalDER: der})
}
