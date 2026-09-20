// SPDX-License-Identifier: BUSL-1.1

package kmip

import (
	"context"
	"time"

	"trstctl.com/trstctl/internal/reconcile/canon/reducers"
)

const TagManagedObject uint32 = 0x540001

type ObjectType string

const (
	ObjectTypePublicKey    ObjectType = "PublicKey"
	ObjectTypePrivateKey   ObjectType = "PrivateKey"
	ObjectTypeSymmetricKey ObjectType = "SymmetricKey"
	ObjectTypeCertificate  ObjectType = "Certificate"
	ObjectTypeSecretData   ObjectType = "SecretData"
	ObjectTypeOpaqueObject ObjectType = "OpaqueObject"
)

type State string

const (
	StatePreActive   State = "Pre-Active"
	StateActive      State = "Active"
	StateDeactivated State = "Deactivated"
	StateCompromised State = "Compromised"
	StateDestroyed   State = "Destroyed"
)

type ManagedObject struct {
	UniqueIdentifier string
	ObjectType       ObjectType
	Algorithm        string
	LengthBits       int
	State            State

	InitialDate      time.Time
	ActivationDate   time.Time
	DeactivationDate time.Time

	IssuerNameDER []byte
	SerialHex     string
	SubjectDN     string
	SPKI          []byte
}

type Snapshot struct {
	Watermark reducers.Watermark
	Objects   []ManagedObject
}

type Source interface {
	KMIPSnapshot(ctx context.Context, tenantID string, sb *reducers.ObservationSandbox) (Snapshot, error)
}

type Endpoint interface {
	Locate(ctx context.Context, tenantID string) ([]string, error)
	GetAttributes(ctx context.Context, uniqueIdentifier string) (ManagedObject, error)
}
