// SPDX-License-Identifier: LicenseRef-trstctl-EE

package depstate

import (
	"encoding/json"
	"fmt"

	"trstctl.com/trstctl/internal/eventspec"
)

const (
	TypeDependencyRegistered        = "dependency.registered"
	TypeDependencyReleased          = "dependency.released"
	TypeDependencyErasureDesignated = "dependency.erasure_designated"
	TypeReprotectionCompleted       = "reprotection.completed"
	TypeRevocationCompleted         = "revocation.completed"
)

const SchemaV1 = 1

type DependentClass string

const (
	DependentCiphertext   DependentClass = "ciphertext"
	DependentWrappedKey   DependentClass = "wrapped_key"
	DependentCredential   DependentClass = "credential"
	DependentLeasedSecret DependentClass = "leased_secret"
	DependentDataSet      DependentClass = "data_set"
)

type RegistrationOrigin string

const (
	RegistrationOriginIssued    RegistrationOrigin = "issued"
	RegistrationOriginDiscovery RegistrationOrigin = "discovery"
	RegistrationOriginImported  RegistrationOrigin = "imported"
)

type Dependent struct {
	Class DependentClass `json:"class"`
	ID    string         `json:"id"`
}

func (d Dependent) key() string {
	return string(d.Class) + "\x00" + d.ID
}

type Payload interface{ isDepStatePayload() }

type DependencyRegisteredV1 struct {
	TenantID  string             `json:"tenant_id"`
	KeyID     string             `json:"key_id"`
	Dependent Dependent          `json:"dependent"`
	Origin    RegistrationOrigin `json:"origin,omitempty"`
}

func (DependencyRegisteredV1) isDepStatePayload() {}

type DependencyReleasedV1 struct {
	TenantID  string    `json:"tenant_id"`
	KeyID     string    `json:"key_id"`
	Dependent Dependent `json:"dependent"`
	Reason    string    `json:"reason,omitempty"`
}

func (DependencyReleasedV1) isDepStatePayload() {}

type DependencyErasureDesignatedV1 struct {
	TenantID       string    `json:"tenant_id"`
	KeyID          string    `json:"key_id"`
	Dependent      Dependent `json:"dependent"`
	DesignationRef string    `json:"designation_ref,omitempty"`
}

func (DependencyErasureDesignatedV1) isDepStatePayload() {}

type ReprotectionCompletedV1 struct {
	TenantID               string                    `json:"tenant_id"`
	KeyID                  string                    `json:"key_id"`
	JobID                  string                    `json:"job_id"`
	Dependent              Dependent                 `json:"dependent"`
	SuccessorKeyID         string                    `json:"successor_key_id,omitempty"`
	CredentialSupersession *CredentialSupersessionV1 `json:"credential_supersession,omitempty"`
}

func (ReprotectionCompletedV1) isDepStatePayload() {}

type CredentialSupersessionV1 struct {
	OldCredentialID string `json:"old_credential_id"`
	NewCredentialID string `json:"new_credential_id"`
}

type RevocationCompletedV1 struct {
	TenantID    string    `json:"tenant_id"`
	KeyID       string    `json:"key_id"`
	JobID       string    `json:"job_id"`
	Dependent   Dependent `json:"dependent"`
	Destination string    `json:"destination,omitempty"`
}

func (RevocationCompletedV1) isDepStatePayload() {}

type Unknown struct {
	Type    string
	Version int
	Raw     []byte
}

func (Unknown) isDepStatePayload() {}

func Encode(p Payload) (eventspec.Event, error) {
	switch v := p.(type) {
	case DependencyRegisteredV1:
		return marshalEvent(TypeDependencyRegistered, SchemaV1, v.TenantID, v)
	case DependencyReleasedV1:
		return marshalEvent(TypeDependencyReleased, SchemaV1, v.TenantID, v)
	case DependencyErasureDesignatedV1:
		return marshalEvent(TypeDependencyErasureDesignated, SchemaV1, v.TenantID, v)
	case ReprotectionCompletedV1:
		return marshalEvent(TypeReprotectionCompleted, SchemaV1, v.TenantID, v)
	case RevocationCompletedV1:
		return marshalEvent(TypeRevocationCompleted, SchemaV1, v.TenantID, v)
	default:
		return eventspec.Event{}, fmt.Errorf("depstate: cannot encode payload of type %T", p)
	}
}

func marshalEvent(typ string, ver int, tenantID string, v any) (eventspec.Event, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return eventspec.Event{}, fmt.Errorf("depstate: marshal %s: %w", typ, err)
	}
	return eventspec.Event{Type: typ, TenantID: tenantID, SchemaVersion: ver, Data: data}, nil
}

func Decode(e eventspec.Event) (Payload, error) {
	ver := e.SchemaVersion
	if ver == 0 {
		ver = eventspec.DefaultSchemaVersion
	}
	switch e.Type {
	case TypeDependencyRegistered:
		return decodeKnown[DependencyRegisteredV1](e, ver)
	case TypeDependencyReleased:
		return decodeKnown[DependencyReleasedV1](e, ver)
	case TypeDependencyErasureDesignated:
		return decodeKnown[DependencyErasureDesignatedV1](e, ver)
	case TypeReprotectionCompleted:
		return decodeKnown[ReprotectionCompletedV1](e, ver)
	case TypeRevocationCompleted:
		return decodeKnown[RevocationCompletedV1](e, ver)
	default:
		return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
	}
}

func decodeKnown[T Payload](e eventspec.Event, ver int) (Payload, error) {
	if ver != SchemaV1 {
		return Unknown{Type: e.Type, Version: ver, Raw: e.Data}, nil
	}
	var p T
	if err := json.Unmarshal(e.Data, &p); err != nil {
		return nil, fmt.Errorf("depstate: decode %s v%d: %w", e.Type, ver, err)
	}
	return p, nil
}
