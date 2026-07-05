// SPDX-License-Identifier: LicenseRef-trstctl-EE

// Package staple carries a succession proof inline in an authentication handshake
// or credential (claims 31, 32): a presenter attaches at least one succession
// record OR a signed epoch checkpoint, and the relying party verifies the
// identity's current algorithm inline — verifying the signatures and confirming
// the epoch against a last-accepted value — without out-of-band resolution or
// algorithm negotiation. Verification reuses ee/succession (PCAS-04/13); all
// crypto routes through the core internal/crypto AN-3 boundary.
package staple

import (
	"encoding/json"
	"errors"
	"fmt"

	"trstctl.com/trstctl/ee/succession"
)

// Illustrative carriage identifiers for the succession attachment.
const (
	TLSExtensionType    uint16 = 0xF3A5
	CertExtensionOID           = "1.3.6.1.4.1.59999.1.31"
	CheckpointFreshness        = 0 // 0 disables the freshness bound (epoch check still applies)
)

// Errors.
var (
	ErrAttachmentRequired   = errors.New("staple: a succession attachment is required but absent")
	ErrNoLimb               = errors.New("staple: attachment carries neither a record chain nor a checkpoint")
	ErrWrongExtension       = errors.New("staple: not a PCAS succession attachment extension")
	ErrStaleCheckpoint      = errors.New("staple: checkpoint epoch does not exceed the last-accepted value")
	ErrMissingAnchor        = errors.New("staple: record-limb verification requires a genesis anchor + trust-root key")
	ErrMissingCheckpointKey = errors.New("staple: checkpoint-limb verification requires the checkpoint key")
)

// Attachment is the inline succession proof: EITHER a chain of records OR a signed
// epoch checkpoint (claim 31). Exactly one limb is populated.
type Attachment struct {
	Records    []succession.SuccessionRecord     `json:"records,omitempty"`
	Checkpoint *succession.SignedEpochCheckpoint `json:"checkpoint,omitempty"`
}

// Encode serializes the attachment for carriage in an extension.
func (a Attachment) Encode() ([]byte, error) { return json.Marshal(a) }

// Decode parses an attachment from its carried bytes.
func Decode(b []byte) (Attachment, error) {
	var a Attachment
	err := json.Unmarshal(b, &a)
	return a, err
}

// Result is the current posture the relying party derived from the attachment.
type Result struct {
	Algorithm string
	PublicDER []byte
	Epoch     uint64
}

// Policy is the relying party's inline-verification policy.
type Policy struct {
	ExpectedTenant    string
	RequireAttachment bool
	LastAccepted      uint64

	// Record-limb anchors.
	Genesis         *succession.GenesisRecord
	TrustRootPubDER []byte

	// Checkpoint-limb key.
	CheckpointKeyDER []byte
}

// VerifyStapled verifies an attachment inline and returns the current posture. A
// nil attachment fails when the policy requires one (claim 32: absence-as-failure).
// It negotiates no algorithm and resolves nothing out of band (claim 31).
func VerifyStapled(att *Attachment, p Policy) (Result, error) {
	if att == nil {
		if p.RequireAttachment {
			return Result{}, ErrAttachmentRequired
		}
		return Result{}, ErrNoLimb
	}

	switch {
	case att.Checkpoint != nil:
		if len(p.CheckpointKeyDER) == 0 {
			return Result{}, ErrMissingCheckpointKey
		}
		c := *att.Checkpoint
		if err := succession.VerifyEpochCheckpoint(p.CheckpointKeyDER, c); err != nil {
			return Result{}, err
		}
		if p.ExpectedTenant != "" && c.TenantID != p.ExpectedTenant {
			return Result{}, fmt.Errorf("staple: checkpoint tenant %q != expected %q", c.TenantID, p.ExpectedTenant)
		}
		if c.Epoch <= p.LastAccepted {
			return Result{}, ErrStaleCheckpoint
		}
		return Result{Algorithm: string(c.Algorithm), PublicDER: c.PublicKeyDER, Epoch: c.Epoch}, nil

	case len(att.Records) > 0:
		if p.Genesis == nil || len(p.TrustRootPubDER) == 0 {
			return Result{}, ErrMissingAnchor
		}
		if err := succession.VerifyGenesis(p.TrustRootPubDER, *p.Genesis); err != nil {
			return Result{}, err
		}
		if p.ExpectedTenant != "" && p.Genesis.TenantID != p.ExpectedTenant {
			return Result{}, fmt.Errorf("staple: genesis tenant %q != expected %q", p.Genesis.TenantID, p.ExpectedTenant)
		}
		if err := succession.VerifyChain(*p.Genesis, att.Records, p.LastAccepted); err != nil {
			return Result{}, err
		}
		head := att.Records[len(att.Records)-1]
		return Result{Algorithm: string(head.Fields.SuccessorAlg), PublicDER: head.Fields.SuccessorPub, Epoch: head.Fields.Epoch}, nil

	default:
		return Result{}, ErrNoLimb
	}
}

// --- carriage (claim 32) ---------------------------------------------------

// TLSExtension models a TLS handshake extension carrying the attachment.
type TLSExtension struct {
	Type uint16
	Data []byte
}

// CertExtension models an X.509/SSH certificate extension carrying the attachment.
type CertExtension struct {
	OID   string
	Value []byte
}

// ToTLSExtension serializes the attachment into a TLS extension.
func (a Attachment) ToTLSExtension() (TLSExtension, error) {
	b, err := a.Encode()
	if err != nil {
		return TLSExtension{}, err
	}
	return TLSExtension{Type: TLSExtensionType, Data: b}, nil
}

// FromTLSExtension extracts an attachment from a TLS extension.
func FromTLSExtension(ext TLSExtension) (Attachment, error) {
	if ext.Type != TLSExtensionType {
		return Attachment{}, ErrWrongExtension
	}
	return Decode(ext.Data)
}

// ToCertExtension serializes the attachment into a certificate extension.
func (a Attachment) ToCertExtension() (CertExtension, error) {
	b, err := a.Encode()
	if err != nil {
		return CertExtension{}, err
	}
	return CertExtension{OID: CertExtensionOID, Value: b}, nil
}

// FromCertExtension extracts an attachment from a certificate extension.
func FromCertExtension(ext CertExtension) (Attachment, error) {
	if ext.OID != CertExtensionOID {
		return Attachment{}, ErrWrongExtension
	}
	return Decode(ext.Value)
}
