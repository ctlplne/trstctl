// SPDX-License-Identifier: BUSL-1.1

package projections

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"time"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/events"
)

// Schema1 remains a closed historical vocabulary. New fields are schema2;
// replay and privacy export must not infer them in an old signed envelope.
type privacyPAMSessionStartedV1 struct {
	ID             string              `json:"id"`
	TargetType     string              `json:"target_type"`
	TargetID       string              `json:"target_id"`
	Role           string              `json:"role"`
	Status         string              `json:"status"`
	Subject        string              `json:"subject"`
	RequestedBy    string              `json:"requested_by"`
	Reason         string              `json:"reason,omitempty"`
	AttestationID  string              `json:"attestation_id,omitempty"`
	Attestation    *attest.Attestation `json:"attestation,omitempty"`
	BackendRef     string              `json:"backend_ref,omitempty"`
	SSHKeyID       string              `json:"ssh_key_id,omitempty"`
	SSHSerial      uint64              `json:"ssh_serial,omitempty"`
	IdempotencyKey string              `json:"idempotency_key,omitempty"`
	Audit          json.RawMessage     `json:"audit,omitempty"`
	StartedAt      time.Time           `json:"started_at"`
	ExpiresAt      time.Time           `json:"expires_at"`
	// ApprovalRequestID names the approval the activation consumed (G1); events
	// recorded before it existed carry none.
	ApprovalRequestID string `json:"approval_request_id,omitempty"`
	// Delivery is "gateway" for a session delivered through a gateway (A254);
	// events recorded before it existed carry none and read as direct.
	// GatewayTicketDigest is the SHA-256 of the requester's one-time ticket —
	// never the ticket.
	Delivery            string `json:"delivery,omitempty"`
	GatewayAgentID      string `json:"gateway_agent_id,omitempty"`
	GatewayTicketDigest string `json:"gateway_ticket_digest,omitempty"`
	// SSHPrincipal is the login a gateway SSH session's certificate names; the
	// gateway's own key is certified when it claims the session.
	SSHPrincipal string `json:"ssh_principal,omitempty"`
}

type privacyPAMTemplateSavedV1 struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Reason            string `json:"reason"`
	RequiredApprovals int    `json:"required_approvals"`
	MaxTTLSeconds     int    `json:"max_ttl_seconds"`
	// RequireRecording (A261 part 3) refuses an unrecorded session and every
	// check-out through the template.
	RequireRecording bool      `json:"require_recording,omitempty"`
	Revision         int64     `json:"revision"`
	Actor            string    `json:"actor"`
	At               time.Time `json:"at"`
}

func decodeClosedPAMCommand(e events.Event, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(e.Data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		return errors.New("projections: PAM event payload is outside its declared schema")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("projections: trailing PAM event payload")
	}
	return nil
}
func decodePAMTemplateVersion(e events.Event, value *PAMTemplateSaved) error {
	if schemaVersionOf(e) == 1 {
		var legacy privacyPAMTemplateSavedV1
		if err := decodeClosedPAMCommand(e, &legacy); err != nil {
			return err
		}
	}
	return decodeClosedPAMCommand(e, value)
}
func decodePAMSessionVersion(e events.Event, value *PAMSessionStarted) error {
	if schemaVersionOf(e) == 1 {
		var legacy privacyPAMSessionStartedV1
		if err := decodeClosedPAMCommand(e, &legacy); err != nil {
			return err
		}
	}
	return decodeClosedPAMCommand(e, value)
}
