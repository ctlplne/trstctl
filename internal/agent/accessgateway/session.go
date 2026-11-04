// SPDX-License-Identifier: BUSL-1.1

// Package accessgateway is the credential-hidden access gateway (A254): a
// gateway-role agent that serves brokered access sessions. A session is one
// agent job: the gateway claims it, redeems the session's upstream credential
// into locked memory, admits only connections that present the session's
// one-time ticket, signs in upstream itself and never returns the credential.
// It never carries MCP traffic and never starts or hosts MCP servers.
package accessgateway

import (
	"errors"
	"net"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto"
)

const (
	// KindSession is the agent job one gateway session rides on.
	KindSession = relay.KindAccessGatewaySession
	// TargetPostgres and TargetSSH are the session types the gateway serves.
	TargetPostgres = "postgres"
	TargetSSH      = "ssh"
	// Preface opens every client connection: "TRSTCTL-GATEWAY/1 <session> <ticket>\n".
	Preface = "TRSTCTL-GATEWAY/1"
	// maxPrefaceBytes bounds the preface line a client may send.
	maxPrefaceBytes = 512
)

// SessionIntent is the job payload: one session, by reference only. A
// PostgreSQL session's upstream credential arrives by redemption under
// CredentialRef; an SSH session redeems nothing — the gateway certifies a key
// of its own for it — and names where to sign in, as whom, and which host keys
// to accept. The ticket arrives only as its digest.
type SessionIntent struct {
	SessionID       string    `json:"session_id"`
	TargetType      string    `json:"target_type"`
	TargetID        string    `json:"target_id"`
	ExpiresAt       time.Time `json:"expires_at"`
	TicketDigest    string    `json:"ticket_digest"`
	CredentialRef   string    `json:"credential_ref,omitempty"`
	RequiredAgentID string    `json:"required_agent_id"`
	// SSHAddress (host:port), SSHPrincipal and SSHHostKeyFingerprints
	// (SHA256:...) route an SSH session; they are public facts.
	SSHAddress             string   `json:"ssh_address,omitempty"`
	SSHPrincipal           string   `json:"ssh_principal,omitempty"`
	SSHHostKeyFingerprints []string `json:"ssh_host_key_fingerprints,omitempty"`
}

// SessionReport is what the gateway reports when a session ends.
type SessionReport struct {
	SessionID   string `json:"session_id"`
	Ended       string `json:"ended"` // deadline, recalled, credential_unavailable
	Connections int    `json:"connections"`
}

// ClaimableKinds is what the gateway's own claim loop asks for. Sessions are
// held for their whole lifetime, so they never enter the shared relay pool.
func ClaimableKinds() []string { return []string{KindSession} }

// JobKey is the one outbox key a session's job carries.
func JobKey(sessionID string) string { return "pam-gateway:" + sessionID }

// CredentialRef names the session's upstream credential at redemption.
func CredentialRef(sessionID string) string { return "pam-session:" + sessionID }

// TicketDigest is the SHA-256 the control plane stores and the gateway
// compares; the ticket itself is held only by the requester.
func TicketDigest(ticket string) string { return crypto.SHA256Hex([]byte(ticket)) }

// TicketMatches reports, in constant time, whether a presented ticket is the
// session's.
func TicketMatches(ticket, digest string) bool {
	return digest != "" && crypto.ConstantTimeEqual([]byte(TicketDigest(ticket)), []byte(digest))
}

// ValidateSessionIntent checks a claimed session job.
func ValidateSessionIntent(in SessionIntent) error {
	switch {
	case in.SessionID == "" || in.TargetID == "" || in.RequiredAgentID == "":
		return errors.New("accessgateway: a session needs its id, target and gateway")
	case in.TargetType != TargetPostgres && in.TargetType != TargetSSH:
		return errors.New("accessgateway: a session is postgres or ssh")
	case len(in.TicketDigest) != 64 || strings.Trim(in.TicketDigest, "0123456789abcdef") != "":
		return errors.New("accessgateway: a session carries its ticket's SHA-256")
	case in.ExpiresAt.IsZero():
		return errors.New("accessgateway: a session has a deadline")
	}
	if in.TargetType == TargetPostgres {
		if in.CredentialRef != CredentialRef(in.SessionID) {
			return errors.New("accessgateway: a session redeems only its own credential")
		}
		if in.SSHAddress != "" || in.SSHPrincipal != "" || len(in.SSHHostKeyFingerprints) != 0 {
			return errors.New("accessgateway: a PostgreSQL session carries no SSH routing")
		}
		return nil
	}
	host, port, err := net.SplitHostPort(in.SSHAddress)
	switch {
	case in.CredentialRef != "":
		return errors.New("accessgateway: an SSH session redeems no credential")
	case err != nil || host == "" || port == "":
		return errors.New("accessgateway: an SSH session names its target's host:port")
	case strings.TrimSpace(in.SSHPrincipal) == "" || strings.ContainsAny(in.SSHPrincipal, " \t\r\n,*"):
		return errors.New("accessgateway: an SSH session names one principal")
	case len(in.SSHHostKeyFingerprints) == 0 || len(in.SSHHostKeyFingerprints) > 8:
		return errors.New("accessgateway: an SSH session pins one to eight host keys")
	}
	for _, fp := range in.SSHHostKeyFingerprints {
		if !strings.HasPrefix(fp, "SHA256:") || len(fp) != len("SHA256:")+43 {
			return errors.New("accessgateway: an SSH host key pin is SHA256:<base64>")
		}
	}
	return nil
}
