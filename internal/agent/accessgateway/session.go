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
	"net/url"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto"
)

const (
	// KindSession is the agent job one gateway session rides on.
	KindSession                = relay.KindAccessGatewaySession
	KindSessionRules           = relay.KindAccessGatewayRulesSession
	KindSessionSSHRules        = relay.KindAccessGatewaySSHRulesSession
	KindSessionMySQLRules      = relay.KindAccessGatewayMySQLRulesSession
	KindSessionRedisRules      = relay.KindAccessGatewayRedisRulesSession
	KindSessionMongoRules      = relay.KindAccessGatewayMongoRulesSession
	KindSessionClickHouseRules = relay.KindAccessGatewayClickHouseRulesSession
	// TargetPostgres, TargetMySQL, TargetMongo, TargetClickHouse,
	// TargetRedis, TargetKubernetes and TargetSSH are the session types the
	// gateway serves.
	TargetPostgres   = "postgres"
	TargetMySQL      = "mysql"
	TargetMongo      = "mongodb"
	TargetClickHouse = "clickhouse"
	TargetKubernetes = "kubernetes"
	TargetRedis      = "redis"
	TargetSSH        = "ssh"
	TargetSnowflake  = "snowflake"
	TargetAWS        = "aws"
	// Preface opens every client connection: "TRSTCTL-GATEWAY/1 <session> <ticket>\n".
	Preface = "TRSTCTL-GATEWAY/1"
	// maxPrefaceBytes bounds the preface line a client may send.
	maxPrefaceBytes = 512
)

// RedeemsCredential reports whether a session type's upstream credential
// arrives by redemption: every database type does, and the gateway signs in
// with it itself (A254, A256). An SSH session redeems nothing.
func RedeemsCredential(targetType string) bool {
	switch targetType {
	case TargetPostgres, TargetMySQL, TargetMongo, TargetClickHouse, TargetRedis, TargetKubernetes, TargetSnowflake, TargetAWS:
		return true
	}
	return false
}

// HTTPUpstream reports whether a session type is spoken to over HTTP and
// names its upstream in the job (its credential names no address).
func HTTPUpstream(targetType string) bool {
	return targetType == TargetClickHouse || targetType == TargetKubernetes || targetType == TargetSnowflake || targetType == TargetAWS
}

// SessionIntent is the job payload: one session, by reference only. A
// database session's upstream credential arrives by redemption under
// CredentialRef; an SSH session redeems nothing — the gateway certifies a key
// of its own for it — and names where to sign in, as whom, and which host keys
// to accept. The ticket arrives only as its digest.
type SessionIntent struct {
	AWSService      string              `json:"aws_service,omitempty"`
	AWSRegion       string              `json:"aws_region,omitempty"`
	CommandPolicy   *accessrules.Policy `json:"command_policy,omitempty"`
	SessionID       string              `json:"session_id"`
	TargetType      string              `json:"target_type"`
	TargetID        string              `json:"target_id"`
	ExpiresAt       time.Time           `json:"expires_at"`
	TicketDigest    string              `json:"ticket_digest"`
	CredentialRef   string              `json:"credential_ref,omitempty"`
	RequiredAgentID string              `json:"required_agent_id"`
	// SSHAddress (host:port), SSHPrincipal and SSHHostKeyFingerprints
	// (SHA256:...) route an SSH session; they are public facts.
	SSHAddress             string   `json:"ssh_address,omitempty"`
	SSHPrincipal           string   `json:"ssh_principal,omitempty"`
	SSHHostKeyFingerprints []string `json:"ssh_host_key_fingerprints,omitempty"`
	// UpstreamURL, UpstreamCAPEM and UpstreamServerName are where a target
	// spoken to over HTTP (ClickHouse) is reached and how its certificate is
	// verified — its provider's endpoint, CA and server name, public facts
	// like SSHAddress; the credential names no address. No CA: the system
	// roots.
	UpstreamURL        string `json:"upstream_url,omitempty"`
	UpstreamCAPEM      string `json:"upstream_ca_pem,omitempty"`
	UpstreamServerName string `json:"upstream_server_name,omitempty"`
	// Record asks the gateway to record the session (A255): masked, and
	// uploaded over its agent channel as the session runs.
	Record bool `json:"record,omitempty"`
}

// SessionReport is what the gateway reports when a session ends.
type SessionReport struct {
	SessionID   string `json:"session_id"`
	Ended       string `json:"ended"` // deadline, recalled, credential_unavailable
	Connections int    `json:"connections"`
}

// ClaimableKinds is what the gateway's own claim loop asks for. Sessions are
// held for their whole lifetime, so they never enter the shared relay pool.
func ClaimableKinds() []string {
	return []string{KindSession, KindSessionRules, KindSessionSSHRules, KindSessionMySQLRules, KindSessionRedisRules, KindSessionMongoRules, KindSessionClickHouseRules}
}

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
	case !RedeemsCredential(in.TargetType) && in.TargetType != TargetSSH:
		return errors.New("accessgateway: a session is postgres, mysql, mongodb, clickhouse, redis, kubernetes, snowflake or ssh")
	case len(in.TicketDigest) != 64 || strings.Trim(in.TicketDigest, "0123456789abcdef") != "":
		return errors.New("accessgateway: a session carries its ticket's SHA-256")
	case in.ExpiresAt.IsZero():
		return errors.New("accessgateway: a session has a deadline")
	}
	if in.TargetType == TargetAWS {
		if (in.AWSService != "s3" && in.AWSService != "sts") || in.AWSRegion == "" || len(in.AWSRegion) > 64 || strings.ContainsAny(in.AWSRegion, "/ \t\r\n") {
			return errors.New("accessgateway: AWS session needs a fixed supported signing scope")
		}
	} else if in.AWSService != "" || in.AWSRegion != "" {
		return errors.New("accessgateway: non-AWS session cannot carry AWS scope")
	}
	if err := accessrules.ValidatePolicy(in.CommandPolicy, in.TargetType); err != nil {
		return err
	}
	if RedeemsCredential(in.TargetType) {
		if in.CredentialRef != CredentialRef(in.SessionID) {
			return errors.New("accessgateway: a session redeems only its own credential")
		}
		if in.SSHAddress != "" || in.SSHPrincipal != "" || len(in.SSHHostKeyFingerprints) != 0 {
			return errors.New("accessgateway: a database session carries no SSH routing")
		}
		if !HTTPUpstream(in.TargetType) {
			if in.UpstreamURL != "" || in.UpstreamCAPEM != "" || in.UpstreamServerName != "" {
				return errors.New("accessgateway: only an HTTP session names an upstream")
			}
			return nil
		}
		if u, err := url.Parse(in.UpstreamURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return errors.New("accessgateway: an HTTP session names its upstream http(s) URL")
		}
		return nil
	}
	if in.UpstreamURL != "" || in.UpstreamCAPEM != "" || in.UpstreamServerName != "" {
		return errors.New("accessgateway: an SSH session names no upstream")
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

// KindForPolicy keeps unruled sessions compatible with their existing wire kind.
func KindForPolicy(p *accessrules.Policy) string {
	if p != nil {
		if len(p.Rules) > 0 && p.Rules[0].Protocol == "clickhouse" {
			return KindSessionClickHouseRules
		}
		if len(p.Rules) > 0 && p.Rules[0].Protocol == "mongodb" {
			return KindSessionMongoRules
		}
		if len(p.Rules) > 0 && p.Rules[0].Protocol == "redis" {
			return KindSessionRedisRules
		}
		if len(p.Rules) > 0 && p.Rules[0].Protocol == "mysql" {
			return KindSessionMySQLRules
		}
		if len(p.Rules) > 0 && p.Rules[0].Protocol == "ssh" {
			return KindSessionSSHRules
		}
		return KindSessionRules
	}
	return KindSession
}
func MatchesSessionJob(kind string, in SessionIntent) bool {
	return kind == KindForPolicy(in.CommandPolicy)
}
