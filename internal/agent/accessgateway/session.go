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
	"regexp"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/accessconsole"
	"trstctl.com/trstctl/internal/accessdesktop"
	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/accessweb"
	"trstctl.com/trstctl/internal/agent/relay"
	"trstctl.com/trstctl/internal/crypto"
)

const (
	// KindSession is the agent job one gateway session rides on.
	KindSession                = relay.KindAccessGatewaySession
	KindSessionDesktop         = relay.KindAccessGatewayDesktopSession
	KindSessionADDesktop       = relay.KindAccessGatewayADDesktopSession
	KindSessionRules           = relay.KindAccessGatewayRulesSession
	KindSessionSSHRules        = relay.KindAccessGatewaySSHRulesSession
	KindSessionMySQLRules      = relay.KindAccessGatewayMySQLRulesSession
	KindSessionRedisRules      = relay.KindAccessGatewayRedisRulesSession
	KindSessionMongoRules      = relay.KindAccessGatewayMongoRulesSession
	KindSessionClickHouseRules = relay.KindAccessGatewayClickHouseRulesSession
	KindSessionNetDevice       = relay.KindAccessGatewayNetDeviceSession
	KindSessionNetDeviceRules  = relay.KindAccessGatewayNetDeviceRulesSession
	KindSessionWeb             = relay.KindAccessGatewayWebSession
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
	TargetGCP        = "gcp"
	TargetAzure      = "azure"
	TargetAWSConsole = accessconsole.TargetAWS
	TargetRDP        = accessdesktop.TargetRDP
	// TargetNetDevice (A270) is a network device's vaulted account: the
	// gateway redeems its password and signs in to the device over SSH.
	TargetNetDevice = "netdevice"
	// TargetWeb (A273) is an internal web admin console's vaulted account:
	// the gateway signs in to the console for the operator's browser.
	TargetWeb = accessweb.TargetWeb
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
	case TargetPostgres, TargetMySQL, TargetMongo, TargetClickHouse, TargetRedis, TargetKubernetes, TargetSnowflake, TargetAWS, TargetGCP, TargetAzure, TargetAWSConsole, TargetRDP, TargetNetDevice, TargetWeb:
		return true
	}
	return false
}

// HTTPUpstream reports whether a session type is spoken to over HTTP and
// names its upstream in the job (its credential names no address).
func HTTPUpstream(targetType string) bool {
	return targetType == TargetClickHouse || targetType == TargetKubernetes || targetType == TargetSnowflake || targetType == TargetAWS || targetType == TargetGCP || targetType == TargetAzure
}

var azureOAuthTenant = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)

// SessionIntent is the job payload: one session, by reference only. A
// database session's upstream credential arrives by redemption under
// CredentialRef; an SSH session redeems nothing — the gateway certifies a key
// of its own for it — and names where to sign in, as whom, and which host keys
// to accept. The ticket arrives only as its digest.
type SessionIntent struct {
	Desktop            *accessdesktop.Binding `json:"desktop,omitempty"`
	Console            *accessconsole.Binding `json:"console,omitempty"`
	ConsoleRole        string                 `json:"console_role,omitempty"`
	OAuthTenant        string                 `json:"oauth_tenant,omitempty"`
	OAuthTokenEndpoint string                 `json:"oauth_token_endpoint,omitempty"`
	OAuthScopes        []string               `json:"oauth_scopes,omitempty"`
	OAuthSubject       string                 `json:"oauth_subject,omitempty"`
	AWSService         string                 `json:"aws_service,omitempty"`
	AWSRegion          string                 `json:"aws_region,omitempty"`
	CommandPolicy      *accessrules.Policy    `json:"command_policy,omitempty"`
	// WebSignIn (A273) is how the gateway signs in to a web console, as the
	// template its reviewers approved says; the console's route is
	// UpstreamURL, UpstreamCAPEM and UpstreamServerName.
	WebSignIn       *accessweb.SignIn `json:"web_sign_in,omitempty"`
	SessionID       string            `json:"session_id"`
	TargetType      string            `json:"target_type"`
	TargetID        string            `json:"target_id"`
	ExpiresAt       time.Time         `json:"expires_at"`
	TicketDigest    string            `json:"ticket_digest"`
	CredentialRef   string            `json:"credential_ref,omitempty"`
	RequiredAgentID string            `json:"required_agent_id"`
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
	return []string{KindSession, KindSessionRules, KindSessionSSHRules, KindSessionMySQLRules, KindSessionRedisRules, KindSessionMongoRules, KindSessionClickHouseRules, KindSessionNetDevice, KindSessionNetDeviceRules, KindSessionWeb}
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
	if in.TargetType == TargetRDP {
		if in.Desktop == nil || in.Desktop.Validate() != nil || in.CommandPolicy != nil {
			return errors.New("accessgateway: desktop needs a reviewed route and cannot carry shell/query rules")
		}
	} else if in.Desktop != nil {
		return errors.New("accessgateway: only desktop sessions carry desktop routing")
	}
	if in.TargetType == TargetAWSConsole {
		if in.Console == nil || in.Console.Validate(true) != nil || in.ConsoleRole == "" || len(in.ConsoleRole) > 128 || strings.ContainsAny(in.ConsoleRole, "\r\n\x00") {
			return errors.New("accessgateway: console session needs reviewed destinations and role")
		}
	} else if in.Console != nil || in.ConsoleRole != "" {
		return errors.New("accessgateway: only a console session carries console destinations")
	}

	if in.TargetType == TargetAWS {
		if (in.AWSService != "s3" && in.AWSService != "sts") || in.AWSRegion == "" || len(in.AWSRegion) > 64 || strings.ContainsAny(in.AWSRegion, "/ \t\r\n") {
			return errors.New("accessgateway: AWS session needs a fixed supported signing scope")
		}
	} else if in.AWSService != "" || in.AWSRegion != "" {
		return errors.New("accessgateway: non-AWS session cannot carry AWS scope")
	}
	if in.TargetType == TargetGCP || in.TargetType == TargetAzure {
		u, err := url.Parse(in.OAuthTokenEndpoint)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || in.OAuthSubject == "" || len(in.OAuthSubject) > 320 || strings.ContainsAny(in.OAuthSubject, " \t\r\n") || len(in.OAuthScopes) == 0 || len(in.OAuthScopes) > 16 {
			return errors.New("accessgateway: cloud session needs a fixed OAuth binding")
		}
		seen := map[string]bool{}
		for _, scope := range in.OAuthScopes {
			u, err := url.Parse(scope)
			if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(scope) > 256 || strings.ContainsAny(scope, " \t\r\n") || seen[scope] {
				return errors.New("accessgateway: invalid OAuth scope")
			}
			seen[scope] = true
		}
	} else if in.OAuthTokenEndpoint != "" || len(in.OAuthScopes) != 0 || in.OAuthSubject != "" || in.OAuthTenant != "" {
		return errors.New("accessgateway: non-OAuth session cannot carry OAuth scope")
	}

	if in.TargetType == TargetAzure {
		u, _ := url.Parse(in.OAuthTokenEndpoint)
		if !azureOAuthTenant.MatchString(in.OAuthTenant) || strings.EqualFold(in.OAuthTenant, "common") || strings.EqualFold(in.OAuthTenant, "organizations") || strings.EqualFold(in.OAuthTenant, "consumers") || u.Path != "/"+in.OAuthTenant+"/oauth2/v2.0/token" || len(in.OAuthScopes) != 1 || !strings.HasSuffix(in.OAuthScopes[0], "/.default") {
			return errors.New("accessgateway: Azure OAuth authority needs one tenant and resource")
		}
	} else if in.OAuthTenant != "" {
		return errors.New("accessgateway: non-Azure session cannot carry an Azure tenant")
	}

	if err := accessrules.ValidatePolicy(in.CommandPolicy, in.TargetType); err != nil {
		return err
	}
	if in.TargetType == TargetWeb {
		route := accessweb.Route{URL: in.UpstreamURL, CAPEM: in.UpstreamCAPEM, ServerName: in.UpstreamServerName}
		switch {
		case in.CredentialRef != CredentialRef(in.SessionID):
			return errors.New("accessgateway: a session redeems only its own credential")
		case in.SSHAddress != "" || in.SSHPrincipal != "" || len(in.SSHHostKeyFingerprints) != 0:
			return errors.New("accessgateway: a web console session carries no SSH routing")
		case in.WebSignIn == nil || in.WebSignIn.Validate() != nil || in.CommandPolicy != nil || route.Validate(true) != nil:
			return errors.New("accessgateway: a web console session needs its reviewed route and sign-in, and carries no command rules")
		}
		return nil
	} else if in.WebSignIn != nil {
		return errors.New("accessgateway: only a web console session carries a web sign-in")
	}
	if in.TargetType == TargetNetDevice {
		// A network device session redeems its vaulted account and routes
		// like an SSH session.
		if in.CredentialRef != CredentialRef(in.SessionID) {
			return errors.New("accessgateway: a session redeems only its own credential")
		}
		return validateSSHRoute(in)
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
	if in.CredentialRef != "" {
		return errors.New("accessgateway: an SSH session redeems no credential")
	}
	return validateSSHRoute(in)
}

// validateSSHRoute checks an SSH or network device session's route: the
// target's host:port, one principal and one to eight pinned host keys.
func validateSSHRoute(in SessionIntent) error {
	if in.UpstreamURL != "" || in.UpstreamCAPEM != "" || in.UpstreamServerName != "" {
		return errors.New("accessgateway: an SSH session names no upstream")
	}
	host, port, err := net.SplitHostPort(in.SSHAddress)
	switch {
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
		if len(p.Rules) > 0 && p.Rules[0].Protocol == "netdevice" {
			return KindSessionNetDeviceRules
		}
		return KindSessionRules
	}
	return KindSession
}
func MatchesSessionJob(kind string, in SessionIntent) bool {
	if in.TargetType == TargetRDP || in.TargetType == TargetNetDevice || in.TargetType == TargetWeb {
		return kind == KindForIntent(in)
	}
	return kind == KindForPolicy(in.CommandPolicy)
}

// KindForIntent keeps native desktop work away from legacy gateways.
func KindForIntent(in SessionIntent) string {
	if in.TargetType == TargetRDP {
		if in.Desktop != nil && in.Desktop.AccountKind == "active_directory" {
			return KindSessionADDesktop
		}
		return KindSessionDesktop
	}
	if in.TargetType == TargetNetDevice && in.CommandPolicy == nil {
		return KindSessionNetDevice
	}
	if in.TargetType == TargetWeb {
		return KindSessionWeb
	}
	return KindForPolicy(in.CommandPolicy)
}
