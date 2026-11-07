// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"trstctl.com/trstctl/internal/accessconsole"
	"trstctl.com/trstctl/internal/accessdesktop"
	"trstctl.com/trstctl/internal/accessrules"
	"trstctl.com/trstctl/internal/accessweb"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/agent/accessgateway"
	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/attest"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/seal"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/objectstore"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	sshca "trstctl.com/trstctl/internal/protocols/ssh"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

const (
	pamTargetPostgres  = "postgres"
	pamTargetSSH       = "ssh"
	pamTargetRedis     = "redis"
	pamTargetMySQL     = "mysql"
	pamTargetMongo     = "mongodb"
	pamTargetCH        = "clickhouse"
	pamTargetK8s       = "kubernetes"
	pamTargetSnowflake = "snowflake"
	pamTargetAWS       = "aws"
	pamTargetGCP       = "gcp"
	pamTargetAzure     = "azure"
	// pamTargetWindowsLocal (A268) is a Windows local administrator account
	// vaulted in an application secret that its native provider rotates on
	// the enrolled host. It is checked out (A261), never opened as a session.
	pamTargetWindowsLocal = "windows_local"
	// pamTargetAccount (A271) is an account its provider rotates in place
	// (ESXi, vCenter single sign-on, Redfish controllers, network devices),
	// vaulted in an application secret. It is checked out, never opened as a
	// session.
	pamTargetAccount = "account"
	// pamTargetBreakGlass (A272) is an identity provider's break-glass
	// administrator, vaulted in an application secret its provider rotates;
	// released only through emergency access, never a session.
	pamTargetBreakGlass = "breakglass"
	pamTargetAWSConsole = accessconsole.TargetAWS
	pamTargetRDP        = accessdesktop.TargetRDP
	// pamTargetNetDevice (A270) is a network device's vaulted account: its
	// gateway signs in to the device over SSH with the account's password.
	pamTargetNetDevice = accessgateway.TargetNetDevice
	// pamTargetWebConsole (A273) is an internal web admin console's vaulted
	// account: its gateway signs in to the console for the operator's
	// browser, as the session's template says.
	pamTargetWebConsole = accessweb.TargetWeb

	defaultPAMTTL            = 15 * time.Minute
	defaultPAMMaxTTL         = time.Hour
	defaultPAMExpiryInterval = 30 * time.Second
	defaultPAMApprovalTTL    = 15 * time.Minute
)

// pamDatabaseProviderTypes maps each provider-backed database target type to
// the dynamic-secret provider type that issues its per-session login (A256).
// PostgreSQL targets may hand the requester that login; every other type is
// served only through an access gateway, which signs in with it itself.
var pamDatabaseProviderTypes = map[string]string{
	pamTargetPostgres:   "postgresql",
	pamTargetRedis:      "redis",
	pamTargetMySQL:      "mysql",
	pamTargetMongo:      "mongodb",
	pamTargetCH:         "clickhouse",
	pamTargetK8s:        "kubernetes",
	pamTargetSnowflake:  "snowflake",
	pamTargetAWS:        "aws-sts",
	pamTargetAWSConsole: "aws-sts",
	pamTargetGCP:        "gcp-iam",
	pamTargetAzure:      "azure-entra",
	pamTargetRDP:        "desktop",
	pamTargetNetDevice:  "netdevice",
	pamTargetWebConsole: "webconsole",
}

// pamDatabaseKinds are the database types' names in operator-facing text.
var pamDatabaseKinds = map[string]string{pamTargetPostgres: "PostgreSQL", pamTargetRedis: "Redis", pamTargetMySQL: "MySQL", pamTargetMongo: "MongoDB", pamTargetCH: "ClickHouse", pamTargetK8s: "Kubernetes", pamTargetSnowflake: "Snowflake", pamTargetAWS: "AWS", pamTargetGCP: "Google Cloud", pamTargetAzure: "Azure", pamTargetAWSConsole: "AWS console", pamTargetRDP: "remote desktop", pamTargetNetDevice: "network device", pamTargetWebConsole: "web console"}

// isPAMDatabaseType reports whether a target type is a provider-backed
// database target.
func isPAMDatabaseType(targetType string) bool {
	_, ok := pamDatabaseProviderTypes[targetType]
	return ok
}

// pamTargetTypesText lists the target types for an operator-facing refusal.
func pamTargetTypesText() string {
	types := []string{pamTargetSSH}
	for t := range pamDatabaseProviderTypes {
		types = append(types, t)
	}
	sort.Strings(types)
	return strings.Join(types, ", ")
}

// PAMConfig enables the served just-in-time privileged-access broker (PAM-01/F33).
// Postgres targets use real scoped login roles; SSH targets use the signer-backed
// SSH CA. Every injected target is tenant-bound. An enabled broker may start
// without targets so a tenant registrar can add one through the API.
type PAMConfig struct {
	Enabled           bool
	DefaultTTL        time.Duration
	MaxTTL            time.Duration
	ExpiryInterval    time.Duration
	ApprovalTTL       time.Duration
	RequiredApprovals int
	// RecordingRetention keeps sealed gateway session recordings this long
	// (A255); zero keeps them.
	RecordingRetention time.Duration
	// SignInRetention keeps the sign-ins bypass detection read this long
	// (A274); zero is 90 days.
	SignInRetention time.Duration
	// UnusedAfter flags a brokered account with no session or check-out for
	// this long (A276); zero is 90 days.
	UnusedAfter time.Duration
	// CertificationInterval starts a certification campaign of brokered
	// accounts and approver lists this often (A276); zero never.
	// CertificationReviewer is the subject such a campaign is assigned to;
	// empty is any distinct reviewer.
	CertificationInterval time.Duration
	CertificationReviewer string
	// HealthInterval is how often each brokered account's stored credential
	// is signed in with (A258); zero is the default, an hour.
	HealthInterval time.Duration
	// WebConsoleAllowLoopback admits web console routes on a loopback
	// address (a lab's stand-in console); off, the gateway is never pointed
	// at its own host's services.
	WebConsoleAllowLoopback bool
	Attestors               []attest.Attestor
	PostgresTargets         []PAMPostgresTarget
	// DatabaseTargets are provider-backed targets of the other database
	// types (A256), each reached only through its access gateway.
	DatabaseTargets []PAMDatabaseTarget
	SSHTargets      []PAMSSHTarget
}

// PAMDatabaseTarget is a provider-backed database target: a PostgreSQL target
// (the PostgresTargets list) or one of the types served only through an
// access gateway. ProviderID names a dynamic-secret provider of the type's
// kind; its administrator credential stays a protected reference there.
type PAMDatabaseTarget struct {
	TargetType     string
	TenantID       string
	ID             string
	ProviderID     string
	AllowedRoles   []string
	GatewayAgentID string
	GatewayAddress string
	// AccountSecret (A261) names the application secret holding the vaulted
	// account the target's sessions sign in as through its gateway.
	AccountSecret string
	// Web (A273) is a web console target's route.
	Web *accessweb.Route
}

type PAMPostgresTarget struct {
	TenantID string
	ID       string
	// ProviderID references a tenant-bound PostgreSQL dynamic-secret provider.
	// Its admin DSN remains a protected file:/secret:// reference in that provider.
	ProviderID   string
	AllowedRoles []string
	// GatewayAgentID and GatewayAddress (A254) bind the target to the gateway
	// that serves it: a session to it is delivered through that gateway only.
	GatewayAgentID, GatewayAddress string
}

type PAMSSHTarget struct {
	TenantID   string
	ID         string
	Host       string
	Port       int
	Principals []string
	// GatewayAgentID and GatewayAddress (A254), as for PostgreSQL targets;
	// HostKeyFingerprints pin the host keys the gateway accepts from it.
	GatewayAgentID, GatewayAddress string
	HostKeyFingerprints            []string
}

type pamService struct {
	windowsDependentInventoryEnabled    bool
	windowsLocalAccountInventoryEnabled bool
	desktopJobEnabled                   bool
	adDesktopJobEnabled                 bool
	netDeviceJobEnabled                 bool
	webJobEnabled                       bool
	commandRuleJobKinds                 map[string]bool
	store                               *store.Store
	log                                 *events.Log
	projector                           *projections.Projector
	audit                               auditsink.Auditor
	attestors                           []attest.Attestor
	databases                           map[pamDatabaseID]*pamDatabaseTarget
	providers                           DynamicSecretProviderRegistry
	kek                                 seal.KeyWrapper
	outbox                              *orchestrator.Outbox
	wakeOutbox                          func()
	tenantCrypto                        tenantseal.Access
	sshTargets                          map[pamTargetID]PAMSSHTarget
	sshCA                               *sshca.CA
	sshProtocol                         *sshProtocol
	defaultTTL                          time.Duration
	maxTTL                              time.Duration
	expiryInterval                      time.Duration
	clock                               func() time.Time
	orch                                *orchestrator.Orchestrator
	approvalTTL                         time.Duration
	requiredApprovals                   int
	targetDeps                          pamDeps
	// agentCAPEM returns the agent CA PEM a client verifies a gateway's
	// certificate against (A254); nil when no agent channel is served.
	agentCAPEM func() []byte
	// recordings stores gateway session recordings (A255); nil when the
	// deployment has no object store, tenant sealing or audit signing key.
	// recordingRetention deletes sealed ones past it (zero keeps them).
	recordings         *pamRecordings
	recordingRetention time.Duration
	// signInRetention is how long recorded sign-ins are kept (A274).
	signInRetention time.Duration
	// unusedAfter is how long a brokered account may go unused before it
	// is flagged (A276); lastFlagScan is when the worker last scanned.
	unusedAfter  time.Duration
	lastFlagScan time.Time
	// certificationInterval starts a certification campaign of brokered
	// accounts and approver lists this often (A276; zero never), assigned to
	// certificationReviewer when it is set; auditSigner signs completed
	// campaigns' results.
	certificationInterval  time.Duration
	certificationReviewer  string
	lastCertificationCheck time.Time
	auditSigner            *jose.SigningKey
	// healthInterval spaces each brokered account's credential sign-in
	// checks, and health is their schedule (A258).
	healthInterval time.Duration
	health         *pamHealth
	// browser holds browser sessions' tickets and terminals (A259).
	browser *pamBrowser
	// discovery marks the privileged account discovery sources being
	// scanned (A260).
	// secretReader reads a vaulted target's account secret (A261).
	secretReader func(ctx context.Context, tenantID, name string) ([]byte, int, error)
	// rotation retires a check-out's revealed credential (A261 part 2).
	rotation pamAccountRotation
	// Fault injection for the gap after signing and before the session event.
	// Production leaves this nil; a served test forces the crash edge.
	afterAutoApprovalDecision func() error
	afterSSHSign              func([]byte, uint64) error
}

type pamDatabaseTarget struct {
	cfg              PAMDatabaseTarget
	roles            map[string]struct{}
	providerRevision string
}

// pamDatabaseID names a database target: ids are tenant-local and per type.
type pamDatabaseID struct {
	tenantID, targetType, id string
}

// digestConfig is the target's configuration as its approval digest binds
// it. A PostgreSQL target keeps the form it had before the other database
// types, so an approval in flight across an upgrade still matches.
func (t *pamDatabaseTarget) digestConfig() any {
	cfg := t.cfg
	cfg.AllowedRoles = append([]string(nil), cfg.AllowedRoles...)
	sort.Strings(cfg.AllowedRoles)
	if cfg.TargetType == pamTargetPostgres {
		return PAMPostgresTarget{TenantID: cfg.TenantID, ID: cfg.ID, ProviderID: cfg.ProviderID, AllowedRoles: cfg.AllowedRoles,
			GatewayAgentID: cfg.GatewayAgentID, GatewayAddress: cfg.GatewayAddress}
	}
	return cfg
}

// Target names are tenant-local. In particular, a matching ID in a different
// tenant must never select an administrator DSN or a trusted SSH principal set.
type pamTargetID struct {
	tenantID string
	id       string
}

type pamDeps struct {
	DesktopJobEnabled                   bool
	ADDesktopJobEnabled                 bool
	NetDeviceJobEnabled                 bool
	WebJobEnabled                       bool
	WindowsDependentInventoryEnabled    bool
	WindowsLocalAccountInventoryEnabled bool
	CommandRuleJobKinds                 map[string]bool
	Config                              PAMConfig
	Store                               *store.Store
	Log                                 *events.Log
	SSHCA                               *sshca.CA
	SSHProtocol                         *sshProtocol
	Audit                               auditsink.Auditor
	Clock                               func() time.Time
	Providers                           DynamicSecretProviderRegistry
	KEK                                 seal.KeyWrapper
	Outbox                              *orchestrator.Outbox
	WakeOutbox                          func()
	TenantCrypto                        tenantseal.Access
	Orch                                *orchestrator.Orchestrator
	// AgentCAPEM is the agent CA a client verifies a gateway against (A254).
	AgentCAPEM func() []byte
	// RecordingObjects and RecordingSigner store and sign gateway session
	// recordings (A255); either unset leaves sessions unrecorded.
	RecordingObjects objectstore.Store
	RecordingSigner  *jose.SigningKey
	// AuditSigner signs completed certification campaigns' results (A276).
	AuditSigner *jose.SigningKey
	// SecretReader reads an application secret's current value: a vaulted
	// target's account (A261). Nil when the secrets API is not served.
	SecretReader func(ctx context.Context, tenantID, name string) ([]byte, int, error)
	// AccountRotation queues the static rotation that retires a check-out's
	// revealed credential (A261 part 2). Unset when the secrets API is not
	// served.
	AccountRotation pamAccountRotation
}

func newPAMService(d pamDeps) (*pamService, error) {
	cfg := d.Config
	if !cfg.Enabled {
		return nil, nil
	}
	if d.Store == nil || d.Log == nil || d.Orch == nil {
		return nil, errors.New("server: PAM requires store, event log, and approval orchestrator")
	}
	defaultTTL := cfg.DefaultTTL
	if defaultTTL <= 0 {
		defaultTTL = defaultPAMTTL
	}
	maxTTL := cfg.MaxTTL
	if maxTTL <= 0 {
		maxTTL = defaultPAMMaxTTL
	}
	if defaultTTL > maxTTL {
		defaultTTL = maxTTL
	}
	expiryInterval := cfg.ExpiryInterval
	if expiryInterval <= 0 {
		expiryInterval = defaultPAMExpiryInterval
	}
	approvalTTL := cfg.ApprovalTTL
	if approvalTTL <= 0 {
		approvalTTL = defaultPAMApprovalTTL
	}
	requiredApprovals := cfg.RequiredApprovals
	if requiredApprovals <= 0 {
		requiredApprovals = 2
	}
	clock := d.Clock
	if clock == nil {
		clock = time.Now
	}
	audit := d.Audit
	if audit == nil {
		audit = auditsink.Nop{}
	}
	for _, a := range cfg.Attestors {
		if a == nil || strings.TrimSpace(a.Method()) == "" {
			return nil, errors.New("server: PAM attestor has empty method")
		}
	}
	databaseTargets, err := buildPAMDatabaseTargets(d)
	if err != nil {
		return nil, err
	}
	sshTargets, err := buildPAMSSHTargets(d)
	if err != nil {
		return nil, err
	}
	var recordings *pamRecordings
	if d.RecordingObjects != nil && d.RecordingSigner != nil && (d.TenantCrypto != nil || d.KEK != nil) {
		recordings = &pamRecordings{objects: d.RecordingObjects, access: d.TenantCrypto, legacy: d.KEK, signer: d.RecordingSigner}
	}
	healthInterval := cfg.HealthInterval
	if healthInterval <= 0 {
		healthInterval = time.Hour
	}
	health, err := newPAMHealth()
	if err != nil {
		return nil, err
	}
	return &pamService{desktopJobEnabled: d.DesktopJobEnabled, adDesktopJobEnabled: d.ADDesktopJobEnabled, netDeviceJobEnabled: d.NetDeviceJobEnabled, webJobEnabled: d.WebJobEnabled,
		commandRuleJobKinds:                 d.CommandRuleJobKinds,
		windowsDependentInventoryEnabled:    d.WindowsDependentInventoryEnabled,
		windowsLocalAccountInventoryEnabled: d.WindowsLocalAccountInventoryEnabled,
		browser:                             newPAMBrowser(),
		recordings:                          recordings, recordingRetention: cfg.RecordingRetention, signInRetention: signInRetentionOrDefault(cfg.SignInRetention), unusedAfter: unusedAfterOrDefault(cfg.UnusedAfter), certificationInterval: cfg.CertificationInterval, certificationReviewer: cfg.CertificationReviewer, auditSigner: d.AuditSigner, healthInterval: healthInterval, health: health,
		store: d.Store, log: d.Log, projector: projections.New(d.Store), audit: audit,
		attestors: cfg.Attestors, databases: databaseTargets,
		providers: d.Providers, kek: d.KEK, outbox: d.Outbox, wakeOutbox: d.WakeOutbox, tenantCrypto: d.TenantCrypto,
		sshTargets: sshTargets, sshCA: d.SSHCA, sshProtocol: d.SSHProtocol, defaultTTL: defaultTTL,
		maxTTL: maxTTL, expiryInterval: expiryInterval, clock: clock,
		orch: d.Orch, approvalTTL: approvalTTL, requiredApprovals: requiredApprovals,
		targetDeps: d, agentCAPEM: d.AgentCAPEM, secretReader: d.SecretReader, rotation: d.AccountRotation,
	}, nil
}

// buildPAMDatabaseTargets checks every configured database target against
// its tenant's providers: a provider of the type's kind that enables each
// allowed role. A PostgreSQL target's roles are the provider's readonly and
// writer; every other type must name its gateway.
func buildPAMDatabaseTargets(d pamDeps) (map[pamDatabaseID]*pamDatabaseTarget, error) {
	cfg := d.Config
	all := make([]PAMDatabaseTarget, 0, len(cfg.PostgresTargets)+len(cfg.DatabaseTargets))
	for _, t := range cfg.PostgresTargets {
		all = append(all, PAMDatabaseTarget{TargetType: pamTargetPostgres, TenantID: t.TenantID, ID: t.ID, ProviderID: t.ProviderID,
			AllowedRoles: t.AllowedRoles, GatewayAgentID: t.GatewayAgentID, GatewayAddress: t.GatewayAddress})
	}
	all = append(all, cfg.DatabaseTargets...)
	targets := make(map[pamDatabaseID]*pamDatabaseTarget, len(all))
	for _, target := range all {
		_, known := pamDatabaseProviderTypes[target.TargetType]
		if !known {
			return nil, fmt.Errorf("server: PAM database target type %q is not one of %s", target.TargetType, pamTargetTypesText())
		}
		kind := target.TargetType
		if _, err := uuid.Parse(target.TenantID); err != nil {
			return nil, fmt.Errorf("server: PAM %s target tenant_id must be a UUID", kind)
		}
		target.ID = strings.TrimSpace(target.ID)
		if target.ID == "" {
			return nil, fmt.Errorf("server: PAM %s target id is required", kind)
		}
		key := pamDatabaseID{target.TenantID, target.TargetType, target.ID}
		if _, exists := targets[key]; exists {
			return nil, fmt.Errorf("server: duplicate PAM %s target %q in tenant %q", kind, target.ID, target.TenantID)
		}
		if len(target.AllowedRoles) == 0 {
			return nil, fmt.Errorf("server: PAM %s target %q requires allowed roles", kind, target.ID)
		}
		if target.TargetType != pamTargetPostgres && (target.GatewayAgentID == "" || target.GatewayAddress == "") {
			return nil, fmt.Errorf("server: PAM %s target %q is served only through an access gateway: name its gateway_agent_id and gateway_address", kind, target.ID)
		}
		if target.TargetType == pamTargetRDP && target.AccountSecret == "" {
			return nil, fmt.Errorf("server: desktop target %q requires a vaulted account_secret", target.ID)
		}
		if target.TargetType == pamTargetNetDevice && target.AccountSecret == "" {
			return nil, fmt.Errorf("server: network device target %q requires a vaulted account_secret", target.ID)
		}
		if target.Web != nil && target.TargetType != pamTargetWebConsole {
			return nil, fmt.Errorf("server: PAM %s target %q has a web console route", kind, target.ID)
		}
		if target.AccountSecret != "" {
			// A261: a vaulted account signs in only through the gateway, and
			// its one role is the secret's: the static rotation keeping it
			// current runs as that role.
			if target.TargetType != pamTargetPostgres && target.TargetType != pamTargetMySQL && target.TargetType != pamTargetRDP && target.TargetType != pamTargetNetDevice && target.TargetType != pamTargetWebConsole {
				return nil, fmt.Errorf("server: PAM %s target %q cannot be vaulted: vaulted accounts are PostgreSQL, MySQL, remote desktop, network devices or web consoles", kind, target.ID)
			}
			if target.GatewayAgentID == "" || target.GatewayAddress == "" {
				return nil, fmt.Errorf("server: vaulted PAM target %q is served only through an access gateway: name its gateway_agent_id and gateway_address", target.ID)
			}
			if len(target.AllowedRoles) != 1 || target.AllowedRoles[0] != target.AccountSecret {
				return nil, fmt.Errorf("server: vaulted PAM target %q allows exactly one role, its account secret %q", target.ID, target.AccountSecret)
			}
		}
		roles := make(map[string]struct{}, len(target.AllowedRoles))
		for _, role := range target.AllowedRoles {
			if target.TargetType == pamTargetPostgres && target.AccountSecret == "" && role != "readonly" && role != "writer" {
				return nil, fmt.Errorf("server: PAM postgres target %q has unsupported role %q", target.ID, role)
			}
			if strings.TrimSpace(role) == "" {
				return nil, fmt.Errorf("server: PAM %s target %q has an empty role", kind, target.ID)
			}
			if target.TargetType == pamTargetAWSConsole && (len(role) > 128 || strings.ContainsAny(role, "\r\n\x00")) {
				return nil, fmt.Errorf("server: console target %q role label must be bounded public text", target.ID)
			}

			if _, exists := roles[role]; exists {
				return nil, fmt.Errorf("server: PAM %s target %q repeats role %q", kind, target.ID, role)
			}
			roles[role] = struct{}{}
		}
		if target.TargetType == pamTargetWebConsole {
			// A273: a web console's vaulted account and the console's own
			// route; no provider rotates it, the gateway only signs in with it.
			if target.AccountSecret == "" || target.ProviderID != "" || target.Web == nil {
				return nil, fmt.Errorf("server: web console target %q names its vaulted account_secret and its route (web), and no provider", target.ID)
			}
			if err := target.Web.Validate(cfg.WebConsoleAllowLoopback); err != nil {
				return nil, fmt.Errorf("server: web console target %q: %v", target.ID, err)
			}
			targets[key] = &pamDatabaseTarget{cfg: target, roles: roles}
			continue
		}
		if target.ProviderID == "" || d.KEK == nil || d.Outbox == nil || d.WakeOutbox == nil {
			return nil, fmt.Errorf("server: PAM %s target %q requires a durable provider and its outbox dependencies", kind, target.ID)
		}
		var matched bool
		var providerRevision string
		for _, provider := range d.Providers.ForTenant(target.TenantID) {
			if provider == nil || provider.Name() != target.ProviderID {
				continue
			}
			profile, ok := provider.(interface {
				DynamicSecretProviderType() string
				DynamicSecretAllowedRoles() []string
				DynamicSecretConfigurationRevision() string
			})
			if !ok || !pamProviderMatches(target.TargetType, profile.DynamicSecretProviderType()) {
				return nil, fmt.Errorf("server: PAM target %q provider must be %s", target.ID, pamDatabaseKinds[target.TargetType])
			}
			if target.TargetType == pamTargetRDP {
				source, ok := provider.(interface {
					DynamicSecretGatewayDesktop(string) (accessdesktop.Binding, error)
				})
				if !ok {
					return nil, fmt.Errorf("server: desktop target %q provider has no reviewed route", target.ID)
				}
				binding, err := source.DynamicSecretGatewayDesktop(target.AllowedRoles[0])
				if err != nil || binding.Validate() != nil {
					return nil, fmt.Errorf("server: desktop target %q needs a valid reviewed route", target.ID)
				}
			}
			if target.TargetType == pamTargetNetDevice {
				route, ok := provider.(pamNetDeviceRoute)
				if !ok {
					return nil, fmt.Errorf("server: network device target %q provider has no SSH route", target.ID)
				}
				if _, _, _, err := route.DynamicSecretGatewaySSH(target.AllowedRoles[0]); err != nil {
					return nil, fmt.Errorf("server: network device target %q needs its provider's SSH address and host key pin: %v", target.ID, err)
				}
			}
			if target.TargetType == pamTargetAWS {
				binding, ok := provider.(interface {
					DynamicSecretGatewayAWS() (string, string, error)
				})
				if !ok {
					return nil, fmt.Errorf("server: AWS target %q provider has no gateway signing scope", target.ID)
				}
				service, region, err := binding.DynamicSecretGatewayAWS()
				if err != nil || (service != "s3" && service != "sts") || region == "" {
					return nil, fmt.Errorf("server: AWS target %q provider needs a configured gateway endpoint/service/region", target.ID)
				}
			}
			if target.TargetType == pamTargetGCP || target.TargetType == pamTargetAzure {
				binding, ok := provider.(interface {
					DynamicSecretGatewayOAuth() (string, []string, string, error)
				})
				if !ok {
					return nil, fmt.Errorf("server: Google Cloud target %q provider has no OAuth binding", target.ID)
				}
				tokenEndpoint, scopes, subject, err := binding.DynamicSecretGatewayOAuth()
				if err != nil || tokenEndpoint == "" || len(scopes) == 0 || subject == "" {
					return nil, fmt.Errorf("server: Google Cloud target %q provider needs a configured gateway origin, token endpoint and scopes", target.ID)
				}
			}

			if target.TargetType == pamTargetAzure {
				binding, ok := provider.(interface{ DynamicSecretGatewayAzureTenant() string })
				if !ok || binding.DynamicSecretGatewayAzureTenant() == "" {
					return nil, fmt.Errorf("server: Azure target %q needs one fixed tenant", target.ID)
				}
			}

			if target.TargetType == pamTargetAWSConsole {
				providerBinding, ok := provider.(interface {
					DynamicSecretGatewayConsole() (accessconsole.Binding, error)
				})
				if !ok {
					return nil, fmt.Errorf("server: console target %q provider has no console binding", target.ID)
				}
				binding, err := providerBinding.DynamicSecretGatewayConsole()
				if err != nil || binding.Validate(true) != nil {
					return nil, fmt.Errorf("server: console target %q needs a valid federation endpoint and destination", target.ID)
				}
			}

			providerRevision = profile.DynamicSecretConfigurationRevision()
			if providerRevision == "" {
				return nil, fmt.Errorf("server: PAM target %q provider has no configuration revision", target.ID)
			}
			providerRoles := make(map[string]bool)
			for _, role := range profile.DynamicSecretAllowedRoles() {
				providerRoles[role] = true
			}
			for role := range roles {
				if !providerRoles[role] {
					return nil, fmt.Errorf("server: PAM target %q role %q is not enabled on its provider", target.ID, role)
				}
			}
			if target.AccountSecret != "" {
				static, ok := provider.(dynsecret.StaticRotationProvider)
				if !ok || !static.AllowsStaticRotation(target.AccountSecret) {
					return nil, fmt.Errorf("server: vaulted PAM target %q: provider %q does not rotate %q as a static credential", target.ID,
						target.ProviderID, target.AccountSecret)
				}
			}
			matched = true
			break
		}
		if !matched {
			return nil, fmt.Errorf("server: PAM target %q provider %q is not configured for its tenant", target.ID, target.ProviderID)
		}
		targets[key] = &pamDatabaseTarget{cfg: target, roles: roles, providerRevision: providerRevision}
	}
	return targets, nil
}

func buildPAMSSHTargets(d pamDeps) (map[pamTargetID]PAMSSHTarget, error) {
	cfg := d.Config
	sshTargets := make(map[pamTargetID]PAMSSHTarget, len(cfg.SSHTargets))
	for _, target := range cfg.SSHTargets {
		if _, err := uuid.Parse(target.TenantID); err != nil {
			return nil, errors.New("server: PAM SSH target tenant_id must be a UUID")
		}
		target.ID = strings.TrimSpace(target.ID)
		if target.ID == "" {
			return nil, errors.New("server: PAM SSH target id is required")
		}
		key := pamTargetID{target.TenantID, target.ID}
		if _, exists := sshTargets[key]; exists {
			return nil, fmt.Errorf("server: duplicate PAM SSH target %q in tenant %q", target.ID, target.TenantID)
		}
		if strings.TrimSpace(target.Host) == "" || target.Port < 1 || target.Port > 65535 {
			return nil, fmt.Errorf("server: PAM SSH target %q requires a host and TCP port", target.ID)
		}
		if len(target.Principals) == 0 {
			return nil, fmt.Errorf("server: PAM SSH target %q requires explicit principals", target.ID)
		}
		for _, principal := range target.Principals {
			if strings.TrimSpace(principal) == "" || principal == "*" {
				return nil, fmt.Errorf("server: PAM SSH target %q has an invalid principal", target.ID)
			}
		}
		if d.SSHCA == nil {
			return nil, errors.New("server: PAM SSH targets require the served SSH CA")
		}
		if d.SSHProtocol == nil || target.TenantID != d.SSHProtocol.tenantID {
			return nil, fmt.Errorf("server: PAM SSH target %q requires its tenant-bound served KRL", target.ID)
		}
		if err := validateSSHGatewayPins(target.GatewayAgentID, target.HostKeyFingerprints); err != nil {
			return nil, fmt.Errorf("server: PAM SSH target %q: %v", target.ID, err)
		}
		sshTargets[key] = target
	}
	return sshTargets, nil
}

func (s *Server) OpenPAMSession(ctx context.Context, tenantID, idempotencyKey, requester string, req api.PAMSessionRequest) (api.PAMSession, error) {
	if s.pam == nil {
		return api.PAMSession{}, api.ErrPAMUnavailable
	}
	return s.pam.OpenPAMSession(ctx, tenantID, idempotencyKey, requester, req)
}

func (s *Server) RequestPAMSession(ctx context.Context, tenantID, requester string, req api.PAMSessionRequest) (api.PAMApprovalRequest, error) {
	if s.pam == nil {
		return api.PAMApprovalRequest{}, api.ErrPAMUnavailable
	}
	return s.pam.RequestPAMSession(ctx, tenantID, requester, req)
}

func (s *Server) GetPAMRequestProgress(ctx context.Context, tenantID, requester, approvalID string) (api.PAMRequestProgress, error) {
	if s.pam == nil {
		return api.PAMRequestProgress{}, api.ErrPAMUnavailable
	}
	return s.pam.GetPAMRequestProgress(ctx, tenantID, requester, approvalID)
}

func (s *pamService) GetPAMRequestProgress(ctx context.Context, tenantID, requester, approvalID string) (api.PAMRequestProgress, error) {
	if _, err := uuid.Parse(approvalID); err != nil || requester == "" {
		return api.PAMRequestProgress{}, store.ErrApprovalRequestNotFound
	}
	row, err := s.store.GetOperationApproval(ctx, tenantID, approvalID)
	if err != nil {
		return api.PAMRequestProgress{}, err
	}
	if row.ResourceKind != "pam" || row.Action != "activate" || row.Requester != requester || !strings.HasPrefix(row.ResourceID, "pam:") {
		return api.PAMRequestProgress{}, store.ErrApprovalRequestNotFound
	}
	status := row.Status
	if (status == store.ApprovalStatusPending || status == store.ApprovalStatusApproved) && !time.Now().Before(row.ExpiresAt) {
		status = store.ApprovalStatusExpired
	}
	return api.PAMRequestProgress{
		RequestID: strings.TrimPrefix(row.ResourceID, "pam:"), ApprovalRequestID: row.ID,
		IntentDigest: row.IntentDigest, Status: status,
		ApprovalCount: row.ApprovalCount, RequiredApprovals: row.RequiredApprovals,
		ExpiresAt: row.ExpiresAt,
	}, nil
}

// RequestPAMSession records only a reviewable intent. It performs no target
// call, credential issuance, signer operation, or session-state transition.
func (s *pamService) RequestPAMSession(ctx context.Context, tenantID, requester string, req api.PAMSessionRequest) (api.PAMApprovalRequest, error) {
	originalReason := strings.TrimSpace(req.Reason)
	if _, err := uuid.Parse(req.RequestID); err != nil {
		return api.PAMApprovalRequest{}, fmt.Errorf("%w: request_id must be a UUID", api.ErrPAMInvalid)
	}
	req, requiredApprovals, templateRefs, err := s.withTemplate(ctx, tenantID, req)
	if err != nil {
		return api.PAMApprovalRequest{}, err
	}
	if err := s.validate(ctx, tenantID, req.RequestID, requester, req); err != nil {
		return api.PAMApprovalRequest{}, err
	}
	_, att, err := s.verifyAttestation(ctx, tenantID, req)
	if err != nil {
		return api.PAMApprovalRequest{}, err
	}
	if err := s.validateAttestedTarget(ctx, tenantID, req, att); err != nil {
		return api.PAMApprovalRequest{}, err
	}
	commandDigest, err := s.approvalCommandDigest(ctx, tenantID, requester, req, att)
	if err != nil {
		return api.PAMApprovalRequest{}, err
	}
	targetEvidence, err := s.targetReviewEvidence(ctx, tenantID, req, att)
	if err != nil {
		return api.PAMApprovalRequest{}, err
	}
	evidenceRefs := append([]string{
		"pam-command-sha256:" + commandDigest,
		"pam-attestor:" + att.Method,
		"pam-subject:" + att.Subject,
		"pam-ttl-seconds:" + fmt.Sprint(int64(s.ttl(req.TTLSeconds)/time.Second)),
	}, append(targetEvidence, templateRefs...)...)
	approval, err := s.pamEnsureReviewedRequest(ctx, tenantID, orchestrator.OperationApprovalIntent{
		ResourceKind: "pam", ResourceID: "pam:" + req.RequestID,
		ResourceName: req.TargetType + "/" + req.TargetID + ":" + req.Role,
		Action:       "activate", Requester: requester,
		FromState: "attested", ToState: "active", TargetVersion: 0,
		Reason:            req.Reason,
		EvidenceRefs:      evidenceRefs,
		RequiredApprovals: requiredApprovals, TTL: s.approvalTTL,
	}, pamAutoApprovalRequest{Kind: "session", TargetType: req.TargetType, TargetID: req.TargetID, Reason: originalReason, TTLSeconds: int(s.ttl(req.TTLSeconds) / time.Second)}, req.RequestID)
	if err != nil {
		return api.PAMApprovalRequest{}, err
	}
	return api.PAMApprovalRequest{
		RequestID: req.RequestID, ApprovalRequestID: approval.ID,
		IntentDigest: approval.IntentDigest, Status: approval.Status,
		Subject: att.Subject, TargetType: req.TargetType, TargetID: req.TargetID, Role: req.Role,
		ApprovalCount: approval.ApprovalCount, RequiredApprovals: approval.RequiredApprovals,
		ExpiresAt: approval.ExpiresAt,
	}, nil
}

// Reviewers see the operator-configured destination as well as the hash that
// binds it. The administrator DSN remains private in its provider reference.
func (s *pamService) targetReviewEvidence(ctx context.Context, tenantID string, req api.PAMSessionRequest, att attest.Attestation) ([]string, error) {
	switch {
	case isPAMDatabaseType(req.TargetType):
		target, err := s.databaseTarget(ctx, tenantID, req.TargetType, req.TargetID)
		if err != nil {
			return nil, err
		}
		return []string{"pam-" + req.TargetType + "-provider:" + target.cfg.ProviderID}, nil
	case req.TargetType == pamTargetSSH:
		cfg, err := s.sshTarget(ctx, tenantID, req.TargetID)
		if err != nil {
			return nil, err
		}
		principal := req.SSHPrincipal
		if principal == "" {
			principal = att.Subject
		}
		return []string{
			"pam-ssh-host:" + cfg.Host + ":" + fmt.Sprint(cfg.Port),
			"pam-ssh-principal:" + principal,
		}, nil
	default:
		return nil, fmt.Errorf("%w: unknown target type", api.ErrPAMInvalid)
	}
}

func (s *pamService) approvalCommandDigest(ctx context.Context, tenantID, requester string, req api.PAMSessionRequest, att attest.Attestation) (string, error) {
	targetDigest, err := s.targetDigest(ctx, tenantID, req)
	if err != nil {
		return "", err
	}
	policyRefs := req.ResolvedTemplateRefs
	if !req.TemplateResolved {
		var err error
		_, policyRefs, _, err = s.pamRequestTemplate(ctx, tenantID, req.TargetType, req.TargetID, req.TemplateID)
		if err != nil {
			return "", err
		}
	}
	command := struct {
		TenantID, RequestID, Requester, TargetType, TargetID, Role, Reason             string
		Method, PayloadDigest, SSHPublicKeyDigest, SSHPrincipal, Subject, TargetDigest string
		Selectors                                                                      []string
		Claims                                                                         map[string]string
		TTLSeconds                                                                     int64
		PolicyRefs                                                                     []string            `json:",omitempty"`
		CommandPolicy                                                                  *accessrules.Policy `json:",omitempty"`
		WebSignIn                                                                      *accessweb.SignIn   `json:",omitempty"`
	}{
		TenantID: tenantID, RequestID: req.RequestID, Requester: requester,
		TargetType: req.TargetType, TargetID: req.TargetID, Role: req.Role, Reason: req.Reason,
		Method: req.Method, PayloadDigest: crypto.SHA256Hex(req.Payload),
		SSHPublicKeyDigest: crypto.SHA256Hex(req.SSHPublicKey), SSHPrincipal: req.SSHPrincipal,
		Subject: att.Subject, Selectors: att.Selectors, Claims: att.Claims, TargetDigest: targetDigest,
		TTLSeconds: int64(s.ttl(req.TTLSeconds) / time.Second), PolicyRefs: policyRefs, CommandPolicy: req.ResolvedCommandPolicy,
		WebSignIn: req.ResolvedWebSignIn,
	}
	raw, err := json.Marshal(command)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(raw)
	return crypto.SHA256Hex(append([]byte("trstctl:pam-session-request:v1\x00"), raw...)), nil
}

func (s *pamService) validateAttestedTarget(ctx context.Context, tenantID string, req api.PAMSessionRequest, att attest.Attestation) error {
	if req.TargetType != pamTargetSSH {
		return nil
	}
	target, err := s.sshTarget(ctx, tenantID, req.TargetID)
	if err != nil {
		return err
	}
	principal := req.SSHPrincipal
	if principal == "" {
		principal = att.Subject
	}
	if !principalAllowed(target.Principals, principal) {
		return fmt.Errorf("%w: principal %q is not allowed on target %q", api.ErrPAMRejected, principal, req.TargetID)
	}
	return nil
}

func (s *pamService) targetDigest(ctx context.Context, tenantID string, req api.PAMSessionRequest) (string, error) {
	var target any
	switch {
	case isPAMDatabaseType(req.TargetType):
		configured, err := s.databaseTarget(ctx, tenantID, req.TargetType, req.TargetID)
		if err != nil {
			return "", err
		}
		target = struct {
			Config           any
			ProviderRevision string
		}{Config: configured.digestConfig(), ProviderRevision: configured.providerRevision}
	case req.TargetType == pamTargetSSH:
		cfg, err := s.sshTarget(ctx, tenantID, req.TargetID)
		if err != nil {
			return "", err
		}
		cfg.Principals = append([]string(nil), cfg.Principals...)
		sort.Strings(cfg.Principals)
		target = cfg
	default:
		return "", fmt.Errorf("%w: unknown target type", api.ErrPAMInvalid)
	}
	raw, err := json.Marshal(target)
	if err != nil {
		return "", err
	}
	defer secret.Wipe(raw)
	return crypto.SHA256Hex(raw), nil
}

func (s *Server) GetPAMSession(ctx context.Context, tenantID, id string) (api.PAMSession, error) {
	if s.pam == nil {
		return api.PAMSession{}, api.ErrPAMUnavailable
	}
	return s.pam.GetPAMSession(ctx, tenantID, id)
}

func (s *Server) ListPAMSessions(ctx context.Context, tenantID string, limit int, cursor string) ([]api.PAMSession, string, error) {
	if s.pam == nil {
		return nil, "", api.ErrPAMUnavailable
	}
	return s.pam.ListPAMSessions(ctx, tenantID, limit, cursor)
}

func (s *Server) RunPAMSessionExpiry(ctx context.Context) {
	if s.pam == nil {
		<-ctx.Done()
		return
	}
	s.pam.RunExpiry(ctx)
}

func (s *Server) RevokePAMSession(ctx context.Context, tenantID, id, requester, reason, idempotencyKey string) (api.PAMSession, error) {
	if s.pam == nil {
		return api.PAMSession{}, api.ErrPAMUnavailable
	}
	return s.pam.RevokePAMSession(ctx, tenantID, id, requester, reason, idempotencyKey)
}

// agentSessionRevokePages bounds one call's passes over an agent's live
// sessions; each pass ends up to 100.
const agentSessionRevokePages = 10

// RevokeAgentPAMSessions ends every active privileged session an agent
// opened, itself or through an access bundle run that acts as it (A257).
// Q4's one-call revoke of the agent's identity calls it. Each session is
// revoked as an operator's revocation is (a gateway session's connections
// close and its login is revoked), under a key derived from the call's own,
// so a retried call revokes nothing twice.
func (s *Server) RevokeAgentPAMSessions(ctx context.Context, tenantID, agent, actor, reason, idempotencyKey string) ([]api.PAMSession, error) {
	if s.pam == nil {
		return nil, nil
	}
	requesters := []string{agent, orchestrator.BundleRunSubjectPrefix + agent}
	var ended []api.PAMSession
	for range agentSessionRevokePages {
		live, err := s.store.ListLivePAMSessionsRequestedBy(ctx, tenantID, requesters, 100)
		if err != nil || len(live) == 0 {
			return ended, err
		}
		for _, rec := range live {
			key := crypto.SHA256Hex([]byte(idempotencyKey + "\x00" + rec.ID))
			session, err := s.pam.RevokePAMSession(ctx, tenantID, rec.ID, actor, reason, key)
			if errors.Is(err, api.ErrPAMTerminal) {
				continue // it ended on its own meanwhile
			}
			if err != nil {
				return ended, fmt.Errorf("end session %s: %w", rec.ID, err)
			}
			ended = append(ended, session)
		}
	}
	return ended, errors.New("server: the agent has more live sessions than one call ends; retry with the same key")
}

func (s *pamService) RevokePAMSession(ctx context.Context, tenantID, id, requester, reason, idempotencyKey string) (api.PAMSession, error) {
	if _, err := uuid.Parse(id); err != nil {
		return api.PAMSession{}, pgx.ErrNoRows
	}
	rec, err := s.store.GetPAMSession(ctx, tenantID, id)
	if err != nil {
		return api.PAMSession{}, err
	}
	if rec.Status != api.PAMSessionStatusActive && rec.Status != store.PAMSessionStatusRevocationFailed {
		return api.PAMSession{}, api.ErrPAMTerminal
	}
	if requester == "" || strings.TrimSpace(reason) == "" || idempotencyKey == "" ||
		(rec.Status == store.PAMSessionStatusRevocationFailed && idempotencyKey == rec.RevocationIdempotencyKey) {
		return api.PAMSession{}, api.ErrPAMInvalid
	}
	if rec.TargetType == pamTargetSSH && (s.sshProtocol == nil || s.sshProtocol.tenantID != tenantID) {
		return api.PAMSession{}, fmt.Errorf("%w: tenant SSH revocation list is unavailable", api.ErrPAMRejected)
	}
	at := s.clock().UTC()
	if rec.Delivery == "gateway" {
		// A254: new logins through the gateway end first — its next lease
		// extension is refused and it closes the session's connections —
		// while the upstream credential's revocation proceeds as for any
		// session.
		kinds := []string{accessgateway.KindForPolicy(rec.CommandPolicy)}
		if rec.TargetType == pamTargetNetDevice {
			kinds = []string{accessgateway.KindSessionNetDevice, accessgateway.KindSessionNetDeviceRules}
		}
		if rec.TargetType == pamTargetWebConsole {
			kinds = []string{accessgateway.KindSessionWeb}
		}
		if rec.TargetType == pamTargetRDP {
			// Recall by the persisted session key across both native versions. The
			// provider may have changed since review; reconstructing its identity
			// binding here can select the wrong job and leave a live desktop open.
			kinds = []string{accessgateway.KindSessionDesktop, accessgateway.KindSessionADDesktop}
		}
		for _, kind := range kinds {
			if err := s.store.RecallPAMGatewayJob(ctx, tenantID, id, kind, accessgateway.JobKey(id), at); err != nil {
				return api.PAMSession{}, err
			}
		}
	}
	if err := s.appendProject(ctx, tenantID, projections.EventPAMSessionRevocationRequested, projections.PAMSessionRevocationRequested{
		ID: id, RequestedBy: requester, Reason: reason, RequestedAt: at,
		IdempotencyKey: idempotencyKey,
		SSHSerial:      rec.SSHSerial, SSHKeyID: rec.SSHKeyID,
	}); err != nil {
		return api.PAMSession{}, err
	}
	current, err := s.GetPAMSession(ctx, tenantID, id)
	if err != nil {
		return api.PAMSession{}, err
	}
	if (current.Status != store.PAMSessionStatusRevoking && current.Status != store.PAMSessionStatusRevoked) ||
		current.RevocationRequestedBy != requester || current.RevocationReason != reason {
		return api.PAMSession{}, api.ErrPAMTerminal
	}
	return current, nil
}

func (s *pamService) OpenPAMSession(ctx context.Context, tenantID, idempotencyKey, requester string, req api.PAMSessionRequest) (api.PAMSession, error) {
	req, _, _, err := s.withTemplate(ctx, tenantID, req)
	if err != nil {
		return api.PAMSession{}, err
	}
	if err := s.validate(ctx, tenantID, idempotencyKey, requester, req); err != nil {
		return api.PAMSession{}, err
	}
	if _, err := uuid.Parse(req.RequestID); err != nil {
		return api.PAMSession{}, fmt.Errorf("%w: request_id must be a UUID", api.ErrPAMInvalid)
	}
	if _, err := uuid.Parse(req.ApprovalRequestID); err != nil || req.IntentDigest == "" {
		return api.PAMSession{}, fmt.Errorf("%w: an exact approval_request_id and intent_digest are required", api.ErrPAMInvalid)
	}
	// The HTTP result cache is time-bounded, while a PAM session is retained for
	// audit. Once that cache has aged out, the same key must never mint another
	// SSH certificate or reopen a PostgreSQL grant under the old session ID.
	id := uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl-pam-session\x00"+tenantID+"\x00"+idempotencyKey)).String()
	if _, err := s.store.GetPAMSession(ctx, tenantID, id); err == nil {
		return api.PAMSession{}, fmt.Errorf("%w: PAM session already exists for this key", orchestrator.ErrIdempotencyConflict)
	} else if !store.IsNotFound(err) {
		return api.PAMSession{}, err
	}
	verifier, att, err := s.verifyAttestation(ctx, tenantID, req)
	if err != nil {
		return api.PAMSession{}, err
	}
	if err := s.validateAttestedTarget(ctx, tenantID, req, att); err != nil {
		return api.PAMSession{}, err
	}
	if req.TargetType == pamTargetSSH {
		var session api.PAMSession
		acquired, err := s.store.WithPAMSSHActivationFence(ctx, tenantID, id, func() error {
			if _, lookupErr := s.store.GetPAMSSHActivation(ctx, tenantID, id); lookupErr == nil {
				return fmt.Errorf("%w: SSH signing was already attempted for this idempotency key; inspect recovery audit and start a fresh approved request", orchestrator.ErrIdempotencyConflict)
			} else if !store.IsNotFound(lookupErr) {
				return lookupErr
			}
			var openErr error
			session, openErr = s.activatePAMSession(ctx, tenantID, idempotencyKey, requester, id, verifier, att, req)
			return openErr
		})
		if err != nil {
			return api.PAMSession{}, err
		}
		if !acquired {
			return api.PAMSession{}, fmt.Errorf("%w: SSH activation or recovery is in progress; retry the same HTTP request", api.ErrPAMRejected)
		}
		return session, nil
	}
	return s.activatePAMSession(ctx, tenantID, idempotencyKey, requester, id, verifier, att, req)
}

func (s *pamService) activatePAMSession(ctx context.Context, tenantID, idempotencyKey, requester, id string, verifier *attest.Verifier, att attest.Attestation, req api.PAMSessionRequest) (api.PAMSession, error) {
	var now time.Time
	err := s.store.WithPAMCatalogLock(ctx, tenantID, func() error {
		var err error
		req, _, _, err = s.withTemplate(ctx, tenantID, req)
		if err != nil {
			return err
		}
		now, err = s.authorizeActivation(ctx, tenantID, idempotencyKey, requester, id, req, att)
		return err
	})
	if err != nil {
		return api.PAMSession{}, err
	}
	expiresAt := now.Add(s.ttl(req.TTLSeconds))
	if !s.clock().UTC().Before(expiresAt) {
		return api.PAMSession{}, fmt.Errorf("%w: approved PAM activation expired before grant completion", api.ErrPAMRejected)
	}
	if err := verifier.Bind(ctx, att, "pam:"+id); err != nil {
		return api.PAMSession{}, fmt.Errorf("server: bind PAM attestation: %w", err)
	}

	switch {
	case isPAMDatabaseType(req.TargetType):
		return s.openDatabase(ctx, tenantID, idempotencyKey, requester, id, now, expiresAt, att, req)
	case req.TargetType == pamTargetSSH:
		return s.openSSH(ctx, tenantID, idempotencyKey, requester, id, now, expiresAt, att, req)
	default:
		return api.PAMSession{}, fmt.Errorf("%w: unsupported target_type %q", api.ErrPAMInvalid, req.TargetType)
	}
}

// authorizeActivation appends one canonical, non-secret command while the exact
// approval row is locked. Its projection consumes authority in the same SQL
// transaction. A crash after the append can replay that event with the same
// request and key; no target effect is attempted before this step commits.
func (s *pamService) authorizeActivation(ctx context.Context, tenantID, idempotencyKey, requester, sessionID string, req api.PAMSessionRequest, att attest.Attestation) (time.Time, error) {
	approval, err := s.store.GetOperationApproval(ctx, tenantID, req.ApprovalRequestID)
	if err != nil {
		return time.Time{}, err
	}
	if approval.ResourceKind != "pam" || approval.ResourceID != "pam:"+req.RequestID ||
		approval.Action != "activate" || approval.Requester != requester ||
		approval.IntentDigest != req.IntentDigest {
		return time.Time{}, fmt.Errorf("%w: PAM approval does not belong to this requester and session request", api.ErrPAMRejected)
	}
	digest, err := s.approvalCommandDigest(ctx, tenantID, requester, req, att)
	if err != nil {
		return time.Time{}, err
	}
	if !containsExactString(approval.EvidenceRefs, "pam-command-sha256:"+digest) {
		return time.Time{}, fmt.Errorf("%w: PAM command differs from the approved intent", api.ErrPAMRejected)
	}
	use, err := store.OperationApprovalUseFromRequest(approval)
	if err != nil {
		return time.Time{}, err
	}
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("trstctl-pam-activation\x00"+tenantID+"\x00"+req.RequestID)).String()
	payload := projections.PAMSessionActivationRequested{
		ID: sessionID, RequestID: req.RequestID, TargetType: req.TargetType, CommandDigest: digest,
		IdempotencyKey: idempotencyKey, TTLSeconds: int64(s.ttl(req.TTLSeconds) / time.Second),
		Approval: use,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return time.Time{}, err
	}
	canonical, found, err := s.log.EventByID(ctx, eventID)
	if err != nil {
		return time.Time{}, err
	}
	if found && (canonical.Type != projections.EventPAMSessionActivationRequested || canonical.TenantID != tenantID || !bytes.Equal(canonical.Data, data)) {
		return time.Time{}, fmt.Errorf("%w: PAM request_id already belongs to a different activation", orchestrator.ErrIdempotencyConflict)
	}
	if found && req.TargetType == pamTargetSSH {
		return time.Time{}, fmt.Errorf("%w: SSH signing was already attempted for this approval; inspect recovery audit and start a fresh approved request", api.ErrPAMRejected)
	}
	err = s.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if !found {
			if _, err := s.store.ValidateOperationApprovalUseTx(ctx, tx, tenantID, use, s.clock().UTC()); err != nil {
				return err
			}
			candidate := events.Event{
				ID: eventID, Type: projections.EventPAMSessionActivationRequested,
				TenantID: tenantID, Time: s.clock().UTC().Truncate(time.Microsecond), Data: data,
			}
			if actor, ok := events.ActorFromContext(ctx); ok {
				candidate.Actor = &actor
			}
			canonical, err = s.log.Append(ctx, candidate)
			if err != nil {
				return err
			}
			if canonical.Type != candidate.Type || canonical.TenantID != tenantID || !bytes.Equal(canonical.Data, data) {
				return fmt.Errorf("%w: canonical PAM activation differs", orchestrator.ErrIdempotencyConflict)
			}
		}
		return s.projector.ApplyTx(ctx, tx, canonical)
	})
	if err != nil {
		return time.Time{}, err
	}
	return canonical.Time, nil
}

func containsExactString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func (s *pamService) verifyAttestation(ctx context.Context, tenantID string, req api.PAMSessionRequest) (*attest.Verifier, attest.Attestation, error) {
	attestors, err := resolveWorkloadAttestors(ctx, s.store, s.attestors, tenantID, req.Method)
	if err != nil {
		return nil, attest.Attestation{}, fmt.Errorf("server: resolve PAM tenant attester trust: %w", err)
	}
	if len(attestors) == 0 {
		return nil, attest.Attestation{}, fmt.Errorf("%w: tenant has no enabled trust source for method %q", api.ErrPAMRejected, req.Method)
	}
	verifier, err := attest.NewVerifier(attest.Config{
		TenantID:  tenantID,
		Attestors: attestors,
		Audit:     s.audit,
	})
	if err != nil {
		return nil, attest.Attestation{}, fmt.Errorf("%w: verifier is invalid: %v", api.ErrPAMInvalid, err)
	}
	att, err := verifier.Verify(ctx, req.Method, req.Payload)
	if err != nil {
		return nil, attest.Attestation{}, fmt.Errorf("%w: %v", api.ErrPAMRejected, err)
	}
	return verifier, att, nil
}

func (s *pamService) GetPAMSession(ctx context.Context, tenantID, id string) (api.PAMSession, error) {
	rec, err := s.store.GetPAMSession(ctx, tenantID, id)
	if err != nil {
		return api.PAMSession{}, err
	}
	session := pamSessionFromStore(rec)
	if rec.Delivery == "gateway" {
		// A254: how to reach the session's gateway, never its ticket.
		session.Gateway = s.gatewayDeliveryForRead(ctx, tenantID, rec)
	}
	if grant, err := s.store.GetPAMEmergencyGrant(ctx, tenantID, id); err == nil {
		view := emergencyView(grant)
		session.Emergency = &view
	} else if !errors.Is(err, store.ErrPAMEmergencyGrantNotFound) {
		return api.PAMSession{}, err
	}
	return session, nil
}

func (s *pamService) ListPAMSessions(ctx context.Context, tenantID string, limit int, _ string) ([]api.PAMSession, string, error) {
	recs, err := s.store.ListPAMSessions(ctx, tenantID, limit)
	if err != nil {
		return nil, "", err
	}
	out := make([]api.PAMSession, 0, len(recs))
	for _, rec := range recs {
		out = append(out, pamSessionFromStore(rec))
	}
	return out, "", nil
}

func (s *pamService) RunExpiry(ctx context.Context) {
	ticker := time.NewTicker(s.expiryInterval)
	defer ticker.Stop()
	for {
		_ = s.expireOnce(ctx)
		s.reconcileEmergencyNotices(ctx)
		s.sweepBrowser(s.clock())
		s.ensureGatewayJobs(ctx)
		s.sealIdleRecordings(ctx)
		s.deleteExpiredRecordings(ctx)
		s.purgeExpiredSignIns(ctx)
		s.scanAccountFlags(ctx)
		s.certifyPeriodically(ctx)
		s.expireCheckouts(ctx, s.clock().UTC())
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *pamService) expireOnce(ctx context.Context) error {
	first := s.recoverIncompleteSSHActivations(ctx)
	revoking, err := s.store.ListRevokingPAMSessions(ctx, 100)
	if err != nil {
		return errors.Join(first, err)
	}
	for _, rec := range revoking {
		if err := s.revokeSession(ctx, rec); err != nil && first == nil {
			first = err
		}
	}
	due, err := s.store.ListDuePAMSessions(ctx, s.clock().UTC(), 100)
	if err != nil {
		return errors.Join(first, err)
	}
	for _, rec := range due {
		if err := s.expireSession(ctx, rec); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// recoverIncompleteSSHActivations runs after startup and on every expiry tick.
// The per-session PostgreSQL lock distinguishes an active signer call on any
// replica from a process that died after consuming approval. The KRL command is
// durable before the read model claims recovery; failures stay revoking and are
// retried on the next tick.
func (s *pamService) recoverIncompleteSSHActivations(ctx context.Context) error {
	items, err := s.store.ListPendingPAMSSHActivations(ctx, 100)
	if err != nil {
		return err
	}
	var first error
	for _, item := range items {
		acquired, err := s.store.WithPAMSSHActivationFence(ctx, item.TenantID, item.SessionID, func() error {
			// A process may die after the event append but before its SQL
			// projection acknowledgement. Finish that canonical event before
			// deciding an unrecorded signature must be revoked.
			started, found, err := s.log.EventByID(ctx, pamSSHStartedEventID(item.TenantID, item.SessionID))
			if err != nil {
				return err
			}
			if found {
				if started.Type != projections.EventPAMSessionStarted || started.TenantID != item.TenantID {
					return orchestrator.ErrIdempotencyConflict
				}
				if err := s.projector.Apply(ctx, started); err != nil {
					return err
				}
			}
			current, err := s.store.GetPAMSSHActivation(ctx, item.TenantID, item.SessionID)
			if err != nil {
				return err
			}
			if current.Status != "pending" && current.Status != "revoking" {
				return nil
			}
			if s.sshProtocol == nil || s.sshProtocol.tenantID != item.TenantID {
				return fmt.Errorf("server: PAM SSH KRL for tenant %s is unavailable", item.TenantID)
			}
			if current.Status == "pending" {
				if err := s.appendSSHRecoveryEvent(ctx, current, projections.EventPAMSSHSigningRecoveryRequested); err != nil {
					return err
				}
			}
			if err := s.sshProtocol.syncRevocations(ctx, true); err != nil {
				return err
			}
			if !s.sshProtocol.krl.IsRevoked(0, current.KeyID) {
				return errors.New("server: recovered PAM SSH key ID is absent from the served KRL")
			}
			return s.appendSSHRecoveryEvent(ctx, current, projections.EventPAMSSHSigningRecovered)
		})
		if acquired && err != nil && first == nil {
			first = err
		}
		if !acquired {
			continue // another replica still owns the signing attempt
		}
	}
	return first
}

func pamSSHStartedEventID(tenantID, sessionID string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("pam-ssh-session-started\x00"+tenantID+"\x00"+sessionID)).String()
}

func (s *pamService) appendSSHSessionStarted(ctx context.Context, tenantID, sessionID string, payload projections.PAMSessionStarted) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	e, err := s.log.Append(ctx, events.Event{
		ID: pamSSHStartedEventID(tenantID, sessionID), Type: projections.EventPAMSessionStarted,
		TenantID: tenantID, Data: data, SchemaVersion: projections.PAMCommandRulesEventSchemaVersion,
	})
	if err != nil {
		return err
	}
	if e.Type != projections.EventPAMSessionStarted || e.TenantID != tenantID || !bytes.Equal(e.Data, data) {
		return orchestrator.ErrIdempotencyConflict
	}
	return s.projector.Apply(ctx, e)
}

func (s *pamService) appendSSHRecoveryEvent(ctx context.Context, item store.PAMSSHActivation, eventType string) error {
	payload := projections.PAMSSHSigningRecoveryRequested{
		ID: item.SessionID, KeyID: item.KeyID,
		Reason: "approved SSH signing ended without a recorded session; deterministic key ID revoked",
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	eventID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(eventType+"\x00"+item.TenantID+"\x00"+item.SessionID)).String()
	e, err := s.log.Append(ctx, events.Event{
		ID: eventID, Type: eventType, TenantID: item.TenantID, Data: data,
	})
	if err != nil {
		return err
	}
	if e.Type != eventType || e.TenantID != item.TenantID || !bytes.Equal(e.Data, data) {
		return orchestrator.ErrIdempotencyConflict
	}
	return s.projector.Apply(ctx, e)
}

func (s *pamService) revokeSession(ctx context.Context, rec store.PAMSession) error {
	switch {
	case isPAMVaultedSession(rec):
		// A261: a vaulted account has no per-session lease to remove; the
		// gateway's recall ends the session's connections.
	case isPAMDatabaseType(rec.TargetType):
		lifecycle, err := s.databaseLifecycle(rec.TenantID)
		if err != nil {
			return err
		}
		lease, err := lifecycle.GetLeaseContext(ctx, rec.BackendRef)
		if err != nil {
			return err
		}
		if lease.RevocationCompletedAt == nil {
			if lease.RevocationStatus == "failed" {
				// A completed bound command means its provider attempt was
				// queued and subsequently failed. A fresh retry key has no
				// completed command yet, so it must be allowed to requeue.
				if rec.RevocationIdempotencyKey == "" {
					return s.pamRevocationFailed(ctx, rec)
				}
				op, lookupErr := s.store.GetDynamicSecretOperationByIdempotencyKey(ctx, rec.TenantID, "pam-revoke:"+rec.RevocationIdempotencyKey)
				if lookupErr != nil && !store.IsNotFound(lookupErr) {
					return lookupErr
				}
				if lookupErr == nil && op.Status == store.DynamicSecretOperationCompleted {
					return s.pamRevocationFailed(ctx, rec)
				}
			}
			if rec.RevocationIdempotencyKey != "" {
				binding := crypto.SHA256Hex([]byte("pam-revoke:v1:" + rec.TenantID + ":" + rec.ID + ":" + rec.RevocationRequestedBy + ":" + rec.RevocationReason))
				_, err = lifecycle.RevokeBound(ctx, rec.BackendRef, "pam-revoke:"+rec.RevocationIdempotencyKey, binding)
			} else {
				// Sessions requested by an older event had no attempt key.
				err = lifecycle.Revoke(ctx, rec.BackendRef)
			}
			if err != nil {
				return err
			}
			return nil
		}
	case rec.TargetType == pamTargetSSH:
		if s.sshProtocol == nil || s.sshProtocol.tenantID != rec.TenantID {
			return fmt.Errorf("server: PAM SSH KRL for tenant %s is unavailable", rec.TenantID)
		}
		if err := s.sshProtocol.syncRevocations(ctx, true); err != nil {
			return err
		}
		if !s.sshProtocol.krl.IsRevoked(rec.SSHSerial, rec.SSHKeyID) {
			return fmt.Errorf("server: PAM SSH revocation absent from served KRL")
		}
	default:
		return fmt.Errorf("server: unknown PAM target type %q", rec.TargetType)
	}
	return s.appendProject(ctx, rec.TenantID, projections.EventPAMSessionRevoked, projections.PAMSessionRevoked{ID: rec.ID, EndedAt: s.clock().UTC()})
}

func (s *pamService) pamRevocationFailed(ctx context.Context, rec store.PAMSession) error {
	return s.appendProject(ctx, rec.TenantID, projections.EventPAMSessionRevocationFailed,
		projections.PAMSessionRevocationFailed{ID: rec.ID, IdempotencyKey: rec.RevocationIdempotencyKey,
			Failure: pamDatabaseKinds[rec.TargetType] + " provider removal failed; repair the target and retry revocation", FailedAt: s.clock().UTC()})
}

func (s *pamService) openDatabase(ctx context.Context, tenantID, idempotencyKey, requester, id string, now, expiresAt time.Time, att attest.Attestation, req api.PAMSessionRequest) (api.PAMSession, error) {
	if req.TargetType == pamTargetRDP {
		if err := s.requireDesktopGateway(ctx, tenantID, req.TargetID); err != nil {
			return api.PAMSession{}, err
		}
	}
	if req.TargetType == pamTargetNetDevice && req.ResolvedCommandPolicy == nil && !s.netDeviceJobEnabled {
		return api.PAMSession{}, fmt.Errorf("%w: enable %s in agent_channel.claimable_job_kinds", api.ErrPAMInvalid, accessgateway.KindSessionNetDevice)
	}
	if req.TargetType == pamTargetWebConsole && !s.webJobEnabled {
		return api.PAMSession{}, fmt.Errorf("%w: enable %s in agent_channel.claimable_job_kinds", api.ErrPAMInvalid, accessgateway.KindSessionWeb)
	}
	if req.TargetType == pamTargetWebConsole && req.ResolvedWebSignIn == nil {
		return api.PAMSession{}, fmt.Errorf("%w: a webconsole session is requested through an access template that sets web_sign_in", api.ErrPAMInvalid)
	}
	target, err := s.databaseTarget(ctx, tenantID, req.TargetType, req.TargetID)
	if err != nil {
		return api.PAMSession{}, err
	}
	return s.openDatabaseProvider(ctx, tenantID, idempotencyKey, requester, id, now, expiresAt, att, req, target)
}

// databaseLifecycle is the tenant's dynamic-secret lifecycle, which issues
// and revokes every database session's per-session login.
func (s *pamService) databaseLifecycle(tenantID string) (*durableDynamicSecretLifecycle, error) {
	return newDurableDynamicSecretLifecycle(tenantID, s.providers.ForTenant(tenantID),
		s.store, s.log, s.kek, s.outbox, s.wakeOutbox, s.tenantCrypto)
}

func (s *pamService) openDatabaseProvider(ctx context.Context, tenantID, idempotencyKey, requester, id string, now, expiresAt time.Time, att attest.Attestation, req api.PAMSessionRequest, target *pamDatabaseTarget) (api.PAMSession, error) {
	if req.TargetType != pamTargetPostgres && target.cfg.GatewayAgentID == "" {
		// Only a PostgreSQL target hands its login to the requester; the
		// target builder already refuses any other type without a gateway.
		return api.PAMSession{}, fmt.Errorf("%w: %s target %q has no access gateway", api.ErrPAMRejected, req.TargetType, req.TargetID)
	}
	if target.cfg.AccountSecret != "" {
		// A261: a vaulted account. The session mints nothing: the gateway
		// signs in as the account with the secret's current value when it
		// claims the session, and nobody else ever receives it.
		return s.startGatewaySession(ctx, tenantID, idempotencyKey, requester, id, now, expiresAt, att, req,
			gatewayStart{backendRef: pamVaultedRef + target.cfg.AccountSecret, agentID: target.cfg.GatewayAgentID,
				address: target.cfg.GatewayAddress, undo: func() {}})
	}
	lifecycle, err := s.databaseLifecycle(tenantID)
	if err != nil {
		return api.PAMSession{}, err
	}
	material, err := json.Marshal(struct {
		Tenant, Requester, Target, Role, Reason, Method, Subject, PayloadDigest string
		TTLSeconds                                                              int64
	}{tenantID, requester, req.TargetID, req.Role, req.Reason, req.Method, att.Subject,
		crypto.SHA256Hex(req.Payload), req.TTLSeconds})
	if err != nil {
		return api.PAMSession{}, err
	}
	binding := crypto.SHA256Hex(material)
	secret.Wipe(material)
	lease, credential, err := lifecycle.IssueBoundNonRenewable(ctx, target.cfg.ProviderID, req.Role,
		expiresAt.Sub(s.clock().UTC()), "pam-"+req.TargetType+":"+idempotencyKey, binding)
	if err != nil {
		return api.PAMSession{}, fmt.Errorf("%w: %s target %q refused session: %v", api.ErrPAMRejected, req.TargetType, req.TargetID, err)
	}
	if target.cfg.GatewayAgentID != "" {
		// A254: the requester receives a ticket for the target's gateway,
		// never this credential; the gateway reopens it from the lease.
		secret.Wipe(credential)
		return s.startGatewaySession(ctx, tenantID, idempotencyKey, requester, id, now, lease.ExpiresAt, att, req,
			gatewayStart{backendRef: lease.ID, agentID: target.cfg.GatewayAgentID, address: target.cfg.GatewayAddress,
				undo: func() { _ = lifecycle.Revoke(context.Background(), lease.ID) }})
	}
	session, payload := s.startedPayload(tenantID, idempotencyKey, requester, id, now, lease.ExpiresAt, att, req, lease.ID, "", 0)
	if err := s.appendProject(ctx, tenantID, projections.EventPAMSessionStarted, payload); err != nil {
		secret.Wipe(credential)
		_ = lifecycle.Revoke(context.Background(), lease.ID)
		return api.PAMSession{}, err
	}
	session.Postgres = api.NewPAMPostgresCredential(lease.BackendRef, credential)
	return session, nil
}

func (s *pamService) openSSH(ctx context.Context, tenantID, idempotencyKey, requester, id string, now, expiresAt time.Time, att attest.Attestation, req api.PAMSessionRequest) (api.PAMSession, error) {
	target, err := s.sshTarget(ctx, tenantID, req.TargetID)
	if err != nil {
		return api.PAMSession{}, err
	}
	principal := req.SSHPrincipal
	if principal == "" {
		principal = att.Subject
	}
	if !principalAllowed(target.Principals, principal) {
		return api.PAMSession{}, fmt.Errorf("%w: principal %q is not allowed on target %q", api.ErrPAMRejected, principal, req.TargetID)
	}
	keyID := "pam:" + id
	if target.GatewayAgentID != "" {
		// A254: nothing is signed now. The gateway certifies its own
		// per-session key when it claims the session; every certificate it
		// gets carries this key ID, so revoking the session revokes them all.
		return s.startGatewaySession(ctx, tenantID, idempotencyKey, requester, id, now, expiresAt, att, req, gatewayStart{
			backendRef: req.TargetID, agentID: target.GatewayAgentID, address: target.GatewayAddress,
			sshKeyID: keyID, sshPrincipal: principal, undo: func() {},
		})
	}
	issued, err := s.sshCA.IssueUserCert(ctx, sshca.Profile{
		Name:           "pam-jit",
		MaxTTL:         s.maxTTL,
		AllowUserCerts: true,
		DefaultExtensions: map[string]string{
			"permit-pty":              "",
			"permit-user-rc":          "",
			"permit-port-forwarding":  "",
			"permit-agent-forwarding": "",
		},
	}, sshca.IssueRequest{
		SubjectPublicKey: req.SSHPublicKey,
		KeyID:            keyID,
		Principals:       []string{principal},
		TTL:              expiresAt.Sub(s.clock().UTC()),
	})
	if err != nil {
		return api.PAMSession{}, fmt.Errorf("%w: ssh target %q refused session: %v", api.ErrPAMRejected, req.TargetID, err)
	}
	if s.afterSSHSign != nil {
		if err := s.afterSSHSign(issued.Certificate, issued.Serial); err != nil {
			secret.Wipe(issued.Certificate)
			return api.PAMSession{}, err
		}
	}
	session, payload := s.startedPayload(tenantID, idempotencyKey, requester, id, now, expiresAt, att, req, req.TargetID, keyID, issued.Serial)
	if err := s.appendSSHSessionStarted(ctx, tenantID, id, payload); err != nil {
		secret.Wipe(issued.Certificate)
		return api.PAMSession{}, err
	}
	activation, err := s.store.GetPAMSSHActivation(ctx, tenantID, id)
	if err != nil || activation.Status != "completed" {
		secret.Wipe(issued.Certificate)
		return api.PAMSession{}, fmt.Errorf("%w: SSH activation was not durably completed", api.ErrPAMRejected)
	}
	session.SSH = api.NewPAMSSHCredential(issued.Certificate, principal, keyID, issued.Serial, issued.ValidBefore)
	return session, nil
}

func (s *pamService) startedPayload(tenantID, idempotencyKey, requester, id string, now, expiresAt time.Time, att attest.Attestation, req api.PAMSessionRequest, backendRef, sshKeyID string, sshSerial uint64) (api.PAMSession, projections.PAMSessionStarted) {
	audit := json.RawMessage(`{}`)
	if data, err := json.Marshal(map[string]any{
		"target_type":  req.TargetType,
		"target_id":    req.TargetID,
		"role":         req.Role,
		"requested_by": requester,
		"subject":      att.Subject,
		"method":       att.Method,
	}); err == nil {
		audit = data
	}
	session := api.PAMSession{
		ID: id, TargetID: req.TargetID, TargetType: req.TargetType, Role: req.Role, CommandPolicy: req.ResolvedCommandPolicy,
		Status: api.PAMSessionStatusActive, Subject: att.Subject, RequestedBy: requester,
		Reason: req.Reason, StartedAt: now, ExpiresAt: expiresAt, Attestation: &att,
		Audit: jsonMap(audit),
	}
	return session, projections.PAMSessionStarted{
		ID: id, TargetType: req.TargetType, TargetID: req.TargetID, Role: req.Role,
		Status: api.PAMSessionStatusActive, Subject: att.Subject, RequestedBy: requester,
		Reason: req.Reason, AttestationID: att.ID, Attestation: &att, BackendRef: backendRef, SSHKeyID: sshKeyID,
		SSHSerial: sshSerial, IdempotencyKey: idempotencyKey, Audit: audit,
		StartedAt: now, ExpiresAt: expiresAt, ApprovalRequestID: req.ApprovalRequestID, CommandPolicy: req.ResolvedCommandPolicy,
		WebSignIn: req.ResolvedWebSignIn,
	}
}

func (s *pamService) expireSession(ctx context.Context, rec store.PAMSession) error {
	switch {
	case isPAMVaultedSession(rec):
		// A261: nothing was minted for a vaulted account's session.
	case isPAMDatabaseType(rec.TargetType):
		lifecycle, err := s.databaseLifecycle(rec.TenantID)
		if err != nil {
			return err
		}
		if err := lifecycle.Revoke(ctx, rec.BackendRef); err != nil {
			return err
		}
		lease, err := lifecycle.GetLeaseContext(ctx, rec.BackendRef)
		if err != nil {
			return err
		}
		if lease.RevocationCompletedAt == nil {
			return nil // outbox has the removal intent; a later tick observes completion
		}
	case rec.TargetType == pamTargetSSH:
		// SSH user certificates auto-expire cryptographically. The read model still
		// records expiry evidence so audit and session lists do not depend on a client
		// attempting to use the cert after its ValidBefore.
	default:
		return fmt.Errorf("server: PAM session %s has unknown target_type %q", rec.ID, rec.TargetType)
	}
	endedAt := s.clock().UTC()
	return s.appendProject(ctx, rec.TenantID, projections.EventPAMSessionExpired, projections.PAMSessionExpired{
		ID: rec.ID, EndedAt: endedAt, Reason: "ttl elapsed",
	})
}

func (s *pamService) appendProject(ctx context.Context, tenantID, eventType string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	version := events.DefaultSchemaVersion
	if eventType == projections.EventPAMTemplateSaved || eventType == projections.EventPAMSessionStarted {
		version = projections.PAMCommandRulesEventSchemaVersion
	}
	e, err := s.log.Append(ctx, events.Event{Type: eventType, TenantID: tenantID, Data: data, SchemaVersion: version})
	if err != nil {
		return err
	}
	return s.projector.Apply(ctx, e)
}

func (s *pamService) validate(ctx context.Context, tenantID, idempotencyKey, requester string, req api.PAMSessionRequest) error {
	if tenantID == "" {
		return fmt.Errorf("%w: tenant id is required", api.ErrPAMInvalid)
	}
	if idempotencyKey == "" {
		return fmt.Errorf("%w: idempotency key is required", api.ErrPAMInvalid)
	}
	if requester == "" {
		return fmt.Errorf("%w: requester is required", api.ErrPAMInvalid)
	}
	if req.TargetType == pamTargetWindowsLocal {
		return fmt.Errorf("%w: a windows_local account has no sessions; request a check-out (POST /api/v1/access/checkouts)", api.ErrPAMInvalid)
	}
	if req.TargetType == pamTargetAccount {
		return fmt.Errorf("%w: an account target has no sessions; request a check-out (POST /api/v1/access/checkouts)", api.ErrPAMInvalid)
	}
	if req.TargetType == pamTargetBreakGlass {
		return fmt.Errorf("%w: a break-glass account has no sessions; it is released only through emergency access (POST /api/v1/access/emergency-checkouts)", api.ErrPAMInvalid)
	}
	if !isPAMDatabaseType(req.TargetType) && req.TargetType != pamTargetSSH {
		return fmt.Errorf("%w: target_type must be one of %s", api.ErrPAMInvalid, pamTargetTypesText())
	}
	if req.TargetID == "" {
		return fmt.Errorf("%w: target_id is required", api.ErrPAMInvalid)
	}
	if req.Role == "" {
		return fmt.Errorf("%w: role is required", api.ErrPAMInvalid)
	}
	if req.TTLSeconds < 0 || req.TTLSeconds > int64(s.maxTTL/time.Second) {
		return fmt.Errorf("%w: ttl_seconds must be between 0 and %d", api.ErrPAMInvalid, int64(s.maxTTL/time.Second))
	}
	if req.Method == "" {
		return fmt.Errorf("%w: method is required", api.ErrPAMInvalid)
	}
	if len(req.Payload) == 0 {
		return fmt.Errorf("%w: attestation payload is required", api.ErrPAMInvalid)
	}
	switch {
	case isPAMDatabaseType(req.TargetType):
		target, err := s.databaseTarget(ctx, tenantID, req.TargetType, req.TargetID)
		if err != nil {
			return err
		}
		if _, allowed := target.roles[req.Role]; !allowed {
			return fmt.Errorf("%w: role %q is not allowed on %s target %q", api.ErrPAMInvalid, req.Role, req.TargetType, req.TargetID)
		}
	case req.TargetType == pamTargetSSH:
		target, err := s.sshTarget(ctx, tenantID, req.TargetID)
		if err != nil {
			return err
		}
		switch {
		case target.GatewayAgentID != "" && len(req.SSHPublicKey) != 0:
			// A254: the gateway certifies a key of its own for the session;
			// the requester holds no SSH credential at all.
			return fmt.Errorf("%w: ssh target %q is reached through its access gateway; omit ssh_public_key", api.ErrPAMInvalid, req.TargetID)
		case target.GatewayAgentID == "" && len(req.SSHPublicKey) == 0:
			return fmt.Errorf("%w: ssh_public_key is required for ssh targets", api.ErrPAMInvalid)
		}
		if req.Role != "user" {
			return fmt.Errorf("%w: SSH target role must be user", api.ErrPAMInvalid)
		}
	}
	return nil
}

func (s *pamService) ttl(seconds int64) time.Duration {
	if seconds <= 0 {
		return s.defaultTTL
	}
	ttl := time.Duration(seconds) * time.Second
	if ttl <= 0 {
		return s.defaultTTL
	}
	if ttl > s.maxTTL {
		return s.maxTTL
	}
	return ttl
}

func principalAllowed(allowed []string, principal string) bool {
	if principal == "" {
		return false
	}
	for _, p := range allowed {
		if p == principal {
			return true
		}
	}
	return false
}

func pamSessionFromStore(rec store.PAMSession) api.PAMSession {
	var verified *attest.Attestation
	if len(rec.Attestation) != 0 {
		var candidate attest.Attestation
		if err := json.Unmarshal(rec.Attestation, &candidate); err == nil &&
			candidate.ID == rec.AttestationID && candidate.Subject == rec.Subject &&
			candidate.Method != "" && !candidate.VerifiedAt.IsZero() {
			verified = &candidate
		}
	}
	return api.PAMSession{
		ID: rec.ID, TargetID: rec.TargetID, TargetType: rec.TargetType, Role: rec.Role, CommandPolicy: rec.CommandPolicy,
		Status: rec.Status, Subject: rec.Subject, RequestedBy: rec.RequestedBy, Reason: rec.Reason,
		StartedAt: rec.StartedAt, ExpiresAt: rec.ExpiresAt, EndedAt: rec.EndedAt,
		RevocationRequestedBy: rec.RevocationRequestedBy, RevocationReason: rec.RevocationReason,
		RevocationRequestedAt: rec.RevocationRequestedAt,
		RevocationFailure:     rec.RevocationFailure, RevocationFailedAt: rec.RevocationFailedAt,
		Attestation: verified,
		Audit:       jsonMap(rec.Audit),
		Delivery:    pamDeliveryName(rec.Delivery),
		GatewayEnd:  pamGatewayEnd(rec), UncertainUntil: pamUncertainUntil(rec),
	}
}

// pamGatewayEnd is the gateway's report of a session's end, if it came.
func pamGatewayEnd(rec store.PAMSession) *api.PAMGatewayEnd {
	if rec.GatewayEndedAt == nil {
		return nil
	}
	return &api.PAMGatewayEnd{Ended: rec.GatewayEnded, EndedAt: *rec.GatewayEndedAt}
}

// pamUncertainUntil bounds what is not known about a revoked or terminated
// gateway session whose gateway has not reported its end (A255): it may still
// be serving connections until the session's native deadline, when its
// credential stops working regardless.
func pamUncertainUntil(rec store.PAMSession) *time.Time {
	if rec.Delivery != "gateway" || rec.RevocationRequestedAt == nil || rec.GatewayEndedAt != nil {
		return nil
	}
	deadline := rec.ExpiresAt
	return &deadline
}

// pamDeliveryName reads a session's delivery; sessions projected before A254
// were all direct.
func pamDeliveryName(d string) string {
	if d == "" {
		return "direct"
	}
	return d
}

func jsonMap(raw []byte) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// pamFromConfig maps the operator's secret-free target references onto the
// broker. The provider's protected administrator ref stays in its own config;
// tenant-managed attester trust is resolved per request.
func pamFromConfig(c config.PAM) PAMConfig {
	out := PAMConfig{Enabled: c.Enabled, RequiredApprovals: c.RequiredApprovals}
	if d, err := time.ParseDuration(strings.TrimSpace(c.DefaultTTL)); err == nil {
		out.DefaultTTL = d
	}
	if d, err := time.ParseDuration(strings.TrimSpace(c.MaxTTL)); err == nil {
		out.MaxTTL = d
	}
	if d, err := time.ParseDuration(strings.TrimSpace(c.ExpiryInterval)); err == nil {
		out.ExpiryInterval = d
	}
	if d, err := time.ParseDuration(strings.TrimSpace(c.ApprovalTTL)); err == nil {
		out.ApprovalTTL = d
	}
	if d, err := time.ParseDuration(strings.TrimSpace(c.RecordingRetention)); err == nil {
		out.RecordingRetention = d
	}
	if d, err := time.ParseDuration(strings.TrimSpace(c.SignInRetention)); err == nil {
		out.SignInRetention = d
	}
	if d, err := time.ParseDuration(strings.TrimSpace(c.UnusedAfter)); err == nil {
		out.UnusedAfter = d
	}
	if d, err := time.ParseDuration(strings.TrimSpace(c.CertificationInterval)); err == nil {
		out.CertificationInterval = d
	}
	out.CertificationReviewer = strings.TrimSpace(c.CertificationReviewer)
	if d, err := time.ParseDuration(strings.TrimSpace(c.HealthCheckInterval)); err == nil {
		out.HealthInterval = d
	}
	for _, target := range c.PostgresTargets {
		out.PostgresTargets = append(out.PostgresTargets, PAMPostgresTarget{
			TenantID: target.TenantID, ID: target.ID, ProviderID: target.ProviderID,
			AllowedRoles:   append([]string(nil), target.AllowedRoles...),
			GatewayAgentID: target.GatewayAgentID, GatewayAddress: target.GatewayAddress,
		})
	}
	out.WebConsoleAllowLoopback = c.WebConsoleAllowLoopback
	for _, target := range c.DatabaseTargets {
		out.DatabaseTargets = append(out.DatabaseTargets, PAMDatabaseTarget{
			TargetType: target.TargetType, TenantID: target.TenantID, ID: target.ID, ProviderID: target.ProviderID,
			AllowedRoles:   append([]string(nil), target.AllowedRoles...),
			GatewayAgentID: target.GatewayAgentID, GatewayAddress: target.GatewayAddress,
		})
	}
	for _, target := range c.KubernetesTargets {
		out.DatabaseTargets = append(out.DatabaseTargets, PAMDatabaseTarget{
			TargetType: pamTargetK8s, TenantID: target.TenantID, ID: target.ID, ProviderID: target.ProviderID,
			AllowedRoles:   append([]string(nil), target.AllowedRoles...),
			GatewayAgentID: target.GatewayAgentID, GatewayAddress: target.GatewayAddress,
		})
	}
	for _, target := range c.SSHTargets {
		out.SSHTargets = append(out.SSHTargets, PAMSSHTarget{
			TenantID: target.TenantID, ID: target.ID, Host: target.Host, Port: target.Port,
			Principals:     append([]string(nil), target.Principals...),
			GatewayAgentID: target.GatewayAgentID, GatewayAddress: target.GatewayAddress,
			HostKeyFingerprints: append([]string(nil), target.HostKeyFingerprints...),
		})
	}
	return out
}

func pamProviderMatches(targetType, providerType string) bool {
	if targetType == pamTargetRDP {
		return providerType == "unix" || providerType == "windows" || providerType == "ldap"
	}
	if targetType == pamTargetNetDevice {
		return pamNetDeviceProviderTypes[providerType]
	}
	return pamDatabaseProviderTypes[targetType] == providerType
}

// pamNetDeviceProviderTypes are the providers a network device target's
// vaulted account can come from (A270).
var pamNetDeviceProviderTypes = map[string]bool{"iosxe": true, "junos": true, "eos": true, "fortigate": true, "bigip": true}

// pamNetDeviceRoute is a network device provider's SSH route for a role: the
// device's SSH address, the account the role rotates (the session's
// principal) and the pinned host key.
type pamNetDeviceRoute interface {
	DynamicSecretGatewaySSH(role string) (address, principal string, pins []string, err error)
}
