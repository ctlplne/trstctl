// SPDX-License-Identifier: BUSL-1.1

// Package sourcecatalog is the shared, operator-facing discovery-source
// contract. The API, CLI, console, documentation checks, and QA matrix consume
// this catalog instead of maintaining separate lists of source kinds and fields.
package sourcecatalog

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

const SchemaVersion = 1

type SetupSurface string

const (
	SetupSourceWizard SetupSurface = "source_wizard"
	SetupContextual   SetupSurface = "contextual"
)

type Field struct {
	Path        string `json:"path"`
	Label       string `json:"label"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	SecretRef   bool   `json:"secret_ref,omitempty"`
	Advanced    bool   `json:"advanced,omitempty"`
	Description string `json:"description"`
}

type Provider struct {
	ID                  string   `json:"id"`
	Label               string   `json:"label"`
	LeastPrivilege      string   `json:"least_privilege"`
	PreferredCredential string   `json:"preferred_credential"`
	Fields              []string `json:"fields"`
}

type Capability struct {
	Kind             string       `json:"kind"`
	Label            string       `json:"label"`
	Purpose          string       `json:"purpose"`
	DataHandling     string       `json:"data_handling"`
	Tool             string       `json:"tool"`
	Route            string       `json:"route"`
	SetupSurface     SetupSurface `json:"setup_surface"`
	Permission       string       `json:"permission"`
	Edition          string       `json:"edition"`
	Execution        string       `json:"execution"`
	Configuration    []Field      `json:"configuration"`
	Providers        []Provider   `json:"providers,omitempty"`
	Lifecycle        []string     `json:"lifecycle"`
	ConsoleStages    []string     `json:"console_stages"`
	DocumentationRef string       `json:"documentation_ref"`
}

type Catalog struct {
	SchemaVersion int          `json:"schema_version"`
	Items         []Capability `json:"items"`
}

var standardLifecycle = []string{"not_configured", "available", "queued", "planning", "running", "succeeded", "succeeded_with_warnings", "failed", "blocked"}
var standardStages = []string{"configure", "preview", "execute", "observe", "recover", "prove"}

var items = []Capability{
	{
		Kind: "network", Label: "TLS endpoints", Tool: "Discover", Route: "/discovery?tab=sources&kind=network", SetupSurface: SetupSourceWizard,
		Purpose:      "Find public TLS certificate metadata on explicitly authorized hosts, addresses, and network ranges.",
		DataHandling: "Connects only to the normalized targets in the approved plan, performs a bounded TLS handshake, and stores public certificate metadata. It does not exploit services or collect private keys.",
		Permission:   "discovery:write", Edition: "core", Execution: "network-role relay",
		Configuration: networkFields(), Lifecycle: standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/discovery-and-inventory.md#network-and-ssh-scopes",
	},
	{
		Kind: "ssh", Label: "SSH endpoints", Tool: "Discover", Route: "/discovery?tab=sources&kind=ssh", SetupSurface: SetupSourceWizard,
		Purpose:      "Find public SSH host-key metadata on explicitly authorized machines and network ranges.",
		DataHandling: "Connects only to the normalized targets in the approved plan, reads the bounded SSH identification and host-key exchange, and stores public fingerprints. It never attempts a login.",
		Permission:   "discovery:write", Edition: "core", Execution: "network-role relay",
		Configuration: networkFields(), Lifecycle: standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/discovery-and-inventory.md#network-and-ssh-scopes",
	},
	{Kind: "ssh_trust", Label: "Agentless SSH trust", Tool: "Discover", Route: "/discovery?tab=sources&kind=ssh_trust", SetupSurface: SetupSourceWizard,
		Purpose:      "Read effective SSH trust posture through an explicitly selected network relay and a restricted remote account.",
		DataHandling: "Authenticates only to pinned targets using vaulted PKCS#8 key references. Calls one fixed read-only helper; stores public trust evidence. No host agent is required. Match contexts and per-user keys are not assessed.",
		Permission:   "discovery:write", Edition: "core", Execution: "network-role relay",
		Configuration: []Field{
			field("enabled", "Enable agentless collection", "boolean", true, false, false, "Explicit opt-in; host-agent inventory remains the default."),
			field("segment", "Authorized scope", "segment_ref", true, false, false, "Declared tenant scope containing every target."),
			field("relay_agent_id", "Network relay", "agent_ref", true, false, false, "One enrolled network-role relay with the collector enabled."),
			field("hosts[].address", "SSH targets", "string", true, false, false, "Canonical host:port; at most 100 explicit hosts."),
			field("hosts[].username", "Read-only account", "string", true, false, false, "Non-root forced-command account; no shell, forwarding or writes."),
			field("hosts[].host_key_fingerprint", "Host identity pin", "string", true, false, false, "Exact SHA256 fingerprint from a trusted administrative channel; no TOFU."),
			field("hosts[].credential_ref", "SSH credential reference", "credential_ref", true, true, false, "Vault secret:// reference to a PKCS#8 private key. The value never enters source configuration."),
			field("allow_rfc1918", "Allow approved RFC1918 targets", "boolean", false, false, true, "Private targets must also belong to the declared scope and local relay egress grant."),
			field("allow_loopback", "Allow loopback", "boolean", false, false, true, "Explicit owned local-test override.")},
		Lifecycle: standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/ssh.md#agentless-trust-collection"},

	{
		Kind: "adcs", Label: "Microsoft AD CS", Tool: "Discover", Route: "/discovery?tab=sources&kind=adcs", SetupSurface: SetupSourceWizard,
		Purpose:      "Inventory AD CS authorities, templates, enrollment rights, and exposed enrollment endpoints through a domain-reachable relay.",
		DataHandling: "Performs bounded read-only LDAP, configured endpoint checks and opt-in fixed-path probes from scoped directory hostnames. Passwords are represented only by credential references; response bodies and private keys are never stored.",
		Permission:   "discovery:write", Edition: "core", Execution: "network-role relay",
		Configuration: []Field{
			field("url", "Directory URL", "url", true, false, false, "LDAPS or LDAP endpoint reachable from the selected relay."),
			field("configuration_dn", "Configuration naming context", "string", true, false, false, "The AD Configuration partition to inspect."),
			field("nested_groups_enabled", "Read nested enrollment groups", "boolean", false, false, true, "Opt-in bounded LDAP in-chain reads; needs an explicit upgraded network relay. Full Windows AccessCheck is unassessed."),
			field("membership_domain_dn", "Membership domain naming context", "string", false, false, false, "Required with nested groups: an explicit domain partition, never an inferred forest scope."),
			field("endpoint_probe.enabled", "Probe directory enrollment hostnames", "boolean", false, false, true, "Default-off fixed HTTP/HTTPS Web Enrollment and NDES client paths; needs an upgraded selected network relay."),
			field("endpoint_probe.dns_suffixes", "Allowed endpoint DNS suffixes", "domain_list", false, false, true, "Required with probing: 1..32 explicit DNS suffixes. This grants no private network range."),
			field("bind_dn", "Bind identity", "string", true, false, false, "A least-privilege directory reader."),
			field("password_ref", "Password reference", "credential_ref", true, true, false, "Reference to the bind password; the value is never sent in this configuration."),
			field("relay_agent_id", "Network relay", "agent_ref", false, false, false, "An enrolled network-role agent that can reach the directory."),
			field("enrollment_endpoints", "Enrollment endpoints", "endpoint_list", false, false, true, "Optional bounded checks for enrollment web services."),
			field("allow_private_endpoint", "Allow approved private endpoints", "boolean", false, false, true, "Requires private-egress authorization and explicit CIDRs."),
			field("private_egress_cidrs", "Approved private endpoint CIDRs", "cidr_list", false, false, true, "Private destinations allowed for this source; metadata, loopback, and link-local ranges remain blocked."),
		},
		Lifecycle: standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/discovery-and-inventory.md#ad-cs",
	},
	cloudCertificateCapability(),
	cloudNetworkPathCapability(),
	cloudAccessKeyCapability(),
	cloudMachineEntitlementCapability(),
	gcpMachineIdentityCapability(),
	azureMachineIdentityCapability(),
	cloudKMSKeyCapability(),
	loadBalancerTLSCapability(),
	cloudSecretCapability("cloud_secret", "Cloud secret managers"),
	cloudSecretCapability("secret_store", "Secret stores"),
	{
		Kind: "ct_log", Label: "Certificate Transparency", Tool: "Discover", Route: "/discovery?tab=findings", SetupSurface: SetupContextual,
		Purpose:      "Watch public Certificate Transparency logs for certificates covering approved domains.",
		DataHandling: "Reads public CT entries and stores public certificate metadata and checkpoints.", Permission: "discovery:write", Edition: "core", Execution: "control plane",
		Configuration: []Field{field("watched_domains", "Watched domains", "domain_list", true, false, false, "Domains trstctl is authorized to monitor in public CT logs.")},
		Lifecycle:     standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/discovery-and-inventory.md#certificate-transparency",
	},
	{
		Kind: "drift", Label: "Credential drift", Tool: "Discover", Route: "/discovery?tab=findings", SetupSurface: SetupContextual,
		Purpose:      "Compare current credential observations with the last approved state.",
		DataHandling: "Stores stable non-secret fingerprints and the exact changed metadata; it does not store credential values.", Permission: "discovery:write", Edition: "core", Execution: "control plane",
		Configuration: []Field{field("watched", "Watched credential metadata", "record_list", true, false, false, "Public or non-secret observations to compare across scans.")},
		Lifecycle:     standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/discovery-and-inventory.md#drift",
	},
	structured("api_key", "API keys and tokens", "observations", "Inventory metadata and references for API keys and non-human tokens; raw token values are rejected."),
	structured("nhi_cross_surface", "Cross-system identities", "observations", "Correlate the same non-human identity across identity providers, cloud, SaaS, code, and CI without collecting credential values."),
	oauthGrantCapability(),
	structured("service_account", "Service accounts", "accounts", "Inventory Active Directory and cloud service-account metadata and credential references without collecting passwords or private keys."),
	structured("nhi_behavior", "Identity behavior", "events", "Analyze bounded, sanitized use metadata for machine identities; credential material is rejected."),
	structured("credential_compromise", "Compromise signals", "signals", "Ingest sanitized detector evidence and credential references; stolen credential values are rejected."),
	{
		Kind: "pam_signin", Label: "Privileged account sign-ins", Tool: "Discover", Route: "/discovery?tab=sources&kind=pam_signin", SetupSurface: SetupSourceWizard,
		Purpose:      "Watch the accounts a dynamic-secret provider manages for sign-ins outside trstctl: each sign-in no session, check-out, rotation or health check explains becomes a compromised-credential finding (A274).",
		DataHandling: "Reads sign-in metadata only — the account, when, from where and how — through the provider's administrator connection: a host's sshd journal and auth log or Windows logon events, a database's current sessions. Never a credential or what a session did.",
		Permission:   "discovery:write", Edition: "core", Execution: "control plane",
		Configuration: []Field{
			field("provider_id", "Provider", "string", true, false, false, "A dynamic-secret provider of the tenant whose static accounts are watched (a Linux, Unix or Windows host, PostgreSQL, MySQL or SQL Server)."),
			field("lookback_seconds", "Lookback seconds", "integer", false, false, true, "How far back each run reads (300 to 604800; default an hour). Overlapping runs refresh a finding, never repeat it."),
		},
		Lifecycle: standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/incident-and-jit.md#bypass-detection-a274",
	},
	structured("k8s_ingress_gateway", "Kubernetes TLS", "resources", "Inventory Kubernetes Ingress and Gateway TLS metadata; Secret values and private keys are rejected."),
	{
		Kind: "agent", Label: "Agent inventory", Tool: "Workloads & Machines", Route: "/agents", SetupSurface: SetupContextual,
		Purpose: "Receive signed, tenant-bound inventory from enrolled agents.", DataHandling: "Created by authenticated agent reports. The generic discovery-source API and wizard cannot declare this reserved source kind.",
		Permission: "agents:write", Edition: "core", Execution: "host or network agent", Configuration: []Field{field("agent_id", "Enrolled agent", "agent_ref", true, false, false, "The enrolled agent that signs and reports the observation.")},
		Lifecycle: standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/discovery-and-inventory.md#agent-based-discovery-f3--what-each-host-can-see-from-the-inside",
	},
	{
		Kind: "manual", Label: "Manual evidence import", Tool: "Discover", Route: "/discovery?tab=sources&kind=manual", SetupSurface: SetupContextual,
		Purpose: "Import bounded public credential metadata from an approved offline workflow.", DataHandling: "Accepts metadata and non-secret fingerprints only; inline credentials are rejected.",
		Permission: "discovery:write", Edition: "core", Execution: "control plane", Configuration: []Field{field("findings", "Findings", "record_list", true, false, false, "Bounded public metadata records with provenance and fingerprints.")},
		Lifecycle: standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/discovery-and-inventory.md#manual-import",
	},
}

func networkFields() []Field {
	return []Field{
		field("segment", "Authorized scope", "segment_ref", true, false, false, "A declared tenant scope that defines the scan denominator."),
		field("relay_agent_id", "Network relay", "agent_ref", false, false, false, "Where connections originate. The relay must have the network role."),
		field("targets", "Hosts and addresses", "target_list", false, false, false, "Individual host:port or address:port targets."),
		field("cidrs", "CIDR ranges", "cidr_list", false, false, false, "IPv4 or IPv6 CIDRs crossed with the selected ports."),
		field("ranges", "Explicit IP ranges", "ip_range_list", false, false, false, "Bounded inclusive start-end address ranges crossed with the selected ports."),
		field("ports", "Ports", "port_list", false, false, false, "Individual ports or bounded ranges normalized before the scan is queued."),
		field("exclude_targets", "Excluded hosts and targets", "target_list", false, false, false, "Exact hostnames, addresses, or host:port destinations removed after normalization."),
		field("exclude_cidrs", "Excluded CIDR ranges", "cidr_list", false, false, false, "Address ranges removed after normalization; exclusions always win."),
		field("exclude_ports", "Excluded ports", "port_list", false, false, false, "Ports removed from every normalized target."),
		field("allow_rfc1918", "Allow approved RFC1918 targets", "boolean", false, false, true, "Permits private IPv4 targets already covered by the declared scope."),
		field("allow_loopback", "Allow loopback", "boolean", false, false, true, "Restricted local-testing override; never implied by private-range access."),
	}
}

func cloudCertificateCapability() Capability {
	return Capability{
		Kind: "cloud_certificate", Label: "Cloud certificate services", Tool: "Discover", Route: "/discovery?tab=sources&kind=cloud_certificate", SetupSurface: SetupSourceWizard,
		Purpose:      "Inventory certificate metadata from AWS Certificate Manager, Azure Key Vault, and Google Cloud Certificate Manager.",
		DataHandling: "Uses read-only provider calls and credential references. It stores public certificate metadata and provider provenance, never private keys or inline cloud credentials.",
		Permission:   "discovery:write", Edition: "core", Execution: "control plane",
		Configuration: cloudFields(false), Providers: []Provider{
			provider("aws-acm", "AWS Certificate Manager", "acm:ListCertificates and acm:DescribeCertificate on the authorized account/regions", "env: credential references", "region", "endpoint", "access_key_id_ref", "secret_access_key_ref", "session_token_ref"),
			provider("azure-keyvault", "Azure Key Vault certificates", "certificates/list and certificates/get on the authorized vault", "token_ref", "vault_url", "token_ref"),
			provider("gcp-certmanager", "Google Cloud Certificate Manager", "certificatemanager.certificates.list/get on the authorized project/location", "token_ref", "project", "location", "token_ref"),
		},
		Lifecycle: standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/discovery-and-inventory.md#cloud-certificate-services",
	}
}

// cloudAccessKeyCapability reads a cloud account's long-lived user access keys
// (M3), a Google Cloud project's service-account keys (M3-L1) and a Microsoft
// Entra tenant's app-registration client secrets (M3-L2): each key's
// owner, status, age and last use, never a secret. An active key nobody has
// used in 90 days is flagged stale.
func cloudAccessKeyCapability() Capability {
	return Capability{
		Kind: "cloud_access_key", Label: "Cloud access keys", Tool: "Discover", Route: "/discovery?tab=sources&kind=cloud_access_key", SetupSurface: SetupSourceWizard,
		Purpose:      "Find the long-lived access keys a cloud account's users authenticate with, with each key's age and last use, so stale and unrotated keys stand out.",
		DataHandling: "Uses read-only provider calls and credential references. It stores each key's ID, owner, status, creation and last-use dates, never a secret access key or any other account contents.",
		Permission:   "discovery:write", Edition: "core", Execution: "control plane",
		Configuration: []Field{
			field("providers[].provider", "Provider", "provider", true, false, false, "The exact read-only provider adapter."),
			field("providers[].endpoint", "API endpoint", "url", false, false, true, "Optional compatible endpoint; the public provider default is safer."),
			field("providers[].allow_private_endpoint", "Allow approved private endpoint", "boolean", false, false, true, "Requires private-egress authorization and explicit CIDRs."),
			field("providers[].private_egress_cidrs", "Approved private endpoint CIDRs", "cidr_list", false, false, true, "Private destinations allowed for this provider; metadata and loopback remain blocked."),
			field("providers[].access_key_id_ref", "Access key ID reference", "credential_ref", true, true, true, "Reference only; use a short-lived least-privilege credential."),
			field("providers[].secret_access_key_ref", "Secret access key reference", "credential_ref", true, true, true, "Reference only; the value never enters source configuration."),
			field("providers[].session_token_ref", "Session token reference", "credential_ref", false, true, true, "Optional short-lived session-token reference."),
			field("providers[].project", "Project", "string", false, false, false, "Google Cloud: the project whose service-account keys are read."),
			field("providers[].token_ref", "Bearer token reference", "credential_ref", false, true, true, "Google Cloud or Microsoft Entra: reference to a short-lived read-only token; the value never enters source configuration."),
			field("providers[].activity_endpoint", "Key activity endpoint", "url", false, false, true, "Google Cloud: where each key's last authentication is read; Policy Analyzer by default."),
		},
		Providers: []Provider{
			provider("aws-iam", "AWS IAM user access keys", "iam:ListUsers, iam:ListAccessKeys and iam:GetAccessKeyLastUsed on the authorized account", "env: credential references", "endpoint", "access_key_id_ref", "secret_access_key_ref", "session_token_ref"),
			provider("gcp-iam", "Google Cloud service-account keys", "iam.serviceAccounts.list and iam.serviceAccountKeys.list on the project, and Policy Analyzer's key last-authentication activity", "a short-lived read-only token reference", "project", "token_ref", "endpoint", "activity_endpoint"),
			provider("azure-entra", "Microsoft Entra app-registration client secrets", "Application.Read.All, and AuditLog.Read.All for each secret's last sign-in", "a short-lived read-only Microsoft Graph token reference", "token_ref", "endpoint"),
		},
		Lifecycle: standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/discovery-and-inventory.md#cloud-access-keys",
	}
}

// cloudKMSKeyCapability reads an account's cloud KMS keys (X4): each key's
// type, size, usage, state and automatic-rotation status, never key material.
// A key the service could rotate but is not rotating is flagged unrotated.
func cloudKMSKeyCapability() Capability {
	return Capability{
		Kind: "cloud_kms_key", Label: "Cloud KMS keys", Tool: "Discover", Route: "/discovery?tab=sources&kind=cloud_kms_key", SetupSurface: SetupSourceWizard,
		Purpose:      "Inventory the keys a cloud account's key management service holds, with each key's type, size and rotation status, so unrotated and quantum-vulnerable keys stand out.",
		DataHandling: "Uses read-only provider calls and credential references. It stores each key's ID, ARN, key spec, usage, state, manager, origin, creation date and rotation status, never key material or any other account contents.",
		Permission:   "discovery:write", Edition: "core", Execution: "control plane",
		Configuration: []Field{
			field("providers[].provider", "Provider", "provider", true, false, false, "The exact read-only provider adapter."),
			field("providers[].region", "Region", "string", true, false, false, "The Region whose keys are read."),
			field("providers[].endpoint", "API endpoint", "url", false, false, true, "Optional compatible endpoint; the public provider default is safer."),
			field("providers[].allow_private_endpoint", "Allow approved private endpoint", "boolean", false, false, true, "Requires private-egress authorization and explicit CIDRs."),
			field("providers[].private_egress_cidrs", "Approved private endpoint CIDRs", "cidr_list", false, false, true, "Private destinations allowed for this provider; metadata and loopback remain blocked."),
			field("providers[].access_key_id_ref", "Access key ID reference", "credential_ref", true, true, true, "Reference only; use a short-lived least-privilege credential."),
			field("providers[].secret_access_key_ref", "Secret access key reference", "credential_ref", true, true, true, "Reference only; the value never enters source configuration."),
			field("providers[].session_token_ref", "Session token reference", "credential_ref", false, true, true, "Optional short-lived session-token reference."),
		},
		Providers: []Provider{
			provider("aws-kms", "AWS Key Management Service keys", "kms:ListKeys, kms:DescribeKey and kms:GetKeyRotationStatus on the authorized account/Region", "env: credential references", "region", "endpoint", "access_key_id_ref", "secret_access_key_ref", "session_token_ref"),
		},
		Lifecycle: standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/discovery-and-inventory.md#cloud-kms-keys",
	}
}

// loadBalancerTLSCapability reads the TLS policy each AWS load-balancer
// listener or F5 BIG-IP virtual server enforces (X4): the protocol versions it
// allows and its ciphers. A listener that allows TLS 1.0 is one weak TLSv1.0
// finding in the crypto inventory.
func loadBalancerTLSCapability() Capability {
	return Capability{
		Kind: "load_balancer_tls", Label: "Load-balancer TLS policies", Tool: "Discover", Route: "/discovery?tab=sources&kind=load_balancer_tls", SetupSurface: SetupSourceWizard,
		Purpose:      "Read the TLS policy each load-balancer listener enforces, so a listener that still allows TLS 1.0 or 1.1 stands out in the crypto inventory.",
		DataHandling: "Uses read-only provider calls and credential references. It stores each listener's name, port, policy, allowed versions and ciphers, never certificates' keys, traffic or other configuration.",
		Permission:   "discovery:write", Edition: "core", Execution: "control plane",
		Configuration: []Field{
			field("providers[].provider", "Provider", "provider", true, false, false, "The exact read-only provider adapter."),
			field("providers[].region", "Region", "string", false, false, false, "The AWS Region whose load balancers are read (aws-elbv2)."),
			field("providers[].endpoint", "API endpoint", "url", false, false, true, "The BIG-IP management URL (f5-bigip, required), or an optional compatible AWS endpoint."),
			field("providers[].allow_private_endpoint", "Allow approved private endpoint", "boolean", false, false, true, "Requires private-egress authorization and explicit CIDRs."),
			field("providers[].private_egress_cidrs", "Approved private endpoint CIDRs", "cidr_list", false, false, true, "Private destinations allowed for this provider; metadata and loopback remain blocked."),
			field("providers[].access_key_id_ref", "Access key ID reference", "credential_ref", false, true, true, "AWS: reference only; use a short-lived least-privilege credential."),
			field("providers[].secret_access_key_ref", "Secret access key reference", "credential_ref", false, true, true, "AWS: reference only; the value never enters source configuration."),
			field("providers[].session_token_ref", "Session token reference", "credential_ref", false, true, true, "AWS: optional short-lived session-token reference."),
			field("providers[].token_ref", "iControl REST token reference", "credential_ref", false, true, true, "BIG-IP: a token for a read-only (Guest or Auditor) user, instead of a user and password."),
			field("providers[].username_ref", "User reference", "credential_ref", false, true, true, "BIG-IP: a read-only (Guest or Auditor) user."),
			field("providers[].password_ref", "Password reference", "credential_ref", false, true, true, "BIG-IP: that user's password, by reference only."),
		},
		Providers: []Provider{
			provider("aws-elbv2", "AWS Application and Network Load Balancers", "elasticloadbalancing:DescribeLoadBalancers, DescribeListeners and DescribeSSLPolicies on the authorized account/Region", "env: credential references", "region", "endpoint", "access_key_id_ref", "secret_access_key_ref", "session_token_ref"),
			provider("f5-bigip", "F5 BIG-IP virtual servers and client SSL profiles", "GET /mgmt/tm/ltm/virtual and /mgmt/tm/ltm/profile/client-ssl as a read-only user", "env: credential references", "endpoint", "token_ref", "username_ref", "password_ref"),
		},
		Lifecycle: standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/discovery-and-inventory.md#load-balancer-tls-policies",
	}
}

// cloudNetworkPathCapability is the cloud account attack-path validation
// reads (A167, A167-L1): which routes, network ACLs, security groups, VPC
// firewall rules and network security groups stand between the internet and
// an exposed NHI endpoint. It runs from the exposure posture,
// against the endpoints the posture names, never as a sweep of the account; a
// full or scheduled run re-validates them (A167-L4).
func cloudNetworkPathCapability() Capability {
	return Capability{
		Kind: "cloud_network_path", Label: "Cloud network paths", Tool: "Discover", Route: "/discovery?tab=sources&kind=cloud_network_path", SetupSurface: SetupSourceWizard,
		Purpose:      "Validate, from the cloud account's own routes, network ACLs, security groups, VPC firewall rules and network security groups, whether the internet can reach the public endpoints the exposure posture names.",
		DataHandling: "Uses read-only provider calls and credential references. It stores each verdict with the identifiers of the resources that decided it, never credentials, traffic or other account contents.",
		Permission:   "discovery:write", Edition: "core", Execution: "control plane",
		Configuration: []Field{
			field("providers[].provider", "Provider", "provider", true, false, false, "The exact read-only provider adapter."),
			field("providers[].region", "Region", "string", false, false, false, "The AWS account region whose network configuration is read."),
			field("providers[].project", "Project", "string", false, false, false, "The Google Cloud project whose VPC firewall rules and routes are read."),
			field("providers[].subscription_id", "Subscription ID", "string", false, false, false, "The Azure subscription whose public IPs, network security groups and route tables are read."),
			field("providers[].endpoint", "API endpoint", "url", false, false, true, "Optional compatible endpoint; public provider defaults are safer."),
			field("providers[].allow_private_endpoint", "Allow approved private endpoint", "boolean", false, false, true, "Requires private-egress authorization and explicit CIDRs."),
			field("providers[].private_egress_cidrs", "Approved private endpoint CIDRs", "cidr_list", false, false, true, "Private destinations allowed for this provider; metadata and loopback remain blocked."),
			field("providers[].access_key_id_ref", "Access key ID reference", "credential_ref", false, true, true, "Reference only; use a short-lived least-privilege credential."),
			field("providers[].secret_access_key_ref", "Secret access key reference", "credential_ref", false, true, true, "Reference only; the value never enters source configuration."),
			field("providers[].session_token_ref", "Session token reference", "credential_ref", false, true, true, "Optional short-lived session-token reference."),
			field("providers[].token_ref", "Bearer token reference", "credential_ref", false, true, true, "Reference only; a short-lived read-only OAuth token (Google Cloud: compute read scope; Azure: a Microsoft Entra token for Resource Manager)."),
		},
		Providers: []Provider{
			provider("gcp-compute", "Google Compute Engine network configuration", "compute.instances.list, compute.firewalls.list and compute.routes.list on the project (roles/compute.networkViewer)", "token_ref", "project", "endpoint", "token_ref"),
			provider("azure-network", "Azure virtual network configuration", "Microsoft.Network/publicIPAddresses/read, networkInterfaces/read, virtualNetworks/subnets/read, networkSecurityGroups/read and routeTables/read on the subscription (the built-in Reader role grants them)", "token_ref", "subscription_id", "endpoint", "token_ref"),
			provider("aws-ec2", "Amazon EC2 network configuration", "ec2:DescribeNetworkInterfaces, ec2:DescribeSecurityGroups, ec2:DescribeRouteTables and ec2:DescribeNetworkAcls on the authorized account/region", "env: credential references", "region", "endpoint", "access_key_id_ref", "secret_access_key_ref", "session_token_ref"),
		},
		Lifecycle: standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/discovery-and-inventory.md#cloud-network-paths",
	}
}

func cloudSecretCapability(kind, label string) Capability {
	return Capability{
		Kind: kind, Label: label, Tool: "Discover", Route: "/discovery?tab=sources&kind=" + kind, SetupSurface: SetupSourceWizard,
		Purpose:      "Inventory every authorized secret resource's metadata without retrieving its value; optionally inspect content for certificates and for the API keys, tokens, and private keys stored in it through a separate explicit choice.",
		DataHandling: "Metadata-only is the default. Optional content inspection retrieves only candidate values, keeps them in wipeable bytes, emits certificate metadata and masked, fingerprinted credential findings only, and never persists, logs, or renders the value.",
		Permission:   "discovery:write", Edition: "core", Execution: "control plane",
		Configuration: cloudFields(true), Providers: []Provider{
			provider("aws-secrets-manager", "AWS Secrets Manager", "Metadata: secretsmanager:ListSecrets. Optional content inspection additionally needs GetSecretValue on the filtered scope.", "env: credential references", "region", "endpoint", "access_key_id_ref", "secret_access_key_ref", "session_token_ref", "tag_key", "tag_value", "name_prefix", "inspect_content"),
			provider("gcp-secret-manager", "Google Secret Manager", "Metadata: secretmanager.secrets.list. Optional content inspection additionally needs secretmanager.versions.access on the filtered scope.", "token_ref", "project", "token_ref", "label_key", "label_value", "name_prefix", "inspect_content"),
			provider("azure-key-vault", "Azure Key Vault secrets", "Metadata: secrets/list. Optional content inspection additionally needs secrets/get on the filtered scope.", "token_ref", "vault_url", "token_ref", "name_prefix", "inspect_content"),
			provider("hashicorp-vault", "HashiCorp Vault KV", "Metadata: list/read on the approved metadata path. Optional content inspection additionally needs read on the filtered data path.", "token_ref", "vault_url", "api_version", "mount", "path_prefix", "token_ref", "inspect_content"),
			provider("github-actions", "GitHub secrets (Actions, Dependabot, Codespaces)", "Metadata only: a fine-grained token with read access to each chosen store on the repository or org (Secrets for Actions, plus Environments for environment secrets; Dependabot secrets; Codespaces secrets), and Codespaces user secrets for the token owner's own. GitHub never returns values, so content inspection is refused.", "token_ref", "endpoint", "owner", "repo", "environments", "org", "stores", "user_codespaces", "token_ref", "name_prefix"),
			provider("gitlab-ci", "GitLab CI/CD variables", "Metadata: a read_api token with at least Maintainer on the project or group, and an administrator's token for instance variables (GitLab returns values in the listing; trstctl wipes them unless content inspection is chosen). Hidden variables are never returned.", "token_ref", "endpoint", "project", "group", "instance", "token_ref", "name_prefix", "inspect_content"),
			provider("infisical", "Infisical secrets", "Metadata: a machine identity with the Viewer role on each project to inventory, signing in with Universal Auth (client ID and client secret) or an access token. A metadata-only run asks Infisical to leave values out; content inspection asks for them.", "client_secret_ref", "endpoint", "client_id", "client_secret_ref", "token_ref", "project", "environments", "path_prefix", "name_prefix", "inspect_content"),
			provider("conjur", "CyberArk Conjur variables", "Metadata: a host (or user) with read on the variables to inventory, signing in with its API key; the resource listing returns only those and never a value. Content inspection also needs execute on them.", "api_key_ref", "endpoint", "account", "login", "api_key_ref", "path_prefix", "name_prefix", "inspect_content"),
			provider("akeyless", "Akeyless static secrets", "Metadata: an API-key auth method whose role may list the folder; the item listing carries no value. Content inspection also needs read on the items.", "client_secret_ref", "endpoint", "client_id", "client_secret_ref", "path_prefix", "name_prefix", "inspect_content"),
			provider("bitwarden-secrets-manager", "Bitwarden Secrets Manager secrets", "Metadata: a machine account with read access to the projects or secrets to inventory. Its access token signs in and carries the key that decrypts names on this side; the listing carries no value. Content inspection reads the values the account can read.", "token_ref", "endpoint", "identity_endpoint", "token_ref", "name_prefix", "inspect_content"),
		},
		Lifecycle: standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/discovery-and-inventory.md#cloud-secret-managers",
	}
}

func cloudFields(secret bool) []Field {
	fields := []Field{
		field("providers[].provider", "Provider", "provider", true, false, false, "The exact read-only provider adapter."),
		field("providers[].region", "Region", "string", false, false, false, "Provider region when applicable."),
		field("providers[].endpoint", "API endpoint", "url", false, false, true, "Optional compatible endpoint; public provider defaults are safer."),
		field("providers[].allow_private_endpoint", "Allow approved private endpoint", "boolean", false, false, true, "Requires private-egress authorization and explicit CIDRs."),
		field("providers[].private_egress_cidrs", "Approved private endpoint CIDRs", "cidr_list", false, false, true, "Private destinations allowed for this provider; metadata and loopback remain blocked."),
		field("providers[].access_key_id_ref", "Access key ID reference", "credential_ref", false, true, true, "Reference only; use a short-lived least-privilege credential."),
		field("providers[].secret_access_key_ref", "Secret access key reference", "credential_ref", false, true, true, "Reference only; the value never enters source configuration."),
		field("providers[].session_token_ref", "Session token reference", "credential_ref", false, true, true, "Optional short-lived session-token reference."),
		field("providers[].vault_url", "Vault URL", "url", false, false, false, "Authorized Azure Key Vault or HashiCorp Vault endpoint."),
		field("providers[].token_ref", "Token reference", "credential_ref", false, true, false, "Reference to a least-privilege token; the value never enters source configuration."),
		field("providers[].project", "Project", "string", false, false, false, "Authorized Google Cloud project, GitLab project, or Infisical project ID."),
		field("providers[].location", "Location", "string", false, false, false, "Certificate Manager location."),
	}
	if secret {
		fields = append(fields,
			field("providers[].api_version", "Vault KV API version", "string", false, false, true, "KV v1 or v2 as configured on the mount."),
			field("providers[].mount", "Vault mount", "string", false, false, false, "Approved KV mount name."),
			field("providers[].path_prefix", "Path prefix", "string", false, false, false, "The least-privilege path to list: a Vault metadata path, an Infisical secret path, a Conjur policy path or an Akeyless folder."),
			field("providers[].tag_key", "AWS tag key", "string", false, false, true, "Optional metadata-only inventory filter."),
			field("providers[].tag_value", "AWS tag value", "string", false, false, true, "Optional metadata-only inventory filter."),
			field("providers[].label_key", "GCP label key", "string", false, false, true, "Optional metadata-only inventory filter."),
			field("providers[].label_value", "GCP label value", "string", false, false, true, "Optional metadata-only inventory filter."),
			field("providers[].name_prefix", "Name prefix", "string", false, false, true, "Optional resource-name filter."),
			field("providers[].owner", "GitHub owner", "string", false, false, false, "Repository owner (user or organization) for repository and environment secrets."),
			field("providers[].repo", "GitHub repository", "string", false, false, false, "Repository whose secrets are listed."),
			field("providers[].environments", "Environments", "string_list", false, false, true, "GitHub deployment environments whose secrets are listed too, or the Infisical environment slugs to list (empty: every environment of the project)."),
			field("providers[].org", "GitHub organization", "string", false, false, false, "Organization whose secrets are listed."),
			field("providers[].stores", "GitHub secret stores", "string_list", false, false, true, "Stores listed for the repository and organization: actions (the default), dependabot, codespaces."),
			field("providers[].user_codespaces", "Token owner's Codespaces secrets", "boolean", false, false, true, "Also list the Codespaces secrets of the user the token belongs to."),
			field("providers[].group", "GitLab group", "string", false, false, false, "Group ID or full path whose CI/CD variables are listed; a project uses the project field."),
			field("providers[].instance", "GitLab instance variables", "boolean", false, false, true, "Also list the instance-level variables every project inherits (an administrator's token on a self-managed instance)."),
			field("providers[].client_id", "Client or access ID", "string", false, false, false, "An Infisical Universal Auth client ID or an Akeyless access ID; not a secret."),
			field("providers[].client_secret_ref", "Client secret or access key reference", "credential_ref", false, true, false, "Reference to the Infisical client secret or the Akeyless access key; the value never enters source configuration."),
			field("providers[].account", "Conjur account", "string", false, false, false, "The Conjur account the variables belong to."),
			field("providers[].login", "Conjur login", "string", false, false, false, "The host (host/<id>) or user that signs in."),
			field("providers[].api_key_ref", "Conjur API key reference", "credential_ref", false, true, false, "Reference to the login's API key; the value never enters source configuration."),
			field("providers[].identity_endpoint", "Bitwarden identity endpoint", "url", false, false, true, "The identity service a self-hosted Bitwarden serves under /identity; Bitwarden's cloud identity service by default."),
			field("providers[].inspect_content", "Inspect content for certificates and credentials", "boolean", false, false, true, "Explicit opt-in to retrieve candidate values into wipeable memory and emit certificate metadata and masked, fingerprinted API-key, token, and private-key findings only."),
		)
	}
	return fields
}

func structured(kind, label, payload, handling string) Capability {
	return Capability{
		Kind: kind, Label: label, Tool: "Discover", Route: "/discovery?tab=sources&kind=" + kind, SetupSurface: SetupSourceWizard,
		Purpose: label + " discovery from bounded, sanitized observations.", DataHandling: handling,
		Permission: "discovery:write", Edition: "core", Execution: "control plane", Configuration: []Field{field(payload, "Observations", "record_list", true, false, false, "One or more validated metadata-only observations.")},
		Lifecycle: standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/discovery-and-inventory.md#metadata-sources",
	}
}

// oauthGrantCapability is the OAuth grant source: metadata observations, plus
// the optional provider admin connections an operator acts through on an
// abusive grant it finds (A170, A171).
func oauthGrantCapability() Capability {
	c := structured("oauth_grant", "OAuth grants", "grants", "Inventory OAuth application grants, scopes, owners, and consent risk without collecting client secrets or access tokens. Optional provider connections hold an admin token reference used only when an operator revokes a grant or blocks an app.")
	c.Configuration = append(c.Configuration,
		field("providers[].provider", "Provider", "string", false, false, true, "okta, microsoft or google: the provider an operator revokes grants or blocks apps at."),
		field("providers[].base_url", "Admin API URL", "url", false, false, true, "The provider's admin API base URL (your Okta org URL, https://graph.microsoft.com, https://admin.googleapis.com)."),
		field("providers[].token_ref", "Admin token reference", "credential_ref", false, true, true, "Reference only (env:NAME) to a token allowed to revoke grants and deactivate apps; the value never enters source configuration."),
		field("providers[].allow_private_endpoint", "Allow approved private endpoint", "boolean", false, false, true, "Requires private-egress authorization and explicit CIDRs."),
		field("providers[].private_egress_cidrs", "Approved private endpoint CIDRs", "cidr_list", false, false, true, "Private destinations allowed for this connection; metadata and loopback remain blocked."),
	)
	return c
}

func field(path, label, kind string, required, secretRef, advanced bool, description string) Field {
	return Field{Path: path, Label: label, Type: kind, Required: required, SecretRef: secretRef, Advanced: advanced, Description: description}
}

func provider(id, label, leastPrivilege, credential string, fields ...string) Provider {
	return Provider{ID: id, Label: label, LeastPrivilege: leastPrivilege, PreferredCredential: credential, Fields: fields}
}

func All() Catalog {
	out := make([]Capability, len(items))
	copy(out, items)
	return Catalog{SchemaVersion: SchemaVersion, Items: out}
}

func Kinds() []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.Kind)
	}
	sort.Strings(out)
	return out
}

func Find(kind string) (Capability, bool) {
	kind = strings.TrimSpace(kind)
	for _, item := range items {
		if item.Kind == kind {
			return item, true
		}
	}
	return Capability{}, false
}

// ValidateConfig closes the empty-object gap at the API boundary. Package-
// specific validators still enforce deeper rules; this function proves that a
// catalog-advertised configuration has its required top-level shape and, for
// provider sources, names a provider the same catalog advertises.
func ValidateConfig(kind string, raw []byte) error {
	capability, ok := Find(kind)
	if !ok {
		return fmt.Errorf("source kind %q is not in the capability catalog", kind)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return errorsForConfig(kind, "must be a JSON object")
	}
	if len(obj) == 0 {
		return errorsForConfig(kind, "must not be empty")
	}
	for _, f := range capability.Configuration {
		if !f.Required {
			continue
		}
		top := strings.Split(strings.TrimSuffix(f.Path, "[]"), ".")[0]
		top = strings.TrimSuffix(top, "[]")
		value, present := obj[top]
		if !present || len(value) == 0 || string(value) == "null" || string(value) == `""` || string(value) == "[]" {
			return errorsForConfig(kind, "requires "+top)
		}
	}
	if len(capability.Providers) == 0 {
		return nil
	}
	var providers []map[string]json.RawMessage
	if err := json.Unmarshal(obj["providers"], &providers); err != nil || len(providers) == 0 {
		return errorsForConfig(kind, "requires at least one provider")
	}
	allowed := map[string]struct{}{}
	for _, provider := range capability.Providers {
		allowed[provider.ID] = struct{}{}
	}
	for i, provider := range providers {
		var id string
		if err := json.Unmarshal(provider["provider"], &id); err != nil || strings.TrimSpace(id) == "" {
			return errorsForConfig(kind, fmt.Sprintf("provider %d requires provider", i+1))
		}
		if _, ok := allowed[id]; !ok {
			return errorsForConfig(kind, fmt.Sprintf("provider %d names unsupported provider %q", i+1, id))
		}
	}
	return nil
}

func errorsForConfig(kind, detail string) error {
	return fmt.Errorf("%s discovery config %s", kind, detail)
}

// Validate is also the negative-oracle entry point: tests deliberately remove
// fields and stages from a copied catalog and prove the parity gate fails.
func Validate(catalog Catalog) error {
	if catalog.SchemaVersion != SchemaVersion {
		return fmt.Errorf("source catalog schema_version=%d, want %d", catalog.SchemaVersion, SchemaVersion)
	}
	seen := map[string]struct{}{}
	for i, item := range catalog.Items {
		if strings.TrimSpace(item.Kind) == "" || strings.TrimSpace(item.Label) == "" || strings.TrimSpace(item.Purpose) == "" || strings.TrimSpace(item.DataHandling) == "" {
			return fmt.Errorf("source catalog item %d has blank identity or operator explanation", i)
		}
		if _, duplicate := seen[item.Kind]; duplicate {
			return fmt.Errorf("source catalog kind %q is duplicated", item.Kind)
		}
		seen[item.Kind] = struct{}{}
		if strings.TrimSpace(item.Permission) == "" || strings.TrimSpace(item.Edition) == "" || strings.TrimSpace(item.Route) == "" || strings.TrimSpace(item.DocumentationRef) == "" {
			return fmt.Errorf("source catalog kind %q has an incomplete permission/edition/route/docs disposition", item.Kind)
		}
		if len(item.Configuration) == 0 {
			return fmt.Errorf("source catalog kind %q has no typed configuration path", item.Kind)
		}
		paths := map[string]struct{}{}
		for _, f := range item.Configuration {
			if f.Path == "" || f.Label == "" || f.Type == "" || f.Description == "" {
				return fmt.Errorf("source catalog kind %q has an incomplete field", item.Kind)
			}
			if _, duplicate := paths[f.Path]; duplicate {
				return fmt.Errorf("source catalog kind %q duplicates field %q", item.Kind, f.Path)
			}
			paths[f.Path] = struct{}{}
			if strings.Contains(f.Path, "secret") && !strings.HasSuffix(f.Path, "_ref") && !f.SecretRef && item.Kind != "cloud_secret" && item.Kind != "secret_store" {
				return fmt.Errorf("source catalog kind %q field %q looks secret-bearing but is not a reference", item.Kind, f.Path)
			}
		}
		for _, required := range standardStages {
			if !contains(item.ConsoleStages, required) {
				return fmt.Errorf("source catalog kind %q is missing console stage %q", item.Kind, required)
			}
		}
	}
	return nil
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func cloudMachineEntitlementCapability() Capability {
	return Capability{
		Kind: "cloud_machine_entitlement", Label: "Cloud machine entitlements", Tool: "Discover", Route: "/discovery?tab=sources&kind=cloud_machine_entitlement", SetupSurface: SetupSourceWizard,
		Purpose:      "Read selected AWS workload users and roles, compare exact policy checks with scoped recorded activity, and identify stale keys and possible policy escalation.",
		DataHandling: "Reads IAM metadata through an operator-approved private STS session file. Stores policy/trust/key identifiers and explicit evidence gaps. Imported organization, resource and activity coverage remains operator-supplied evidence. No mutation occurs.",
		Permission:   "discovery:write", Edition: "core", Execution: "control plane",
		Configuration: []Field{
			field("session_file_ref", "STS session file reference", "credential_ref", true, true, false, "Operator-approved env: reference whose value names an owner-only standard STS JSON response file; no inline credentials or tenant-chosen file paths."),
			field("principals", "Workload identities", "record_list", true, false, false, "Explicit IAM user/role names used by workloads; at most 256, never assumed to be all account users."),
			field("assessment", "Permission and activity evidence", "object", true, false, false, "Exact action/resource/context checks with separately identified recorded organization/resource policies and activity coverage; gaps remain visible."),
			field("endpoint", "IAM endpoint", "url", false, false, true, "Fixed IAM origin; defaults to https://iam.amazonaws.com."),
			field("region", "Signing region", "string", false, false, true, "IAM signing region; defaults to us-east-1."),
			field("ca_pem", "Private endpoint trust anchor", "string", false, false, true, "Optional public PEM root for a private endpoint; hostname verification remains required."),
			field("allow_private_endpoint", "Allow approved private endpoint", "boolean", false, false, true, "Requires private-egress authorization and explicit private CIDRs; plaintext is allowed only on loopback."),
			field("private_egress_cidrs", "Approved private endpoint CIDRs", "cidr_list", false, false, true, "Only these approved private destinations can be reached; no redirects occur."),
		}, Lifecycle: standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/discovery-and-inventory.md#cloud-machine-entitlements",
	}
}

func gcpMachineIdentityCapability() Capability {
	return Capability{Kind: "gcp_machine_identity", Label: "GCP workload identities", Tool: "Discover", Route: "/discovery?tab=sources&kind=gcp_machine_identity", SetupSurface: SetupSourceWizard, Purpose: "Read selected service accounts, user-managed key metadata, trust policies, project role bindings and scoped observed audit use.", DataHandling: "Uses an operator-approved private bearer-token file. Captures typed public metadata only. No private key download or mutation. Bindings and observed-only audit records do not establish effective permissions or proof of non-use.", Permission: "discovery:write", Edition: "core", Execution: "control plane", Configuration: []Field{
		field("project", "GCP project ID", "string", true, false, false, "Project containing the selected workload service accounts."),
		field("service_accounts", "Service-account emails", "string_list", true, false, false, "Between 1 and 64 explicitly selected workload account emails; never assumed to be all project identities."),
		field("token_file_ref", "Reader token file reference", "credential_ref", true, true, false, "Operator-approved env: reference to a private raw OAuth access-token file; no inline material or tenant-chosen file path."),
		field("activity_lookback_days", "Audit lookback days", "integer", false, false, false, "Zero disables audit reads; 1..90 enables observed-only scoped Cloud Logging reads."),
		field("iam_endpoint", "IAM origin", "url", false, false, true, "Defaults to https://iam.googleapis.com; fixed origin, no redirects."),
		field("resource_manager_endpoint", "Resource Manager origin", "url", false, false, true, "Defaults to https://cloudresourcemanager.googleapis.com."),
		field("logging_endpoint", "Logging origin", "url", false, false, true, "Defaults to https://logging.googleapis.com."),
		field("ca_pem", "Private endpoint trust anchor", "string", false, false, true, "Public PEM root; hostname verification remains required."),
		field("allow_private_endpoint", "Allow approved private endpoint", "boolean", false, false, true, "Requires private-egress authorization and explicit private CIDRs. Plaintext is loopback-only."),
		field("private_egress_cidrs", "Approved private CIDRs", "cidr_list", false, false, true, "Only approved private destinations can be reached.")}, Lifecycle: standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/discovery-and-inventory.md#gcp-workload-identity-inventory"}
}

func azureMachineIdentityCapability() Capability {
	return Capability{Kind: "azure_machine_identity", Label: "Azure workload identities", Tool: "Discover", Route: "/discovery?tab=sources&kind=azure_machine_identity", SetupSurface: SetupSourceWizard, Purpose: "Read selected service principals and managed identities, public credential dates, app roles, federation, subscription RBAC and optional beta workload sign-ins.", DataHandling: "Uses separate operator-approved private Graph/ARM bearer-token files. Persists typed public metadata, never secret values or password hints. Bindings do not prove effective access; observed sign-ins do not prove non-use.", Permission: "discovery:write", Edition: "core", Execution: "control plane", Configuration: []Field{
		field("azure_tenant_id", "Azure tenant UUID", "string", true, false, false, "Must match the native Graph organization and ARM subscription tenant."),
		field("subscription_id", "Subscription UUID", "string", true, false, false, "Read-only RBAC scope; native subscription ownership is verified."),
		field("service_principal_ids", "Workload principal UUIDs", "string_list", true, false, false, "1..64 selected service-principal object IDs, including ManagedIdentity type."),
		field("graph_token_file_ref", "Graph reader file reference", "credential_ref", true, true, false, "Approved env: reference to a private raw Graph-audience access-token file."),
		field("arm_token_file_ref", "ARM reader file reference", "credential_ref", true, true, false, "Separate approved env: reference to a private ARM-audience access-token file."),
		field("read_beta_signins", "Read beta workload sign-ins", "boolean", false, false, false, "Explicit opt-in to beta API; tenant permissions/license and retention may limit evidence."),
		field("activity_lookback_days", "Beta sign-in lookback days", "integer", false, false, false, "1..30 with beta opt-in; otherwise zero."),
		field("managed_identity_resources", "Managed identity ARM bindings", "object", false, false, true, "Selected principal UUID to exact user-assigned ARM resource ID; system-assigned linkage remains unqualified."),
		field("graph_endpoint", "Graph origin", "url", false, false, true, "Defaults to https://graph.microsoft.com; fixed origin without redirects."),
		field("arm_endpoint", "ARM origin", "url", false, false, true, "Defaults to https://management.azure.com; separate audience."),
		field("ca_pem", "Private endpoint trust anchor", "string", false, false, true, "Public PEM root; hostname verification remains required."),
		field("allow_private_endpoint", "Allow approved private endpoint", "boolean", false, false, true, "Requires private-egress permission and explicit private CIDRs. Plaintext is loopback-only."),
		field("private_egress_cidrs", "Approved private CIDRs", "cidr_list", false, false, true, "Only approved private destinations can be reached.")}, Lifecycle: standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/discovery-and-inventory.md#azure-workload-identity-inventory"}
}
