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
	{
		Kind: "adcs", Label: "Microsoft AD CS", Tool: "Discover", Route: "/discovery?tab=sources&kind=adcs", SetupSurface: SetupSourceWizard,
		Purpose:      "Inventory AD CS authorities, templates, enrollment rights, and exposed enrollment endpoints through a domain-reachable relay.",
		DataHandling: "Performs bounded read-only LDAP and configured endpoint checks. Passwords are represented only by credential references; response bodies and private keys are never stored.",
		Permission:   "discovery:write", Edition: "core", Execution: "network-role relay",
		Configuration: []Field{
			field("url", "Directory URL", "url", true, false, false, "LDAPS or LDAP endpoint reachable from the selected relay."),
			field("configuration_dn", "Configuration naming context", "string", true, false, false, "The AD Configuration partition to inspect."),
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
	structured("oauth_grant", "OAuth grants", "grants", "Inventory OAuth application grants, scopes, owners, and consent risk without collecting client secrets or access tokens."),
	structured("service_account", "Service accounts", "accounts", "Inventory Active Directory and cloud service-account metadata and credential references without collecting passwords or private keys."),
	structured("nhi_behavior", "Identity behavior", "events", "Analyze bounded, sanitized use metadata for machine identities; credential material is rejected."),
	structured("credential_compromise", "Compromise signals", "signals", "Ingest sanitized detector evidence and credential references; stolen credential values are rejected."),
	structured("k8s_ingress_gateway", "Kubernetes TLS", "resources", "Inventory Kubernetes Ingress and Gateway TLS metadata; Secret values and private keys are rejected."),
	{
		Kind: "agent", Label: "Agent inventory", Tool: "Workloads & Machines", Route: "/agents", SetupSurface: SetupContextual,
		Purpose: "Receive signed, tenant-bound inventory from enrolled agents.", DataHandling: "Configured from the Agents tool. The generic discovery-source wizard cannot create a useful agent source.",
		Permission: "agents:write", Edition: "core", Execution: "host or network agent", Configuration: []Field{field("agent_id", "Enrolled agent", "agent_ref", true, false, false, "The enrolled agent that signs and reports the observation.")},
		Lifecycle: standardLifecycle, ConsoleStages: standardStages, DocumentationRef: "docs/features/agent.md",
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

func cloudSecretCapability(kind, label string) Capability {
	return Capability{
		Kind: kind, Label: label, Tool: "Discover", Route: "/discovery?tab=sources&kind=" + kind, SetupSurface: SetupSourceWizard,
		Purpose:      "Inventory every authorized secret resource's metadata without retrieving its value; optionally inspect content for certificates through a separate explicit choice.",
		DataHandling: "Metadata-only is the default. Optional content inspection retrieves only candidate values, keeps them in wipeable bytes, emits certificate metadata only, and never persists, logs, or renders the value.",
		Permission:   "discovery:write", Edition: "core", Execution: "control plane",
		Configuration: cloudFields(true), Providers: []Provider{
			provider("aws-secrets-manager", "AWS Secrets Manager", "Metadata: secretsmanager:ListSecrets. Optional content inspection additionally needs GetSecretValue on the filtered scope.", "env: credential references", "region", "endpoint", "access_key_id_ref", "secret_access_key_ref", "session_token_ref", "tag_key", "tag_value", "name_prefix", "inspect_content"),
			provider("gcp-secret-manager", "Google Secret Manager", "Metadata: secretmanager.secrets.list. Optional content inspection additionally needs secretmanager.versions.access on the filtered scope.", "token_ref", "project", "token_ref", "label_key", "label_value", "name_prefix", "inspect_content"),
			provider("azure-key-vault", "Azure Key Vault secrets", "Metadata: secrets/list. Optional content inspection additionally needs secrets/get on the filtered scope.", "token_ref", "vault_url", "token_ref", "name_prefix", "inspect_content"),
			provider("hashicorp-vault", "HashiCorp Vault KV", "Metadata: list/read on the approved metadata path. Optional content inspection additionally needs read on the filtered data path.", "token_ref", "vault_url", "api_version", "mount", "path_prefix", "token_ref", "inspect_content"),
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
		field("providers[].project", "Project", "string", false, false, false, "Authorized Google Cloud project."),
		field("providers[].location", "Location", "string", false, false, false, "Certificate Manager location."),
	}
	if secret {
		fields = append(fields,
			field("providers[].api_version", "Vault KV API version", "string", false, false, true, "KV v1 or v2 as configured on the mount."),
			field("providers[].mount", "Vault mount", "string", false, false, false, "Approved KV mount name."),
			field("providers[].path_prefix", "Vault path prefix", "string", false, false, false, "The least-privilege metadata path to list."),
			field("providers[].tag_key", "AWS tag key", "string", false, false, true, "Optional metadata-only inventory filter."),
			field("providers[].tag_value", "AWS tag value", "string", false, false, true, "Optional metadata-only inventory filter."),
			field("providers[].label_key", "GCP label key", "string", false, false, true, "Optional metadata-only inventory filter."),
			field("providers[].label_value", "GCP label value", "string", false, false, true, "Optional metadata-only inventory filter."),
			field("providers[].name_prefix", "Name prefix", "string", false, false, true, "Optional resource-name filter."),
			field("providers[].inspect_content", "Inspect content for certificates", "boolean", false, false, true, "Explicit opt-in to retrieve candidate values into wipeable memory and emit certificate metadata only."),
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
