// SPDX-License-Identifier: MPL-2.0

package coverage

import "time"

// AssetClass is a category of credential or cryptographic estate a discovery
// source can observe. Classes are declared per served source kind below; the
// classification buckets are computed over the union of all declared classes
// plus the structurally-unobservable classes in unobservable.go.
type AssetClass string

const (
	AssetTLSEndpoint          AssetClass = "tls-endpoint"
	AssetCertificateKey       AssetClass = "certificate-key"
	AssetSSHHostKey           AssetClass = "ssh-host-key"
	AssetSSHPrivateKey        AssetClass = "ssh-private-key"
	AssetCloudCertificate     AssetClass = "cloud-certificate"
	AssetStoredSecret         AssetClass = "stored-secret"
	AssetCTExposedCertificate AssetClass = "ct-exposed-certificate"
	AssetDeployedCertificate  AssetClass = "deployed-certificate"
	AssetNHIIdentity          AssetClass = "nhi-identity"
	AssetOAuthGrant           AssetClass = "oauth-grant"
	AssetServiceAccount       AssetClass = "service-account"
	AssetNHIBehavior          AssetClass = "nhi-behavior"
	AssetAPIKeyToken          AssetClass = "api-key-token"
	AssetCompromisedCred      AssetClass = "compromised-credential"
	AssetKubernetesTLS        AssetClass = "kubernetes-tls-endpoint"
	AssetRepositorySecret     AssetClass = "repository-secret"
	AssetThirdPartySecret     AssetClass = "third-party-secret"
	AssetOperatorDeclared     AssetClass = "operator-declared"
)

// Precondition names what must be true of the deployment before a source of a
// kind can observe its classes. Preconditions surface in UNOBSERVED reasons so
// every gap names the action that would close it.
type Precondition string

const (
	PrecondRangesConfigured     Precondition = "scan-ranges-configured"
	PrecondTargetsConfigured    Precondition = "scan-targets-configured"
	PrecondCloudCredential      Precondition = "cloud-credential-configured"
	PrecondDomainsConfigured    Precondition = "monitored-domains-configured"
	PrecondBaselineConfigured   Precondition = "deployment-baseline-configured"
	PrecondConnectorCredential  Precondition = "connector-credential-configured"
	PrecondClusterCredential    Precondition = "cluster-credential-configured"
	PrecondRepositoryConfigured Precondition = "repository-configured"
	PrecondOperatorFindings     Precondition = "operator-supplied-findings"
)

// DefaultFreshness is the declared window after a completed run inside which
// an observation still counts as OBSERVED. Discovery is operator-scheduled;
// a day-old successful run is the declared default for "current" across all
// kinds until a kind earns a sharper window.
const DefaultFreshness = 24 * time.Hour

// Envelope is one source kind's observability declaration: what it can see,
// what the deployment must provide for it to run, and how long an observation
// stays fresh.
type Envelope struct {
	Kind          string
	Observes      []AssetClass
	Preconditions []Precondition
	Freshness     time.Duration
}

// ManualKind is the served fallback: a source of any kind with no dedicated
// connector records operator-supplied findings. Its envelope is exactly that —
// the operator's own declarations, nothing observed by trstctl itself.
const ManualKind = "manual"

// Envelopes returns the observability envelope for every served discovery
// source kind, keyed by kind. TestEveryDiscoverySourceDeclaresEnvelope welds
// this registry to the server's executable set in both directions; edit the
// two together.
func Envelopes() map[string]Envelope {
	env := func(kind string, observes []AssetClass, pre ...Precondition) Envelope {
		return Envelope{Kind: kind, Observes: observes, Preconditions: pre, Freshness: DefaultFreshness}
	}
	out := map[string]Envelope{}
	for _, e := range []Envelope{
		// Active TLS handshakes against declared ranges: what is listening,
		// and the certificate it serves — never passive capture (F2).
		env("network", []AssetClass{AssetTLSEndpoint, AssetCertificateKey}, PrecondRangesConfigured),
		// Host-key scans plus on-host private-key inventory (F42).
		env("ssh", []AssetClass{AssetSSHHostKey, AssetSSHPrivateKey}, PrecondTargetsConfigured),
		// Agentless cloud certificate managers: ACM, Key Vault, GCP CM (F49).
		env("cloud_certificate", []AssetClass{AssetCloudCertificate}, PrecondCloudCredential),
		// Secret-manager metadata, never values (F35/F36). secret_store is a
		// served alias routed through the same connectors.
		env("cloud_secret", []AssetClass{AssetStoredSecret}, PrecondCloudCredential),
		env("secret_store", []AssetClass{AssetStoredSecret}, PrecondCloudCredential),
		env("ct_log", []AssetClass{AssetCTExposedCertificate}, PrecondDomainsConfigured),
		env("drift", []AssetClass{AssetDeployedCertificate}, PrecondBaselineConfigured),
		env("nhi_cross_surface", []AssetClass{AssetNHIIdentity}, PrecondConnectorCredential),
		env("oauth_grant", []AssetClass{AssetOAuthGrant}, PrecondConnectorCredential),
		env("service_account", []AssetClass{AssetServiceAccount}, PrecondConnectorCredential),
		env("nhi_behavior", []AssetClass{AssetNHIBehavior}, PrecondConnectorCredential),
		env("api_key", []AssetClass{AssetAPIKeyToken}, PrecondConnectorCredential),
		env("credential_compromise", []AssetClass{AssetCompromisedCred}, PrecondConnectorCredential),
		env("k8s_ingress_gateway", []AssetClass{AssetKubernetesTLS}, PrecondClusterCredential),
		env("secret_repo", []AssetClass{AssetRepositorySecret}, PrecondRepositoryConfigured),
		env("secret_third_party", []AssetClass{AssetThirdPartySecret}, PrecondConnectorCredential),
		env(ManualKind, []AssetClass{AssetOperatorDeclared}, PrecondOperatorFindings),
	} {
		out[e.Kind] = e
	}
	return out
}

// EnvelopeFor resolves a source kind to its envelope; a kind with no dedicated
// connector resolves to the manual envelope, mirroring the server's fallback.
func EnvelopeFor(kind string) Envelope {
	if e, ok := Envelopes()[kind]; ok {
		return e
	}
	return Envelopes()[ManualKind]
}
