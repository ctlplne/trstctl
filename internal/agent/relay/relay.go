// SPDX-License-Identifier: MPL-2.0

// Package relay is the agent-side executor for network-relay connector work
// (epic A3). It is what makes the credential lease mean something: a relay
// claims a connector job, redeems its credential for exactly that attempt,
// drives the appliance from inside its own network segment, and wipes.
//
// It runs in the agent binary, so it links only host-neutral packages — the
// connector core, the crypto boundary, and the transport contract. It has no
// database, no event log, no control-plane wiring; everything it learns arrives
// over the mTLS channel the agent opened outbound, and everything it reports
// goes back the same way. docs/agent_binary_import_boundary_test.go enforces
// that structurally.
//
// The custody contract, in order:
//
//  1. Claim a job. Its payload is a reference-only intent — names, never values.
//  2. Redeem, once, for this attempt. The material arrives and is moved
//     immediately into locked buffers (AN-8).
//  3. Execute inside secret.Buffer.Use, so the bytes are live only while the
//     connector holds them.
//  4. Destroy every buffer on every path, including panic and timeout.
//  5. Report. The agent's own words never carry the material: the control plane
//     withholds the detail of a credential-bearing attempt from durable history
//     precisely because a short appliance password defeats every redactor.
package relay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/connector/a10"
	"trstctl.com/trstctl/internal/connector/cisco"
	"trstctl.com/trstctl/internal/connector/f5"
	"trstctl.com/trstctl/internal/connector/fortigate"
	"trstctl.com/trstctl/internal/connector/kemp"
	"trstctl.com/trstctl/internal/connector/netscaler"
	"trstctl.com/trstctl/internal/connector/paloalto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// DeployIntent is the reference-only envelope a relay receives when it claims a
// connector job. It mirrors the control plane's projection: what to deploy and
// where, plus the NAMES of the credentials this attempt may redeem.
type DeployIntent struct {
	Connector      string          `json:"connector"`
	Target         string          `json:"target"`
	TargetID       string          `json:"target_id,omitempty"`
	Revision       string          `json:"target_revision,omitempty"`
	IdentityID     string          `json:"identity_id,omitempty"`
	Fingerprint    string          `json:"fingerprint,omitempty"`
	TargetConfig   json.RawMessage `json:"target_config,omitempty"`
	CredentialRefs []string        `json:"credential_refs,omitempty"`

	// VerifyAddress is the host:port of the listener this deploy updates, and
	// it is the one thing the pipeline could never derive (epic D2).
	//
	// Not TargetConfig.Endpoint: that is an appliance's MANAGEMENT API, and an
	// F5's management plane and the virtual server it fronts are different
	// sockets. Not Target either: that is a connector routing string. A
	// listener address is operator knowledge, so it arrives as operator
	// configuration or verification does not happen — and an empty value means
	// exactly that, rather than meaning verified.
	VerifyAddress string `json:"verify_address,omitempty"`
	// VerifyServerName overrides SNI when the listener answers to a name other
	// than the address host — a virtual host behind an IP, most often.
	VerifyServerName string `json:"verify_server_name,omitempty"`

	// SubjectCommonName and SubjectDNSNames name what a host-generated renewal
	// should certify (epic B2). Present on endpoint.renew only.
	//
	// They are an INSTRUCTION, not a grant. The control plane re-reads the same
	// names from the job payload it queued when the CSR arrives and refuses
	// anything outside that set, so an agent that edited these before building
	// its CSR would get a refusal rather than a wider certificate.
	SubjectCommonName string   `json:"subject_common_name,omitempty"`
	SubjectDNSNames   []string `json:"subject_dns_names,omitempty"`
	// PredecessorCertificateID is control-plane bookkeeping the agent never
	// reads. It is declared so the intent round-trips without loss.
	PredecessorCertificateID string `json:"predecessor_certificate_id,omitempty"`
}

// TargetConfig is the relay-side view of a deployment target: the routing
// fields the seven relay-vantage connectors need, and the reference NAMES for
// their credentials. It deliberately covers only relay-vantage connectors —
// host-local targets are a host agent's business, and cloud stores are the
// control plane's. RelayConnectorKinds is the census this must stay aligned
// with, and a guard test fails if the two drift.
type TargetConfig struct {
	Endpoint         string `json:"endpoint,omitempty"`
	Username         string `json:"username,omitempty"`
	PasswordRef      string `json:"password_ref,omitempty"`
	TokenRef         string `json:"token_ref,omitempty"`
	APIKeyRef        string `json:"api_key_ref,omitempty"`
	ObjectName       string `json:"object_name,omitempty"`
	ClientSSLProfile string `json:"client_ssl_profile,omitempty"`
	FileLocation     string `json:"file_location,omitempty"`
	SecretName       string `json:"secret_name,omitempty"`
	// PeerEndpoint names the standby BIG-IP of an F5 HA pair (epic E1). When
	// set, the relay deploys, rolls back, and reads back BOTH peers, because an
	// F5 pair keeps its certificate objects in separate stores — updating only
	// the active node leaves the standby serving the old certificate until a
	// failover. Empty is a single appliance, unchanged. The peer shares the
	// pair's synced admin credential; PeerObjectName overrides the crypto
	// object base name on the peer when it differs.
	PeerEndpoint   string `json:"peer_endpoint,omitempty"`
	PeerObjectName string `json:"peer_object_name,omitempty"`
}

// RelayConnectorKinds is the closed set a relay can execute.
//
// It READS the control plane's census rather than repeating it. The previous
// version was a second literal list under a comment asserting it was "exactly
// the connectors the control plane's census declares VantageNetworkRelay" — an
// alignment nothing enforced, and the same shape as the duplicated executor
// marker B2's review found, where a comment claimed a guard test existed and no
// such test did. Anything else reaching a relay is a bug in the claim gate and
// is refused here too rather than trusted.
func RelayConnectorKinds() []string {
	return connector.RelayVantageFamilies()
}

// Executes reports whether this relay can execute the named connector.
func Executes(name string) bool {
	for _, kind := range RelayConnectorKinds() {
		if kind == name {
			return true
		}
	}
	return false
}

// Material is the credential set redeemed for one attempt, keyed by reference
// name. The values are borrowed, not owned: Execute reads them inside the
// caller's locked-buffer lifetime and never retains them.
type Material map[string][]byte

// Execute drives one connector deploy against a real target and returns what
// the sandbox denied along the way.
//
// client is the relay's own HTTP client. It deliberately does NOT carry the
// control plane's egress guard or SSRF transport: a relay is inside the private
// segment by design, and re-running a public-internet egress policy here would
// block every appliance it exists to reach. That is a real reduction in what
// the control plane can promise about where a relay connects, and it is stated
// in docs/limitations.md rather than left to be discovered.
func Execute(ctx context.Context, client *http.Client, intent DeployIntent, material Material) (connector.Stats, error) {
	if !Executes(intent.Connector) {
		return connector.Stats{}, fmt.Errorf("relay: connector %q is not relay-executable", intent.Connector)
	}
	certPEM, ok := material["credential.cert_pem"]
	if !ok || len(certPEM) == 0 {
		return connector.Stats{}, errors.New("relay: redeemed material carries no certificate")
	}
	keyPEM, ok := material["credential.key_pem"]
	if !ok || len(keyPEM) == 0 {
		return connector.Stats{}, errors.New("relay: redeemed material carries no private key")
	}

	var target TargetConfig
	if len(intent.TargetConfig) > 0 {
		if err := json.Unmarshal(intent.TargetConfig, &target); err != nil {
			return connector.Stats{}, fmt.Errorf("relay: decode target config: %w", err)
		}
	}
	if strings.TrimSpace(target.Endpoint) == "" {
		return connector.Stats{}, errors.New("relay: target config carries no endpoint")
	}

	built, err := buildRelayConnector(intent.Connector, target, material)
	if err != nil {
		return connector.Stats{}, err
	}
	return connector.Run(ctx, built, connector.NewHTTPOps(client), connector.Deployment{
		Target:      intent.Target,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		Fingerprint: intent.Fingerprint,
	})
}

// RollbackIntent is an appliance re-bind or host-local restore an agent executes.
//
// It carries no certificate and no key. That is not an omission — it is the
// reason a rollback is executable at all: the control plane holds no subject
// key after B1. What travels is the predecessor's FINGERPRINT, which names an
// object already installed on an appliance or an encrypted predecessor in the
// exact host agent's local ledger.
type RollbackIntent struct {
	Connector    string          `json:"connector"`
	Target       string          `json:"target"`
	TargetID     string          `json:"target_id,omitempty"`
	IdentityID   string          `json:"identity_id,omitempty"`
	TargetConfig json.RawMessage `json:"target_config,omitempty"`
	// PredecessorFingerprint identifies the installed object to bind back to.
	PredecessorFingerprint string `json:"predecessor_fingerprint"`
	SuccessorFingerprint   string `json:"successor_fingerprint,omitempty"`
	// Host restores re-run the same local listener verification the successor
	// deploy used. Empty still means "restored but not listener-verified".
	VerifyAddress    string `json:"verify_address,omitempty"`
	VerifyServerName string `json:"verify_server_name,omitempty"`
	// Reason is operator context for the transcript. It never reaches the
	// appliance.
	Reason string `json:"reason,omitempty"`
}

// Rollback drives the appliance re-bind model. Host restore is implemented in
// runRollback because it needs the agent-local predecessor ledger.
//
// The credential material it takes is the APPLIANCE credential — the password
// or token that authenticates to the management interface — never a subject
// key. A relay still has to log in to re-point a listener; it just has nothing
// to upload once it is there.
func Rollback(ctx context.Context, client *http.Client, intent RollbackIntent, material Material) (connector.Stats, error) {
	if !Executes(intent.Connector) {
		return connector.Stats{}, fmt.Errorf("relay: connector %q is not relay-executable", intent.Connector)
	}
	if !connector.CanRollback(intent.Connector) {
		// Refused rather than attempted. A connector whose API cannot address an
		// installed object separately from uploading one has no re-bind to
		// perform, and pretending otherwise would report a rollback that did
		// nothing while a bad certificate kept serving traffic.
		return connector.Stats{}, connector.ErrRollbackUnsupported
	}
	if strings.TrimSpace(intent.PredecessorFingerprint) == "" {
		return connector.Stats{}, connector.ErrNoPredecessorInstalled
	}

	var target TargetConfig
	if len(intent.TargetConfig) > 0 {
		if err := json.Unmarshal(intent.TargetConfig, &target); err != nil {
			return connector.Stats{}, fmt.Errorf("relay: decode target config: %w", err)
		}
	}
	if strings.TrimSpace(target.Endpoint) == "" {
		return connector.Stats{}, errors.New("relay: target config carries no endpoint")
	}

	built, err := buildRelayConnector(intent.Connector, target, material)
	if err != nil {
		return connector.Stats{}, err
	}
	return connector.RunRollback(ctx, built, connector.NewHTTPOps(client), connector.Rollback{
		Target:                 intent.Target,
		PredecessorFingerprint: intent.PredecessorFingerprint,
		Reason:                 intent.Reason,
	})
}

// RollbackCapableKinds is the relay-side census: connectors this relay can both
// reach AND re-bind. It is the intersection, because either half missing means
// the same thing to an operator — this rollback will not execute here.
func RollbackCapableKinds() []string {
	var out []string
	for _, kind := range RelayConnectorKinds() {
		if connector.CanRollback(kind) {
			out = append(out, kind)
		}
	}
	return out
}

// RollbackExecutableKinds is the full agent-side rollback surface: appliance
// re-bind plus host-local predecessor restore. Each row's role still chooses
// the correct executor.
func RollbackExecutableKinds() []string {
	out := append([]string(nil), RollbackCapableKinds()...)
	out = append(out, HostConnectorKinds()...)
	sort.Strings(out)
	return out
}

// buildRelayConnector constructs the named appliance connector from the target's
// routing fields and the credential the relay redeemed for this attempt. It
// mirrors the control plane's factory for the same seven kinds — same
// constructors, same options — because they are the same implementations; only
// the host differs.
func buildRelayConnector(name string, target TargetConfig, material Material) (connector.Connector, error) {
	// require pulls a redeemed value by reference name. A missing reference is a
	// refusal, never an empty credential: deploying with no password would
	// either fail confusingly or, worse, succeed against an unauthenticated
	// appliance.
	require := func(ref, what string) ([]byte, error) {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return nil, fmt.Errorf("relay: %s connector needs a %s reference", name, what)
		}
		value, ok := material[ref]
		if !ok || len(value) == 0 {
			return nil, fmt.Errorf("relay: %s was not redeemed for this attempt", what)
		}
		return value, nil
	}

	switch name {
	case "f5":
		password, err := require(target.PasswordRef, "f5 password")
		if err != nil {
			return nil, err
		}
		options := []f5.Option{f5.WithBasicAuthBytes(target.Username, password)}
		if target.ObjectName != "" {
			options = append(options, f5.WithName(target.ObjectName))
		}
		active := f5.New(target.Endpoint, target.ClientSSLProfile, options...)
		if strings.TrimSpace(target.PeerEndpoint) == "" {
			return active, nil
		}
		// HA pair: the standby shares the synced admin credential (E1). Both
		// peers must converge, so the relay drives an HAPair over them.
		peerOptions := []f5.Option{f5.WithBasicAuthBytes(target.Username, password)}
		peerName := target.ObjectName
		if target.PeerObjectName != "" {
			peerName = target.PeerObjectName
		}
		if peerName != "" {
			peerOptions = append(peerOptions, f5.WithName(peerName))
		}
		peer := f5.New(target.PeerEndpoint, target.ClientSSLProfile, peerOptions...)
		return f5.NewHAPair(active, peer), nil
	case "netscaler":
		password, err := require(target.PasswordRef, "netscaler password")
		if err != nil {
			return nil, err
		}
		var options []netscaler.Option
		if target.FileLocation != "" {
			options = append(options, netscaler.WithFileLocation(target.FileLocation))
		}
		return netscaler.New(target.Endpoint, target.Username, password, options...), nil
	case "a10":
		password, err := require(target.PasswordRef, "a10 password")
		if err != nil {
			return nil, err
		}
		return a10.New(target.Endpoint, target.Username, password), nil
	case "kemp":
		token, err := require(target.TokenRef, "kemp token")
		if err != nil {
			return nil, err
		}
		return kemp.New(target.Endpoint, token), nil
	case "cisco":
		password, err := require(target.PasswordRef, "cisco password")
		if err != nil {
			return nil, err
		}
		return cisco.New(target.Endpoint, target.Username, password), nil
	case "fortigate":
		token, err := require(target.TokenRef, "fortigate token")
		if err != nil {
			return nil, err
		}
		return fortigate.New(target.Endpoint, token), nil
	case "paloalto":
		apiKey, err := require(target.APIKeyRef, "palo alto api key")
		if err != nil {
			return nil, err
		}
		return paloalto.New(target.Endpoint, apiKey), nil
	default:
		return nil, fmt.Errorf("relay: connector %q is not relay-executable", name)
	}
}

// AdoptMaterial moves redeemed values into locked, zeroized buffers (AN-8) and
// returns them alongside the destroy that ends their life. The caller MUST
// defer destroy on every path.
//
// The wire values are wiped as they are adopted, so the only surviving copies
// are the locked ones. A failure part-way through destroys everything already
// adopted rather than leaking the ones that succeeded.
func AdoptMaterial(items map[string][]byte) (Material, func(), error) {
	buffers := make([]*secret.Buffer, 0, len(items))
	destroy := func() {
		for _, buffer := range buffers {
			buffer.Destroy()
		}
	}
	out := make(Material, len(items))
	names := make([]string, 0, len(items))
	for name := range items {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		value := items[name]
		buffer, err := secret.NewFrom(value)
		secret.Wipe(value)
		if err != nil {
			destroy()
			return nil, func() {}, fmt.Errorf("relay: adopt %s: %w", name, err)
		}
		buffers = append(buffers, buffer)
		out[name] = buffer.Bytes()
	}
	return out, destroy, nil
}
