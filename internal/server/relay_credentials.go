// SPDX-License-Identifier: MPL-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/agent/transport"
	"trstctl.com/trstctl/internal/connector"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// Just-in-time credential resolution for relay jobs (epic A3).
//
// A claimed connector job carries references; this is the control-plane side
// that turns them back into material for exactly one redeemed attempt. The
// sealed payload is opened here — never on the agent, which cannot open it and
// must never be able to — and each secret:// reference in the target config is
// resolved through the same tenant-sealed secret store the control plane's own
// delivery path uses, into locked buffers that are destroyed the moment the
// response is encoded.
//
// The names of the references are metadata (they already appear in the tenant's
// target configuration); the VALUES exist outside the seal only between
// resolution and wipe.

// relayCredentialResolver holds the custody dependencies. It is constructed in
// the agent-channel assembly from the same Deps the issuance dispatcher seals
// with, so the two sides of the seal can never use different keys.
type relayCredentialResolver struct {
	store        *store.Store
	kek          sealKeyWrapper
	tenantCrypto tenantseal.Access
}

// redeemedMaterial is one resolved attempt's material plus the wipe that ends
// its life outside the seal. Wipe is safe to call more than once.
type redeemedMaterial struct {
	items    []transport.RedeemedSecret
	refNames []string
	wipe     func()
}

// resolveJobCredential opens a claimed connector job's sealed payload and
// resolves every credential reference it carries. Nothing is returned for
// non-connector destinations: no other job kind references credentials, and a
// redemption request against one is a caller doing something the protocol does
// not mean.
func (r *relayCredentialResolver) resolveJobCredential(
	ctx context.Context,
	tenantID string,
	job store.AgentJobForRedemption,
) (redeemedMaterial, error) {
	switch job.Destination {
	case "adcs.inventory":
		// F1: an AD CS inventory redeems a directory bind credential. Its
		// payload is not a sealed connector deploy, so it resolves the
		// secret:// references named in the job payload directly.
		return r.resolveJobReferences(ctx, tenantID, job)
	case "connector.deploy", "connector.rollback", "connector.test":
		// connector.test redeems too (D5). A dry-run exists to find out whether
		// the credential works; one that skipped redemption would pass right up
		// until the deploy that mattered.
	default:
		return redeemedMaterial{}, fmt.Errorf("job kind %q carries no redeemable credential", job.Destination)
	}
	if r == nil || r.store == nil {
		return redeemedMaterial{}, errors.New("relay credential resolution is not configured")
	}

	payload, err := r.openSealedDeploy(ctx, tenantID, job)
	if err != nil {
		return redeemedMaterial{}, err
	}
	// The opened payload's key bytes are wiped on EVERY exit path below; on
	// success their ownership passes to the returned material's wipe.

	lease := &connectorCredentialLease{store: r.store, kek: r.kek, crypto: r.tenantCrypto, tenantID: tenantID}
	wipeAll := func() {
		wipeConnectorDeployPayload(&payload)
		lease.Close()
	}

	var items []transport.RedeemedSecret
	var refNames []string
	if len(payload.CertPEM) > 0 {
		items = append(items, transport.RedeemedSecret{Name: "credential.cert_pem", Value: secret.JSONBytes(payload.CertPEM)})
		refNames = append(refNames, "credential.cert_pem")
	}
	if len(payload.KeyPEM) > 0 {
		items = append(items, transport.RedeemedSecret{Name: "credential.key_pem", Value: secret.JSONBytes(payload.KeyPEM)})
		refNames = append(refNames, "credential.key_pem")
	}
	for _, ref := range collectSecretRefs(payload.TargetConfig) {
		value, leaseErr := lease.require(ctx, ref)
		if leaseErr != nil {
			wipeAll()
			return redeemedMaterial{}, fmt.Errorf("resolve credential reference: %w", leaseErr)
		}
		items = append(items, transport.RedeemedSecret{Name: ref, Value: secret.JSONBytes(value)})
		refNames = append(refNames, ref)
	}
	return redeemedMaterial{items: items, refNames: refNames, wipe: wipeAll}, nil
}

// resolveJobReferences resolves the secret:// references a non-connector job
// names, without opening a sealed connector container — there is none. It is
// the same tenant-sealed secret-store read the connector path uses, so a
// reference behaves identically whichever kind of job named it.
func (r *relayCredentialResolver) resolveJobReferences(
	ctx context.Context,
	tenantID string,
	job store.AgentJobForRedemption,
) (redeemedMaterial, error) {
	refs := collectSecretRefs(job.Payload)
	if len(refs) == 0 {
		return redeemedMaterial{}, errors.New("job names no credential references to redeem")
	}
	lease := &connectorCredentialLease{store: r.store, kek: r.kek, crypto: r.tenantCrypto, tenantID: tenantID}
	var items []transport.RedeemedSecret
	var refNames []string
	for _, ref := range refs {
		value, err := lease.require(ctx, ref)
		if err != nil {
			lease.Close()
			return redeemedMaterial{}, fmt.Errorf("resolve credential reference: %w", err)
		}
		items = append(items, transport.RedeemedSecret{Name: ref, Value: secret.JSONBytes(value)})
		refNames = append(refNames, ref)
	}
	return redeemedMaterial{items: items, refNames: refNames, wipe: lease.Close}, nil
}

// openSealedDeploy opens the sealed container the dispatcher wrote at enqueue,
// binding the same AAD — tenant, destination, idempotency key, identity,
// fingerprint — so a row moved between tenants or destinations does not open.
func (r *relayCredentialResolver) openSealedDeploy(
	ctx context.Context,
	tenantID string,
	job store.AgentJobForRedemption,
) (connector.DeployPayload, error) {
	var wrapped sealedConnectorDeployPayload
	if err := json.Unmarshal(job.Payload, &wrapped); err != nil || wrapped.Format != connectorDeploySealedFormat {
		// An unsealed connector payload carries no key material by construction
		// (sealConnectorDeployBytes passes key-less payloads through), so there
		// is nothing to redeem — refuse rather than hand back an empty grant.
		return connector.DeployPayload{}, errors.New("job payload is not a sealed credential container")
	}
	if wrapped.Version != connectorDeploySealedVersion || len(wrapped.Sealed) == 0 {
		return connector.DeployPayload{}, errors.New("unsupported sealed connector deploy payload")
	}
	if r.kek == nil {
		return connector.DeployPayload{}, errors.New("sealed connector payload requires a credential KEK")
	}
	identityID := strings.TrimSpace(wrapped.IdentityID)
	fingerprint := strings.TrimSpace(wrapped.Fingerprint)
	plaintext, err := openTenantValue(ctx, r.tenantCrypto, r.kek, tenantID, wrapped.Sealed,
		connectorDeployAAD(tenantID, job.Destination, job.IdempotencyKey, identityID, fingerprint))
	if err != nil {
		return connector.DeployPayload{}, fmt.Errorf("open sealed connector deploy payload: %w", err)
	}
	defer secret.Wipe(plaintext)
	var p connector.DeployPayload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return connector.DeployPayload{}, fmt.Errorf("decode sealed connector deploy payload: %w", err)
	}
	if strings.TrimSpace(p.IdentityID) != identityID || strings.TrimSpace(p.Fingerprint) != fingerprint {
		wipeConnectorDeployPayload(&p)
		return connector.DeployPayload{}, errors.New("sealed connector deploy payload metadata mismatch")
	}
	// The routing fields the agent was told about must match what the seal
	// actually holds. They are outside the AAD (see sealedConnectorDeployPayload),
	// so this is where tampering is caught — before any credential moves. Rows
	// sealed before those fields existed carry them empty and skip the check.
	if publicConnector := strings.TrimSpace(wrapped.Connector); publicConnector != "" && publicConnector != strings.TrimSpace(p.Connector) {
		wipeConnectorDeployPayload(&p)
		return connector.DeployPayload{}, errors.New("sealed connector deploy payload routing mismatch")
	}
	if publicTarget := strings.TrimSpace(wrapped.Target); publicTarget != "" && publicTarget != strings.TrimSpace(p.Target) {
		wipeConnectorDeployPayload(&p)
		return connector.DeployPayload{}, errors.New("sealed connector deploy payload routing mismatch")
	}
	return p, nil
}

// collectSecretRefs walks a target config and returns every secret:// reference
// in it, deduplicated and ordered. Walking the JSON rather than the per-connector
// typed schema means a connector added later cannot silently carry a reference
// this misses: any string value that IS a reference is resolved, whatever field
// it sits in.
func collectSecretRefs(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var walk func(v any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			if strings.HasPrefix(strings.TrimSpace(t), "secret://") {
				seen[strings.TrimSpace(t)] = true
			}
		case map[string]any:
			for _, child := range t {
				walk(child)
			}
		case []any:
			for _, child := range t {
				walk(child)
			}
		}
	}
	walk(decoded)
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for ref := range seen {
		out = append(out, ref)
	}
	sort.Strings(out)
	return out
}

// RelayDeployIntent is what a relay actually receives when it claims a connector
// job (epic A3): enough to know what to deploy and where, and the NAMES of the
// credentials it may redeem — never the credentials, and never the sealed
// container holding them.
//
// The agent cannot open the seal, so shipping it would be pointless; worse, it
// would leave a copy of the tenant's credential ciphertext sitting on a host in
// the estate, waiting for a future key compromise to make it readable. The
// reference names are already visible to the tenant in its own target config.
type RelayDeployIntent struct {
	Connector    string          `json:"connector"`
	Target       string          `json:"target"`
	TargetID     string          `json:"target_id,omitempty"`
	Revision     string          `json:"target_revision,omitempty"`
	IdentityID   string          `json:"identity_id,omitempty"`
	Fingerprint  string          `json:"fingerprint,omitempty"`
	TargetConfig json.RawMessage `json:"target_config,omitempty"`
	// CredentialRefs names what RedeemJobCredential will return for this
	// attempt, so an agent can refuse work it has no executor for before
	// redeeming anything.
	CredentialRefs []string `json:"credential_refs,omitempty"`
}

// relayDeployIntentFromSealed reads the PUBLIC envelope of a sealed connector
// payload and builds the agent's intent. It never opens the seal: everything
// here comes from the unsealed wrapper the dispatcher wrote alongside it, which
// is why this can run on the claim path with no custody dependency at all.
func relayDeployIntentFromSealed(job store.AgentJob) (RelayDeployIntent, error) {
	var wrapped sealedConnectorDeployPayload
	if err := json.Unmarshal(job.Payload, &wrapped); err != nil {
		return RelayDeployIntent{}, fmt.Errorf("decode connector job envelope: %w", err)
	}
	if wrapped.Format != connectorDeploySealedFormat {
		// An unsealed connector payload carries no key material by construction
		// (the dispatcher passes key-less payloads through unsealed), so its
		// public fields are safe to project directly.
		var plain connector.DeployPayload
		if err := json.Unmarshal(job.Payload, &plain); err != nil {
			return RelayDeployIntent{}, fmt.Errorf("decode connector job payload: %w", err)
		}
		if len(plain.KeyPEM) > 0 {
			// Defensive: an unsealed payload must never carry key material.
			return RelayDeployIntent{}, errors.New("unsealed connector job carries key material")
		}
		return RelayDeployIntent{
			Connector: plain.Connector, Target: plain.Target, TargetID: plain.TargetID,
			Revision: plain.TargetRevision, IdentityID: plain.IdentityID,
			Fingerprint: plain.Fingerprint, TargetConfig: plain.TargetConfig,
			CredentialRefs: collectSecretRefs(plain.TargetConfig),
		}, nil
	}
	// Sealed: the routing fields ride outside the seal precisely so this
	// projection needs no custody. The credential reference names tell the agent
	// what it will be handed, so it can refuse work it has no executor for
	// before redeeming anything.
	refs := []string{"credential.cert_pem", "credential.key_pem"}
	refs = append(refs, collectSecretRefs(wrapped.TargetConfig)...)
	return RelayDeployIntent{
		Connector:      strings.TrimSpace(wrapped.Connector),
		Target:         strings.TrimSpace(wrapped.Target),
		TargetID:       strings.TrimSpace(wrapped.TargetID),
		Revision:       strings.TrimSpace(wrapped.Revision),
		IdentityID:     strings.TrimSpace(wrapped.IdentityID),
		Fingerprint:    strings.TrimSpace(wrapped.Fingerprint),
		TargetConfig:   append(json.RawMessage(nil), wrapped.TargetConfig...),
		CredentialRefs: refs,
	}, nil
}

// RelayRollbackIntent is what a relay receives when it claims a rollback job
// (epic D4).
//
// It carries no certificate and no key, and it never needs to: a rollback
// re-binds a listener to an object already installed on the appliance. The
// credential reference names are the APPLIANCE credential — what authenticates
// to the management interface — because a relay still has to log in to
// re-point a listener.
type RelayRollbackIntent struct {
	Connector    string          `json:"connector"`
	Target       string          `json:"target"`
	TargetID     string          `json:"target_id,omitempty"`
	IdentityID   string          `json:"identity_id,omitempty"`
	TargetConfig json.RawMessage `json:"target_config,omitempty"`
	// PredecessorFingerprint names the installed object to bind back to.
	PredecessorFingerprint string   `json:"predecessor_fingerprint"`
	Reason                 string   `json:"reason,omitempty"`
	CredentialRefs         []string `json:"credential_refs,omitempty"`
}

// projectRollbackIntent builds the agent's view of a rollback job.
//
// A rollback payload is enqueued unsealed because it holds nothing to seal. The
// projection still runs so credential REFERENCES are named — the agent refuses
// work it cannot execute before redeeming anything — and so a payload that
// somehow carried key material is refused rather than forwarded.
func projectRollbackIntent(job store.AgentJob) ([]byte, error) {
	var intent RelayRollbackIntent
	if err := json.Unmarshal(job.Payload, &intent); err != nil {
		return nil, fmt.Errorf("decode connector rollback payload: %w", err)
	}
	if strings.TrimSpace(intent.PredecessorFingerprint) == "" {
		return nil, errors.New("connector rollback payload names no predecessor")
	}
	// Defensive, and cheap: nothing about a rollback should ever carry a key,
	// so a payload that does is a bug worth failing on rather than shipping to
	// a host in the estate.
	if bytes.Contains(job.Payload, []byte("PRIVATE KEY")) {
		return nil, errors.New("connector rollback payload carries key material")
	}
	intent.CredentialRefs = collectSecretRefs(intent.TargetConfig)
	return json.Marshal(intent)
}

// sealRelayDeployForTest seals a connector deploy payload through the SAME
// resolver, KEK, tenant custody and AAD the redemption path opens with. It
// exists so an acceptance test can enqueue a genuinely sealed relay job rather
// than a hand-rolled approximation that could pass while production sealing is
// broken. It is a thin wrapper over the production seal — no test-only crypto.
func (s *Server) sealRelayDeployForTest(ctx context.Context, tenantID, destination, idempotencyKey string, payload []byte) ([]byte, error) {
	svc, ok := s.agentServiceForTest()
	if !ok || svc.relayCredentials == nil {
		return nil, errors.New("relay credential resolver is not assembled")
	}
	r := svc.relayCredentials
	var p connector.DeployPayload
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, err
	}
	identityID := strings.TrimSpace(p.IdentityID)
	fingerprint := strings.TrimSpace(p.Fingerprint)
	sealed, err := sealTenantValue(ctx, r.tenantCrypto, r.kek, tenantID, payload,
		connectorDeployAAD(tenantID, destination, idempotencyKey, identityID, fingerprint))
	if err != nil {
		return nil, err
	}
	return json.Marshal(sealedConnectorDeployPayload{
		Format:      connectorDeploySealedFormat,
		Version:     connectorDeploySealedVersion,
		IdentityID:  identityID,
		Fingerprint: fingerprint,
		Sealed:      sealed,
	})
}

// sealTenantSecretForTest seals a value for the tenant secret store the same way
// the served secrets API does, so a test can plant a secret:// reference target.
func (s *Server) sealTenantSecretForTest(ctx context.Context, tenantID, name string, value []byte) ([]byte, error) {
	svc, ok := s.agentServiceForTest()
	if !ok || svc.relayCredentials == nil {
		return nil, errors.New("relay credential resolver is not assembled")
	}
	r := svc.relayCredentials
	return sealTenantValue(ctx, r.tenantCrypto, r.kek, tenantID, value,
		[]byte(tenantID+"/secret-store/"+name))
}

// agentServiceForTest unwraps the bulkheaded channel service to the concrete
// implementation. The two helpers above need the assembled resolver, and the
// bulkhead wrapper does not expose it.
func (s *Server) agentServiceForTest() (*agentService, bool) {
	switch svc := s.agentSvc.(type) {
	case *agentService:
		return svc, true
	case *bulkheadedAgentService:
		inner, ok := svc.next.(*agentService)
		return inner, ok
	default:
		return nil, false
	}
}
