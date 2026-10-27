// SPDX-License-Identifier: BUSL-1.1

// Package relying is the relying-service half of the agent framework reference
// integration. It decides whether to honor a tool call an agent makes, from four
// things: the agent's identity on the mutually authenticated connection, the
// chain-bound credential the agent presents, the delegation chain behind that
// credential, and the credential's current status in trstctl.
//
// The credential and its scope are verified offline against the tenant's pinned
// issuing CA by trstctl's relying-party verifier. The chain and the status are read
// from trstctl's API: the chain once per credential, the status at most once per
// StatusTTL, which bounds how long a revoked credential keeps working here.
package relying

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"trstctl.com/trstctl/internal/agentid/delegation"
	"trstctl.com/trstctl/internal/agentid/verify"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/test/interop/agentframeworks/present"
)

// The headers an agent presents its delegated credential in, on every request.
const (
	CredentialHeader   = present.CredentialHeader
	CredentialIDHeader = present.CredentialIDHeader
)

// Policy is what the relying service's operator decided to honor.
type Policy struct {
	// ApprovedAgentStacks are the hex agent-stack digests (prompt, tool manifest and
	// model) this service accepts.
	ApprovedAgentStacks []string `json:"approved_agent_stacks"`
	// ToolManifest is the tool manifest bound in those agent stacks.
	ToolManifest []string `json:"tool_manifest"`
	// Operations maps an authority class to the operations it may perform here.
	Operations map[string][]string `json:"operations"`
	// ToolOperations names the operation each served tool performs.
	ToolOperations map[string]string `json:"tool_operations"`
}

// Config configures a Gate. Everything in it is pinned by the operator.
type Config struct {
	TenantID string
	// IssuingCADER is the tenant's agent issuing CA certificate
	// (GET /api/v1/agent-delegation/issuing-ca).
	IssuingCADER []byte
	// RootAnchorDERs are the tenant's delegation root public keys
	// (GET /api/v1/agent-delegation/root-anchors).
	RootAnchorDERs [][]byte
	Policy         Policy
	// Trstctl reads delegation chains and credential status.
	Trstctl *Client
	// StatusTTL is how long one status read is reused.
	StatusTTL time.Duration
	// Audit receives one JSON line per decision.
	Audit io.Writer
	Now   func() time.Time
}

// Presentation is what one request carries: the agent ID its verified connection
// identity names, and the credential it presents.
type Presentation struct {
	AgentID       string
	CredentialID  string
	CredentialDER []byte
}

// PresentationFromHeaders reads the credential headers. A missing or malformed
// credential leaves its field empty, and Authorize refuses it.
func PresentationFromHeaders(agentID string, header func(string) string) Presentation {
	p := Presentation{AgentID: agentID, CredentialID: strings.TrimSpace(header(CredentialIDHeader))}
	if der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header(CredentialHeader))); err == nil {
		p.CredentialDER = der
	}
	return p
}

// Decision is the outcome of one authorization.
type Decision struct {
	Allowed bool
	Reason  string
}

// AuditRecord is one decision as the audit log records it.
type AuditRecord struct {
	Time         time.Time `json:"time"`
	Agent        string    `json:"agent"`
	CredentialID string    `json:"credential_id"`
	Tool         string    `json:"tool"`
	Operation    string    `json:"operation"`
	Allowed      bool      `json:"allowed"`
	Reason       string    `json:"reason"`
	// Chain is the delegation path from the root principal to the agent, verified
	// against the chain head the credential binds.
	Chain       []string `json:"chain,omitempty"`
	Status      string   `json:"status,omitempty"`
	DirectiveID string   `json:"directive_id,omitempty"`
}

// Gate authorizes tool calls.
type Gate struct {
	cfg    Config
	policy verify.LocalPolicy

	mu       sync.Mutex
	statuses map[string]cachedStatus
	chains   map[string][]string
	auditMu  sync.Mutex
}

type cachedStatus struct {
	status CredentialStatus
	read   time.Time
}

// NewGate validates the configuration and builds a gate.
func NewGate(cfg Config) (*Gate, error) {
	if cfg.TenantID == "" || len(cfg.IssuingCADER) == 0 || len(cfg.RootAnchorDERs) == 0 {
		return nil, errors.New("relying: a tenant, its issuing CA and at least one root anchor are required")
	}
	if cfg.Trstctl == nil {
		return nil, errors.New("relying: a trstctl client is required")
	}
	if cfg.StatusTTL <= 0 {
		return nil, errors.New("relying: a positive status TTL is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Audit == nil {
		cfg.Audit = io.Discard
	}
	policy := verify.NewLocalPolicy().WithToolManifest(cfg.Policy.ToolManifest...)
	for _, stack := range cfg.Policy.ApprovedAgentStacks {
		digest, err := hex.DecodeString(stack)
		if err != nil || len(digest) == 0 {
			return nil, fmt.Errorf("relying: approved agent stack %q is not a hex digest", stack)
		}
		policy = policy.ApproveAgentStack(digest)
	}
	for class, ops := range cfg.Policy.Operations {
		policy = policy.PermitClass(class).GrantOperations(class, ops...)
	}
	return &Gate{cfg: cfg, policy: policy, statuses: map[string]cachedStatus{}, chains: map[string][]string{}}, nil
}

// Authorize decides one tool call and records the decision in the audit log.
func (g *Gate) Authorize(ctx context.Context, p Presentation, tool string) Decision {
	rec := AuditRecord{Time: g.cfg.Now().UTC(), Agent: p.AgentID, CredentialID: p.CredentialID, Tool: tool}
	decision := g.authorize(ctx, p, tool, &rec)
	rec.Allowed, rec.Reason = decision.Allowed, decision.Reason
	g.writeAudit(rec)
	return decision
}

func (g *Gate) authorize(ctx context.Context, p Presentation, tool string, rec *AuditRecord) Decision {
	op, served := g.cfg.Policy.ToolOperations[tool]
	if !served {
		return Decision{Reason: "this service does not serve tool " + tool}
	}
	rec.Operation = op
	if p.AgentID == "" {
		return Decision{Reason: "the connection carried no agent identity"}
	}
	if len(p.CredentialDER) == 0 || p.CredentialID == "" {
		return Decision{Reason: "no delegated credential was presented"}
	}
	// 1. The credential, its agent stack and its authority, offline.
	if _, err := verify.Verify(
		verify.Credential{Form: verify.FormX509, Bytes: p.CredentialDER},
		verify.TrustRoot{CACertDER: g.cfg.IssuingCADER},
		g.policy,
		verify.Action{Operation: op, Tool: tool},
		clock{g.cfg.Now},
	); err != nil {
		return Decision{Reason: "the delegated credential does not authorize this call: " + strings.TrimPrefix(err.Error(), "verify: ")}
	}
	// 2. The chain: the credential was delegated to the agent on this connection,
	// from one of the tenant's root principals.
	chain, err := g.chain(ctx, p)
	if err != nil {
		return Decision{Reason: err.Error()}
	}
	rec.Chain = chain
	// 3. The credential's status in trstctl, read at most once per StatusTTL.
	status, err := g.status(ctx, p.CredentialID)
	if err != nil {
		return Decision{Reason: "the credential's status could not be read, so it is not honored"}
	}
	rec.Status, rec.DirectiveID = status.Status, status.DirectiveID
	if status.CredentialSHA256 != crypto.SHA256Hex(p.CredentialDER) {
		return Decision{Reason: "the presented credential is not the one trstctl issued under that ID"}
	}
	if status.Status != "active" {
		return Decision{Reason: "the credential is " + status.Status + " in trstctl"}
	}
	return Decision{Allowed: true, Reason: "within the delegated scope"}
}

// chain reads and verifies a credential's delegation chain once, then reuses the
// verified path for that credential.
func (g *Gate) chain(ctx context.Context, p Presentation) ([]string, error) {
	g.mu.Lock()
	path, ok := g.chains[p.CredentialID]
	g.mu.Unlock()
	if !ok {
		records, err := g.cfg.Trstctl.Chain(ctx, p.CredentialID)
		if err != nil {
			return nil, errors.New("the credential's delegation chain could not be read")
		}
		bound, err := delegation.ExtractBindingMaterial(p.CredentialDER)
		if err != nil {
			return nil, errors.New("the credential binds no delegation chain")
		}
		path, err = VerifyChain(g.cfg.TenantID, records, g.cfg.RootAnchorDERs, bound.ChainHeadDigest)
		if err != nil {
			return nil, err
		}
		g.mu.Lock()
		g.chains[p.CredentialID] = path
		g.mu.Unlock()
	}
	if path[len(path)-1] != p.AgentID {
		return nil, fmt.Errorf("the credential was delegated to %s, not to the connected agent %s", path[len(path)-1], p.AgentID)
	}
	return append([]string(nil), path...), nil
}

// VerifyChain checks a root-first delegation chain: every hop is signed by the key
// its parent delegated to, the root is one of the pinned root anchors, the head is
// the one the credential binds, and every hop belongs to the tenant. It returns the
// principal path from the root delegator to the final delegate.
func VerifyChain(tenantID string, records [][]byte, roots [][]byte, boundHead []byte) ([]string, error) {
	if len(records) == 0 {
		return nil, errors.New("the credential has no delegation chain")
	}
	var path []string
	var prev delegation.Record
	var prevDigest []byte
	for i, raw := range records {
		var env delegation.RecordEnvelope
		if err := json.Unmarshal(raw, &env); err != nil {
			return nil, errors.New("the delegation chain is unreadable")
		}
		r := env.Record
		if r.TenantID != tenantID {
			return nil, errors.New("the delegation chain belongs to another tenant")
		}
		if err := r.ValidateLinkage(); err != nil {
			return nil, errors.New("the delegation chain is not linked")
		}
		if err := r.Verify(crypto.PublicKey{DER: env.DelegatorPublicDER}, nil); err != nil {
			return nil, fmt.Errorf("delegation hop %d is not signed by its delegator", i)
		}
		if i == 0 {
			if !r.RootAnchor || !containsDER(roots, env.DelegatorPublicDER) {
				return nil, errors.New("the delegation chain does not start at a pinned root principal")
			}
			path = append(path, r.DelegatorID)
		} else {
			if !bytes.Equal(r.ParentDigest, prevDigest) || r.DelegatorID != prev.DelegateID {
				return nil, fmt.Errorf("delegation hop %d does not continue its parent", i)
			}
			if len(prev.DelegateKeyThumbprint) > 0 && !bytes.Equal(prev.DelegateKeyThumbprint, delegation.DelegateKeyThumbprintOf(env.DelegatorPublicDER)) {
				return nil, fmt.Errorf("delegation hop %d is signed by a key its parent did not delegate to", i)
			}
		}
		digest, err := r.Digest(nil)
		if err != nil {
			return nil, errors.New("the delegation chain is unreadable")
		}
		prev, prevDigest = r, digest
		path = append(path, r.DelegateID)
	}
	if !bytes.Equal(prevDigest, boundHead) {
		return nil, errors.New("the delegation chain is not the one the credential binds")
	}
	return path, nil
}

func (g *Gate) status(ctx context.Context, credentialID string) (CredentialStatus, error) {
	now := g.cfg.Now()
	g.mu.Lock()
	cached, ok := g.statuses[credentialID]
	g.mu.Unlock()
	if ok && now.Sub(cached.read) < g.cfg.StatusTTL {
		return cached.status, nil
	}
	status, err := g.cfg.Trstctl.CredentialStatus(ctx, credentialID)
	if err != nil {
		return CredentialStatus{}, err
	}
	g.mu.Lock()
	g.statuses[credentialID] = cachedStatus{status: status, read: now}
	g.mu.Unlock()
	return status, nil
}

func (g *Gate) writeAudit(rec AuditRecord) {
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	g.auditMu.Lock()
	defer g.auditMu.Unlock()
	_, _ = g.cfg.Audit.Write(append(line, '\n'))
}

func containsDER(set [][]byte, der []byte) bool {
	for _, candidate := range set {
		if bytes.Equal(candidate, der) {
			return true
		}
	}
	return false
}

type clock struct{ now func() time.Time }

func (c clock) Now() time.Time { return c.now() }
