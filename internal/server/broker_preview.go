// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api"
	"trstctl.com/trstctl/internal/crypto"
)

func (s *Server) PreviewBrokerAgentIdentity(ctx context.Context, tenantID, requester string, req api.BrokerAgentIdentityRequest) (api.BrokerAgentIdentityPreview, error) {
	if s.agentBroker == nil {
		return api.BrokerAgentIdentityPreview{}, api.ErrBrokerUnavailable
	}
	return s.agentBroker.PreviewBrokerAgentIdentity(ctx, tenantID, requester, req)
}

// PreviewBrokerAgentIdentity reads tenant public trust and hashes exact inputs.
// Policy evaluation, attestors and the licensed task gate can have effects, so
// none runs here. An operator must explicitly issue to verify authority.
func (s *agentBrokerService) PreviewBrokerAgentIdentity(ctx context.Context, tenantID, requester string, req api.BrokerAgentIdentityRequest) (api.BrokerAgentIdentityPreview, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(requester) == "" {
		return api.BrokerAgentIdentityPreview{}, fmt.Errorf("%w: tenant and requester are required", api.ErrBrokerInvalid)
	}
	methods, err := availableWorkloadAttestationMethods(ctx, s.store, s.methods, tenantID)
	if err != nil {
		return api.BrokerAgentIdentityPreview{}, fmt.Errorf("%w: resolve tenant trust: %v", api.ErrBrokerInvalid, err)
	}
	method := strings.TrimSpace(req.Method)
	configured := false
	for _, available := range methods {
		configured = configured || method == available
	}
	blockers := []string{}
	if !configured {
		blockers = append(blockers, fmt.Sprintf("Attestation method %q is not configured for this tenant. Add or enable its public trust source first.", method))
	}
	if strings.TrimSpace(req.AgentID) == "" {
		blockers = append(blockers, "Name the agent whose requested scopes will be checked by policy.")
	}
	if len(req.Scopes) == 0 {
		blockers = append(blockers, "Specify at least one scope for policy to check.")
	}
	if len(req.Payload) == 0 {
		blockers = append(blockers, "Provide fresh workload proof before issuing.")
	}
	if err := crypto.ValidatePublicKeyDER(req.PublicKeyDER); err != nil {
		blockers = append(blockers, "Provide a valid public key; keep its private key on the workload.")
	}
	taskVerification, taskDigest := "not_requested", ""
	if len(req.TaskEnvelope) > 0 {
		taskDigest = crypto.SHA256Hex(req.TaskEnvelope)
		taskVerification = "execution_only"
		if s.taskEnvelopeGate == nil {
			taskVerification = "unavailable"
			blockers = append(blockers, "This deployment cannot verify the supplied task envelope. Configure the licensed task gate; the broker will not silently issue an unscoped identity.")
		}
	}
	return api.BrokerAgentIdentityPreview{
		Capability: "agent_broker", Ready: len(blockers) == 0, EffectFree: true,
		AgentID: strings.TrimSpace(req.AgentID), Method: method, Requester: strings.TrimSpace(requester), TrustDomain: s.trustDomain,
		Scopes: append([]string{}, req.Scopes...), SupportedMethods: methods,
		RequestedTTLSeconds: req.TTLSeconds, EffectiveTTLSeconds: int64(s.ttl(req.TTLSeconds) / time.Second),
		DefaultTTLSeconds: int64(s.defaultTTL / time.Second), MaxTTLSeconds: int64(s.maxTTL / time.Second),
		TTLDefaulted: req.TTLSeconds <= 0, TTLClamped: req.TTLSeconds > int64(s.maxTTL/time.Second),
		RequiredPermission: "certs:issue", AttestationVerification: "execution_only", PolicyEvaluation: "execution_only",
		TaskEnvelopeVerification: taskVerification, PayloadSHA256: crypto.SHA256Hex(req.Payload), PublicKeySHA256: crypto.SHA256Hex(req.PublicKeyDER), TaskEnvelopeSHA256: taskDigest,
		PreviewWrites: []string{}, PreviewExternalEffects: []string{}, PreviewSignerCalls: []string{},
		ExecutionWrites: []string{
			"Record verification and issuance events, the agent owner, its shared certificate inventory row, and the idempotent result.",
			"Publish the issuing CA's initial certificate revocation list, or refresh it when due, before reporting successful issuance.",
		},
		ExecutionExternalEffects: []string{},
		ExecutionSignerCalls: []string{
			"Ask the isolated signer for one certificate with the verified workload subject and the effective lifetime.",
			"Sign the public certificate revocation list when it is missing or due for refresh; this does not sign another workload certificate.",
		},
		Steps: []string{
			"Review the exact agent, scopes, proof fingerprints, and effective lifetime. Ready means configured, not verified or authorized.",
			"Issue explicitly. The server checks tenant trust, any task envelope, scope policy, and attestation before signing.",
			"Inspect the shared certificate record and audit trail. The workload keeps the private key and receives only a public certificate.",
		},
		Blockers: blockers,
		RecoverySteps: []string{
			"If the response is lost, retry the unchanged request with the same Idempotency-Key. Do not create a new key just because delivery was uncertain.",
			"If proof or policy is refused, correct tenant trust, request permitted scopes, or obtain fresh proof and review a new command. Never disable verification to continue.",
			"If signing is unavailable, restore the isolated signer, then retry the unchanged command. Use the certificate inventory and audit trail to inspect the outcome.",
			"If initial revocation-list publication fails after the certificate was recorded, retry the same command. The server recovers that certificate and completes publication instead of issuing another leaf.",
		},
		DataHandling: []string{
			"Preview returns digests and operational metadata only. Raw proof and task-envelope bytes are not returned; their server buffers are wiped after the request.",
			"Preview does not verify or consume one-time evidence, evaluate policy, append events, reserve a key, or call the signer.",
			"Scopes are issuance-policy inputs. A certificate proves identity; each receiving service must still enforce its own access policy.",
			"No private key is uploaded, generated, stored, or returned by this workflow.",
		},
	}, nil
}
