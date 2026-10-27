// SPDX-License-Identifier: BUSL-1.1

package k8s

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// An opt-in approver for native CertificateSigningRequests addressed to
// trstctl signer names (A195).
//
// Kubernetes leaves approval to an approver it trusts, and by default that is
// still a Kubernetes approver: this controller signs only what someone else
// approved. With an Approver configured, the controller asks the issuing CA
// whether it would issue the request under its profile, and writes Approved
// or Denied, with the CA's reason, through the approval subresource. The CA
// decides by the same checks issuance makes, so an approval here is never
// followed by a refusal at signing for a reason the CA could have said first.

// ApprovalDecision is the issuing CA's answer on one request.
type ApprovalDecision struct {
	Allowed bool
	Reason  string
}

// Approver decides one CSR for the issuing CA.
type Approver interface {
	Evaluate(ctx context.Context, csrDER []byte, ttl time.Duration) (ApprovalDecision, error)
}

// ApproverFunc adapts a function to Approver.
type ApproverFunc func(ctx context.Context, csrDER []byte, ttl time.Duration) (ApprovalDecision, error)

// Evaluate calls f.
func (f ApproverFunc) Evaluate(ctx context.Context, csrDER []byte, ttl time.Duration) (ApprovalDecision, error) {
	return f(ctx, csrDER, ttl)
}

// csrApprovalReason is the condition reason both decisions carry, so an
// operator can tell trstctl's decisions from a Kubernetes approver's.
const csrApprovalReason = "TrstctlProfilePolicy"

// WithCSRApprover turns the opt-in approver on and returns c.
func (c *IssuerController) WithCSRApprover(approver Approver) *IssuerController {
	c.approver = approver
	return c
}

// decideKubernetesCSR writes the issuing CA's decision on one pending CSR and
// returns the updated object. An evaluation that could not be made is an
// error, and the request stays pending for the next pass.
func (c *IssuerController) decideKubernetesCSR(ctx context.Context, csr map[string]any, config issuerConfig) (map[string]any, error) {
	spec, _ := csr["spec"].(map[string]any)
	reqB64, _ := spec["request"].(string)
	var decision ApprovalDecision
	if csrDER, err := decodeKubernetesCSRRequest(reqB64); err != nil {
		decision.Reason = "spec.request is not a readable certificate request"
	} else if ttl, err := kubernetesCSRRequestedTTL(spec); err != nil {
		decision.Reason = "spec.expirationSeconds is not a positive whole number of seconds"
	} else if decision, err = c.approver.Evaluate(ctx, csrDER, config.limitTTL(ttl)); err != nil {
		return nil, fmt.Errorf("k8s: evaluate CertificateSigningRequest: %w", err)
	}
	condition := map[string]any{
		"type": "Denied", "status": "True", "reason": csrApprovalReason,
		"message":        "trstctl denied this request: " + decision.Reason,
		"lastUpdateTime": time.Now().UTC().Format(time.RFC3339),
	}
	if decision.Allowed {
		condition["type"] = "Approved"
		condition["message"] = "trstctl approved this request: the issuing CA's profile allows it"
	}
	status, _ := csr["status"].(map[string]any)
	if status == nil {
		status = map[string]any{}
	}
	conditions, _ := status["conditions"].([]any)
	status["conditions"] = append(conditions, condition)
	csr["status"] = status
	meta, _ := csr["metadata"].(map[string]any)
	name, _ := meta["name"].(string)
	st, body, err := c.client.request(ctx, http.MethodPut, certificateSigningRequestsPath()+"/"+name+"/approval", csr)
	if err != nil {
		return nil, err
	}
	if st/100 != 2 {
		return nil, fmt.Errorf("k8s: write CertificateSigningRequest %s approval: %d: %s", name, st, string(body))
	}
	var updated map[string]any
	if err := json.Unmarshal(body, &updated); err != nil {
		return nil, fmt.Errorf("k8s: decode CertificateSigningRequest %s after approval: %w", name, err)
	}
	return updated, nil
}
