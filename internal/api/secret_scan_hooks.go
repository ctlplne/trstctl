// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Provider-native repository webhooks (P6). GitHub signs every delivery with
// the hook's own secret (X-Hub-Signature-256: HMAC-SHA256 over the exact body);
// trstctl checks it in constant time before reading anything else, refuses a
// missing or wrong signature, and turns a verified push into the same
// repository secret scan the normalized webhook queues. The delivery ID is the
// idempotency key, so a redelivered push queues nothing new. Polling and the
// normalized route stay available for installs that cannot take webhooks.

// ErrUnknownSecretScanHook is returned by a lookup for a hook that is not
// configured.
var ErrUnknownSecretScanHook = errors.New("api: no such secret scan webhook")

// SecretScanHookLookup resolves a configured scan webhook: its tenant, its
// provider and its signing secret, which the caller destroys.
type SecretScanHookLookup func(ctx context.Context, hookID string) (tenantID, provider string, signingKey *secret.Buffer, err error)

// WithSecretScanHooks attaches the provider-native scan webhooks (P6).
func WithSecretScanHooks(lookup SecretScanHookLookup) Option {
	return func(c *config) { c.secretScanHooks = lookup }
}

const secretScanHookMaxBody = 1 << 20

// githubDeliveryIdempotencyKey is the native GitHub webhook's idempotency key:
// GitHub's own unique X-GitHub-Delivery ID, which it keeps on every redelivery
// of the same event (GitHub sends no Idempotency-Key header).
func githubDeliveryIdempotencyKey(r *http.Request) string {
	delivery := strings.TrimSpace(r.Header.Get("X-GitHub-Delivery"))
	if delivery == "" || len(delivery) > 128 {
		return ""
	}
	return "github-delivery:" + delivery
}

// Why a delivery's signature was refused (P6-L3).
const (
	secretScanHookSignatureMissing = "signature_missing"
	secretScanHookSignatureWrong   = "signature_mismatch"
)

// auditSecretScanHookRefused records a delivery the hook refused for its
// signature (P6-L3): the hook, GitHub's delivery ID and whether the signature
// was missing or wrong, so forged or misconfigured deliveries show in the
// tenant's audit trail. Never the body or the signature. The route's abuse
// control bounds how fast anyone can add these. Best-effort, like the other
// secret audit records: the refusal stands either way.
func (a *API) auditSecretScanHookRefused(ctx context.Context, tenantID, hookID, delivery, reason string) {
	if a.secrets == nil || a.secrets.be.Audit == nil {
		return
	}
	if delivery = strings.TrimSpace(delivery); len(delivery) > 128 {
		delivery = ""
	}
	payload, err := json.Marshal(map[string]string{"hook_id": hookID, "delivery": delivery, "reason": reason})
	if err != nil {
		return
	}
	_ = auditsink.Emit(ctx, a.secrets.be.Audit, nil, "secret.scan_hook.refused", tenantID, payload)
}

type githubPushPayload struct {
	Ref        string `json:"ref"`
	After      string `json:"after"`
	Deleted    bool   `json:"deleted"`
	Repository struct {
		FullName string `json:"full_name"`
		CloneURL string `json:"clone_url"`
	} `json:"repository"`
}

// receiveSecretScanHook verifies a GitHub delivery and queues the scan a push
// asks for.
//
//trstctl:mutation
func (a *API) receiveSecretScanHook(w http.ResponseWriter, r *http.Request) {
	if !a.allowSpecialRouteRequest(w, r, specialRouteAbuseRequest{}) {
		return
	}
	if a.secretScanHooks == nil || a.secrets == nil || a.orch == nil {
		a.writeProblem(w, problem.New(http.StatusNotFound, "no secret scan webhooks are configured"))
		return
	}
	tenantID, provider, key, err := a.secretScanHooks(r.Context(), r.PathValue("hook_id"))
	if errors.Is(err, ErrUnknownSecretScanHook) {
		a.writeProblem(w, problem.New(http.StatusNotFound, "no such secret scan webhook"))
		return
	}
	if err != nil {
		a.logInternalError(w, err)
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "the webhook's signing secret is unavailable"))
		return
	}
	defer key.Destroy()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, secretScanHookMaxBody))
	if err != nil {
		a.writeProblem(w, problem.New(http.StatusRequestEntityTooLarge, "the webhook body is too large"))
		return
	}
	mac := crypto.HMACSHA256(key.Bytes(), body)
	want := []byte("sha256=" + hex.EncodeToString(mac))
	signature := strings.TrimSpace(r.Header.Get("X-Hub-Signature-256"))
	if !crypto.ConstantTimeEqual([]byte(signature), want) {
		reason := secretScanHookSignatureWrong
		if signature == "" {
			reason = secretScanHookSignatureMissing
		}
		a.auditSecretScanHookRefused(r.Context(), tenantID, r.PathValue("hook_id"), r.Header.Get("X-GitHub-Delivery"), reason)
		a.writeProblem(w, problem.New(http.StatusUnauthorized, "the webhook signature does not verify"))
		return
	}
	idempotencyKey := githubDeliveryIdempotencyKey(r)
	if idempotencyKey == "" {
		a.writeProblem(w, problem.New(http.StatusBadRequest, "X-GitHub-Delivery is required"))
		return
	}
	switch event := r.Header.Get("X-GitHub-Event"); event {
	case "ping":
		a.writeJSON(w, http.StatusOK, map[string]any{"pong": true})
		return
	case "push":
	default:
		a.writeJSON(w, http.StatusAccepted, map[string]any{"ignored": event})
		return
	}
	var push githubPushPayload
	if err := json.Unmarshal(body, &push); err != nil {
		a.writeProblem(w, problem.New(http.StatusBadRequest, "the push payload is not JSON"))
		return
	}
	if push.Deleted {
		a.writeJSON(w, http.StatusAccepted, map[string]any{"ignored": "a deleted branch has nothing to scan"})
		return
	}
	req := secretRepoScanWebhookRequest{
		Repository: push.Repository.FullName, CloneURL: push.Repository.CloneURL,
		Ref: push.Ref, CommitSHA: push.After, Event: "push",
	}
	binding := "secret-scan-hook:v1:" + crypto.SHA256Hex([]byte(r.PathValue("hook_id"))) + ":" + crypto.SHA256Hex(body)
	a.mutatePublicTenantBound(w, r, tenantID, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		return a.queueSecretRepoScan(ctx, tenantID, provider, req)
	})
}
