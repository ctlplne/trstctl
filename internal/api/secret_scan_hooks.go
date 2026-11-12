// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/auditsink"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
)

// Provider-native repository webhooks (P6, OD-3). Each provider proves a
// delivery its own way, and trstctl checks that proof in constant time before
// reading anything else: GitHub signs the exact body (X-Hub-Signature-256,
// HMAC-SHA256); GitLab signs webhook-id, webhook-timestamp and the body with
// the hook's signing token (webhook-signature, the Standard Webhooks scheme; a
// delivery stamped more than five minutes from now is refused) or, for a hook
// with a secret token instead, sends that token in X-Gitlab-Token; Bitbucket
// signs the exact body (X-Hub-Signature, HMAC-SHA256). A missing or wrong
// proof is refused and audited. A verified push becomes the same repository
// secret scan the normalized webhook queues, one per pushed branch or tag. The
// provider's delivery ID is the idempotency key, so a redelivered push queues
// nothing new. Polling and the normalized route stay available for installs
// that cannot take webhooks.

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

// SecretScanHookCloneCredential names the credential_ref (and its user name)
// a hook's pushed private repository clones with (OD-1); empty for none.
type SecretScanHookCloneCredential func(hookID string) (credentialRef, username string)

// WithSecretScanHookCloneCredentials attaches the hooks' clone credentials.
func WithSecretScanHookCloneCredentials(lookup SecretScanHookCloneCredential) Option {
	return func(c *config) { c.secretScanHookClone = lookup }
}

const secretScanHookMaxBody = 1 << 20

// secretScanHookMaxSkew bounds how far a signed GitLab delivery's timestamp
// may be from now, so a captured delivery cannot be replayed later.
const secretScanHookMaxSkew = 5 * time.Minute

// secretScanHookMaxRefs bounds the branches and tags one delivery scans.
const secretScanHookMaxRefs = 10

// secretScanHookDelivery names a delivery by the provider's own ID, which it
// keeps on every redelivery of the same event, and the header it came from:
// GitHub's X-GitHub-Delivery (GitHub sends no Idempotency-Key header);
// GitLab's webhook-id, Idempotency-Key or X-Gitlab-Event-UUID; Bitbucket
// Cloud's X-Request-UUID or Data Center's X-Request-Id.
func secretScanHookDelivery(provider string, h http.Header) (id, header string) {
	names := []string{"X-GitHub-Delivery"}
	switch provider {
	case "gitlab":
		names = []string{"webhook-id", "Idempotency-Key", "X-Gitlab-Event-UUID"}
	case "bitbucket":
		names = []string{"X-Request-UUID", "X-Request-Id"}
	}
	for _, name := range names {
		if v := strings.TrimSpace(h.Get(name)); v != "" {
			return v, name
		}
	}
	return "", strings.Join(names, " or ")
}

// secretScanHookIdempotencyKey is a native hook's idempotency key: the
// provider's own delivery ID (secretScanHookDelivery), which it keeps on every
// redelivery of the same event, under the provider's name; "" when the
// delivery names none or one too long to be an ID.
func secretScanHookIdempotencyKey(provider string, r *http.Request) string {
	delivery, _ := secretScanHookDelivery(provider, r.Header)
	if delivery == "" || len(delivery) > 128 {
		return ""
	}
	return provider + "-delivery:" + delivery
}

// Why a delivery's signature was refused (P6-L3).
const (
	secretScanHookSignatureMissing = "signature_missing"
	secretScanHookSignatureWrong   = "signature_mismatch"
	secretScanHookSignatureStale   = "signature_stale"
)

// verifySecretScanHook checks a delivery's proof against the hook's secret
// and returns why it is refused, or "" for an authentic delivery.
func verifySecretScanHook(provider string, key []byte, h http.Header, body []byte, now time.Time) string {
	switch provider {
	case "gitlab":
		if bytes.HasPrefix(key, []byte("whsec_")) {
			return verifyStandardWebhookSignature(key, h, body, now)
		}
		token := h.Get("X-Gitlab-Token")
		if token == "" {
			return secretScanHookSignatureMissing
		}
		if !crypto.ConstantTimeEqual([]byte(token), key) {
			return secretScanHookSignatureWrong
		}
		return ""
	case "bitbucket":
		return verifyBodySignature(key, body, h.Get("X-Hub-Signature"))
	default:
		return verifyBodySignature(key, body, h.Get("X-Hub-Signature-256"))
	}
}

// verifyBodySignature checks "sha256=<hex HMAC-SHA256 of the body>".
func verifyBodySignature(key, body []byte, signature string) string {
	signature = strings.TrimSpace(signature)
	if signature == "" {
		return secretScanHookSignatureMissing
	}
	want := []byte("sha256=" + hex.EncodeToString(crypto.HMACSHA256(key, body)))
	if !crypto.ConstantTimeEqual([]byte(signature), want) {
		return secretScanHookSignatureWrong
	}
	return ""
}

// verifyStandardWebhookSignature checks a GitLab signing token's signature:
// HMAC-SHA256, keyed by the base64 secret after the token's whsec_ prefix,
// over "<webhook-id>.<webhook-timestamp>.<body>", matching any v1 entry of
// webhook-signature, from a delivery stamped within five minutes of now.
func verifyStandardWebhookSignature(key []byte, h http.Header, body []byte, now time.Time) string {
	id, stamp, signatures := strings.TrimSpace(h.Get("webhook-id")), strings.TrimSpace(h.Get("webhook-timestamp")), h.Get("webhook-signature")
	if id == "" || stamp == "" || strings.TrimSpace(signatures) == "" {
		return secretScanHookSignatureMissing
	}
	seconds, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil {
		return secretScanHookSignatureWrong
	}
	if skew := now.Sub(time.Unix(seconds, 0)); skew > secretScanHookMaxSkew || skew < -secretScanHookMaxSkew {
		return secretScanHookSignatureStale
	}
	encoded := bytes.TrimPrefix(key, []byte("whsec_"))
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	defer secret.Wipe(raw)
	n, err := base64.StdEncoding.Decode(raw, encoded)
	if err != nil || n == 0 {
		return secretScanHookSignatureWrong
	}
	signed := make([]byte, 0, len(id)+len(stamp)+len(body)+2)
	signed = append(append(append(append(append(signed, id...), '.'), stamp...), '.'), body...)
	want := []byte(base64.StdEncoding.EncodeToString(crypto.HMACSHA256(raw[:n], signed)))
	for _, entry := range strings.Fields(signatures) {
		version, value, ok := strings.Cut(entry, ",")
		if ok && version == "v1" && crypto.ConstantTimeEqual([]byte(value), want) {
			return ""
		}
	}
	return secretScanHookSignatureWrong
}

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

// gitlabPushPayload is a GitLab push or tag push event.
type gitlabPushPayload struct {
	Ref         string `json:"ref"`
	After       string `json:"after"`
	CheckoutSHA string `json:"checkout_sha"`
	Project     struct {
		PathWithNamespace string `json:"path_with_namespace"`
		GitHTTPURL        string `json:"git_http_url"`
	} `json:"project"`
}

// bitbucketCloudPushPayload is a Bitbucket Cloud repo:push event: one change
// per pushed branch or tag, new null where it was deleted.
type bitbucketCloudPushPayload struct {
	Push struct {
		Changes []struct {
			New *struct {
				Type   string `json:"type"`
				Name   string `json:"name"`
				Target struct {
					Hash string `json:"hash"`
				} `json:"target"`
			} `json:"new"`
		} `json:"changes"`
	} `json:"push"`
	Repository struct {
		FullName string `json:"full_name"`
		Links    struct {
			HTML struct {
				Href string `json:"href"`
			} `json:"html"`
		} `json:"links"`
	} `json:"repository"`
}

// bitbucketDataCenterPushPayload is a Bitbucket Data Center repo:refs_changed
// event.
type bitbucketDataCenterPushPayload struct {
	Repository struct {
		Slug    string `json:"slug"`
		Project struct {
			Key string `json:"key"`
		} `json:"project"`
		Links struct {
			Clone []struct {
				Href string `json:"href"`
				Name string `json:"name"`
			} `json:"clone"`
		} `json:"links"`
	} `json:"repository"`
	Changes []struct {
		Ref struct {
			ID string `json:"id"`
		} `json:"ref"`
		ToHash string `json:"toHash"`
		Type   string `json:"type"`
	} `json:"changes"`
}

// secretScanHookRef is one pushed branch or tag to scan, at its pushed commit.
type secretScanHookRef struct{ Ref, Commit string }

// secretScanHookPush is what a verified push asks to scan.
type secretScanHookPush struct {
	Repository, CloneURL string
	Refs                 []secretScanHookRef
}

// errSecretScanHookPayload is a verified delivery whose payload is not the
// push its event names.
var errSecretScanHookPayload = errors.New("the push payload is not the event's JSON")

const zeroCommit = "0000000000000000000000000000000000000000"

// secretScanHookEvent reads a verified delivery: a push to scan, or, for an
// event that scans nothing, the status and reply to answer with.
func secretScanHookEvent(provider string, h http.Header, body []byte) (secretScanHookPush, int, map[string]any, error) {
	var push secretScanHookPush
	ignored := func(what string) (secretScanHookPush, int, map[string]any, error) {
		return push, http.StatusAccepted, map[string]any{"ignored": what}, nil
	}
	pong := map[string]any{"pong": true}
	switch provider {
	case "gitlab":
		// GitLab has no ping; its "Test" button sends a sample push.
		event := h.Get("X-Gitlab-Event")
		if event != "Push Hook" && event != "Tag Push Hook" {
			return ignored(event)
		}
		var p gitlabPushPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return push, 0, nil, errSecretScanHookPayload
		}
		push.Repository, push.CloneURL = p.Project.PathWithNamespace, p.Project.GitHTTPURL
		commit := strings.TrimSpace(p.CheckoutSHA)
		if commit == "" {
			commit = strings.TrimSpace(p.After)
		}
		if commit != "" && commit != zeroCommit {
			push.Refs = []secretScanHookRef{{Ref: p.Ref, Commit: commit}}
		}
	case "bitbucket":
		switch event := h.Get("X-Event-Key"); event {
		case "diagnostics:ping":
			return push, http.StatusOK, pong, nil
		case "repo:push":
			var p bitbucketCloudPushPayload
			if err := json.Unmarshal(body, &p); err != nil {
				return push, 0, nil, errSecretScanHookPayload
			}
			push.Repository = p.Repository.FullName
			if href := strings.TrimSuffix(strings.TrimSpace(p.Repository.Links.HTML.Href), "/"); href != "" {
				push.CloneURL = href + ".git"
			}
			for _, change := range p.Push.Changes {
				if change.New == nil || change.New.Name == "" || change.New.Target.Hash == "" {
					continue // a deleted branch or tag
				}
				ref := "refs/heads/" + change.New.Name
				if change.New.Type == "tag" || change.New.Type == "annotated_tag" {
					ref = "refs/tags/" + change.New.Name
				}
				push.Refs = append(push.Refs, secretScanHookRef{Ref: ref, Commit: change.New.Target.Hash})
			}
		case "repo:refs_changed":
			var p bitbucketDataCenterPushPayload
			if err := json.Unmarshal(body, &p); err != nil {
				return push, 0, nil, errSecretScanHookPayload
			}
			if p.Repository.Project.Key != "" && p.Repository.Slug != "" {
				push.Repository = p.Repository.Project.Key + "/" + p.Repository.Slug
			}
			for _, link := range p.Repository.Links.Clone {
				// Data Center names its https clone link "http".
				if link.Name == "http" {
					push.CloneURL = link.Href
				}
			}
			for _, change := range p.Changes {
				if change.Type == "DELETE" || change.ToHash == "" || change.ToHash == zeroCommit {
					continue
				}
				push.Refs = append(push.Refs, secretScanHookRef{Ref: change.Ref.ID, Commit: change.ToHash})
			}
		default:
			return ignored(event)
		}
	default:
		switch event := h.Get("X-GitHub-Event"); event {
		case "ping":
			return push, http.StatusOK, pong, nil
		case "push":
		default:
			return ignored(event)
		}
		var p githubPushPayload
		if err := json.Unmarshal(body, &p); err != nil {
			return push, 0, nil, errSecretScanHookPayload
		}
		push.Repository, push.CloneURL = p.Repository.FullName, p.Repository.CloneURL
		if !p.Deleted {
			push.Refs = []secretScanHookRef{{Ref: p.Ref, Commit: p.After}}
		}
	}
	if len(push.Refs) == 0 {
		return ignored("a deleted branch has nothing to scan")
	}
	return push, 0, nil, nil
}

// receiveSecretScanHook verifies a provider delivery and queues the scans a
// push asks for.
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
	hookID := r.PathValue("hook_id")
	tenantID, provider, key, err := a.secretScanHooks(r.Context(), hookID)
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
	delivery, deliveryHeader := secretScanHookDelivery(provider, r.Header)
	if reason := verifySecretScanHook(provider, key.Bytes(), r.Header, body, time.Now()); reason != "" {
		a.auditSecretScanHookRefused(r.Context(), tenantID, hookID, delivery, reason)
		a.writeProblem(w, problem.New(http.StatusUnauthorized, "the webhook signature does not verify"))
		return
	}
	idempotencyKey := secretScanHookIdempotencyKey(provider, r)
	if idempotencyKey == "" {
		a.writeProblem(w, problem.New(http.StatusBadRequest, deliveryHeader+" is required"))
		return
	}
	push, status, reply, err := secretScanHookEvent(provider, r.Header, body)
	if err != nil {
		a.writeError(w, errStatusFrom(http.StatusBadRequest, err))
		return
	}
	if reply != nil {
		a.writeJSON(w, status, reply)
		return
	}
	refs := push.Refs
	if len(refs) > secretScanHookMaxRefs {
		refs = refs[:secretScanHookMaxRefs]
	}
	var credentialRef, credentialUser string
	if a.secretScanHookClone != nil {
		credentialRef, credentialUser = a.secretScanHookClone(hookID)
	}
	binding := "secret-scan-hook:v1:" + crypto.SHA256Hex([]byte(hookID)) + ":" + crypto.SHA256Hex(body)
	a.mutatePublicTenantBound(w, r, tenantID, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		var receipt secretRepoScanWebhookResponse
		var runs []secretRepoScanQueuedRun
		for i, ref := range refs {
			status, out, err := a.queueSecretRepoScan(ctx, tenantID, provider, secretRepoScanWebhookRequest{
				Repository: push.Repository, CloneURL: push.CloneURL, Ref: ref.Ref, CommitSHA: ref.Commit, Event: "push",
				CredentialRef: credentialRef, CredentialUsername: credentialUser,
			})
			if err != nil {
				return status, nil, err
			}
			queued, _ := out.(secretRepoScanWebhookResponse)
			if i == 0 {
				receipt = queued
			}
			runs = append(runs, secretRepoScanQueuedRun{Ref: ref.Ref, RunID: queued.RunID, DiscoveryRunPath: queued.DiscoveryRunPath})
		}
		if len(runs) > 1 || len(push.Refs) > len(refs) {
			// A push of several branches or tags queues one scan each; the
			// receipt names the first and lists them all.
			receipt.Runs, receipt.RefsNotScanned = runs, len(push.Refs)-len(refs)
		}
		return http.StatusAccepted, receipt, nil
	})
}
