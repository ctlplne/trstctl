// SPDX-License-Identifier: BUSL-1.1

// Package rightsize is the entitlement-service conversation behind
// connector.right_size: one idempotent PATCH that removes scopes from a
// target's entitlement, the vendor's attestation of exactly those removals,
// and an independent GET readback whose digest becomes the receipt's
// fingerprint. It lives outside the server so the control-plane worker and a
// network relay (A64) run the same bytes against the same contract; neither
// retains the bearer token or any response text beyond the receipt fields.
// No crypto/* here (AN-3): the digest is taken through the crypto boundary.
package rightsize

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/secretjson"
	"trstctl.com/trstctl/internal/secrettext"
)

// Input is one right-size intent as the executor receives it. Token is
// borrowed: the caller owns and wipes it.
type Input struct {
	Endpoint         string
	Token            []byte
	TenantID         string
	IdempotencyKey   string
	Connector        string
	Target           string
	InventoryID      string
	TargetIdentityID string
	Reason           string
	ScopeDelta       json.RawMessage
}

// Mutation is independently read-back evidence that the entitlement API
// applied one intent.
type Mutation struct {
	MutationID     string `json:"mutation_id"`
	RollbackRef    string `json:"rollback_ref"`
	ReadbackDigest string `json:"readback_digest"`
}

// ScopeDelta is the intent's scope change.
type ScopeDelta struct {
	RemoveScopes      []string `json:"remove_scopes"`
	RecommendedScopes []string `json:"recommended_scopes"`
}

type request struct {
	SchemaVersion     int      `json:"schema_version"`
	TenantID          string   `json:"tenant_id"`
	Connector         string   `json:"connector"`
	Target            string   `json:"target"`
	InventoryID       string   `json:"inventory_id,omitempty"`
	TargetIdentityID  string   `json:"target_identity_id,omitempty"`
	RemoveScopes      []string `json:"remove_scopes"`
	RecommendedScopes []string `json:"recommended_scopes"`
	Reason            string   `json:"reason,omitempty"`
}

type response struct {
	Status        secretjson.StringBytes   `json:"status"`
	MutationID    secretjson.StringBytes   `json:"mutation_id"`
	RemovedScopes []secretjson.StringBytes `json:"removed_scopes"`
	RollbackRef   secretjson.StringBytes   `json:"rollback_ref"`
}

type readback struct {
	Scopes []secretjson.StringBytes `json:"scopes"`
}

// Apply runs the conversation. Every error is safe to persist: it names the
// step that failed and never carries response text or the token.
func Apply(ctx context.Context, client *http.Client, in Input) (Mutation, error) {
	if client == nil {
		return Mutation{}, errors.New("right-size: no HTTP client")
	}
	endpointBase := strings.TrimRight(strings.TrimSpace(in.Endpoint), "/")
	target := strings.TrimSpace(in.Target)
	if endpointBase == "" || target == "" || strings.TrimSpace(in.TenantID) == "" || strings.TrimSpace(in.IdempotencyKey) == "" {
		return Mutation{}, errors.New("right-size: intent needs an endpoint, target, tenant and idempotency key")
	}
	if len(in.Token) == 0 {
		return Mutation{}, errors.New("right-size: no bearer token was redeemed for this attempt")
	}
	var delta ScopeDelta
	if err := json.Unmarshal(in.ScopeDelta, &delta); err != nil {
		return Mutation{}, fmt.Errorf("right-size: decode scope delta: %w", err)
	}
	remove, err := NormalizedScopes(delta.RemoveScopes, true)
	if err != nil {
		return Mutation{}, fmt.Errorf("right-size: remove_scopes: %w", err)
	}
	recommended, err := NormalizedScopes(delta.RecommendedScopes, false)
	if err != nil {
		return Mutation{}, fmt.Errorf("right-size: recommended_scopes: %w", err)
	}
	for _, scope := range recommended {
		if ContainsScope(remove, scope) {
			return Mutation{}, fmt.Errorf("right-size: scope %q cannot be both removed and recommended", scope)
		}
	}
	requestBody, err := json.Marshal(request{
		SchemaVersion: 1, TenantID: in.TenantID, Connector: in.Connector,
		Target: target, InventoryID: in.InventoryID, TargetIdentityID: in.TargetIdentityID,
		RemoveScopes: remove, RecommendedScopes: recommended, Reason: in.Reason,
	})
	if err != nil {
		return Mutation{}, err
	}
	endpoint := endpointBase + "/v1/entitlements/" + url.PathEscape(target)

	applyRequest, err := http.NewRequestWithContext(ctx, http.MethodPatch, endpoint, bytes.NewReader(requestBody))
	if err != nil {
		return Mutation{}, err
	}
	setHeaders(applyRequest, in)
	applyResponse, err := client.Do(applyRequest)
	if err != nil {
		return Mutation{}, fmt.Errorf("right-size: mutation request: %w", err)
	}
	applyBody, err := readResponse(applyResponse)
	if err != nil {
		return Mutation{}, err
	}
	defer secret.Wipe(applyBody)
	if responseContainsCredential(applyBody, in.Token) {
		return Mutation{}, errors.New("right-size: mutation response reflected the request credential")
	}
	var applied response
	defer applied.wipe()
	if err := json.Unmarshal(applyBody, &applied); err != nil {
		return Mutation{}, errors.New("right-size: mutation returned invalid JSON")
	}
	if applied.containsCredential(in.Token) {
		return Mutation{}, errors.New("right-size: mutation response reflected the request credential")
	}
	mutationID := bytes.TrimSpace(applied.MutationID)
	rollbackRef := bytes.TrimSpace(applied.RollbackRef)
	if !bytes.Equal(applied.Status, []byte("applied")) || !ValidReceiptRef(mutationID) || !ValidReceiptRef(rollbackRef) || !equalByteScopes(applied.RemovedScopes, remove) {
		return Mutation{}, errors.New("right-size: mutation response did not attest the requested scope removal")
	}

	readbackRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Mutation{}, err
	}
	setHeaders(readbackRequest, in)
	readbackResponse, err := client.Do(readbackRequest)
	if err != nil {
		return Mutation{}, fmt.Errorf("right-size: readback request: %w", err)
	}
	readbackBody, err := readResponse(readbackResponse)
	if err != nil {
		return Mutation{}, err
	}
	defer secret.Wipe(readbackBody)
	if responseContainsCredential(readbackBody, in.Token) {
		return Mutation{}, errors.New("right-size: readback response reflected the request credential")
	}
	var observed readback
	defer observed.wipe()
	if err := json.Unmarshal(readbackBody, &observed); err != nil {
		return Mutation{}, errors.New("right-size: readback returned invalid JSON")
	}
	if observed.containsCredential(in.Token) {
		return Mutation{}, errors.New("right-size: readback response reflected the request credential")
	}
	if !validByteScopes(observed.Scopes) {
		return Mutation{}, errors.New("right-size: readback returned invalid scopes")
	}
	for _, scope := range remove {
		if containsByteScope(observed.Scopes, scope) {
			return Mutation{}, fmt.Errorf("right-size: readback still contains removed scope %q", scope)
		}
	}
	if len(recommended) > 0 && !equalByteScopes(observed.Scopes, recommended) {
		return Mutation{}, errors.New("right-size: readback does not match recommended scopes")
	}
	return Mutation{
		MutationID: string(mutationID), RollbackRef: string(rollbackRef),
		ReadbackDigest: crypto.SHA256Hex(readbackBody),
	}, nil
}

// NormalizedScopes trims, rejects empties and duplicates, and sorts.
func NormalizedScopes(values []string, required bool) ([]string, error) {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, raw := range values {
		scope := strings.TrimSpace(raw)
		if scope == "" {
			return nil, errors.New("scope must not be empty")
		}
		if seen[scope] {
			return nil, fmt.Errorf("scope %q is duplicated", scope)
		}
		seen[scope] = true
		out = append(out, scope)
	}
	if required && len(out) == 0 {
		return nil, errors.New("at least one scope is required")
	}
	sort.Strings(out)
	return out, nil
}

// ContainsScope reports membership in a NormalizedScopes result.
func ContainsScope(values []string, want string) bool {
	index := sort.SearchStrings(values, want)
	return index < len(values) && values[index] == want
}

// ValidReceiptRef accepts the printable, bounded identifiers an entitlement
// service may hand back as mutation and rollback references.
func ValidReceiptRef(value []byte) bool {
	if len(value) == 0 || len(value) > 1024 {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func (r *response) wipe() {
	secret.Wipe(r.Status)
	secret.Wipe(r.MutationID)
	for _, scope := range r.RemovedScopes {
		secret.Wipe(scope)
	}
	secret.Wipe(r.RollbackRef)
}

func (r response) containsCredential(token []byte) bool {
	fields := make([]secretjson.StringBytes, 0, 3+len(r.RemovedScopes))
	fields = append(fields, r.Status, r.MutationID, r.RollbackRef)
	fields = append(fields, r.RemovedScopes...)
	return fieldsContainCredential(fields, token)
}

func (r *readback) wipe() {
	for _, scope := range r.Scopes {
		secret.Wipe(scope)
	}
}

func (r readback) containsCredential(token []byte) bool {
	return fieldsContainCredential(r.Scopes, token)
}

func responseContainsCredential(body, token []byte) bool {
	if len(token) == 0 {
		return false
	}
	quoted := secretjson.QuoteBytes(token)
	defer secret.Wipe(quoted)
	base64Quoted := secretjson.QuoteBase64(token)
	defer secret.Wipe(base64Quoted)
	return bytes.Contains(body, token) || bytes.Contains(body, quoted[1:len(quoted)-1]) || bytes.Contains(body, base64Quoted[1:len(base64Quoted)-1])
}

func fieldsContainCredential(fields []secretjson.StringBytes, token []byte) bool {
	if len(token) == 0 {
		return false
	}
	base64Quoted := secretjson.QuoteBase64(token)
	defer secret.Wipe(base64Quoted)
	encoded := base64Quoted[1 : len(base64Quoted)-1]
	for _, field := range fields {
		if bytes.Contains(field, token) || bytes.Contains(field, encoded) {
			return true
		}
	}
	return false
}

func validByteScopes(values []secretjson.StringBytes) bool {
	for index, value := range values {
		if len(value) == 0 || !bytes.Equal(value, bytes.TrimSpace(value)) {
			return false
		}
		for previous := 0; previous < index; previous++ {
			if bytes.Equal(value, values[previous]) {
				return false
			}
		}
	}
	return true
}

func containsByteScope(values []secretjson.StringBytes, want string) bool {
	for _, value := range values {
		if bytes.Equal(value, []byte(want)) {
			return true
		}
	}
	return false
}

func equalByteScopes(values []secretjson.StringBytes, wanted []string) bool {
	if len(values) != len(wanted) || !validByteScopes(values) {
		return false
	}
	for _, want := range wanted {
		if !containsByteScope(values, want) {
			return false
		}
	}
	return true
}

func setHeaders(request *http.Request, in Input) {
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+secrettext.String(in.Token))
	request.Header.Set("Idempotency-Key", in.IdempotencyKey)
	request.Header.Set("X-Trstctl-Tenant", in.TenantID)
}

// ReadResponse drains a bounded response body and refuses non-2xx answers
// without retaining their text.
func ReadResponse(response *http.Response) ([]byte, error) { return readResponse(response) }

func readResponse(response *http.Response) ([]byte, error) {
	if response == nil {
		return nil, errors.New("right-size: endpoint returned no response")
	}
	defer func() { _ = response.Body.Close() }()
	body, err := secret.ReadBounded(response.Body, (1<<20)+1)
	if err != nil {
		return nil, fmt.Errorf("right-size: read response: %w", err)
	}
	if len(body) > 1<<20 {
		secret.Wipe(body)
		return nil, errors.New("right-size: response exceeds 1 MiB")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		secret.Wipe(body)
		return nil, fmt.Errorf("right-size: endpoint returned HTTP %d", response.StatusCode)
	}
	return body, nil
}
