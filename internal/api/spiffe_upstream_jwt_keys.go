// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/store"
)

// A205: SPIRE servers publish their JWT signing keys through the trstctl
// upstream authority plugin, and each receives every key the tenant's servers
// have published, so servers that share a trust domain through trstctl verify
// each other's JWT-SVIDs. A205-L2: the set also carries trstctl's own SPIFFE
// JWT authority, every workload JWT key it publishes (the one that signs, a
// next key published ahead, a retiring one until it retires), so SPIRE
// servers verify the JWT-SVIDs trstctl issues too.

// SPIFFEJWTAuthorityPublisher is the published_by of trstctl's own keys.
const SPIFFEJWTAuthorityPublisher = "trstctl-spiffe-jwt-authority"

type spiffeUpstreamJWTKeyRequest struct {
	KeyID string `json:"key_id"`
	// PublicKey is the PKIX DER public key, base64.
	PublicKey []byte     `json:"public_key"`
	ExpiresAt *time.Time `json:"expires_at"`
	Tainted   bool       `json:"tainted"`
}

type spiffeUpstreamJWTKeyResponse struct {
	KeyID       string     `json:"key_id"`
	PublicKey   []byte     `json:"public_key"`
	ExpiresAt   *time.Time `json:"expires_at"`
	Tainted     bool       `json:"tainted"`
	PublishedBy string     `json:"published_by"`
	// PublishedAt is absent for trstctl's first-generation key, published
	// since the SPIFFE protocol began serving the tenant (A205-L2).
	PublishedAt *time.Time `json:"published_at,omitempty"`
}

func (a *API) spiffeUpstreamJWTKeyRoutes() []route {
	return []route{
		{method: "POST", path: "/api/v1/spiffe/upstream-jwt-keys", opID: "publishSPIFFEUpstreamJWTKey", summary: "Publish a SPIRE server's JWT signing key and get every unexpired key the tenant's SPIRE servers have published", handler: a.publishSPIFFEUpstreamJWTKey, reqSchema: "SPIFFEUpstreamJWTKeyRequest", resSchema: "SPIFFEUpstreamJWTKeyList", successCode: "200", mutation: true, perm: authz.IssuersWrite},
		{method: "GET", path: "/api/v1/spiffe/upstream-jwt-keys", opID: "listSPIFFEUpstreamJWTKeys", summary: "List the unexpired JWT signing keys the tenant's SPIRE servers have published", handler: a.listSPIFFEUpstreamJWTKeys, resSchema: "SPIFFEUpstreamJWTKeyList", successCode: "200", perm: authz.IssuersRead},
	}
}

func spiffeUpstreamJWTKeySchemas() map[string]*Schema {
	key := object(map[string]*Schema{
		"key_id":       str(),
		"public_key":   {Type: "string", Format: "byte", Description: "PKIX (SubjectPublicKeyInfo) DER public key, base64"},
		"expires_at":   {Type: "string", Format: "date-time", Description: "when the key expires; null for a key without an expiry"},
		"tainted":      {Type: "boolean", Description: "the publishing server no longer considers the key safe to use"},
		"published_by": {Type: "string", Description: "the token subject that first published the key, or trstctl-spiffe-jwt-authority for trstctl's own workload JWT keys (A205-L2)"},
		"published_at": {Type: "string", Format: "date-time", Description: "when the key was first published; absent for trstctl's first-generation key, published since the SPIFFE protocol began serving the tenant"},
	}, "key_id", "public_key", "expires_at", "tainted", "published_by")
	return map[string]*Schema{
		"SPIFFEUpstreamJWTKeyRequest": object(map[string]*Schema{
			"key_id":     {Type: "string", Description: "the key ID SPIRE signs JWT-SVIDs with (the JWT kid)"},
			"public_key": {Type: "string", Format: "byte", Description: "PKIX (SubjectPublicKeyInfo) DER public key, base64: EC P-256/P-384/P-521, RSA or Ed25519"},
			"expires_at": {Type: "string", Format: "date-time", Description: "when the key expires; omit for a key without an expiry"},
			"tainted":    {Type: "boolean", Description: "mark an already published key as no longer safe to use"},
		}, "key_id", "public_key"),
		"SPIFFEUpstreamJWTKey":     key,
		"SPIFFEUpstreamJWTKeyList": object(map[string]*Schema{"items": {Type: "array", Items: ref("SPIFFEUpstreamJWTKey")}}, "items"),
	}
}

func toSPIFFEUpstreamJWTKeyResponses(keys []store.SPIFFEUpstreamJWTKey) []spiffeUpstreamJWTKeyResponse {
	out := make([]spiffeUpstreamJWTKeyResponse, 0, len(keys))
	for _, k := range keys {
		publishedAt := k.PublishedAt
		out = append(out, spiffeUpstreamJWTKeyResponse{
			KeyID: k.KeyID, PublicKey: k.PublicKeyDER, ExpiresAt: k.ExpiresAt, Tainted: k.Tainted,
			PublishedBy: k.PublishedBy, PublishedAt: &publishedAt,
		})
	}
	return out
}

// withSPIFFEJWTAuthority adds trstctl's own published workload JWT keys to
// the SPIRE servers' keys (A205-L2). A tenant the SPIFFE protocol does not
// serve, or a control plane without one, adds nothing. A key ID a SPIRE
// server already published under is left as that server published it.
func (a *API) withSPIFFEJWTAuthority(ctx context.Context, tenantID string, items []spiffeUpstreamJWTKeyResponse) ([]spiffeUpstreamJWTKeyResponse, error) {
	source, ok := a.workloadJWTKeys.(WorkloadJWTPublicKeySource)
	if !ok {
		return items, nil
	}
	keys, served, err := source.WorkloadJWTPublicKeysFor(ctx, tenantID)
	if err != nil || !served {
		return items, err
	}
	for _, key := range keys {
		if slices.ContainsFunc(items, func(item spiffeUpstreamJWTKeyResponse) bool { return item.KeyID == key.KeyID }) {
			continue
		}
		items = append(items, spiffeUpstreamJWTKeyResponse{
			KeyID: key.KeyID, PublicKey: key.PublicKeyDER, ExpiresAt: key.RetiresAt,
			PublishedBy: SPIFFEJWTAuthorityPublisher, PublishedAt: key.PublishedAt,
		})
	}
	return items, nil
}

func mapSPIFFEUpstreamJWTKeyError(err error) error {
	var invalid *orchestrator.InvalidSPIFFEUpstreamJWTKeyError
	switch {
	case errors.As(err, &invalid):
		return errStatus(http.StatusBadRequest, strings.TrimPrefix(invalid.Error(), "orchestrator: "))
	case errors.Is(err, orchestrator.ErrSPIFFEUpstreamJWTKeyConflict):
		return errStatus(http.StatusConflict, "that key ID is already published with a different key or expiry")
	}
	return err
}

//trstctl:mutation
func (a *API) publishSPIFFEUpstreamJWTKey(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "SPIRE JWT key publication is not configured")
		}
		var req spiffeUpstreamJWTKeyRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, err
		}
		keys, err := a.orch.PublishSPIFFEUpstreamJWTKey(ctx, tenantID, orchestrator.SPIFFEUpstreamJWTKeyInput{
			KeyID: req.KeyID, PublicKeyDER: req.PublicKey, ExpiresAt: req.ExpiresAt, Tainted: req.Tainted,
		})
		if err != nil {
			return 0, nil, mapSPIFFEUpstreamJWTKeyError(err)
		}
		items, err := a.withSPIFFEJWTAuthority(ctx, tenantID, toSPIFFEUpstreamJWTKeyResponses(keys))
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, map[string]any{"items": items}, nil
	})
}

func (a *API) listSPIFFEUpstreamJWTKeys(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.store == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "SPIRE JWT key publication is not configured"))
		return
	}
	keys, err := a.store.ListSPIFFEUpstreamJWTKeys(r.Context(), tenantID, time.Now())
	if err != nil {
		a.writeError(w, err)
		return
	}
	items, err := a.withSPIFFEJWTAuthority(r.Context(), tenantID, toSPIFFEUpstreamJWTKeyResponses(keys))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}
