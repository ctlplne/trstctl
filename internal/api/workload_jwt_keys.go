// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"time"

	"trstctl.com/trstctl/internal/authz"
)

// WorkloadJWTKey is one generation of the workload JWT signing key (N5-L3):
// the key that signs JWT-SVIDs and the tokens the OpenID issuer publishes.
// State is active (it signs), next (published ahead of signing), retiring
// (published after the switch until RetiresAt) or retired.
type WorkloadJWTKey struct {
	KeyID       string     `json:"key_id"`
	Generation  int        `json:"generation"`
	State       string     `json:"state"`
	PublishedAt *time.Time `json:"published_at,omitempty"`
	ActivatesAt *time.Time `json:"activates_at,omitempty"`
	RetiresAt   *time.Time `json:"retires_at,omitempty"`
}

// WorkloadJWTKeys is the key set's generations, oldest first.
type WorkloadJWTKeys struct {
	Keys []WorkloadJWTKey `json:"keys"`
}

// WorkloadJWTKeySource reports and rotates the tenant's workload JWT key;
// served is false when the SPIFFE protocol does not serve the tenant.
type WorkloadJWTKeySource interface {
	WorkloadJWTKeysFor(ctx context.Context, tenantID string) (keys []WorkloadJWTKey, served bool, err error)
	RotateWorkloadJWTKey(ctx context.Context, tenantID string, publishAhead, retain time.Duration) ([]WorkloadJWTKey, error)
}

// WorkloadJWTPublicKey is the public half of a published workload JWT key
// (A205-L2): what a SPIRE server sharing the trust domain needs to verify the
// JWT-SVIDs trstctl issues. PublishedAt is nil for the first generation,
// published since the SPIFFE protocol began serving the tenant.
type WorkloadJWTPublicKey struct {
	KeyID        string
	PublicKeyDER []byte
	PublishedAt  *time.Time
	RetiresAt    *time.Time
}

// WorkloadJWTPublicKeySource is a WorkloadJWTKeySource that also hands out
// the published keys' public halves; served is false when the SPIFFE protocol
// does not serve the tenant.
type WorkloadJWTPublicKeySource interface {
	WorkloadJWTPublicKeysFor(ctx context.Context, tenantID string) (keys []WorkloadJWTPublicKey, served bool, err error)
}

// WithWorkloadJWTKeys serves GET /api/v1/workloads/jwt-keys and
// POST /api/v1/workloads/jwt-keys/rotate.
func WithWorkloadJWTKeys(source WorkloadJWTKeySource) Option {
	return func(c *config) { c.workloadJWTKeys = source }
}

type workloadJWTKeyRotateRequest struct {
	PublishAheadSeconds *int64 `json:"publish_ahead_seconds,omitempty"`
	RetainSeconds       *int64 `json:"retain_seconds,omitempty"`
}

// Rotation defaults: a day ahead, and a day after the switch.
const (
	defaultWorkloadJWTKeyPublishAhead = 24 * time.Hour
	defaultWorkloadJWTKeyRetain       = 24 * time.Hour
	maxWorkloadJWTKeyWindowSeconds    = 30 * 24 * 60 * 60
)

func (a *API) workloadJWTKeyRoutes() []route {
	return []route{
		{method: "GET", path: "/api/v1/workloads/jwt-keys", opID: "listWorkloadJWTKeys", summary: "List the workload JWT signing key's generations: the one that signs, the next one published ahead of signing, and earlier ones still published until they retire", handler: a.listWorkloadJWTKeys, resSchema: "WorkloadJWTKeys", successCode: "200", perm: authz.CertsRead},
		{method: "POST", path: "/api/v1/workloads/jwt-keys/rotate", opID: "rotateWorkloadJWTKey", summary: "Rotate the workload JWT signing key: publish the next key now, sign with it after publish_ahead_seconds, and keep the current key published for retain_seconds after that", handler: a.rotateWorkloadJWTKey, reqSchema: "WorkloadJWTKeyRotateRequest", resSchema: "WorkloadJWTKeys", successCode: "200", mutation: true, perm: authz.IssuersWrite},
	}
}

func (a *API) listWorkloadJWTKeys(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.workloadJWTKeys == nil {
		a.writeError(w, errStatus(http.StatusNotFound, "this control plane serves no workload JWT key: enable protocols.spiffe"))
		return
	}
	keys, served, err := a.workloadJWTKeys.WorkloadJWTKeysFor(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if !served {
		a.writeError(w, errStatus(http.StatusNotFound, "the workload JWT key belongs to the SPIFFE protocol's tenant (protocols.spiffe.tenant_id)"))
		return
	}
	a.writeJSON(w, http.StatusOK, WorkloadJWTKeys{Keys: keys})
}

//trstctl:mutation
func (a *API) rotateWorkloadJWTKey(w http.ResponseWriter, r *http.Request) {
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.workloadJWTKeys == nil {
			return 0, nil, errStatus(http.StatusNotFound, "this control plane serves no workload JWT key: enable protocols.spiffe")
		}
		var req workloadJWTKeyRotateRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		publishAhead, retain := defaultWorkloadJWTKeyPublishAhead, defaultWorkloadJWTKeyRetain
		if req.PublishAheadSeconds != nil {
			if *req.PublishAheadSeconds < 0 || *req.PublishAheadSeconds > maxWorkloadJWTKeyWindowSeconds {
				return 0, nil, errStatus(http.StatusBadRequest, "publish_ahead_seconds must be between 0 and 30 days")
			}
			publishAhead = time.Duration(*req.PublishAheadSeconds) * time.Second
		}
		if req.RetainSeconds != nil {
			if *req.RetainSeconds < 0 || *req.RetainSeconds > maxWorkloadJWTKeyWindowSeconds {
				return 0, nil, errStatus(http.StatusBadRequest, "retain_seconds must be between 1 hour and 30 days")
			}
			retain = time.Duration(*req.RetainSeconds) * time.Second
		}
		keys, err := a.workloadJWTKeys.RotateWorkloadJWTKey(ctx, tenantID, publishAhead, retain)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, WorkloadJWTKeys{Keys: keys}, nil
	})
}

func workloadJWTKeySchemas() map[string]*Schema {
	timestamp := func(description string) *Schema {
		return &Schema{Type: "string", Format: "date-time", Description: description}
	}
	return map[string]*Schema{
		"WorkloadJWTKey": {Type: "object", Properties: map[string]*Schema{
			"key_id":     {Type: "string", Description: "the kid tokens signed with this key carry"},
			"generation": {Type: "integer", Description: "1 is the key provisioned with the SPIFFE protocol; each rotation adds one"},
			"state": {Type: "string", Enum: []string{"active", "next", "retiring", "retired"},
				Description: "active signs; next is published ahead of signing; retiring is published until retires_at; retired is no longer published"},
			"published_at": timestamp("when the key was first published (absent for generation 1)"),
			"activates_at": timestamp("when the key starts signing (absent for generation 1)"),
			"retires_at":   timestamp("when the key leaves the published set, once a later key has replaced it"),
		}, Required: []string{"key_id", "generation", "state"}},
		"WorkloadJWTKeys": {Type: "object", Properties: map[string]*Schema{
			"keys": {Type: "array", Items: &Schema{Ref: "#/components/schemas/WorkloadJWTKey"}},
		}, Required: []string{"keys"}},
		"WorkloadJWTKeyRotateRequest": {Type: "object", Properties: map[string]*Schema{
			"publish_ahead_seconds": {Type: "integer", Description: "how long the next key is published before it signs, 0 to 30 days (default 1 day): longer than the clouds cache the key set"},
			"retain_seconds":        {Type: "integer", Description: "how long the current key stays published after the switch, 1 hour to 30 days (default 1 day): longer than its tokens live and than the clouds cache the key set"},
		}},
	}
}
