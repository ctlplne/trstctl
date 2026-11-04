// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/authz"
)

// Factory provisioning for devices (P12). A factory batch is a quota of birth
// certificates a station on the production line issues offline under one edge
// delegation. The station has no network listener: the line's tooling runs
// `trstctl-agent --factory-issue` once per device, which certifies the
// device's own key, refuses past the quota and appends to the batch journal.
// The journal reconciles here when the station reconnects; a birth certificate
// past the quota is recorded as over-production and cannot enroll. On first
// boot a device enrolls over EST at /.well-known/est/factory with a proof
// signed by its birth key, through the relay enrollment proxy where it has no
// route, and renews in the field the same way with its operational key.

// FactoryBatchService runs factory batches over the edge delegations.
type FactoryBatchService interface {
	CreateFactoryBatch(ctx context.Context, tenantID, creator string, req FactoryBatchRequest) (FactoryBatch, error)
	ListFactoryBatches(ctx context.Context, tenantID string) ([]FactoryBatch, error)
	GetFactoryBatch(ctx context.Context, tenantID, id string) (FactoryBatchDetail, error)
	FactoryBatchManifest(ctx context.Context, tenantID, id string) (FactoryManifest, error)
	ReconcileFactoryBatch(ctx context.Context, tenantID, id string, req FactoryReconcileRequest) (FactoryReconcileResult, error)
}

// WithFactoryBatches serves P12's routes.
func WithFactoryBatches(service FactoryBatchService) Option {
	return func(c *config) { c.factoryBatches = service }
}

var (
	// ErrFactoryBatchNotFound is a batch this tenant does not have.
	ErrFactoryBatchNotFound = errors.New("factory batch not found")
	// ErrFactoryDelegationUnusable is a delegation a batch cannot issue under.
	ErrFactoryDelegationUnusable = errors.New("the edge delegation is not an active delegation of this tenant")
)

// FactoryBatchRequest creates a batch.
type FactoryBatchRequest struct {
	DelegationID       string `json:"delegation_id"`
	Label              string `json:"label"`
	Quota              int    `json:"quota"`
	BirthTTLSeconds    int    `json:"birth_ttl_seconds"`
	OperationalProfile string `json:"operational_profile,omitempty"`
}

// FactoryBatch is one batch with what its journals have reconciled.
type FactoryBatch struct {
	ID                 string    `json:"id"`
	DelegationID       string    `json:"delegation_id"`
	Label              string    `json:"label"`
	Quota              int       `json:"quota"`
	BirthTTLSeconds    int       `json:"birth_ttl_seconds"`
	OperationalProfile string    `json:"operational_profile,omitempty"`
	CreatedBy          string    `json:"created_by"`
	CreatedAt          time.Time `json:"created_at"`
	Recorded           int       `json:"recorded"`
	OverQuota          int       `json:"over_quota"`
	Enrolled           int       `json:"enrolled"`
}

// FactoryBirth is one reconciled birth certificate and its device's enrollment.
type FactoryBirth struct {
	Serial            string     `json:"serial"`
	DeviceName        string     `json:"device_name"`
	Fingerprint       string     `json:"fingerprint"`
	NotAfter          time.Time  `json:"not_after"`
	OverQuota         bool       `json:"over_quota"`
	Enrolled          bool       `json:"enrolled"`
	EnrolledAt        *time.Time `json:"enrolled_at,omitempty"`
	OperationalSerial string     `json:"operational_serial,omitempty"`
	Renewals          int        `json:"renewals"`
}

// FactoryBatchDetail is a batch with its birth certificates.
type FactoryBatchDetail struct {
	FactoryBatch
	Births []FactoryBirth `json:"births"`
}

// FactoryManifest is what the station is given: the batch it issues for, its
// delegation and quota.
type FactoryManifest struct {
	BatchID               string `json:"batch_id"`
	TenantID              string `json:"tenant_id"`
	DelegationID          string `json:"delegation_id"`
	DelegationFingerprint string `json:"delegation_fingerprint"`
	Label                 string `json:"label"`
	Quota                 int    `json:"quota"`
	BirthTTLSeconds       int    `json:"birth_ttl_seconds"`
	ESTPath               string `json:"est_path"`
}

// FactoryReconcileRequest is a station's batch journal.
type FactoryReconcileRequest struct {
	Host            string   `json:"host"`
	BatchID         string   `json:"batch_id,omitempty"`
	CertificatesPEM []string `json:"certificates_pem"`
}

// FactoryReconcileResult counts what a reconcile recorded.
type FactoryReconcileResult struct {
	Recorded  int `json:"recorded"`
	OverQuota int `json:"over_quota"`
	Already   int `json:"already"`
	Rejected  int `json:"rejected"`
}

const maxFactoryQuota = 1_000_000

func (a *API) factoryBatchRoutes() []route {
	idPath := []param{pathString("id", "factory batch id")}
	return []route{
		{method: "POST", path: "/api/v1/edge/factory-batches", opID: "createFactoryBatch", summary: "Create a factory batch: a quota of device birth certificates a station issues offline under one edge delegation", handler: a.createFactoryBatch, reqSchema: "FactoryBatchRequest", resSchema: "FactoryBatch", successCode: "201", mutation: true, perm: authz.IssuersWrite},
		{method: "GET", path: "/api/v1/edge/factory-batches", opID: "listFactoryBatches", summary: "List factory batches with what their stations' journals have reconciled", handler: a.listFactoryBatches, resSchema: "FactoryBatchList", successCode: "200", perm: authz.IssuersRead},
		{method: "GET", path: "/api/v1/edge/factory-batches/{id}", opID: "getFactoryBatch", summary: "Get a factory batch with its birth certificates and each device's enrollment", handler: a.getFactoryBatch, pathParams: idPath, resSchema: "FactoryBatchDetail", successCode: "200", perm: authz.IssuersRead},
		{method: "GET", path: "/api/v1/edge/factory-batches/{id}/manifest", opID: "getFactoryBatchManifest", summary: "Get the manifest a factory station issues the batch from", handler: a.getFactoryBatchManifest, pathParams: idPath, resSchema: "FactoryManifest", successCode: "200", perm: authz.IssuersRead},
		{method: "POST", path: "/api/v1/edge/factory-batches/{id}/reconcile", opID: "reconcileFactoryBatch", summary: "Reconcile a factory station's batch journal: each birth certificate is recorded once, and those past the quota as over-production", handler: a.reconcileFactoryBatch, pathParams: idPath, reqSchema: "FactoryReconcileRequest", resSchema: "FactoryReconcileResult", successCode: "200", mutation: true, perm: authz.IssuersWrite},
	}
}

func factoryAPIError(err error) error {
	switch {
	case errors.Is(err, ErrFactoryBatchNotFound):
		return errStatusFrom(http.StatusNotFound, err)
	case errors.Is(err, ErrFactoryDelegationUnusable):
		return errStatusFrom(http.StatusConflict, err)
	}
	return err
}

//trstctl:mutation
func (a *API) createFactoryBatch(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.factoryBatches == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "factory provisioning is not configured")
		}
		var req FactoryBatchRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		req.DelegationID, req.Label = strings.TrimSpace(req.DelegationID), strings.TrimSpace(req.Label)
		req.OperationalProfile = strings.TrimSpace(req.OperationalProfile)
		switch {
		case req.DelegationID == "":
			return 0, nil, errStatus(http.StatusBadRequest, "delegation_id names the edge delegation the station issues under")
		case req.Label == "" || len(req.Label) > 100:
			return 0, nil, errStatus(http.StatusBadRequest, "label is required (at most 100 characters)")
		case req.Quota <= 0 || req.Quota > maxFactoryQuota:
			return 0, nil, errStatus(http.StatusBadRequest, "quota must be between 1 and 1000000 birth certificates")
		case req.BirthTTLSeconds <= 0:
			return 0, nil, errStatus(http.StatusBadRequest, "birth_ttl_seconds must be positive")
		}
		creator, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		batch, err := a.factoryBatches.CreateFactoryBatch(ctx, tenantID, creator, req)
		return http.StatusCreated, batch, factoryAPIError(err)
	})
}

func (a *API) listFactoryBatches(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.factoryBatches == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "factory provisioning is not configured"))
		return
	}
	batches, err := a.factoryBatches.ListFactoryBatches(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": batches})
}

func (a *API) getFactoryBatch(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.factoryBatches == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "factory provisioning is not configured"))
		return
	}
	detail, err := a.factoryBatches.GetFactoryBatch(r.Context(), tenantID, strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		a.writeError(w, factoryAPIError(err))
		return
	}
	a.writeJSON(w, http.StatusOK, detail)
}

func (a *API) getFactoryBatchManifest(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.factoryBatches == nil {
		a.writeError(w, errStatus(http.StatusServiceUnavailable, "factory provisioning is not configured"))
		return
	}
	manifest, err := a.factoryBatches.FactoryBatchManifest(r.Context(), tenantID, strings.TrimSpace(r.PathValue("id")))
	if err != nil {
		a.writeError(w, factoryAPIError(err))
		return
	}
	a.writeJSON(w, http.StatusOK, manifest)
}

//trstctl:mutation
func (a *API) reconcileFactoryBatch(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	a.mutate(w, r, idempotencyKey, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.factoryBatches == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "factory provisioning is not configured")
		}
		var req FactoryReconcileRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		id := strings.TrimSpace(r.PathValue("id"))
		if req.BatchID != "" && req.BatchID != id {
			return 0, nil, errStatus(http.StatusBadRequest, "the journal belongs to another batch")
		}
		if len(req.CertificatesPEM) == 0 {
			return 0, nil, errStatus(http.StatusBadRequest, "certificates_pem is required: the journal reports the birth certificates the station issued")
		}
		result, err := a.factoryBatches.ReconcileFactoryBatch(ctx, tenantID, id, req)
		return http.StatusOK, result, factoryAPIError(err)
	})
}

func factoryBatchSchemas() map[string]*Schema {
	str := func() *Schema { return &Schema{Type: "string"} }
	integer := func() *Schema { return &Schema{Type: "integer"} }
	boolean := func() *Schema { return &Schema{Type: "boolean"} }
	ts := func() *Schema { return &Schema{Type: "string", Format: "date-time"} }
	object := func(props map[string]*Schema, required ...string) *Schema {
		return &Schema{Type: "object", Properties: props, Required: required}
	}
	batchProps := func() map[string]*Schema {
		return map[string]*Schema{"id": str(), "delegation_id": str(), "label": str(), "quota": integer(), "birth_ttl_seconds": integer(),
			"operational_profile": str(), "created_by": str(), "created_at": ts(), "recorded": integer(), "over_quota": integer(),
			"enrolled": integer()}
	}
	batchRequired := []string{"id", "delegation_id", "label", "quota", "birth_ttl_seconds", "created_by", "created_at", "recorded", "over_quota", "enrolled"}
	batch := object(batchProps(), batchRequired...)
	birth := object(map[string]*Schema{"serial": str(), "device_name": str(), "fingerprint": str(), "not_after": ts(),
		"over_quota": boolean(), "enrolled": boolean(), "enrolled_at": ts(), "operational_serial": str(), "renewals": integer()},
		"serial", "device_name", "fingerprint", "not_after", "over_quota", "enrolled", "renewals")
	detailProps := batchProps()
	detailProps["births"] = &Schema{Type: "array", Items: birth}
	return map[string]*Schema{
		"FactoryBatchRequest": object(map[string]*Schema{"delegation_id": str(), "label": str(), "quota": integer(),
			"birth_ttl_seconds": integer(), "operational_profile": str()}, "delegation_id", "label", "quota", "birth_ttl_seconds"),
		"FactoryBatch":       batch,
		"FactoryBatchList":   object(map[string]*Schema{"items": {Type: "array", Items: batch}}, "items"),
		"FactoryBatchDetail": object(detailProps, append(batchRequired, "births")...),
		"FactoryManifest": object(map[string]*Schema{"batch_id": str(), "tenant_id": str(), "delegation_id": str(),
			"delegation_fingerprint": str(), "label": str(), "quota": integer(), "birth_ttl_seconds": integer(), "est_path": str()},
			"batch_id", "tenant_id", "delegation_id", "delegation_fingerprint", "label", "quota", "birth_ttl_seconds", "est_path"),
		"FactoryReconcileRequest": object(map[string]*Schema{"host": str(), "batch_id": str(),
			"certificates_pem": {Type: "array", Items: str()}}, "certificates_pem"),
		"FactoryReconcileResult": object(map[string]*Schema{"recorded": integer(), "over_quota": integer(), "already": integer(),
			"rejected": integer()}, "recorded", "over_quota", "already", "rejected"),
	}
}
