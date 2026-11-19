// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	googleuuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// KubernetesTrustRolloutStore reads projected rollouts. The shipped binary attaches the projected store explicitly.
type KubernetesTrustRolloutStore interface {
	ListKubernetesTrustRollouts(context.Context, string) ([]store.KubernetesTrustRollout, error)
	GetKubernetesTrustRollout(context.Context, string, string) (store.KubernetesTrustRollout, error)
}

// WithKubernetesTrustRollouts serves multi-cluster TrustBundle rollouts (A138).
func WithKubernetesTrustRollouts(reader KubernetesTrustRolloutStore) Option {
	return func(c *config) { c.kubernetesTrustRollouts = reader }
}

type kubernetesTrustRolloutRequest struct {
	Name          string   `json:"name"`
	CABundlePEM   string   `json:"ca_bundle_pem"`
	ConfigMapName string   `json:"config_map_name,omitempty"`
	Key           string   `json:"key,omitempty"`
	Namespaces    []string `json:"namespaces"`
	Clusters      []string `json:"clusters"`
}

// KubernetesTrustRolloutCluster is one cluster's progress in a rollout.
type KubernetesTrustRolloutCluster struct {
	ClusterID    string     `json:"cluster_id"`
	Position     int        `json:"position"`
	Canary       bool       `json:"canary"`
	State        string     `json:"state"`
	Reason       string     `json:"reason,omitempty"`
	ReportID     string     `json:"report_id,omitempty"`
	ObservedHash string     `json:"observed_hash,omitempty"`
	DispatchedAt *time.Time `json:"dispatched_at,omitempty"`
	VerifiedAt   *time.Time `json:"verified_at,omitempty"`
}

// KubernetesTrustRollout is a TrustBundle rolled out to several clusters,
// canary first. A cluster reads verified only after its own controller reported
// the bundle distributed with BundleSHA256.
type KubernetesTrustRollout struct {
	ID            string                          `json:"id"`
	Name          string                          `json:"name"`
	CABundlePEM   string                          `json:"ca_bundle_pem"`
	BundleSHA256  string                          `json:"bundle_sha256"`
	ConfigMapName string                          `json:"config_map_name"`
	Key           string                          `json:"key"`
	Namespaces    []string                        `json:"namespaces"`
	State         string                          `json:"state"`
	Verified      int                             `json:"verified_clusters"`
	CreatedAt     time.Time                       `json:"created_at"`
	UpdatedAt     time.Time                       `json:"updated_at"`
	Clusters      []KubernetesTrustRolloutCluster `json:"clusters"`
}

// KubernetesTrustRolloutList is the tenant's rollouts, newest first.
type KubernetesTrustRolloutList struct {
	Items []KubernetesTrustRollout `json:"items"`
}

func kubernetesTrustRolloutView(r store.KubernetesTrustRollout) KubernetesTrustRollout {
	view := KubernetesTrustRollout{
		ID: r.ID, Name: r.Name, CABundlePEM: r.CABundlePEM, BundleSHA256: r.BundleSHA256,
		ConfigMapName: r.ConfigMapName, Key: r.BundleKey, Namespaces: r.Namespaces, State: r.State,
		CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt, Clusters: make([]KubernetesTrustRolloutCluster, 0, len(r.Clusters)),
	}
	for _, c := range r.Clusters {
		if c.State == store.KubernetesTrustClusterVerified {
			view.Verified++
		}
		view.Clusters = append(view.Clusters, KubernetesTrustRolloutCluster{
			ClusterID: c.ClusterID, Position: c.Position, Canary: c.Position == 0, State: c.State,
			Reason: c.Reason, ReportID: c.ReportID, ObservedHash: c.ObservedHash,
			DispatchedAt: c.DispatchedAt, VerifiedAt: c.VerifiedAt,
		})
	}
	return view
}

func (a *API) kubernetesTrustRolloutReader(w http.ResponseWriter) (KubernetesTrustRolloutStore, bool) {
	if a.kubernetesTrustRollouts == nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "Kubernetes trust rollouts are not configured"))
		return nil, false
	}
	return a.kubernetesTrustRollouts, true
}

//trstctl:mutation
func (a *API) startKubernetesTrustRollout(w http.ResponseWriter, r *http.Request) {
	reader, ok := a.kubernetesTrustRolloutReader(w)
	if !ok {
		return
	}
	var req kubernetesTrustRolloutRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, "invalid JSON body: "+err.Error()))
		return
	}
	name := strings.TrimSpace(req.Name)
	configMap := firstNonBlank(strings.TrimSpace(req.ConfigMapName), name)
	key := firstNonBlank(strings.TrimSpace(req.Key), "ca-bundle.pem")
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	// Preserve the principal-bound v1 request bytes for completed historical
	// retries. Current effect admission runs inside the durable callback.
	bindingPayload, err := json.Marshal(kubernetesTrustRolloutRequest{
		Name: name, CABundlePEM: strings.TrimSpace(req.CABundlePEM) + "\n", ConfigMapName: configMap, Key: key, Namespaces: req.Namespaces, Clusters: req.Clusters,
	})
	if err != nil {
		a.writeError(w, err)
		return
	}
	idempotencyKey := r.Header.Get("Idempotency-Key")
	binding := crypto.SHA256Hex([]byte("kubernetes-trust-rollout\x00" + principal + "\x00" + string(bindingPayload)))
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		started := projections.KubernetesTrustRolloutStarted{
			RolloutID: googleuuid.NewSHA1(googleuuid.NameSpaceOID, []byte("kubernetes-trust-rollout\x00"+tenantID+"\x00"+idempotencyKey)).String(),
			Name:      name, CABundlePEM: req.CABundlePEM, ConfigMapName: configMap, Key: key,
			Namespaces: req.Namespaces, Clusters: req.Clusters,
		}
		if err := a.orch.StartKubernetesTrustRollout(ctx, tenantID, started); err != nil {
			switch {
			case errors.Is(err, orchestrator.ErrKubernetesTrustRolloutTargets):
				return 0, nil, errStatusFrom(http.StatusBadRequest, err)
			case errors.Is(err, orchestrator.ErrKubernetesTrustRolloutInput):
				return 0, nil, errStatusFrom(http.StatusUnprocessableEntity, err)
			default:
				return 0, nil, err
			}
		}
		rollout, err := reader.GetKubernetesTrustRollout(ctx, tenantID, started.RolloutID)
		if errors.Is(err, store.ErrKubernetesTrustRolloutNotFound) {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "retained Kubernetes trust rollout is awaiting ordered projection recovery; preserve this Idempotency-Key")
		}
		if err != nil {
			return 0, nil, err
		}
		return http.StatusCreated, kubernetesTrustRolloutView(rollout), nil
	})
}

func (a *API) listKubernetesTrustRollouts(w http.ResponseWriter, r *http.Request) {
	reader, ok := a.kubernetesTrustRolloutReader(w)
	if !ok {
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	rollouts, err := reader.ListKubernetesTrustRollouts(r.Context(), tenantID)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := KubernetesTrustRolloutList{Items: make([]KubernetesTrustRollout, 0, len(rollouts))}
	for _, rollout := range rollouts {
		out.Items = append(out.Items, kubernetesTrustRolloutView(rollout))
	}
	a.writeJSON(w, http.StatusOK, out)
}

func (a *API) getKubernetesTrustRollout(w http.ResponseWriter, r *http.Request) {
	reader, ok := a.kubernetesTrustRolloutReader(w)
	if !ok {
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	rollout, err := reader.GetKubernetesTrustRollout(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, kubernetesTrustRolloutError(err))
		return
	}
	a.writeJSON(w, http.StatusOK, kubernetesTrustRolloutView(rollout))
}

//trstctl:mutation
func (a *API) pauseKubernetesTrustRollout(w http.ResponseWriter, r *http.Request) {
	a.controlKubernetesTrustRollout(w, r, r.Header.Get("Idempotency-Key"), false)
}

//trstctl:mutation
func (a *API) resumeKubernetesTrustRollout(w http.ResponseWriter, r *http.Request) {
	a.controlKubernetesTrustRollout(w, r, r.Header.Get("Idempotency-Key"), true)
}

func (a *API) controlKubernetesTrustRollout(w http.ResponseWriter, r *http.Request, idempotencyKey string, resume bool) {
	reader, ok := a.kubernetesTrustRolloutReader(w)
	if !ok {
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	id := r.PathValue("id")
	operation, from, verb := "pause", store.KubernetesTrustRolloutRunning, "paused"
	if resume {
		operation, from, verb = "resume", store.KubernetesTrustRolloutPaused, "resumed"
	}
	binding := crypto.SHA256Hex([]byte("kubernetes-trust-rollout-" + operation + "\x00" + principal + "\x00" + id))
	a.mutateDurableBound(w, r, idempotencyKey, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		current, err := reader.GetKubernetesTrustRollout(ctx, tenantID, id)
		if err != nil {
			return 0, nil, kubernetesTrustRolloutError(err)
		}
		if current.State != from {
			return 0, nil, errStatus(http.StatusConflict, "the rollout is "+current.State+"; only a "+from+" rollout can be "+verb)
		}
		if err := a.orch.ControlKubernetesTrustRollout(ctx, tenantID, id, resume, idempotencyKey); err != nil {
			return 0, nil, err
		}
		updated, err := reader.GetKubernetesTrustRollout(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, kubernetesTrustRolloutView(updated), nil
	})
}

func kubernetesTrustRolloutError(err error) error {
	if errors.Is(err, store.ErrKubernetesTrustRolloutNotFound) {
		return errStatus(http.StatusNotFound, "no such Kubernetes trust rollout")
	}
	return err
}
