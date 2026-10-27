// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/api/problem"
	"trstctl.com/trstctl/internal/crypto/tenantwrap"
	"trstctl.com/trstctl/internal/store"
	"trstctl.com/trstctl/internal/tenantseal"
)

// DeploymentKEKLifecycle is the API's view of the deployment KEK's served
// rotation (A198). It returns the recorded state, never a key, a wrapped key
// or a wrapper path.
type DeploymentKEKLifecycle interface {
	Status(context.Context) (store.DeploymentKEKDomain, bool, error)
	Begin(context.Context, string, tenantseal.WrapperRef) (store.DeploymentKEKDomain, error)
}

// DeploymentKEKService is the deployment KEK lifecycle, the one tenant whose
// principals may rotate it, and the hook that starts the rotation worker.
type DeploymentKEKService struct {
	Lifecycle        DeploymentKEKLifecycle
	OperatorTenantID string
	Wake             func()
}

// WithDeploymentKEK wires the deployment KEK's status and served rotation.
func WithDeploymentKEK(service DeploymentKEKService) Option {
	return func(c *config) { c.deploymentKEK = service }
}

type deploymentKEKRotateRequest struct {
	WrapperKind string `json:"wrapper_kind"`
	WrapperID   string `json:"wrapper_id"`
}

// DeploymentKEKStatus is safe operator metadata about the deployment KEK.
type DeploymentKEKStatus struct {
	Served             bool                   `json:"served"`
	Generation         int64                  `json:"generation"`
	Custody            string                 `json:"custody"`
	WrapperKind        string                 `json:"wrapper_kind,omitempty"`
	WrapperID          string                 `json:"wrapper_id,omitempty"`
	PreviousGeneration int64                  `json:"previous_generation,omitempty"`
	RotatedAt          *time.Time             `json:"rotated_at,omitempty"`
	Rotation           *DeploymentKEKRotation `json:"rotation,omitempty"`
	RotationAuthority  string                 `json:"rotation_authority"`
	CanRotate          bool                   `json:"can_rotate"`
	Detail             string                 `json:"detail"`
}

// DeploymentKEKRotation is the latest recorded rotation and its evidence:
// counts of data keys re-wrapped and read back.
type DeploymentKEKRotation struct {
	OperationID            string     `json:"operation_id"`
	Status                 string     `json:"status"`
	Stage                  string     `json:"stage"`
	NextGeneration         int64      `json:"next_generation,omitempty"`
	NextWrapperKind        string     `json:"next_wrapper_kind,omitempty"`
	NextWrapperID          string     `json:"next_wrapper_id,omitempty"`
	StartedAt              *time.Time `json:"started_at,omitempty"`
	VerifiedAt             *time.Time `json:"verified_at,omitempty"`
	TenantsTotal           int64      `json:"tenants_total"`
	TenantsDone            int64      `json:"tenants_done"`
	ContainersRewrapped    int64      `json:"containers_rewrapped"`
	HistoryEventsRewrapped int64      `json:"history_events_rewrapped"`
	FilesRewrapped         int64      `json:"files_rewrapped"`
	ContainersVerified     int64      `json:"containers_verified"`
	VerifyPasses           int64      `json:"verify_passes"`
	FailureCode            string     `json:"failure_code,omitempty"`
	Failure                string     `json:"failure,omitempty"`
}

const (
	deploymentKEKCustodyKeyFile = "key_file"

	deploymentKEKAuthorityOperator      = "operator_tenant"
	deploymentKEKAuthorityOtherTenant   = "another_tenant"
	deploymentKEKAuthorityNotConfigured = "not_configured"
)

func (a *API) getDeploymentKEK(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	if a.deploymentKEK.Lifecycle == nil {
		a.writeJSON(w, http.StatusOK, DeploymentKEKStatus{
			Custody: deploymentKEKCustodyKeyFile, RotationAuthority: a.deploymentKEKAuthority(tenantID),
			Detail: "The deployment KEK is the local key file; this deployment has no database-backed rotation.",
		})
		return
	}
	domain, found, err := a.deploymentKEK.Lifecycle.Status(r.Context())
	if err != nil {
		a.writeProblem(w, problem.New(http.StatusServiceUnavailable, "the deployment KEK status could not be read"))
		return
	}
	a.writeJSON(w, http.StatusOK, a.deploymentKEKStatus(domain, found, tenantID))
}

//trstctl:mutation
func (a *API) rotateDeploymentKEK(w http.ResponseWriter, r *http.Request) {
	a.mutateDurable(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.deploymentKEK.Lifecycle == nil {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "deployment KEK rotation is not configured")
		}
		switch a.deploymentKEKAuthority(tenantID) {
		case deploymentKEKAuthorityNotConfigured:
			return 0, nil, errStatus(http.StatusForbidden, "no tenant may rotate the deployment KEK until secrets.kek_operator_tenant_id names one")
		case deploymentKEKAuthorityOtherTenant:
			return 0, nil, errStatus(http.StatusForbidden, "only the deployment KEK operator tenant (secrets.kek_operator_tenant_id) may rotate the deployment KEK")
		}
		var req deploymentKEKRotateRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		ref := tenantseal.WrapperRef{Kind: strings.TrimSpace(req.WrapperKind), ID: strings.TrimSpace(req.WrapperID)}
		if (ref.Kind != tenantseal.WrapperKindLocalFile && ref.Kind != tenantseal.WrapperKindPKCS11) || ref.ID == "" {
			return 0, nil, errStatus(http.StatusBadRequest, "wrapper_kind must be local_file or pkcs11, with the wrapper_id of a configured wrapper")
		}
		domain, err := a.deploymentKEK.Lifecycle.Begin(ctx, tenantID, ref)
		if err != nil {
			return 0, nil, mapDeploymentKEKError(err)
		}
		if a.deploymentKEK.Wake != nil {
			a.deploymentKEK.Wake()
		}
		return http.StatusAccepted, a.deploymentKEKStatus(domain, true, tenantID), nil
	})
}

func (a *API) deploymentKEKAuthority(tenantID string) string {
	switch a.deploymentKEK.OperatorTenantID {
	case "":
		return deploymentKEKAuthorityNotConfigured
	case tenantID:
		return deploymentKEKAuthorityOperator
	default:
		return deploymentKEKAuthorityOtherTenant
	}
}

func (a *API) deploymentKEKStatus(d store.DeploymentKEKDomain, found bool, tenantID string) DeploymentKEKStatus {
	authority := a.deploymentKEKAuthority(tenantID)
	out := DeploymentKEKStatus{
		Served: true, Custody: deploymentKEKCustodyKeyFile,
		RotationAuthority: authority, CanRotate: authority == deploymentKEKAuthorityOperator,
	}
	if !found {
		out.Detail = "The deployment KEK is the local key file (generation 0); it has never rotated."
		return out
	}
	out.Generation, out.PreviousGeneration, out.RotatedAt = d.Generation, d.PreviousGeneration, d.RotatedAt
	if d.Generation > 0 {
		out.Custody, out.WrapperKind, out.WrapperID = d.WrapperKind, d.WrapperKind, d.WrapperID
	}
	out.Rotation = &DeploymentKEKRotation{
		OperationID: d.OperationID, Status: d.OperationStatus, Stage: d.Stage,
		NextGeneration: d.NextGeneration, NextWrapperKind: d.NextWrapperKind, NextWrapperID: d.NextWrapperID,
		StartedAt: d.StartedAt, VerifiedAt: d.VerifiedAt,
		TenantsTotal: d.TenantsTotal, TenantsDone: d.TenantsDone,
		ContainersRewrapped: d.ContainersRewrapped, HistoryEventsRewrapped: d.HistoryEventsRewrapped,
		FilesRewrapped: d.FilesRewrapped, ContainersVerified: d.ContainersVerified, VerifyPasses: d.VerifyPasses,
		FailureCode: d.LastErrorCode, Failure: d.LastError,
	}
	switch {
	case d.Rotating() && d.OperationStatus == store.DeploymentKEKOperationFailed:
		out.Detail = "The rotation stopped; new data is still wrapped under the next generation. Resume it with the same wrapper."
	case d.Rotating():
		out.Detail = "A rotation is re-wrapping every stored data key under the next generation; requests are served throughout."
	case d.Generation > 0:
		out.Detail = "Every stored data key was re-wrapped under this generation and read back; the previous generation is retired."
	}
	return out
}

func mapDeploymentKEKError(err error) error {
	switch {
	case errors.Is(err, tenantseal.ErrDeploymentRotationConflict):
		return errStatus(http.StatusConflict, "a rotation to another wrapper is not complete; resume it with its own wrapper first")
	case errors.Is(err, tenantseal.ErrInvalidWrapperConfig):
		return errStatus(http.StatusBadRequest, "wrapper_kind must be local_file or pkcs11, with the wrapper_id of a configured wrapper")
	case errors.Is(err, tenantseal.ErrWrapperNotConfigured):
		return errStatus(http.StatusServiceUnavailable, "the requested wrapper is not configured")
	case errors.Is(err, tenantwrap.ErrUnavailable), errors.Is(err, tenantwrap.ErrInvalidWrapperKey):
		return errStatus(http.StatusServiceUnavailable, "the requested wrapper is unavailable")
	default:
		return errStatus(http.StatusInternalServerError, "the deployment KEK rotation could not start")
	}
}
