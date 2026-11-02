// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// A238: secret delivery reports. A consumer that writes secrets for an
// application (an agent rendering files, a CSI volume) reports, per secret, the
// version it wrote ("injected") and, separately, the version its application
// proved it uses ("verified"). A consumer can report only secrets it may read,
// at versions that exist; the list shows, per consumer, whether it is verified
// on the current version, injected only, or behind.

var secretDeliveryConsumer = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$`)

type secretDeliveryRequest struct {
	Consumer string                           `json:"consumer"`
	State    string                           `json:"state"`
	Secrets  []projections.SecretDeliveryItem `json:"secrets"`
}

type secretDeliveryConsumerResponse struct {
	Consumer        string     `json:"consumer"`
	InjectedVersion int        `json:"injected_version"`
	InjectedAt      *time.Time `json:"injected_at,omitempty"`
	VerifiedVersion int        `json:"verified_version"`
	VerifiedAt      *time.Time `json:"verified_at,omitempty"`
	State           string     `json:"state"`
}

type secretDeliveriesResponse struct {
	Name           string                           `json:"name"`
	CurrentVersion int                              `json:"current_version"`
	Consumers      []secretDeliveryConsumerResponse `json:"consumers"`
}

func (a *API) secretDeliveryRoutes() []route {
	return []route{
		{method: "POST", path: "/api/v1/secrets/deliveries", opID: "reportSecretDelivery",
			summary: "Report the secret versions a consumer wrote (injected) or its application proved it uses (verified)",
			handler: a.reportSecretDelivery, reqSchema: "SecretDeliveryReport", resSchema: "SecretDeliveryReport",
			successCode: "200", mutation: true, perm: authz.SecretsRead},
		{method: "GET", path: "/api/v1/secrets/deliveries", opID: "listSecretDeliveries",
			summary: "List, per consumer, the injected and verified versions of one secret against its current version",
			handler: a.listSecretDeliveries, query: []param{{name: "name", typ: "string", required: true, desc: "secret name"}},
			resSchema: "SecretDeliveries", successCode: "200", perm: authz.SecretsRead},
	}
}

func secretDeliverySchemas() map[string]*Schema {
	item := object(map[string]*Schema{"name": str(), "version": {Type: "integer"}}, "name", "version")
	return map[string]*Schema{
		"SecretDeliveryReport": object(map[string]*Schema{
			"consumer": str(), "state": {Type: "string", Enum: []string{store.SecretDeliveryInjected, store.SecretDeliveryVerified}},
			"secrets": {Type: "array", Items: item},
		}, "consumer", "state", "secrets"),
		"SecretDeliveries": object(map[string]*Schema{
			"name": str(), "current_version": {Type: "integer"},
			"consumers": {Type: "array", Items: object(map[string]*Schema{
				"consumer": str(), "injected_version": {Type: "integer"}, "injected_at": timestamp(),
				"verified_version": {Type: "integer"}, "verified_at": timestamp(),
				"state": {Type: "string", Enum: []string{"verified", "injected", "behind"}},
			}, "consumer", "injected_version", "verified_version", "state")},
		}, "name", "current_version", "consumers"),
	}
}

//trstctl:mutation
func (a *API) reportSecretDelivery(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.store == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	a.mutate(w, r, r.Header.Get("Idempotency-Key"), func(ctx context.Context, tenantID string) (int, any, error) {
		var req secretDeliveryRequest
		if err := decodeJSON(r, &req); err != nil {
			return 0, nil, errWithStatus(http.StatusBadRequest, err)
		}
		switch {
		case !secretDeliveryConsumer.MatchString(req.Consumer):
			return 0, nil, errStatus(http.StatusBadRequest, "consumer is a label of letters, digits and . _ : / @ - (at most 128)")
		case req.State != store.SecretDeliveryInjected && req.State != store.SecretDeliveryVerified:
			return 0, nil, errStatus(http.StatusBadRequest, "state is injected or verified")
		case len(req.Secrets) == 0 || len(req.Secrets) > 100:
			return 0, nil, errStatus(http.StatusBadRequest, "secrets lists 1 to 100 secret versions")
		}
		for _, item := range req.Secrets {
			// A consumer reports only what it may read, at a version that exists.
			if err := a.requireSecretRead(ctx, tenantID, item.Name); err != nil {
				return 0, nil, a.deliverySecretError(err)
			}
			rec, err := a.secrets.be.Store.GetSecret(ctx, tenantID, item.Name)
			if err != nil {
				return 0, nil, a.deliverySecretError(err)
			}
			if item.Version < 1 || item.Version > rec.Version {
				return 0, nil, errStatus(http.StatusBadRequest, "secret "+item.Name+" has no version "+strconv.Itoa(item.Version))
			}
		}
		subject, err := requestPrincipalSubject(ctx)
		if err != nil {
			return 0, nil, err
		}
		if err := a.orch.ReportSecretDelivery(ctx, tenantID, projections.SecretDeliveryReported{
			Consumer: req.Consumer, State: req.State, Items: req.Secrets, ReportedBy: subject,
		}); err != nil {
			return 0, nil, err
		}
		return http.StatusOK, req, nil
	})
}

func (a *API) deliverySecretError(err error) error {
	if errors.Is(err, store.ErrSecretNotFound) {
		return errStatus(http.StatusNotFound, "no such secret")
	}
	return err
}

func (a *API) listSecretDeliveries(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.store == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "name is required"))
		return
	}
	if err := a.requireSecretRead(r.Context(), tenantID, name); err != nil {
		a.writeError(w, a.deliverySecretError(err))
		return
	}
	rec, err := a.secrets.be.Store.GetSecret(r.Context(), tenantID, name)
	if err != nil {
		a.writeError(w, a.deliverySecretError(err))
		return
	}
	rows, err := a.store.ListSecretDeliveries(r.Context(), tenantID, name)
	if err != nil {
		a.writeError(w, err)
		return
	}
	out := secretDeliveriesResponse{Name: name, CurrentVersion: rec.Version, Consumers: []secretDeliveryConsumerResponse{}}
	for _, d := range rows {
		state := "behind"
		switch {
		case d.VerifiedVersion >= rec.Version:
			state = "verified"
		case d.InjectedVersion >= rec.Version:
			state = "injected"
		}
		out.Consumers = append(out.Consumers, secretDeliveryConsumerResponse{
			Consumer: d.Consumer, InjectedVersion: d.InjectedVersion, InjectedAt: d.InjectedAt,
			VerifiedVersion: d.VerifiedVersion, VerifiedAt: d.VerifiedAt, State: state,
		})
	}
	a.writeJSON(w, http.StatusOK, out)
}
