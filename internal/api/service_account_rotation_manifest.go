// SPDX-License-Identifier: BUSL-1.1
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"time"

	googleuuid "github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/servicedependents"
	"trstctl.com/trstctl/internal/store"
)

type dependentManifestOpenRequest struct {
	SecretName string `json:"secret_name"`
	Mode       string `json:"mode,omitempty"`
}
type dependentManifestSealRequest struct {
	HeaderDigest string `json:"header_digest"`
	TailDigest   string `json:"tail_digest"`
}

func manifestConflict() error {
	return errStatus(http.StatusConflict, "native review differs from its retained sources; retry the exact pending write or rebuild projections")
}
func manifestPathID(r *http.Request) (string, error) {
	id := r.PathValue("id")
	parsed, err := googleuuid.Parse(id)
	if err != nil || parsed == googleuuid.Nil || parsed.String() != id {
		return "", errStatus(http.StatusBadRequest, "canonical native review ID required")
	}
	return id, nil
}
func manifestPageNumber(r *http.Request) (int64, error) {
	value, err := strconv.ParseInt(r.PathValue("page"), 10, 64)
	if err != nil || value < 0 || value == math.MaxInt64 || strconv.FormatInt(value, 10) != r.PathValue("page") {
		return 0, errStatus(http.StatusBadRequest, "nonnegative canonical page number required")
	}
	return value, nil
}
func manifestRequestBinding(actor, path string, input any) (string, error) {
	raw, err := json.Marshal(struct {
		Actor string `json:"actor"`
		Path  string `json:"path"`
		Input any    `json:"input"`
	}{actor, path, input})
	if err != nil {
		return "", err
	}
	return crypto.SHA256Hex(append([]byte("trstctl.service-dependent.manifest-request.v1\x00"), raw...)), nil
}
func (a *API) canonicalManifestHeader(ctx context.Context, tenantID, id string) (store.ServiceDependentManifest, error) {
	var none store.ServiceDependentManifest
	source, found, err := a.log.EventByID(ctx, servicedependents.RotationManifestHeaderSourceID(tenantID, id))
	if err != nil {
		return none, err
	}
	if !found {
		return none, errStatus(http.StatusNotFound, "native rotation review not found")
	}
	var opened projections.ServiceDependentManifestOpened
	if source.TenantID != tenantID || json.Unmarshal(source.Data, &opened) != nil || projections.ValidateServiceDependentManifestOpened(source, opened) != nil || opened.Header.ID != id {
		return none, manifestConflict()
	}
	state, err := a.store.GetServiceDependentManifest(ctx, tenantID, id)
	if err != nil {
		return none, manifestConflict()
	}
	digest, err := opened.Header.Digest()
	if err != nil || digest != state.HeaderDigest || state.Actor != opened.Actor {
		return none, manifestConflict()
	}
	sealed, found, err := a.log.EventByID(ctx, servicedependents.RotationManifestSealSourceID(tenantID, id))
	if err != nil {
		return none, err
	}
	if found {
		var value projections.ServiceDependentManifestSealed
		if sealed.TenantID != tenantID || json.Unmarshal(sealed.Data, &value) != nil || projections.ValidateServiceDependentManifestSealed(sealed, value, state.Header) != nil || value.Actor != state.Actor || state.Seal == nil || value.Seal.Digest != state.Seal.Digest {
			return none, manifestConflict()
		}
	} else if state.Seal != nil {
		return none, manifestConflict()
	}
	return state, nil
}
func (a *API) canonicalManifestPage(ctx context.Context, tenantID string, state store.ServiceDependentManifest, number int64) (servicedependents.RotationManifestPage, error) {
	var none servicedependents.RotationManifestPage
	source, found, err := a.log.EventByID(ctx, servicedependents.RotationManifestPageSourceID(tenantID, state.Header.ID, number))
	if err != nil {
		return none, err
	}
	if !found {
		return none, manifestConflict()
	}
	var recorded projections.ServiceDependentManifestPageRecorded
	if source.TenantID != tenantID || json.Unmarshal(source.Data, &recorded) != nil || projections.ValidateServiceDependentManifestPage(source, recorded, state.Header) != nil || recorded.Actor != state.Actor || recorded.Page.Number != number {
		return none, manifestConflict()
	}
	saved, err := a.store.GetServiceDependentManifestPage(ctx, tenantID, state.Header.ID, number)
	if err != nil || saved.Digest != recorded.Page.Digest {
		return none, manifestConflict()
	}
	return recorded.Page, nil
}

// Read bounded pages from canonical sources. Normalized SQL rows are only an
// index and must match each source entry before they can select native work.
func (a *API) validateCanonicalManifest(ctx context.Context, tenantID string, state store.ServiceDependentManifest, checkScans bool) (*servicedependents.RotationManifestPage, error) {
	var previous *servicedependents.RotationManifestPage
	entries := int64(0)
	hosts := make(map[string]string)
	for number := int64(0); number < state.PageCount; number++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		page, err := a.canonicalManifestPage(ctx, tenantID, state, number)
		if err != nil {
			return nil, err
		}
		if servicedependents.ValidateRotationManifestLink(state.Header, page, previous) != nil || math.MaxInt64-entries < int64(len(page.Entries)) {
			return nil, manifestConflict()
		}
		if err := a.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
			return a.store.VerifyServiceDependentManifestPageCacheTx(ctx, tx, tenantID, page, entries)
		}); err != nil {
			return nil, manifestConflict()
		}
		for _, host := range page.Hosts {
			raw, err := json.Marshal(host)
			if err != nil {
				return nil, err
			}
			digest := crypto.SHA256Hex(raw)
			if first, found := hosts[host.Binding.AgentID]; found {
				if first != digest {
					return nil, manifestConflict()
				}
				continue
			}
			hosts[host.Binding.AgentID] = digest
			if checkScans {
				if err := a.validateManifestHostSource(ctx, tenantID, state.Header, host); err != nil {
					return nil, err
				}
			}
		}
		entries += int64(len(page.Entries))
		previous = &page
	}
	if _, found, err := a.log.EventByID(ctx, servicedependents.RotationManifestPageSourceID(tenantID, state.Header.ID, state.PageCount)); err != nil {
		return nil, err
	} else if found {
		return nil, manifestConflict()
	}
	if entries != state.EntryCount || int64(len(hosts)) != state.HostCount {
		return nil, manifestConflict()
	}
	if state.Seal != nil && (previous == nil || previous.Digest != state.Seal.TailDigest) {
		return nil, manifestConflict()
	}
	return previous, nil
}
func (a *API) validateManifestHostSource(ctx context.Context, tenantID string, header servicedependents.RotationManifestHeader, host servicedependents.RotationManifestHost) error {
	_, err := a.manifestHostSource(ctx, tenantID, header, host)
	return err
}
func (a *API) manifestHostSource(ctx context.Context, tenantID string, header servicedependents.RotationManifestHeader, host servicedependents.RotationManifestHost) (servicedependents.RotationHostInput, error) {
	var none servicedependents.RotationHostInput
	if host.Validate(header) != nil {
		return none, manifestConflict()
	}
	saved, err := a.store.GetServiceDependentScan(ctx, tenantID, host.InventoryRunID)
	if err != nil {
		return none, err
	}
	if saved.Report == nil || saved.Status != "complete" || saved.Intent.Binding != host.Binding || saved.ReportDigest != host.InventoryDigest || !saved.Report.ObservedAt.Equal(host.ObservedAt) {
		return none, manifestConflict()
	}
	if err := a.validateDependentScanSource(ctx, tenantID, saved); err != nil {
		return none, err
	}
	queued, found, err := a.log.EventByID(ctx, saved.QueuedEventID)
	if err != nil {
		return none, err
	}
	var native projections.ServiceDependentScanQueued
	if !found || queued.TenantID != tenantID || queued.Type != projections.EventServiceDependentScanQueued || json.Unmarshal(queued.Data, &native) != nil || native.Intent.Binding != host.Binding {
		return none, manifestConflict()
	}
	return servicedependents.RotationHostInput{Binding: saved.Intent.Binding, Inventory: *saved.Report, InventoryDigest: saved.ReportDigest}, nil
}
func (a *API) appendManifestSource(ctx context.Context, tenantID, id, kind string, at time.Time, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	expected := events.Event{ID: id, TenantID: tenantID, Type: kind, SchemaVersion: 1, Time: at, Data: raw}
	if actor, ok := events.ActorFromContext(ctx); ok {
		expected.Actor = &actor
	}
	source, err := a.log.Append(ctx, expected)
	if err != nil {
		return err
	}
	if source.ID != id || source.TenantID != tenantID || source.Type != kind || source.SchemaVersion != 1 || !bytes.Equal(source.Data, raw) {
		return store.ErrIdempotencyConflict
	}
	return projections.New(a.store).Apply(ctx, source)
}
func (a *API) manifestWritePrincipal(w http.ResponseWriter, r *http.Request, key string) (string, string, bool) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return "", "", false
	}
	if err := a.dependentRotationPermission(r.Context(), r, tenantID, key); err != nil {
		a.writeError(w, err)
		return "", "", false
	}
	actor, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return "", "", false
	}
	return tenantID, actor, true
}
func (a *API) firstManifestAccount(ctx context.Context, tenantID, accountID string) (servicedependents.AccountBinding, error) {
	svc, err := a.serviceDependentDiscovery()
	if err != nil {
		return servicedependents.AccountBinding{}, err
	}
	after := ""
	for {
		page, err := svc.ListPAMServiceDependentHosts(ctx, tenantID, accountID, after, 256)
		if err != nil {
			return servicedependents.AccountBinding{}, serviceDependentError(err)
		}
		for _, host := range page.Items {
			if host.Binding.Enabled && host.Binding.Account.AccountID == accountID {
				return host.Binding.Account, nil
			}
		}
		if page.NextCursor == "" {
			break
		}
		if page.NextCursor == after {
			return servicedependents.AccountBinding{}, errors.New("api: host review cursor did not advance")
		}
		after = page.NextCursor
	}
	return servicedependents.AccountBinding{}, errStatus(http.StatusConflict, "select and scan the enrolled member hosts before reviewing this account")
}

//trstctl:mutation
func (a *API) openPAMServiceDependentReview(w http.ResponseWriter, r *http.Request) {
	var req dependentManifestOpenRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	_, actor, ok := a.manifestWritePrincipal(w, r, req.SecretName)
	if !ok {
		return
	}
	binding, err := manifestRequestBinding(actor, r.URL.Path, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	key := r.Header.Get("Idempotency-Key")
	a.mutateDurableBound(w, r, key, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		if a.secrets == nil {
			return 0, nil, ErrPAMUnavailable
		}
		id := googleuuid.NewSHA1(googleuuid.NameSpaceOID, []byte("trstctl.service-dependent.manifest-request-id.v1\x00"+tenantID+"\x00"+r.PathValue("account_id")+"\x00"+key)).String()
		err := a.store.WithPAMCatalogLock(ctx, tenantID, func() error {
			source, found, err := a.log.EventByID(ctx, servicedependents.RotationManifestHeaderSourceID(tenantID, id))
			if err != nil {
				return err
			}
			if found {
				var first projections.ServiceDependentManifestOpened
				if source.TenantID != tenantID || json.Unmarshal(source.Data, &first) != nil || projections.ValidateServiceDependentManifestOpened(source, first) != nil || first.Actor != actor || first.Header.SecretName != req.SecretName || first.Header.Mode != req.Mode || first.Header.Account.AccountID != r.PathValue("account_id") {
					return store.ErrIdempotencyConflict
				}
				return projections.New(a.store).Apply(ctx, source)
			}
			account, err := a.firstManifestAccount(ctx, tenantID, r.PathValue("account_id"))
			if err != nil {
				return err
			}
			provider, _, err := a.staticRotationProvider(tenantID, account.ProviderID, req.SecretName)
			if err != nil {
				return err
			}
			provider, pins, err := selectDependentRotationProvider(provider, req.SecretName, req.Mode)
			if err != nil {
				return err
			}
			prepared, ok := provider.(dynsecret.PreparedStaticRotationProvider)
			if !ok || staticRotationPhase(provider, req.SecretName) != dynsecret.RotationSinglePhase {
				return errStatus(http.StatusConflict, "a prepared single-phase native AD provider is required")
			}
			if _, ok := provider.(dynsecret.StaticCredentialRestorer); !ok {
				return errStatus(http.StatusConflict, "a native AD inverse is required")
			}
			current, err := a.secrets.be.Store.GetSecret(ctx, tenantID, req.SecretName)
			if err != nil {
				return err
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			header := servicedependents.RotationManifestHeader{Version: 1, ID: id, Account: account, SecretName: req.SecretName, ExpectedVersion: current.Version, ProviderBinding: prepared.StaticRotationBinding(req.SecretName), Mode: req.Mode, Reconcile: pins, CreatedAt: now, ExpiresAt: now.Add(servicedependents.RotationInventoryMaxAge)}
			if err := header.Validate(); err != nil {
				return errWithStatus(http.StatusUnprocessableEntity, err)
			}
			return a.appendManifestSource(ctx, tenantID, servicedependents.RotationManifestHeaderSourceID(tenantID, id), projections.EventServiceDependentManifestOpened, now, projections.ServiceDependentManifestOpened{Header: header, Actor: actor, At: now})
		})
		if err != nil {
			return 0, nil, err
		}
		state, err := a.canonicalManifestHeader(ctx, tenantID, id)
		return http.StatusCreated, state, err
	})
}

func (a *API) manifestOpenedSource(ctx context.Context, tenantID, id string) (projections.ServiceDependentManifestOpened, error) {
	var opened projections.ServiceDependentManifestOpened
	source, found, err := a.log.EventByID(ctx, servicedependents.RotationManifestHeaderSourceID(tenantID, id))
	if err != nil {
		return opened, err
	}
	if !found {
		return opened, errStatus(http.StatusNotFound, "native rotation review not found")
	}
	if source.TenantID != tenantID || json.Unmarshal(source.Data, &opened) != nil || projections.ValidateServiceDependentManifestOpened(source, opened) != nil || opened.Header.ID != id {
		return opened, manifestConflict()
	}
	return opened, nil
}
func (a *API) currentManifestAuthority(ctx context.Context, tenantID string, header servicedependents.RotationManifestHeader) error {
	intent := servicedependents.RotationIntent{Mode: header.Mode, Reconcile: header.Reconcile, Plan: servicedependents.RotationPlan{Account: header.Account, SecretName: header.SecretName}, ExpectedVersion: header.ExpectedVersion, ProviderBinding: header.ProviderBinding}
	if _, err := a.dependentIntentProvider(tenantID, intent); err != nil {
		return err
	}
	if a.secrets == nil {
		return ErrPAMUnavailable
	}
	current, err := a.secrets.be.Store.GetSecret(ctx, tenantID, header.SecretName)
	if err != nil {
		return err
	}
	if current.Version != header.ExpectedVersion {
		return errStatus(http.StatusConflict, "vault generation changed; open a new complete native review")
	}
	return nil
}
func (a *API) currentManifestHost(ctx context.Context, tenantID string, header servicedependents.RotationManifestHeader, host servicedependents.RotationManifestHost) error {
	_, err := a.currentManifestHostInput(ctx, tenantID, header, host)
	return err
}
func (a *API) currentManifestHostInput(ctx context.Context, tenantID string, header servicedependents.RotationManifestHeader, host servicedependents.RotationManifestHost) (servicedependents.RotationHostInput, error) {
	var none servicedependents.RotationHostInput
	input, err := a.manifestHostSource(ctx, tenantID, header, host)
	if err != nil {
		return none, err
	}
	saved, err := a.store.GetServiceDependentHost(ctx, tenantID, header.Account.AccountID, host.Binding.AgentID)
	if err != nil {
		return none, err
	}
	if saved.Binding != host.Binding || host.Binding.Revision <= 0 {
		return none, manifestConflict()
	}
	event, found, err := a.log.EventAtSequence(ctx, uint64(host.Binding.Revision))
	if err != nil {
		return none, err
	}
	var selected projections.ServiceDependentHostSaved
	if !found || event.TenantID != tenantID || event.Type != projections.EventServiceDependentHostSaved || json.Unmarshal(event.Data, &selected) != nil || selected.Account != host.Binding.Account || selected.AgentID != host.Binding.AgentID || !selected.Enabled {
		return none, manifestConflict()
	}
	return input, nil
}

//trstctl:mutation
func (a *API) appendPAMServiceDependentReviewPage(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	id, err := manifestPathID(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	number, err := manifestPageNumber(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, servicedependents.MaxRotationManifestPageBytes+1))
	if err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	if len(raw) > servicedependents.MaxRotationManifestPageBytes {
		a.writeError(w, errStatus(http.StatusRequestEntityTooLarge, "native review page exceeds 64 KiB; send smaller pages"))
		return
	}
	input, err := servicedependents.DecodeRotationManifestPageInput(raw)
	if err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	opened, err := a.manifestOpenedSource(r.Context(), tenantID, id)
	if err != nil {
		a.writeError(w, err)
		return
	}
	_, actor, ok := a.manifestWritePrincipal(w, r, opened.Header.SecretName)
	if !ok {
		return
	}
	if actor != opened.Actor {
		a.writeError(w, errStatus(http.StatusForbidden, "only the review author can append its native scope"))
		return
	}
	page, err := input.Page(opened.Header, number)
	if err != nil {
		a.writeError(w, errWithStatus(http.StatusUnprocessableEntity, err))
		return
	}
	binding, err := manifestRequestBinding(actor, r.URL.Path, input)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, r.Header.Get("Idempotency-Key"), binding, func(ctx context.Context, tenantID string) (int, any, error) {
		err := a.store.WithPAMCatalogLock(ctx, tenantID, func() error {
			sourceID := servicedependents.RotationManifestPageSourceID(tenantID, id, number)
			source, found, err := a.log.EventByID(ctx, sourceID)
			if err != nil {
				return err
			}
			if found {
				var first projections.ServiceDependentManifestPageRecorded
				if source.TenantID != tenantID || json.Unmarshal(source.Data, &first) != nil || projections.ValidateServiceDependentManifestPage(source, first, opened.Header) != nil || first.Page.Digest != page.Digest || first.Actor != actor {
					return store.ErrIdempotencyConflict
				}
				return projections.New(a.store).Apply(ctx, source)
			}
			state, err := a.canonicalManifestHeader(ctx, tenantID, id)
			if err != nil {
				return err
			}
			if state.Seal != nil || number != state.PageCount {
				return errStatus(http.StatusConflict, "append only the exact next page of an unsealed native review")
			}
			previous, err := a.validateCanonicalManifest(ctx, tenantID, state, false)
			if err != nil {
				return err
			}
			if servicedependents.ValidateRotationManifestLink(opened.Header, page, previous) != nil {
				return manifestConflict()
			}
			if err := a.currentManifestAuthority(ctx, tenantID, opened.Header); err != nil {
				return err
			}
			for _, host := range page.Hosts {
				if err := a.currentManifestHost(ctx, tenantID, opened.Header, host); err != nil {
					return err
				}
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			if !now.Before(opened.Header.ExpiresAt) {
				return errStatus(http.StatusConflict, "native review expired; open a fresh review without extending the old one")
			}
			return a.appendManifestSource(ctx, tenantID, sourceID, projections.EventServiceDependentManifestPageRecorded, now, projections.ServiceDependentManifestPageRecorded{Page: page, Actor: actor, At: now})
		})
		return http.StatusCreated, page, err
	})
}

//trstctl:mutation
func (a *API) sealPAMServiceDependentReview(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	id, err := manifestPathID(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	var req dependentManifestSealRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	opened, err := a.manifestOpenedSource(r.Context(), tenantID, id)
	if err != nil {
		a.writeError(w, err)
		return
	}
	_, actor, ok := a.manifestWritePrincipal(w, r, opened.Header.SecretName)
	if !ok {
		return
	}
	if actor != opened.Actor {
		a.writeError(w, errStatus(http.StatusForbidden, "only the review author can seal its complete native scope"))
		return
	}
	digest, err := opened.Header.Digest()
	if err != nil {
		a.writeError(w, err)
		return
	}
	if req.HeaderDigest != digest {
		a.writeError(w, manifestConflict())
		return
	}
	binding, err := manifestRequestBinding(actor, r.URL.Path, req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, r.Header.Get("Idempotency-Key"), binding, func(ctx context.Context, tenantID string) (int, any, error) {
		err := a.store.WithPAMCatalogLock(ctx, tenantID, func() error {
			sourceID := servicedependents.RotationManifestSealSourceID(tenantID, id)
			source, found, err := a.log.EventByID(ctx, sourceID)
			if err != nil {
				return err
			}
			if found {
				var first projections.ServiceDependentManifestSealed
				if source.TenantID != tenantID || json.Unmarshal(source.Data, &first) != nil || projections.ValidateServiceDependentManifestSealed(source, first, opened.Header) != nil || first.Seal.TailDigest != req.TailDigest || first.Actor != actor {
					return store.ErrIdempotencyConflict
				}
				return projections.New(a.store).Apply(ctx, source)
			}
			state, err := a.canonicalManifestHeader(ctx, tenantID, id)
			if err != nil {
				return err
			}
			tail, err := a.validateCanonicalManifest(ctx, tenantID, state, true)
			if err != nil {
				return err
			}
			if tail == nil || tail.Digest != req.TailDigest {
				return manifestConflict()
			}
			if err := a.currentManifestAuthority(ctx, tenantID, opened.Header); err != nil {
				return err
			}
			// Source-bind each current host before reading the complete frozen counts.
			for number := int64(0); number < state.PageCount; number++ {
				page, err := a.canonicalManifestPage(ctx, tenantID, state, number)
				if err != nil {
					return err
				}
				for _, host := range page.Hosts {
					if err := a.currentManifestHost(ctx, tenantID, opened.Header, host); err != nil {
						return err
					}
				}
			}
			now := time.Now().UTC().Truncate(time.Microsecond)
			var seal servicedependents.RotationManifestSeal
			err = a.store.WithTenant(ctx, tenantID, func(tx pgx.Tx) error {
				var err error
				seal, err = a.store.ValidateServiceDependentManifestCompletenessTx(ctx, tx, tenantID, id, now, true)
				return err
			})
			if err != nil {
				return errWithStatus(http.StatusConflict, err)
			}
			if seal.TailDigest != tail.Digest {
				return manifestConflict()
			}
			return a.appendManifestSource(ctx, tenantID, sourceID, projections.EventServiceDependentManifestSealed, now, projections.ServiceDependentManifestSealed{Seal: seal, Actor: actor, At: now})
		})
		if err != nil {
			return 0, nil, err
		}
		state, err := a.canonicalManifestHeader(ctx, tenantID, id)
		return http.StatusCreated, state, err
	})
}
func (a *API) getPAMServiceDependentReview(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	id, err := manifestPathID(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	state, err := a.canonicalManifestHeader(r.Context(), tenantID, id)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if err := a.requireSecretRead(r.Context(), tenantID, state.Header.SecretName); err != nil {
		a.writeError(w, err)
		return
	}
	if _, err := a.validateCanonicalManifest(r.Context(), tenantID, state, false); err != nil {
		a.writeError(w, err)
		return
	}
	view := struct {
		store.ServiceDependentManifest
		Intent       *servicedependents.RotationIntent `json:"intent,omitempty"`
		IntentDigest string                            `json:"intent_digest,omitempty"`
	}{ServiceDependentManifest: state}
	if state.Seal != nil {
		intent, err := servicedependents.NewRotationIntentFromManifest(state.Header, *state.Seal)
		if err != nil {
			a.writeError(w, err)
			return
		}
		digest, err := intent.Digest()
		if err != nil {
			a.writeError(w, err)
			return
		}
		view.Intent = &intent
		view.IntentDigest = digest
	}
	a.writeJSON(w, http.StatusOK, view)
}
func (a *API) getPAMServiceDependentReviewPage(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	id, err := manifestPathID(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	number, err := manifestPageNumber(r)
	if err != nil {
		a.writeError(w, err)
		return
	}
	state, err := a.canonicalManifestHeader(r.Context(), tenantID, id)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if err := a.requireSecretRead(r.Context(), tenantID, state.Header.SecretName); err != nil {
		a.writeError(w, err)
		return
	}
	if number >= state.PageCount {
		a.writeError(w, errStatus(http.StatusNotFound, "native review page not found"))
		return
	}
	page, err := a.canonicalManifestPage(r.Context(), tenantID, state, number)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, page)
}
func (a *API) dependentManifestRoutes() []route {
	root := "/api/v1/access/discovery/dependent-reviews/{id}"
	return []route{
		{method: "POST", path: "/api/v1/access/discovery/accounts/{account_id}/dependents/reviews", opID: "openPAMServiceDependentReview", summary: "Open a complete native account review assembled from bounded immutable pages", handler: a.openPAMServiceDependentReview, pathParams: []param{pathUUID("account_id")}, reqSchema: "PAMServiceDependentReviewOpenRequest", resSchema: "PAMServiceDependentReview", successCode: "201", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "GET", path: root, opID: "getPAMServiceDependentReview", summary: "Read native review authority, exact coverage and whole-account seal without queuing a reset", handler: a.getPAMServiceDependentReview, pathParams: []param{pathUUID("id")}, resSchema: "PAMServiceDependentReview", successCode: "200", perm: authz.AccessRead},
		{method: "PUT", path: root + "/pages/{page}", opID: "appendPAMServiceDependentReviewPage", summary: "Record the exact next ordered native host and dependent page", handler: a.appendPAMServiceDependentReviewPage, pathParams: []param{pathUUID("id"), pathInteger("page", "zero-based native review page")}, reqSchema: "PAMServiceDependentReviewPageRequest", resSchema: "PAMServiceDependentReviewPage", successCode: "201", mutation: true, perm: authz.AccessTargetsWrite},
		{method: "GET", path: root + "/pages/{page}", opID: "getPAMServiceDependentReviewPage", summary: "Read one complete bounded page of frozen native scope and useful-work probes", handler: a.getPAMServiceDependentReviewPage, pathParams: []param{pathUUID("id"), pathInteger("page", "zero-based native review page")}, resSchema: "PAMServiceDependentReviewPage", successCode: "200", perm: authz.AccessRead},
		{method: "POST", path: root + "/seal", opID: "sealPAMServiceDependentReview", summary: "Seal complete ordered native scope without resetting the directory credential", handler: a.sealPAMServiceDependentReview, pathParams: []param{pathUUID("id")}, reqSchema: "PAMServiceDependentReviewSealRequest", resSchema: "PAMServiceDependentReview", successCode: "201", mutation: true, perm: authz.AccessTargetsWrite},
	}
}
