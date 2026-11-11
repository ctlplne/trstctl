// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"net/http"
	"slices"
)

// A235-L2: an operator can place a dynamic-secret provider in a secrets
// project environment (secret_environment = "<project>/<environment>" in its
// configuration). In a restricted environment only the members granted it use
// the provider: read sees it and its leases, write issues, renews and revokes
// them. That holds on every path that reaches a provider: the native lease
// routes, the Vault-compatible creds, sts and lease paths and their role and
// connection listings, and the dynamic-lease rotations. A machine session or
// the SDK agent calls those routes under its own principal, so it is held to
// the same grant. A provider with no placement, or placed in an unrestricted
// environment, is governed by its routes alone; a placement naming an
// environment the tenant does not have closes the provider until it exists.

type dynamicProviderUse int

const (
	dynamicProviderHidden   dynamicProviderUse = iota // not even visible to the caller
	dynamicProviderReadable                           // its leases are visible; nothing else
	dynamicProviderWritable                           // issue, renew and revoke too
)

// dynamicProviderAccess is what the request's principal may do with provider.
// A request with no principal is an internal job, checked when it was set up.
func (a *API) dynamicProviderAccess(ctx context.Context, tenantID string, provider dynamicSecretConfiguredProvider) (dynamicProviderUse, error) {
	if provider.Environment == "" {
		return dynamicProviderWritable, nil
	}
	subject, err := requestPrincipalSubject(ctx)
	if err != nil || a.store == nil {
		return dynamicProviderWritable, nil
	}
	scope, err := a.store.SecretScopeFor(ctx, tenantID, provider.Environment+"/"+provider.ID, subject)
	if err != nil {
		return dynamicProviderHidden, err
	}
	switch {
	case !scope.InProject:
		return dynamicProviderHidden, nil
	case !scope.Restricted || scope.CanWrite:
		return dynamicProviderWritable, nil
	case scope.CanRead:
		return dynamicProviderReadable, nil
	}
	return dynamicProviderHidden, nil
}

// requireDynamicProviderRead answers missing — the route's own "no such"
// error — when the caller may not see provider.
func (a *API) requireDynamicProviderRead(ctx context.Context, tenantID string, provider dynamicSecretConfiguredProvider, missing error) error {
	use, err := a.dynamicProviderAccess(ctx, tenantID, provider)
	if err != nil {
		return err
	}
	if use == dynamicProviderHidden {
		return missing
	}
	return nil
}

// requireDynamicProviderWrite answers missing when the caller may not see
// provider and 403 when it may only read there.
func (a *API) requireDynamicProviderWrite(ctx context.Context, tenantID string, provider dynamicSecretConfiguredProvider, missing error) error {
	use, err := a.dynamicProviderAccess(ctx, tenantID, provider)
	if err != nil {
		return err
	}
	switch use {
	case dynamicProviderHidden:
		return missing
	case dynamicProviderReadable:
		return errStatus(http.StatusForbidden, "this dynamic-secret provider is in a restricted environment where you are not a member with write access")
	}
	return nil
}

// requireDynamicLeaseProvider checks a lease's provider by ID: a lease of a
// provider the caller may not see is "no such dynamic secret lease".
func (a *API) requireDynamicLeaseProvider(ctx context.Context, tenantID, providerID string, write bool) error {
	provider, found := a.secrets.configuredDynamicSecretProvider(tenantID, providerID)
	if !found {
		return nil
	}
	missing := errStatus(http.StatusNotFound, "no such dynamic secret lease")
	if write {
		return a.requireDynamicProviderWrite(ctx, tenantID, provider, missing)
	}
	return a.requireDynamicProviderRead(ctx, tenantID, provider, missing)
}

// visibleDynamicSecretProviders leaves out the providers the caller may not
// see, so listings and Vault engine mounts never name them.
func (a *API) visibleDynamicSecretProviders(ctx context.Context, tenantID string, providers []dynamicSecretConfiguredProvider) ([]dynamicSecretConfiguredProvider, error) {
	out := slices.Clone(providers)
	var firstErr error
	out = slices.DeleteFunc(out, func(provider dynamicSecretConfiguredProvider) bool {
		use, err := a.dynamicProviderAccess(ctx, tenantID, provider)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		return use == dynamicProviderHidden
	})
	if firstErr != nil {
		return nil, firstErr
	}
	if out == nil {
		out = []dynamicSecretConfiguredProvider{}
	}
	return out, nil
}

// dynamicLeaseRotationProviderFor is dynamicLeaseRotationProvider for a
// request: a rotation that leases from a provider in a restricted environment
// needs write there; to a caller not granted it the provider is unavailable,
// as a missing one is.
func (a *API) dynamicLeaseRotationProviderFor(ctx context.Context, tenantID, provider, role string, ttlSeconds int) (dynamicSecretConfiguredProvider, error) {
	configured, err := a.dynamicLeaseRotationProvider(tenantID, provider, role, ttlSeconds)
	if err != nil {
		return configured, err
	}
	if err := a.requireDynamicProviderWrite(ctx, tenantID, configured, errStatus(http.StatusServiceUnavailable, dynamicLeaseRotationTypeUnavailableDetail)); err != nil {
		return dynamicSecretConfiguredProvider{}, err
	}
	return configured, nil
}
