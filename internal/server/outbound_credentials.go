// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"trstctl.com/trstctl/internal/outboundcred"
)

// Operator-bound env credentials at run time (CR-008).
//
// A tenant-authored integration names an env:NAME reference; the value behind it is
// a deployment secret. The API refuses a declaration whose reference is not bound
// to the tenant, the integration kind and the destination, but a stored
// declaration may predate the operator's current bindings, so a worker never
// trusts the declaration alone: it resolves a reference only inside the scope of
// the tenant and integration it runs for, checks the binding immediately before it
// reads the value, and pins every HTTP client it hands the value to so that client
// reaches only the bound origins. Fixed-destination clients name their exact
// destinations instead.

type outboundCredentialScopeKey struct{}

type outboundCredentialScope struct {
	bindings    *outboundcred.Bindings
	tenantID    string
	integration string
}

// withOutboundCredentialScope records the tenant a worker runs for and the
// integration kind whose stored configuration it is about to execute.
func withOutboundCredentialScope(ctx context.Context, bindings *outboundcred.Bindings, tenantID, integration string) context.Context {
	return context.WithValue(ctx, outboundCredentialScopeKey{}, outboundCredentialScope{
		bindings: bindings, tenantID: tenantID, integration: integration,
	})
}

// outboundCredentialScope scopes ctx to tenantID's integration with the
// operator's bindings.
func (d *issuanceDispatcher) outboundCredentialScope(ctx context.Context, tenantID, integration string) context.Context {
	return withOutboundCredentialScope(ctx, d.outboundCredentials, tenantID, integration)
}

// authorizeBoundCredentialRef checks ref against the binding for the scope in ctx and
// returns the origins it may reach; every destination given must be one of them.
func authorizeBoundCredentialRef(ctx context.Context, ref string, destinations ...string) ([]string, error) {
	scope, ok := ctx.Value(outboundCredentialScopeKey{}).(outboundCredentialScope)
	if !ok {
		return nil, fmt.Errorf("%w: no tenant integration scope is resolving it", outboundcred.ErrNotBound)
	}
	return scope.bindings.Authorize(ref, scope.tenantID, scope.integration, destinations...)
}

// resolveBoundCredentialRef resolves a tenant-authored env:NAME reference for the
// tenant and integration in ctx. The binding is checked before the value is read,
// and each client the value is handed to is first pinned to the bound origins; a
// call that names no client is refused, so no value leaves unpinned.
func resolveBoundCredentialRef(ctx context.Context, ref string, clients ...*http.Client) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", errors.New("credential reference is required")
	}
	if !strings.HasPrefix(ref, "env:") {
		return "", errors.New("unsupported credential reference; use env:NAME")
	}
	if len(clients) == 0 {
		return "", fmt.Errorf("%w: no destination client to pin", outboundcred.ErrNotBound)
	}
	origins, err := authorizeBoundCredentialRef(ctx, ref)
	if err != nil {
		return "", err
	}
	for _, client := range clients {
		if err := outboundcred.PinClient(client, origins); err != nil {
			return "", err
		}
	}
	return lookupEnvCredential(ref)
}

func resolveBoundCredentialBytesRef(ctx context.Context, ref string, clients ...*http.Client) ([]byte, error) {
	value, err := resolveBoundCredentialRef(ctx, ref, clients...)
	if err != nil {
		return nil, err
	}
	return []byte(value), nil
}

func resolveOptionalBoundCredentialRef(ctx context.Context, ref string, clients ...*http.Client) (string, error) {
	if strings.TrimSpace(ref) == "" {
		return "", nil
	}
	return resolveBoundCredentialRef(ctx, ref, clients...)
}

func resolveOptionalBoundCredentialBytesRef(ctx context.Context, ref string, clients ...*http.Client) ([]byte, error) {
	if strings.TrimSpace(ref) == "" {
		return nil, nil
	}
	return resolveBoundCredentialBytesRef(ctx, ref, clients...)
}

// boundCredentialEnvValue returns the env value behind a tenant-authored reference
// whose client is fixed to the given destinations (a bearer-token or STS session
// file path, a syslog receiver's CA or client certificate), after checking that
// the binding names the origin of every destination.
func boundCredentialEnvValue(ctx context.Context, ref string, destinations ...string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if len(destinations) == 0 {
		return "", fmt.Errorf("%w: it names no destination", outboundcred.ErrNotBound)
	}
	if _, err := authorizeBoundCredentialRef(ctx, ref, destinations...); err != nil {
		return "", err
	}
	return lookupEnvCredential(ref)
}

// resolveOperatorCredentialRef resolves an env:NAME reference the operator's own
// configuration names with its destination (a ServiceNow binding, the Slack app).
// Tenant-authored references use resolveBoundCredentialRef.
func resolveOperatorCredentialRef(ctx context.Context, ref string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", errors.New("credential reference is required")
	}
	if !strings.HasPrefix(ref, "env:") {
		return "", errors.New("unsupported credential reference; use env:NAME")
	}
	return lookupEnvCredential(ref)
}

func resolveOperatorCredentialBytesRef(ctx context.Context, ref string) ([]byte, error) {
	value, err := resolveOperatorCredentialRef(ctx, ref)
	if err != nil {
		return nil, err
	}
	return []byte(value), nil
}

func lookupEnvCredential(ref string) (string, error) {
	name := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(ref), "env:"))
	if name == "" {
		return "", errors.New("env credential reference is empty")
	}
	value, ok := os.LookupEnv(name)
	if !ok || value == "" {
		// The unset variable's name is the operator's diagnostic. It is printed
		// only when it is a well-formed environment variable name, so a raw value
		// pasted where a reference belongs is never echoed (CR-405 class).
		if outboundcred.ValidEnvName(name) {
			return "", fmt.Errorf("env credential reference %s is not set", name)
		}
		return "", errors.New("env credential reference is not set")
	}
	return value, nil
}

// warnRetiredOutboundEnvCredentialRefs tells the operator that the retired
// process-wide list approves nothing, and which of its references no binding
// covers: every use of those is refused until the operator binds them.
func warnRetiredOutboundEnvCredentialRefs(logger *slog.Logger, legacy []string, bindings *outboundcred.Bindings) {
	if logger == nil || len(legacy) == 0 {
		return
	}
	bound := map[string]bool{}
	for _, ref := range bindings.Refs() {
		bound[ref] = true
	}
	// Only well-formed names are logged; an entry that is not one could be a
	// value pasted where a reference belongs, so it is only counted.
	unbound, malformed := []string{}, 0
	for _, raw := range legacy {
		ref, ok := outboundcred.NormalizeRef(raw)
		if !ok || !outboundcred.ValidEnvName(strings.TrimPrefix(ref, "env:")) {
			malformed++
			continue
		}
		if !bound[ref] {
			unbound = append(unbound, ref)
		}
	}
	logger.Warn("outbound_env_credential_refs (TRSTCTL_OUTBOUND_ENV_CREDENTIAL_REFS) no longer approves any use: "+
		"bind each env credential reference to one tenant, its integration kinds and exact destination origins in "+
		"outbound_env_credential_bindings (TRSTCTL_OUTBOUND_ENV_CREDENTIAL_BINDINGS); every use of an unbound reference is refused",
		slog.Int("retired_entries", len(legacy)), slog.Any("unbound_refs", unbound), slog.Int("malformed_entries", malformed))
}
