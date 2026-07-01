package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"trstctl.com/trstctl/internal/app"
	"trstctl.com/trstctl/internal/auth"
	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/config"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/events"
	"trstctl.com/trstctl/internal/store"
)

// TokenCreateOptions parameterizes the first-run bootstrap that mints the first
// tenant-scoped API token (WIRE-002).
type TokenCreateOptions struct {
	// TenantID is the tenant the token is scoped to. It is required and must be a
	// UUID; the bootstrap registers it through the event-sourced spine if it does
	// not already exist (so the read model and audit trail stay projections of the
	// log, AN-2). A single-tenant deployment uses one well-known tenant id here.
	TenantID string
	// TenantName is the human label recorded for a freshly registered tenant. It is
	// ignored when the tenant already exists.
	TenantName string
	// Subject is the token's principal subject (who the token acts as), recorded on
	// the token and stamped onto every event the token's requests append.
	Subject string
	// Scopes is the exact permission set granted to the token. When empty the
	// bootstrap grants BootstrapAdminScopes — full operator control DELIBERATELY
	// EXCLUDING the issuance authority (certs:issue), so a bootstrap credential can
	// administer the platform but cannot self-issue a certificate (RED-004). The
	// bootstrap mints an API credential only; it invokes no signing/issuance path.
	Scopes []string
}

// BootstrapAdminScopes is the default scope set for the first bootstrap token: it
// grants every operator permission so the operator can drive the platform from a
// fresh boot, but DELIBERATELY omits certs:issue. Minting the first credential
// must not hand out issuance authority — that gate stays behind the RA split
// (certs:request -> approve -> certs:issue); this token only creates an API
// credential and never touches the signer (RED-004 / AN-4).
func BootstrapAdminScopes() []string {
	return []string{
		string(authz.OwnersRead), string(authz.OwnersWrite),
		string(authz.IssuersRead), string(authz.IssuersWrite),
		string(authz.IdentitiesRead), string(authz.IdentitiesWrite),
		string(authz.CertsRead), string(authz.CertsWrite),
		string(authz.ProfilesRead), string(authz.ProfilesWrite),
		string(authz.AuditRead), string(authz.GraphRead),
		string(authz.RiskRead),
		string(authz.AgentsRead), string(authz.AgentsWrite),
		string(authz.AccessRead), string(authz.AccessWrite),
		// certs:request is granted so the operator can drive the RA request side;
		// certs:issue is INTENTIONALLY withheld (the loaded-gun guard, RED-004).
		string(authz.CertsRequest),
	}
}

// RunTokenCreate is the network-trust-free first-run bootstrap that mints the
// first tenant-scoped API token and returns its raw secret (WIRE-002). It is the
// served path's missing on-ramp: with OIDC not yet wired and every guarded route
// failing closed (401), a fresh binary otherwise has no obtainable credential. It
// requires NO existing credential — it is an operator/admin command run against
// the local datastore, not an HTTP call.
//
// It opens the datastore exactly as Run does (bundled single-node, or external by
// DSN), applies pending migrations, registers the tenant through the event-sourced
// spine (app.RegisterTenant, so tenant state remains a projection of the event log
// per AN-2 and is idempotent per AN-5), then inserts the token under the tenant's
// row-level-security context (store.CreateAPIToken, AN-1). Only the token's hash
// is stored; the raw secret is returned to the caller exactly once and is NEVER
// written to any log.
//
// It deliberately touches no signing/issuance authority: it creates an API
// credential and nothing else, so bootstrapping a first token cannot open
// self-issue (RED-004).
func RunTokenCreate(ctx context.Context, cfg *config.Config, opts TokenCreateOptions) (rawToken []byte, err error) {
	if opts.TenantID == "" {
		return nil, errors.New("bootstrap: a tenant id is required (--tenant); it must be a UUID")
	}
	if opts.Subject == "" {
		opts.Subject = "bootstrap-admin"
	}
	scopes := opts.Scopes
	if len(scopes) == 0 {
		scopes = BootstrapAdminScopes()
	}

	// A quiet logger: the bundled-datastore startup logs through it, but the token
	// itself is NEVER handed to a logger. We discard at warn+ to keep the command's
	// stdout clean for the one thing it prints — the raw token.
	logger := slog.New(slog.NewTextHandler(discardWriter{}, &slog.HandlerOptions{Level: slog.LevelError}))

	dsn, stopPG, err := openDatastore(cfg.Postgres, logger)
	if err != nil {
		return nil, err
	}
	defer func() {
		if stopPG != nil {
			_ = stopPG()
		}
	}()

	st, err := store.Open(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: open store: %w", err)
	}
	defer st.Close()

	// Apply the schema so a genuinely fresh datastore works on first run. The
	// migration runner serializes on a PostgreSQL advisory lock, so this is safe to
	// run alongside a starting control plane.
	if err := st.Migrate(ctx); err != nil {
		return nil, fmt.Errorf("bootstrap: migrate: %w", err)
	}

	// Register the tenant through the event-sourced spine so the tenants read model
	// is built by a projection of the log, never written directly (AN-2). The fixed
	// idempotency key makes re-running the bootstrap for the same tenant a no-op
	// rather than a second registration (AN-5).
	log, err := events.Open(ctx, cfg.NATS)
	if err != nil {
		return nil, fmt.Errorf("bootstrap: open event log: %w", err)
	}
	defer func() { _ = log.Close() }()

	svc := app.New(log, st)
	defer svc.Close()
	if err := svc.RegisterTenant(ctx, opts.TenantID, opts.TenantName, "bootstrap-tenant:"+opts.TenantID); err != nil {
		return nil, fmt.Errorf("bootstrap: register tenant: %w", err)
	}

	// Mint the token: generate a high-entropy secret, store ONLY its hash under the
	// tenant's RLS context (AN-1), and return the raw secret to the caller to print
	// once. The secret never reaches a log or the database.
	raw, hash, err := auth.GenerateAPIToken()
	if err != nil {
		return nil, fmt.Errorf("bootstrap: generate token: %w", err)
	}
	if _, err := st.CreateAPIToken(ctx, store.APITokenRecord{
		TenantID:  opts.TenantID,
		TokenHash: hash,
		Subject:   opts.Subject,
		Scopes:    scopes,
	}); err != nil {
		secret.Wipe(raw)
		return nil, fmt.Errorf("bootstrap: store token: %w", err)
	}
	return raw, nil
}

// discardWriter is an io.Writer that drops everything written to it. It backs the
// bootstrap's quiet logger so datastore startup chatter never competes with the
// single token line on stdout.
type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
