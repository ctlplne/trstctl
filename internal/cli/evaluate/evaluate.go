// SPDX-License-Identifier: BUSL-1.1

// Package evaluate implements `trstctl evaluate`, the design-partner
// evaluation kit. It drives one end-to-end certificate journey against an
// endpoint the partner chooses (discovery, ownership, issuance, deployment,
// independent verification, renewal, revocation and a signed audit export)
// through the control plane's own API, and writes what happened at each step
// as an evidence pack with a pass/fail summary and the limits of what it
// shows. The pack is signed by the deployment's audit-evidence key and checks
// offline with `trstctl evaluate verify`.
//
// A step that cannot run because an earlier one failed is skipped, never
// passed, so a failed journey can never read as a passed one.
package evaluate

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/auditanchor"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/certinfo"
	"trstctl.com/trstctl/internal/crypto/jose"
	"trstctl.com/trstctl/internal/crypto/tlsprobe"
	"trstctl.com/trstctl/internal/netsec"
)

// PackFormat names the evidence pack's schema.
const PackFormat = "trstctl.evaluation-pack/v1"

// maxOwnerPages bounds the owner search before the journey creates its own.
const maxOwnerPages = 50

// Status is one step's outcome.
type Status string

const (
	StatusPass    Status = "pass"
	StatusFail    Status = "fail"
	StatusSkipped Status = "skipped"
)

// The journey's steps, in order.
const (
	StepDiscovery    = "discovery"
	StepOwnership    = "ownership"
	StepIssuance     = "issuance"
	StepDeployment   = "deployment"
	StepVerification = "verification"
	StepRenewal      = "renewal"
	StepRevocation   = "revocation"
	StepAuditExport  = "audit_export"
)

// Basis says how a passed step's outcome is known: recorded is the product's
// own record of what it did; observed was read from outside that record.
const (
	BasisRecorded = "recorded"
	BasisObserved = "observed"
)

// Options is one evaluation run.
type Options struct {
	// Server is the control plane's base URL; Token an operator API token.
	Server string
	Token  string
	// HTTPClient talks to the control plane; nil uses a hardened default.
	HTTPClient *http.Client
	// DeploymentTarget is the connector target the partner configured for the
	// endpoint. Endpoint and Name default to its verify_address and
	// verify_server_name.
	DeploymentTarget string
	Endpoint         string
	Name             string
	// Owner names the owner the issued identity gets; Profile an optional
	// certificate profile.
	Owner   string
	Profile string
	// Timeout bounds each wait; PollInterval spaces the reads within it.
	Timeout      time.Duration
	PollInterval time.Duration
	// Probe is the evaluator's own TLS handshake; nil uses tlsprobe.
	Probe func(ctx context.Context, addr, serverName string) (tlsprobe.Result, error)
	Now   func() time.Time
}

// Pack is the evaluation evidence pack.
type Pack struct {
	Format      string    `json:"format"`
	GeneratedAt time.Time `json:"generated_at"`
	StartedAt   time.Time `json:"started_at"`
	Server      string    `json:"server"`
	TenantID    string    `json:"tenant_id,omitempty"`
	Target      Target    `json:"target"`
	Verdict     Status    `json:"verdict"`
	Summary     Summary   `json:"summary"`
	Steps       []Step    `json:"steps"`
	// Limits says what the journey does not show.
	Limits []string `json:"limits"`
	// AuditExport is the signed audit export of the journey and the key set
	// it was checked with, for a reader to check again with keys of their own.
	AuditExport *AuditEvidence `json:"audit_export,omitempty"`
	Signature   *Signature     `json:"signature,omitempty"`
}

// Target is what the partner chose.
type Target struct {
	Endpoint           string `json:"endpoint"`
	Name               string `json:"name"`
	DeploymentTargetID string `json:"deployment_target_id"`
	Connector          string `json:"connector,omitempty"`
}

// Summary counts the steps by outcome.
type Summary struct {
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
}

// Step is one step's outcome and its evidence.
type Step struct {
	Name       string            `json:"name"`
	Status     Status            `json:"status"`
	Basis      string            `json:"basis,omitempty"`
	Detail     string            `json:"detail"`
	Evidence   map[string]string `json:"evidence,omitempty"`
	StartedAt  time.Time         `json:"started_at"`
	FinishedAt time.Time         `json:"finished_at"`
}

// AuditEvidence is the signed audit export of the journey.
type AuditEvidence struct {
	Export []byte `json:"export"`
	JWKS   []byte `json:"jwks"`
}

// Signature is the pack's signature by the audit-evidence key.
type Signature struct {
	Alg   string `json:"alg"`
	KeyID string `json:"key_id"`
	JWS   string `json:"jws"`
}

// certificate is one issued certificate the journey follows.
type certificate struct {
	ID, Fingerprint, Serial, KeyOrigin string
	DER                                []byte
	Chain                              [][]byte
}

type journey struct {
	opts     Options
	api      *apiClient
	pack     *Pack
	failed   string
	ownerID  string
	identity string
	tenant   string
	issued   certificate
	renewed  certificate
	// servedChain is the chain the endpoint last served this evaluator.
	servedChain [][]byte
	keyPrefix   string
}

// Evaluate drives the journey and returns its pack, unsigned. It returns an
// error only when the journey could not start; every step's own failure is in
// the pack.
func Evaluate(ctx context.Context, opts Options) (Pack, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Minute
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = 2 * time.Second
	}
	if opts.Probe == nil {
		opts.Probe = func(ctx context.Context, addr, serverName string) (tlsprobe.Result, error) {
			return tlsprobe.Probe(ctx, addr, tlsprobe.WithServerName(serverName), tlsprobe.WithTimeout(15*time.Second))
		}
	}
	if strings.TrimSpace(opts.Owner) == "" {
		opts.Owner = "design-partner-evaluation"
	}
	base := strings.TrimSuffix(strings.TrimSpace(opts.Server), "/")
	if base == "" || strings.TrimSpace(opts.Token) == "" || strings.TrimSpace(opts.DeploymentTarget) == "" {
		return Pack{}, errors.New("evaluate: a server, an API token and a deployment target are required")
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = netsec.HardenedClient(60 * time.Second)
	}
	started := opts.Now().UTC()
	j := &journey{
		opts: opts, api: &apiClient{base: base, token: opts.Token, http: opts.HTTPClient},
		pack: &Pack{
			Format: PackFormat, StartedAt: started, Server: base, Steps: []Step{},
			Target: Target{DeploymentTargetID: opts.DeploymentTarget},
		},
		keyPrefix: "evaluate-" + strconv.FormatInt(started.UnixNano(), 36) + "-",
	}
	if err := j.resolveTarget(ctx); err != nil {
		return Pack{}, err
	}
	j.step(ctx, StepDiscovery, j.discover)
	j.step(ctx, StepOwnership, j.own)
	j.step(ctx, StepIssuance, j.issue)
	j.step(ctx, StepDeployment, j.deploy)
	j.step(ctx, StepVerification, j.verify)
	j.step(ctx, StepRenewal, j.renew)
	j.step(ctx, StepRevocation, j.revoke)
	// The audit export runs even after a failure: it records what was tried.
	j.failed = ""
	j.step(ctx, StepAuditExport, func(ctx context.Context, s *Step) error { return j.exportAudit(ctx, s, started) })
	j.finish()
	return *j.pack, nil
}

// resolveTarget reads the partner's deployment target for the endpoint and the
// name clients use for it.
func (j *journey) resolveTarget(ctx context.Context) error {
	var target struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		Connector string `json:"connector"`
		Enabled   bool   `json:"enabled"`
		Config    struct {
			VerifyAddress    string `json:"verify_address"`
			VerifyServerName string `json:"verify_server_name"`
		} `json:"config"`
	}
	if err := j.api.get(ctx, "/api/v1/connectors/targets/"+url.PathEscape(j.opts.DeploymentTarget), &target); err != nil {
		return fmt.Errorf("evaluate: read deployment target %s: %w", j.opts.DeploymentTarget, err)
	}
	endpoint := firstNonEmpty(j.opts.Endpoint, target.Config.VerifyAddress)
	name := firstNonEmpty(j.opts.Name, target.Config.VerifyServerName)
	if endpoint == "" || name == "" {
		return fmt.Errorf("evaluate: deployment target %s names no verify_address and verify_server_name; pass --endpoint and --name", j.opts.DeploymentTarget)
	}
	if _, _, err := net.SplitHostPort(endpoint); err != nil {
		return fmt.Errorf("evaluate: endpoint %q is not host:port", endpoint)
	}
	j.pack.Target = Target{Endpoint: endpoint, Name: name, DeploymentTargetID: target.ID, Connector: target.Connector}
	return nil
}

// step runs one step unless an earlier one failed.
func (j *journey) step(ctx context.Context, name string, fn func(context.Context, *Step) error) {
	s := Step{Name: name, StartedAt: j.opts.Now().UTC(), Evidence: map[string]string{}}
	if j.failed != "" {
		s.Status, s.Detail = StatusSkipped, "Skipped because the "+strings.ReplaceAll(j.failed, "_", " ")+" step failed."
	} else if err := fn(ctx, &s); err != nil {
		s.Status, s.Detail, s.Basis = StatusFail, sentence(err.Error()), ""
		j.failed = name
	} else {
		s.Status = StatusPass
	}
	if len(s.Evidence) == 0 {
		s.Evidence = nil
	}
	s.FinishedAt = j.opts.Now().UTC()
	j.pack.Steps = append(j.pack.Steps, s)
}

// poll reads until done says so, the step's wait runs out, or ctx ends.
func (j *journey) poll(ctx context.Context, what string, done func(context.Context) (bool, error)) error {
	deadline := j.opts.Now().Add(j.opts.Timeout)
	for {
		ok, err := done(ctx)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if j.opts.Now().After(deadline) {
			return fmt.Errorf("%s within %s", what, j.opts.Timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(j.opts.PollInterval):
		}
	}
}

func (j *journey) key(step string) string { return j.keyPrefix + step }

// discover has the control plane complete a TLS handshake with the endpoint
// and record what it served.
func (j *journey) discover(ctx context.Context, s *Step) error {
	var scan struct {
		Report struct {
			Failed int `json:"failed"`
		} `json:"report"`
		ObservedAssetIDs []string `json:"observed_asset_ids"`
	}
	endpoint := j.pack.Target.Endpoint
	if err := j.api.post(ctx, "/api/v1/cbom/scans", map[string]any{"tls_endpoints": []string{endpoint}}, j.key("discovery"), &scan); err != nil {
		return fmt.Errorf("the control plane could not scan %s: %w", endpoint, err)
	}
	if scan.Report.Failed > 0 || len(scan.ObservedAssetIDs) == 0 {
		return fmt.Errorf("the control plane could not complete a TLS handshake with %s", endpoint)
	}
	var assets struct {
		Items []struct {
			ID                     string `json:"id"`
			Location               string `json:"location"`
			CertificateFingerprint string `json:"certificate_fingerprint"`
		} `json:"items"`
	}
	if err := j.api.get(ctx, "/api/v1/cbom/assets", &assets); err != nil {
		return err
	}
	observed := map[string]bool{}
	for _, id := range scan.ObservedAssetIDs {
		observed[id] = true
	}
	for _, asset := range assets.Items {
		if observed[asset.ID] && asset.CertificateFingerprint != "" {
			s.Basis = BasisObserved
			s.Evidence["crypto_asset_id"] = asset.ID
			s.Evidence["served_fingerprint"] = asset.CertificateFingerprint
			s.Detail = fmt.Sprintf("The control plane completed a TLS handshake with %s and recorded the certificate it served (SHA-256 %s).", endpoint, short(asset.CertificateFingerprint))
			return nil
		}
	}
	return fmt.Errorf("the scan of %s recorded no served certificate", endpoint)
}

// own finds or creates the owner the issued identity will have.
func (j *journey) own(ctx context.Context, s *Step) error {
	cursor := ""
	for page := 0; page < maxOwnerPages && j.ownerID == ""; page++ {
		var owners struct {
			Items []struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"items"`
			NextCursor string `json:"next_cursor"`
		}
		if err := j.api.get(ctx, "/api/v1/owners?limit=100&cursor="+url.QueryEscape(cursor), &owners); err != nil {
			return err
		}
		for _, o := range owners.Items {
			if o.Name == j.opts.Owner {
				j.ownerID = o.ID
			}
		}
		if cursor = owners.NextCursor; cursor == "" {
			break
		}
	}
	created := false
	if j.ownerID == "" {
		var owner struct {
			ID string `json:"id"`
		}
		if err := j.api.post(ctx, "/api/v1/owners", map[string]any{"kind": "team", "name": j.opts.Owner}, j.key("owner"), &owner); err != nil {
			return err
		}
		j.ownerID, created = owner.ID, true
	}
	s.Basis = BasisRecorded
	s.Evidence["owner_id"] = j.ownerID
	s.Detail = fmt.Sprintf("Owner %s (%s) owns the identity issued for %s.", j.opts.Owner, j.ownerID, j.pack.Target.Name)
	if created {
		s.Detail = fmt.Sprintf("Owner %s was created (%s) to own the identity issued for %s.", j.opts.Owner, j.ownerID, j.pack.Target.Name)
	}
	return nil
}

// issue binds the endpoint to a new identity on the platform CA after the
// reviewed preview, and waits for the issued certificate.
func (j *journey) issue(ctx context.Context, s *Step) error {
	request := map[string]any{
		"owner_id": j.ownerID, "identity_name": j.pack.Target.Name, "target_id": j.pack.Target.DeploymentTargetID,
		"issuer": map[string]string{"source": "platform", "id": "trstctl-issuing-ca"},
		"reason": "design-partner evaluation",
	}
	if j.opts.Profile != "" {
		request["profile_name"] = j.opts.Profile
	}
	var preview struct {
		RequestFingerprint string `json:"request_fingerprint"`
	}
	if err := j.api.post(ctx, "/api/v1/lifecycle/endpoint-bindings/preview", request, "", &preview); err != nil {
		return fmt.Errorf("the endpoint binding preview was refused: %w", err)
	}
	request["preview_fingerprint"] = preview.RequestFingerprint
	key := j.key("issue")
	var binding struct {
		Identity struct {
			ID       string `json:"id"`
			TenantID string `json:"tenant_id"`
		} `json:"identity"`
	}
	if err := j.api.post(ctx, "/api/v1/lifecycle/endpoint-bindings", request, key, &binding); err != nil {
		return fmt.Errorf("the endpoint binding was refused: %w", err)
	}
	j.identity, j.tenant = binding.Identity.ID, binding.Identity.TenantID
	j.pack.TenantID = j.tenant
	s.Evidence["identity_id"] = j.identity
	cert, err := j.awaitIssuance(ctx, key, "the certificate for "+j.pack.Target.Name+" was not issued")
	if err != nil {
		return err
	}
	j.issued = cert
	s.Basis = BasisRecorded
	s.Evidence["certificate_id"], s.Evidence["fingerprint"], s.Evidence["serial"] = cert.ID, cert.Fingerprint, cert.Serial
	where := "by the platform CA"
	if cert.KeyOrigin != "" {
		s.Evidence["key_origin"] = cert.KeyOrigin
		where += ", for a key whose origin is recorded as " + cert.KeyOrigin
	}
	s.Detail = fmt.Sprintf("Identity %s was issued certificate %s (SHA-256 %s) %s.", j.identity, cert.ID, short(cert.Fingerprint), where)
	return nil
}

// awaitIssuance waits for the exact issuance a request key accepted. When the
// target's agent generates the key, the certificate is issued to the agent's
// renewal job rather than to the request, and first appears as the identity's
// deployed certificate.
func (j *journey) awaitIssuance(ctx context.Context, key, what string) (certificate, error) {
	var cert certificate
	err := j.poll(ctx, what, func(ctx context.Context) (bool, error) {
		if deployed, _, ok, err := j.deployedCertificate(ctx, ""); err != nil || ok {
			cert = deployed
			return ok, err
		}
		var result struct {
			State       string `json:"state"`
			Certificate *struct {
				ID          string `json:"id"`
				Fingerprint string `json:"fingerprint"`
				Serial      string `json:"serial"`
			} `json:"certificate"`
			CertificatePEM string `json:"certificate_pem"`
		}
		path := "/api/v1/identities/" + url.PathEscape(j.identity) + "/issuance-result?request_key=" + url.QueryEscape(key)
		if err := j.api.get(ctx, path, &result); err != nil {
			return false, err
		}
		switch result.State {
		case "issued":
			if result.Certificate == nil {
				return false, errors.New("the issuance result names no certificate")
			}
			chain := pemChain([]byte(result.CertificatePEM))
			if len(chain) == 0 {
				return false, errors.New("the issuance result carries no certificate")
			}
			cert = certificate{ID: result.Certificate.ID, Fingerprint: result.Certificate.Fingerprint,
				Serial: result.Certificate.Serial, DER: chain[0], Chain: chain}
			return true, nil
		case "pending", "unavailable", "":
			return false, j.identityFailed(ctx)
		case "failed", "cancelled":
			return false, fmt.Errorf("issuance %s", result.State)
		}
		return false, nil
	})
	return cert, err
}

// deploy waits for the identity's completed deployment of the issued
// certificate and its connector receipt.
func (j *journey) deploy(ctx context.Context, s *Step) error {
	var receipt delivery
	if err := j.poll(ctx, "the certificate was not delivered to "+j.pack.Target.DeploymentTargetID, func(ctx context.Context) (bool, error) {
		cert, r, ok, err := j.deployedCertificate(ctx, "")
		if err != nil || !ok {
			return false, err
		}
		if cert.Fingerprint != j.issued.Fingerprint {
			return false, fmt.Errorf("the identity's deployed certificate is %s, not the issued %s", short(cert.Fingerprint), short(j.issued.Fingerprint))
		}
		receipt = r
		return true, nil
	}); err != nil {
		return err
	}
	s.Basis = BasisRecorded
	s.Evidence["receipt_id"], s.Evidence["receipt_status"] = receipt.ID, receipt.Status
	s.Detail = fmt.Sprintf("The %s connector reported delivering certificate %s to %s (receipt %s, %s).",
		firstNonEmpty(receipt.Connector, j.pack.Target.Connector), short(j.issued.Fingerprint), firstNonEmpty(receipt.Target, j.pack.Target.DeploymentTargetID), receipt.ID, receipt.Status)
	return nil
}

type delivery struct {
	ID          string `json:"id"`
	Connector   string `json:"connector"`
	Target      string `json:"target"`
	Fingerprint string `json:"fingerprint"`
	Status      string `json:"status"`
	Detail      string `json:"detail"`
}

// deployedCertificate reads the identity's last completed deployment: its
// certificate and receipt, when the receipt says delivered or verified and the
// certificate is not exclude. A failed receipt for another certificate is the
// step's failure.
func (j *journey) deployedCertificate(ctx context.Context, exclude string) (certificate, delivery, bool, error) {
	var evidence struct {
		Receipt     *delivery `json:"receipt"`
		Certificate *struct {
			ID          string `json:"id"`
			Fingerprint string `json:"fingerprint"`
			Serial      string `json:"serial"`
			KeyOrigin   string `json:"key_origin"`
		} `json:"certificate"`
	}
	err := j.api.get(ctx, "/api/v1/identities/"+url.PathEscape(j.identity)+"/deployment-evidence", &evidence)
	var refused *apiError
	if errors.As(err, &refused) && refused.Status == http.StatusNotFound {
		return certificate{}, delivery{}, false, nil
	}
	if err != nil {
		return certificate{}, delivery{}, false, err
	}
	if evidence.Certificate == nil || evidence.Receipt == nil || evidence.Certificate.Fingerprint == exclude {
		return certificate{}, delivery{}, false, j.deliveryFailed(ctx, exclude)
	}
	switch evidence.Receipt.Status {
	case "delivered", "verified":
		c := evidence.Certificate
		return certificate{ID: c.ID, Fingerprint: c.Fingerprint, Serial: c.Serial, KeyOrigin: c.KeyOrigin}, *evidence.Receipt, true, nil
	}
	return certificate{}, delivery{}, false, j.deliveryFailed(ctx, exclude)
}

// deliveryFailed reports a failed connector receipt for any certificate but
// exclude.
func (j *journey) deliveryFailed(ctx context.Context, exclude string) error {
	var list struct {
		Items []delivery `json:"items"`
	}
	if err := j.api.get(ctx, "/api/v1/connectors/deliveries?identity_id="+url.QueryEscape(j.identity)+"&limit=50", &list); err != nil {
		return err
	}
	for _, d := range list.Items {
		if d.Fingerprint != exclude && (d.Status == "failed" || d.Status == "verify_failed") {
			return fmt.Errorf("the connector reported %s delivering %s: %s", d.Status, short(d.Fingerprint), firstNonEmpty(d.Detail, "no detail"))
		}
	}
	return j.identityFailed(ctx)
}

// identityFailed reports an identity whose issuance or renewal failed.
func (j *journey) identityFailed(ctx context.Context) error {
	var identity struct {
		Status string `json:"status"`
	}
	if err := j.api.get(ctx, "/api/v1/identities/"+url.PathEscape(j.identity), &identity); err != nil {
		return err
	}
	if identity.Status == "renewal_failed" || identity.Status == "failed" || identity.Status == "revoked" {
		return fmt.Errorf("identity %s is %s", j.identity, identity.Status)
	}
	return nil
}

// verify has the evaluator itself complete a TLS handshake with the endpoint,
// from where it runs, and compare what it is served with what was issued.
func (j *journey) verify(ctx context.Context, s *Step) error {
	if err := j.awaitServed(ctx, j.issued.Fingerprint); err != nil {
		return err
	}
	if len(j.issued.Chain) < 2 && len(j.servedChain) > 0 {
		j.issued.DER, j.issued.Chain = j.servedChain[0], j.servedChain
	}
	s.Basis = BasisObserved
	s.Evidence["served_fingerprint"] = j.issued.Fingerprint
	s.Evidence["served_chain_length"] = strconv.Itoa(len(j.servedChain))
	s.Detail = fmt.Sprintf("This evaluator completed its own TLS handshake with %s as %s and was served the issued certificate (SHA-256 %s).",
		j.pack.Target.Endpoint, j.pack.Target.Name, short(j.issued.Fingerprint))
	return nil
}

// awaitServed waits until the endpoint serves fingerprint to this evaluator,
// and keeps the chain it served.
func (j *journey) awaitServed(ctx context.Context, fingerprint string) error {
	var last string
	err := j.poll(ctx, "the endpoint did not serve the expected certificate", func(ctx context.Context) (bool, error) {
		result, err := j.opts.Probe(ctx, j.pack.Target.Endpoint, j.pack.Target.Name)
		if err != nil {
			last = "the TLS handshake failed: " + err.Error()
			return false, nil
		}
		if len(result.PeerCertificates) == 0 {
			last = "the endpoint presented no certificate"
			return false, nil
		}
		served := crypto.SHA256Hex(result.PeerCertificates[0])
		if served == fingerprint {
			j.servedChain = result.PeerCertificates
			return true, nil
		}
		last = "it served " + short(served) + " instead of " + short(fingerprint)
		return false, nil
	})
	if err != nil && last != "" {
		return fmt.Errorf("%s at %s: %s", strings.TrimSuffix(err.Error(), "."), j.pack.Target.Endpoint, last)
	}
	return err
}

// renew asks for the identity's renewal and waits until the endpoint serves
// the renewed certificate.
func (j *journey) renew(ctx context.Context, s *Step) error {
	key := j.key("renew")
	if err := j.api.post(ctx, "/api/v1/identities/"+url.PathEscape(j.identity)+"/transitions",
		map[string]any{"to": "renewing", "reason": "design-partner evaluation renewal"}, key, nil); err != nil {
		return fmt.Errorf("the renewal was refused: %w", err)
	}
	var receipt delivery
	if err := j.poll(ctx, "the renewed certificate was not deployed", func(ctx context.Context) (bool, error) {
		cert, r, ok, err := j.deployedCertificate(ctx, j.issued.Fingerprint)
		if ok {
			j.renewed, receipt = cert, r
		}
		return ok, err
	}); err != nil {
		return err
	}
	if err := j.awaitServed(ctx, j.renewed.Fingerprint); err != nil {
		return err
	}
	s.Basis = BasisObserved
	s.Evidence["certificate_id"], s.Evidence["fingerprint"], s.Evidence["receipt_id"] = j.renewed.ID, j.renewed.Fingerprint, receipt.ID
	s.Detail = fmt.Sprintf("Renewal replaced certificate %s with %s, and this evaluator's own TLS handshake was then served the renewed one.",
		short(j.issued.Fingerprint), short(j.renewed.Fingerprint))
	return nil
}

// revoke revokes the superseded certificate and checks its status the way a
// relying party would, over OCSP.
func (j *journey) revoke(ctx context.Context, s *Step) error {
	var result struct {
		TotalRevoked int `json:"total_revoked"`
		Items        []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
			Error  string `json:"error"`
		} `json:"items"`
	}
	if err := j.api.post(ctx, "/api/v1/certificates/bulk-revoke",
		map[string]any{"certificate_ids": []string{j.issued.ID}, "reason": "superseded"}, j.key("revoke"), &result); err != nil {
		return fmt.Errorf("revoking the superseded certificate was refused: %w", err)
	}
	if len(result.Items) != 1 || result.Items[0].Status != "revoked" {
		detail := "no outcome"
		if len(result.Items) == 1 {
			detail = firstNonEmpty(result.Items[0].Error, result.Items[0].Status)
		}
		return fmt.Errorf("revoking the superseded certificate %s was not completed: %s", j.issued.ID, detail)
	}
	if len(j.issued.Chain) < 2 {
		return errors.New("neither the issuance result nor the endpoint supplied the issuing CA certificate, so OCSP cannot be asked")
	}
	issuer := j.issued.Chain[1]
	request, err := crypto.BuildOCSPRequest(j.issued.DER, issuer)
	if err != nil {
		return err
	}
	responder := j.api.base + "/ocsp/" + url.PathEscape(j.tenant)
	if info, err := certinfo.Inspect(j.issued.DER); err == nil && len(info.OCSPServers) > 0 {
		responder = info.OCSPServers[0]
	}
	var status crypto.OCSPStatusInfo
	if err := j.poll(ctx, "OCSP did not report the certificate revoked", func(ctx context.Context) (bool, error) {
		raw, err := j.api.postRaw(ctx, responder, "application/ocsp-request", request)
		if err != nil {
			return false, err
		}
		if status, err = crypto.ParseOCSPResponse(raw, issuer); err != nil {
			return false, fmt.Errorf("the OCSP answer did not verify: %w", err)
		}
		return status.Status == "revoked", nil
	}); err != nil {
		return err
	}
	s.Basis = BasisObserved
	s.Evidence["certificate_id"], s.Evidence["ocsp_responder"], s.Evidence["ocsp_status"] = j.issued.ID, responder, status.Status
	s.Detail = fmt.Sprintf("The superseded certificate %s was revoked, and an OCSP request to %s returned a signed answer saying revoked.", short(j.issued.Fingerprint), responder)
	return nil
}

// exportAudit downloads the signed audit export of the journey and verifies
// it with the published audit keys.
func (j *journey) exportAudit(ctx context.Context, s *Step, since time.Time) error {
	query := url.Values{"format": {"jws"}, "since": {since.Format(time.RFC3339)}}
	if j.identity != "" {
		query.Set("q", j.identity)
	}
	export, err := j.api.do(ctx, http.MethodGet, "/api/v1/audit/export?"+query.Encode(), nil, "")
	if err != nil {
		return fmt.Errorf("the audit export was refused: %w", err)
	}
	jwks, err := j.api.do(ctx, http.MethodGet, "/api/v1/audit/verification-keys", nil, "")
	if err != nil {
		return err
	}
	keys, err := jose.ParseJWKSet(jwks)
	if err != nil {
		return fmt.Errorf("the audit verification keys do not parse: %w", err)
	}
	result, err := auditanchor.VerifyArtifact(export, auditanchor.VerificationOptions{Format: auditanchor.FormatJWS, AuditKeys: keys, AllowUnanchoredJWS: true})
	if err != nil {
		return fmt.Errorf("the audit export did not verify: %w", err)
	}
	j.pack.AuditExport = &AuditEvidence{Export: export, JWKS: jwks}
	if !result.AuditSignatureVerified || result.RecordCount == 0 {
		return errors.New("the audit export holds no signed record of the journey")
	}
	s.Basis = BasisRecorded
	s.Evidence["record_count"], s.Evidence["chain_head"] = strconv.Itoa(result.RecordCount), result.ChainHead
	s.Detail = fmt.Sprintf("The signed audit export of the journey verified with the published audit keys: %d records, chain head %s.", result.RecordCount, short(result.ChainHead))
	return nil
}

// finish counts the steps, sets the verdict and states the limits.
func (j *journey) finish() {
	p := j.pack
	for _, s := range p.Steps {
		switch s.Status {
		case StatusPass:
			p.Summary.Passed++
		case StatusFail:
			p.Summary.Failed++
		default:
			p.Summary.Skipped++
		}
	}
	p.Verdict = StatusPass
	if p.Summary.Failed > 0 || p.Summary.Skipped > 0 {
		p.Verdict = StatusFail
	}
	p.GeneratedAt = j.opts.Now().UTC()
	p.Limits = []string{
		"Discovery is the control plane's own TLS handshake with the endpoint (a CBOM scan). A network relay's scan, which a partner network would use to find endpoints it was not told about, is not part of this journey.",
		"Verification and the renewal check are this evaluator's own TLS handshakes from where it ran: they show what that vantage was served, not what every client is served.",
		"Revocation was checked over OCSP at the responder the pack names. CRL publication is asynchronous and was not checked.",
		"The audit export was checked with the audit keys this server published. Check the pack and the export again with an audit JWK set obtained separately: trstctl evaluate verify --pack <file> --audit-jwks <file>.",
		"The journey ran once against one endpoint. It is not a load, failover or long-running test.",
	}
}

func pemChain(raw []byte) [][]byte {
	var out [][]byte
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			return out
		}
		if block.Type == "CERTIFICATE" {
			out = append(out, block.Bytes)
		}
	}
}

func short(digest string) string {
	if len(digest) > 16 {
		return digest[:16]
	}
	return digest
}

func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	s = strings.ToUpper(s[:1]) + s[1:]
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
