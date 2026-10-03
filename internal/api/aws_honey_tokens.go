// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	gouuid "github.com/google/uuid"

	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/crypto/secret"
	"trstctl.com/trstctl/internal/dynsecret"
	"trstctl.com/trstctl/internal/projections"
	"trstctl.com/trstctl/internal/store"
)

// AWSHoneyAccount is the secret-free topology of an operator-configured AWS
// decoy attachment. The IAM writer and CloudTrail reader credentials never pass
// through this type or the browser.
type AWSHoneyAccount struct {
	ID                  string   `json:"id"`
	AccountID           string   `json:"account_id"`
	Regions             []string `json:"regions"`
	MaxTTLSeconds       int64    `json:"max_ttl_seconds"`
	PollIntervalSeconds int64    `json:"poll_interval_seconds"`
}

type awsHoneyCreateRequest struct {
	AccountID          string `json:"account_id"`
	Name               string `json:"name"`
	Placement          string `json:"placement"`
	TTLSeconds         int64  `json:"ttl_seconds"`
	PreviewFingerprint string `json:"preview_fingerprint,omitempty"`
}

type awsHoneyPreview struct {
	Ready                  bool     `json:"ready"`
	EffectFree             bool     `json:"effect_free"`
	RemoteAuthorityChecked bool     `json:"remote_authority_checked"`
	AccountAttachmentID    string   `json:"account_attachment_id"`
	AWSAccountID           string   `json:"aws_account_id"`
	Name                   string   `json:"name"`
	Placement              string   `json:"placement"`
	TTLSeconds             int64    `json:"ttl_seconds"`
	Regions                []string `json:"regions"`
	IAMActions             []string `json:"iam_actions"`
	DetectionScope         string   `json:"detection_scope"`
	Recovery               string   `json:"recovery"`
	Verification           string   `json:"verification"`
	PreviewFingerprint     string   `json:"preview_fingerprint"`
}

type awsHoneyCreateResponse struct {
	store.HoneyToken
	AccessKeyID     string          `json:"access_key_id"`
	SecretAccessKey secretJSONBytes `json:"secret_access_key"`
}

func (r *awsHoneyCreateResponse) wipeSecrets() { r.SecretAccessKey.wipe() }

type awsHoneyDetail struct {
	store.HoneyToken
	Lease      dynamicLeaseResponse `json:"lease"`
	Monitoring []store.AWSHoneyScan `json:"monitoring"`
	Uses       []store.AWSHoneyUse  `json:"uses"`
}

func (a *API) tenantAWSHoneyAccounts(tenantID string) []AWSHoneyAccount {
	if a.secrets == nil || a.secrets.be.AWSHoneyAccountsForTenant == nil {
		return nil
	}
	return a.secrets.be.AWSHoneyAccountsForTenant(tenantID)
}

func (a *API) awsHoneyAccount(tenantID, id string) (AWSHoneyAccount, bool) {
	for _, account := range a.tenantAWSHoneyAccounts(tenantID) {
		if account.ID == id {
			return account, true
		}
	}
	return AWSHoneyAccount{}, false
}

func (a *API) listAWSHoneyAccounts(w http.ResponseWriter, r *http.Request) {
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	accounts := a.tenantAWSHoneyAccounts(tenantID)
	if accounts == nil {
		accounts = []AWSHoneyAccount{}
	}
	a.writeJSON(w, http.StatusOK, map[string]any{
		"accounts":        accounts,
		"detection_scope": "CloudTrail LookupEvents management events in the configured account and Regions; AWS delivery is delayed and data events are not covered",
	})
}

func awsHoneyCreateBinding(principal string, req awsHoneyCreateRequest, account AWSHoneyAccount) (string, error) {
	material, err := json.Marshal(struct {
		Operation string `json:"operation"`
		Principal string `json:"principal"`
		Request   struct {
			AccountID  string `json:"account_id"`
			Name       string `json:"name"`
			Placement  string `json:"placement"`
			TTLSeconds int64  `json:"ttl_seconds"`
		} `json:"request"`
		Account AWSHoneyAccount `json:"account"`
	}{"aws-honeytoken.create", principal, struct {
		AccountID  string `json:"account_id"`
		Name       string `json:"name"`
		Placement  string `json:"placement"`
		TTLSeconds int64  `json:"ttl_seconds"`
	}{req.AccountID, req.Name, req.Placement, req.TTLSeconds}, account})
	if err != nil {
		return "", err
	}
	defer secret.Wipe(material)
	return crypto.SHA256Hex(material), nil
}

func (a *API) validateAWSHoneyCreate(tenantID string, req *awsHoneyCreateRequest) (AWSHoneyAccount, error) {
	req.AccountID, req.Name, req.Placement = strings.TrimSpace(req.AccountID), strings.TrimSpace(req.Name), strings.TrimSpace(req.Placement)
	if !validHoneyTokenLabel(req.Name, 128) || !validHoneyTokenLabel(req.Placement, 256) || req.AccountID == "" {
		return AWSHoneyAccount{}, errStatus(http.StatusUnprocessableEntity, "account_id, name (1-128), and placement (1-256) are required without control characters")
	}
	account, found := a.awsHoneyAccount(tenantID, req.AccountID)
	if !found {
		return AWSHoneyAccount{}, errStatus(http.StatusUnprocessableEntity, "AWS honeytoken account is not configured for this tenant")
	}
	if req.TTLSeconds < 2*account.PollIntervalSeconds || req.TTLSeconds > account.MaxTTLSeconds {
		return AWSHoneyAccount{}, errStatus(http.StatusUnprocessableEntity, "ttl_seconds must cover at least two monitoring intervals and stay within the configured maximum")
	}
	return account, nil
}

func (a *API) previewAWSHoneyToken(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	var req awsHoneyCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	account, err := a.validateAWSHoneyCreate(tenantID, &req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := awsHoneyCreateBinding(principal, req, account)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, awsHoneyPreview{
		Ready: true, EffectFree: true, RemoteAuthorityChecked: false, AccountAttachmentID: account.ID,
		AWSAccountID: account.AccountID, Name: req.Name, Placement: req.Placement,
		TTLSeconds: req.TTLSeconds, Regions: account.Regions,
		IAMActions:         []string{"iam.create_tagged_user", "iam.install_and_verify_deny_all", "iam.create_access_key", "cloudtrail.queue_monitor"},
		DetectionScope:     "CloudTrail LookupEvents management events in the configured account and Regions; delivery is delayed and data events are not covered",
		Recovery:           "If creation fails, retry with the same Idempotency-Key; retire deletes the exact owned IAM user and verifies absence",
		Verification:       "Sign a request with the bait key; verify AccessDenied, a CloudTrail incident and critical alert, then confirm IAM NoSuchEntity after retirement",
		PreviewFingerprint: binding,
	})
}

//trstctl:mutation
func (a *API) createAWSHoneyToken(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.orch == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	var req awsHoneyCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		a.writeError(w, errWithStatus(http.StatusBadRequest, err))
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	account, err := a.validateAWSHoneyCreate(tenantID, &req)
	if err != nil {
		a.writeError(w, err)
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	binding, err := awsHoneyCreateBinding(principal, req, account)
	if err != nil {
		a.writeError(w, err)
		return
	}
	if req.PreviewFingerprint != "" && req.PreviewFingerprint != binding {
		a.writeError(w, errStatus(http.StatusConflict, "AWS decoy preview is stale; review the current account and request again"))
		return
	}
	a.mutateSealedDynamicLease(w, r, key, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		engine, err := a.secrets.dynamicLeaseEngine(tenantID)
		if err != nil {
			return 0, nil, err
		}
		issuer, ok := engine.(boundDynamicLeaseIssuer)
		if !ok {
			return 0, nil, errStatus(http.StatusServiceUnavailable, "durable AWS honeytoken issuance is not configured")
		}
		lease, credential, err := issuer.IssueBound(ctx, "honey.aws."+account.ID, "decoy", time.Duration(req.TTLSeconds)*time.Second, key, binding)
		if err != nil {
			return 0, nil, dynamicLeaseError(err)
		}
		defer secret.Wipe(credential)
		accountID, decoyID, accessKeyID, _, refOK := dynsecret.AWSHoneyReference(lease.BackendRef)
		if !refOK || accountID != account.AccountID || decoyID != lease.ID {
			return 0, nil, errors.New("api: AWS honeytoken IAM identity does not match the durable decoy lease")
		}
		var revealed struct {
			AccessKeyID     string           `json:"access_key_id"`
			SecretAccessKey secret.JSONBytes `json:"secret_access_key"`
		}
		if err := json.Unmarshal(credential, &revealed); err != nil || revealed.AccessKeyID != accessKeyID || len(revealed.SecretAccessKey) == 0 {
			secret.Wipe(revealed.SecretAccessKey)
			return 0, nil, errors.New("api: AWS honeytoken reveal does not match the IAM lease")
		}
		planted, err := a.orch.CreateAWSHoneyToken(ctx, tenantID, projections.AWSHoneyTokenCreated{
			Name: req.Name, Placement: req.Placement, AccountConfigID: account.ID,
			AccountID: account.AccountID, AccessKeyID: accessKeyID, LeaseID: lease.ID,
			Regions: account.Regions, PollIntervalSeconds: int(account.PollIntervalSeconds),
		})
		if err != nil {
			secret.Wipe(revealed.SecretAccessKey)
			return 0, nil, err
		}
		return http.StatusCreated, &awsHoneyCreateResponse{HoneyToken: planted,
			AccessKeyID: accessKeyID, SecretAccessKey: secretJSONBytes(revealed.SecretAccessKey)}, nil
	})
}

func (a *API) listAWSHoneyTokens(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	limit, after, err := a.pageParams(r)
	if err != nil {
		a.writeError(w, errStatus(http.StatusBadRequest, err.Error()))
		return
	}
	items, err := a.store.ListAWSHoneyTokensPage(r.Context(), tenantID, after, limit)
	if err != nil {
		a.writeError(w, err)
		return
	}
	engine, engineErr := a.secrets.dynamicLeaseEngine(tenantID)
	if engineErr == nil {
		for i := range items {
			if lease, readErr := getDynamicLeaseContext(r.Context(), engine, items[i].AWSLeaseID); readErr == nil {
				items[i].State = awsHoneyVisibleState(items[i].State, lease)
			}
		}
	}
	next := ""
	if len(items) == limit {
		next = encodeCursor(items[len(items)-1].ID)
	}
	a.writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

func awsHoneyVisibleState(honeyState string, lease dynsecret.Lease) string {
	if lease.State == dynsecret.LeaseRevoked {
		if lease.RevocationStatus == string(store.DynamicSecretRevocationCompleted) {
			return "revoked"
		}
		if lease.RevocationStatus == string(store.DynamicSecretRevocationFailed) {
			return "retirement_failed"
		}
		return "retiring"
	}
	if lease.State == dynsecret.LeaseFailed {
		return "failed"
	}
	return honeyState
}

func (a *API) awsHoneyDetails(ctx context.Context, tenantID, id string) (awsHoneyDetail, error) {
	if _, err := gouuid.Parse(id); err != nil {
		return awsHoneyDetail{}, errStatus(http.StatusNotFound, "AWS honeytoken not found")
	}
	h, err := a.store.GetHoneyToken(ctx, tenantID, id)
	if store.IsNotFound(err) || (err == nil && h.Kind != "aws") {
		return awsHoneyDetail{}, errStatus(http.StatusNotFound, "AWS honeytoken not found")
	}
	if err != nil {
		return awsHoneyDetail{}, err
	}
	engine, err := a.secrets.dynamicLeaseEngine(tenantID)
	if err != nil {
		return awsHoneyDetail{}, err
	}
	lease, err := getDynamicLeaseContext(ctx, engine, h.AWSLeaseID)
	if err != nil || lease.Provider != "honey.aws."+h.AWSAccountConfigID {
		return awsHoneyDetail{}, errors.New("api: AWS honeytoken lost its tenant-bound IAM lease")
	}
	h.State = awsHoneyVisibleState(h.State, lease)
	scans, err := a.store.ListAWSHoneyScans(ctx, tenantID, id)
	if err != nil {
		return awsHoneyDetail{}, err
	}
	uses, err := a.store.ListAWSHoneyUses(ctx, tenantID, id, 100)
	if err != nil {
		return awsHoneyDetail{}, err
	}
	return awsHoneyDetail{HoneyToken: h, Lease: toDynamicLeaseResponse(lease, nil), Monitoring: scans, Uses: uses}, nil
}

func (a *API) getAWSHoneyToken(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	tenantID, ok := a.tenant(r)
	if !ok {
		a.writeProblem(w, problemUnauthorized())
		return
	}
	detail, err := a.awsHoneyDetails(r.Context(), tenantID, r.PathValue("id"))
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.writeJSON(w, http.StatusOK, detail)
}

//trstctl:mutation
func (a *API) retireAWSHoneyToken(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	id := r.PathValue("id")
	binding, err := dynamicLeaseMutationBinding("aws-honeytoken.retire", principal, id, 0)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, key, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		detail, err := a.awsHoneyDetails(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		if detail.Lease.State == string(dynsecret.LeaseActive) || detail.Lease.RevocationStatus == string(store.DynamicSecretRevocationFailed) {
			engine, engineErr := a.secrets.dynamicLeaseEngine(tenantID)
			if engineErr != nil {
				return 0, nil, engineErr
			}
			revoker, ok := engine.(boundDynamicLeaseRevoker)
			if !ok {
				return 0, nil, errStatus(http.StatusServiceUnavailable, "durable IAM retirement is unavailable")
			}
			if _, err := revoker.RevokeBound(ctx, detail.AWSLeaseID, key, binding); err != nil {
				return 0, nil, dynamicLeaseError(err)
			}
		}
		detail, err = a.awsHoneyDetails(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		return http.StatusOK, detail, nil
	})
}

//trstctl:mutation
func (a *API) rearmAWSHoneyToken(w http.ResponseWriter, r *http.Request) {
	if a.secrets == nil || a.orch == nil {
		a.writeProblem(w, secretsDisabledProblem())
		return
	}
	key := r.Header.Get("Idempotency-Key")
	if key == "" {
		a.writeError(w, errStatus(http.StatusBadRequest, "Idempotency-Key header is required for mutations"))
		return
	}
	principal, err := requestPrincipalSubject(r.Context())
	if err != nil {
		a.writeError(w, err)
		return
	}
	id := r.PathValue("id")
	binding, err := dynamicLeaseMutationBinding("aws-honeytoken.rearm", principal, id, 0)
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, key, binding, func(ctx context.Context, tenantID string) (int, any, error) {
		detail, err := a.awsHoneyDetails(ctx, tenantID, id)
		if err != nil {
			return 0, nil, err
		}
		if detail.State != "triggered" || detail.Lease.State != string(dynsecret.LeaseActive) {
			return 0, nil, errStatus(http.StatusConflict, "only an active triggered AWS decoy can be rearmed")
		}
		if _, err := a.orch.RearmAWSHoneyToken(ctx, tenantID, id, key); err != nil {
			return 0, nil, err
		}
		detail, err = a.awsHoneyDetails(ctx, tenantID, id)
		return http.StatusOK, detail, err
	})
}
