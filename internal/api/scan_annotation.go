// SPDX-License-Identifier: BUSL-1.1

package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trstctl.com/trstctl/internal/authz"
	"trstctl.com/trstctl/internal/crypto"
	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/secretscan"
	"trstctl.com/trstctl/internal/store"
)

// Annotating a leaked-secret finding at its provider (A174). A third-party
// scan finding is written back where the credential was seen: a reply in the
// Slack thread, a comment on the Jira issue, a commit status on the CI run's
// commit, a referrer on the container image. It goes through the annotation
// connection the scan's source names; the finding records the request and
// then what the provider confirmed.

// FindingAnnotationRequest is the operator's reason for the annotation.
type FindingAnnotationRequest struct {
	Reason string `json:"reason,omitempty"`
}

type findingAnnotationResponse struct {
	RequestID string            `json:"request_id"`
	FindingID string            `json:"finding_id"`
	Provider  string            `json:"provider"`
	Object    map[string]string `json:"object"`
	Status    string            `json:"status"`
}

func (a *API) scanAnnotationRoutes() []route {
	return []route{
		{method: "POST", path: "/api/v1/discovery/findings/{id}/annotate", opID: "annotateFindingAtProvider",
			summary: "Write a leaked-secret finding back at the provider where the credential was seen",
			handler: a.annotateFindingAtProvider, pathParams: []param{pathUUID("id")}, reqSchema: "FindingAnnotationRequest", reqOptional: true,
			resSchema: "FindingAnnotationResult", successCode: "202", mutation: true, perm: authz.ConnectorsWrite},
	}
}

//trstctl:mutation
func (a *API) annotateFindingAtProvider(w http.ResponseWriter, r *http.Request) {
	idempotencyKey := r.Header.Get("Idempotency-Key")
	findingID := r.PathValue("id")
	var request FindingAnnotationRequest
	if r.ContentLength != 0 {
		if err := decodeJSON(r, &request); err != nil {
			a.writeError(w, errWithStatus(http.StatusBadRequest, err))
			return
		}
	}
	request.Reason = strings.TrimSpace(request.Reason)
	principal, _ := r.Context().Value(principalCtxKey).(authz.Principal)
	binding, err := json.Marshal(struct {
		Domain    string `json:"domain"`
		Actor     string `json:"actor"`
		FindingID string `json:"finding_id"`
		Reason    string `json:"reason"`
	}{"trstctl.scan-annotation.v1", principal.Subject, findingID, request.Reason})
	if err != nil {
		a.writeError(w, err)
		return
	}
	a.mutateDurableBound(w, r, idempotencyKey, crypto.SHA256Hex(binding), func(ctx context.Context, tenantID string) (int, any, error) {
		if a.orch == nil {
			return 0, nil, errors.New("scan annotation orchestrator is unavailable")
		}
		intent, err := a.findingAnnotationIntent(ctx, tenantID, findingID, request.Reason)
		if err != nil {
			return 0, nil, err
		}
		queued, err := a.orch.QueueFindingAnnotation(ctx, tenantID, crypto.SHA256Hex([]byte(tenantID+"\x00"+idempotencyKey)), principal.Subject, intent)
		if errors.Is(err, store.ErrIdempotencyConflict) {
			return 0, nil, errStatus(http.StatusConflict, "the finding changed after review; read it again")
		}
		if err != nil {
			return 0, nil, err
		}
		return http.StatusAccepted, findingAnnotationResponse{
			RequestID: queued.RequestID, FindingID: queued.FindingID, Provider: queued.Provider,
			Object: queued.Object, Status: orchestrator.AnnotationQueued,
		}, nil
	})
}

// findingAnnotationIntent checks the finding came from a third-party scan
// whose source has an annotation connection, and that trstctl knows where
// at the provider the credential was seen.
func (a *API) findingAnnotationIntent(ctx context.Context, tenantID, findingID, reason string) (orchestrator.FindingAnnotationIntent, error) {
	finding, err := a.store.GetDiscoveryFinding(ctx, tenantID, findingID)
	if errors.Is(err, pgx.ErrNoRows) {
		return orchestrator.FindingAnnotationIntent{}, errStatus(http.StatusNotFound, "no such discovery finding")
	}
	if err != nil {
		return orchestrator.FindingAnnotationIntent{}, err
	}
	var meta struct {
		Capability     string            `json:"capability"`
		RuleID         string            `json:"rule_id"`
		ProviderObject map[string]string `json:"provider_object"`
	}
	_ = json.Unmarshal(finding.Metadata, &meta)
	if finding.Kind != "leaked_secret" {
		return orchestrator.FindingAnnotationIntent{}, errStatus(http.StatusConflict, "only leaked secret findings are annotated at their provider")
	}
	source, err := a.store.GetDiscoverySource(ctx, tenantID, finding.SourceID)
	if err != nil {
		return orchestrator.FindingAnnotationIntent{}, errStatus(http.StatusConflict, "the scan source that found this credential is gone")
	}
	provider := ""
	switch {
	case source.Kind == secretscan.RepositorySourceKind:
		// A174-L5: a first-party repository scan annotates through GitHub
		// code scanning.
		var cfg secretscan.RepositoryScanConfig
		if err := json.Unmarshal(source.Config, &cfg); err != nil || cfg.AnnotationProvider() == "" {
			return orchestrator.FindingAnnotationIntent{}, errStatus(http.StatusConflict,
				"the repository scan that found this credential has no annotation connection; send the GitHub push with annotation.base_url and annotation.token_ref")
		}
		provider = cfg.AnnotationProvider()
	case meta.Capability == "CAP-SCAN-04":
		var cfg secretscan.ThirdPartyScanConfig
		if err := json.Unmarshal(source.Config, &cfg); err != nil || cfg.Annotation == nil {
			return orchestrator.FindingAnnotationIntent{}, errStatus(http.StatusConflict,
				"the scan that found this credential has no annotation connection; ingest it with annotation.base_url and annotation.token_ref")
		}
		provider = cfg.AnnotationProvider()
	default:
		return orchestrator.FindingAnnotationIntent{}, errStatus(http.StatusConflict, "only third-party and repository scan findings are annotated at their provider")
	}
	if len(meta.ProviderObject) == 0 {
		return orchestrator.FindingAnnotationIntent{}, errStatus(http.StatusConflict,
			"trstctl could not tell which message, issue, commit or image this credential was seen in, so there is nowhere to annotate")
	}
	return orchestrator.FindingAnnotationIntent{
		FindingID: finding.ID, SourceID: finding.SourceID, Provider: provider, Rule: meta.RuleID,
		Location: finding.Ref, DetectedAt: finding.DiscoveredAt.UTC().Format(time.RFC3339), Object: meta.ProviderObject, Reason: reason,
	}, nil
}

// requireAnnotationAllowed holds an ingest's annotation connection to the
// same rules as a discovery source's provider connection: a private endpoint
// needs the private-egress grant and its CIDRs, and every reference must be
// one the installation allows.
func (a *API) requireAnnotationAllowed(ctx context.Context, tenantID string, ann *secretscan.AnnotationConfig) error {
	if ann == nil {
		return nil
	}
	return a.requireConnectionAllowed(ctx, tenantID, ann)
}

// requireCollectAllowed holds a native collection's connection (N6) to the
// same rules as an annotation's: private egress needs its permission, and its
// credential references must be operator-approved.
func (a *API) requireCollectAllowed(ctx context.Context, tenantID string, collect *secretscan.CollectConfig) error {
	if collect == nil {
		return nil
	}
	return a.requireConnectionAllowed(ctx, tenantID, collect)
}

func (a *API) requireConnectionAllowed(ctx context.Context, tenantID string, connection any) error {
	raw, err := json.Marshal(connection)
	if err != nil {
		return err
	}
	private, err := discoveryPrivateEgressRequested(raw)
	if err != nil {
		return err
	}
	if private {
		if err := a.requirePrivateEgressPermission(ctx, tenantID); err != nil {
			return err
		}
	}
	return a.requireDiscoveryCredentialRefsAllowed(raw)
}
