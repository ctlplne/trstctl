// SPDX-License-Identifier: BUSL-1.1

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"trstctl.com/trstctl/internal/orchestrator"
	"trstctl.com/trstctl/internal/scanannotate"
	"trstctl.com/trstctl/internal/secretscan"
	"trstctl.com/trstctl/internal/store"
)

// The control-plane executor of a finding annotation (A174): it reopens the
// scan source's annotation connection, resolves the token reference, writes
// the note at the provider and records what the provider confirmed on the
// finding. Throttling, the provider's own failures and the network leave the
// row to retry; any other refusal is recorded as failed with the provider's
// answer, because it would fail the same way every time.
func (d *issuanceDispatcher) handleScanAnnotation(ctx context.Context, m orchestrator.Message) error {
	if d.store == nil || d.orch == nil {
		return errors.New("server: scan annotations are not configured")
	}
	var in orchestrator.FindingAnnotationIntent
	if err := json.Unmarshal(m.Payload, &in); err != nil || strings.TrimSpace(in.RequestID) == "" || strings.TrimSpace(in.SourceID) == "" {
		return orchestrator.DefiniteNoEffect(errors.New("server: scan annotation row is malformed"))
	}
	fail := func(detail string) error {
		if err := d.orch.RecordFindingAnnotation(ctx, m.TenantID, in, orchestrator.AnnotationFailed, "", detail); err != nil {
			return err
		}
		return orchestrator.DefiniteNoEffect(errors.New("server: scan annotation failed: " + detail))
	}
	source, err := d.store.GetDiscoverySource(ctx, m.TenantID, in.SourceID)
	if err != nil {
		return fail("the scan source that found the credential is gone")
	}
	var cfg secretscan.ThirdPartyScanConfig
	if err := json.Unmarshal(source.Config, &cfg); err != nil || cfg.Annotation == nil {
		return fail("the scan source no longer has an annotation connection")
	}
	conn := cfg.Annotation
	token, err := resolveDiscoveryCredentialRef(ctx, conn.TokenRef)
	if err != nil {
		return fail("resolve the annotation token reference: " + err.Error())
	}
	username := ""
	if strings.TrimSpace(conn.UsernameRef) != "" {
		if username, err = resolveDiscoveryCredentialRef(ctx, conn.UsernameRef); err != nil {
			return fail("resolve the annotation username reference: " + err.Error())
		}
	}
	client, err := cloudHTTPClient(conn.BaseURL, conn.AllowPrivateEndpoint, conn.PrivateEgressCIDRs)
	if err != nil {
		return fail("the annotation endpoint is refused: " + err.Error())
	}
	annotator, closeAnnotator, err := scanannotate.New(scanannotate.Connection{Provider: in.Provider, BaseURL: conn.BaseURL,
		Token: []byte(token), Username: username, Doer: client})
	if err != nil {
		return fail(err.Error())
	}
	defer closeAnnotator()
	annotation := scanannotate.Annotation{
		FindingID: in.FindingID, Rule: in.Rule, Location: in.Location, DetectedAt: in.DetectedAt,
		Object: annotationObject(in.Object), Retry: m.Attempts > 0,
	}
	if annotation.Retry && in.Action != orchestrator.FindingActionResolveAnnotation {
		annotation.EarlierOutcomeUnknown = d.annotationOutcomeUnknown(ctx, m.TenantID, in)
	}
	if in.Action == orchestrator.FindingActionResolveAnnotation {
		return d.resolveScanAnnotation(ctx, m, in, annotator, annotation, fail)
	}
	result, err := annotator.Annotate(ctx, annotation)
	if err != nil {
		if scanannotate.Retryable(err) {
			if errors.Is(err, scanannotate.ErrOutcomeUnknown) {
				if recErr := d.orch.RecordFindingAnnotationUnconfirmed(ctx, m.TenantID, in,
					"the note reached the provider but its answer was lost; the next attempt looks for it before writing again"); recErr != nil {
					return recErr
				}
			}
			return fmt.Errorf("server: scan annotation: %w", err)
		}
		return fail(err.Error())
	}
	status := orchestrator.AnnotationConfirmed
	if result.Status == scanannotate.AlreadyPresent {
		status = orchestrator.AnnotationAlreadyPresent
	}
	return d.orch.RecordFindingAnnotation(ctx, m.TenantID, in, status, result.ProviderRef, result.Detail)
}

// annotationOutcomeUnknown reports whether this request's earlier attempt
// left its annotation unconfirmed: its write reached the provider and the
// answer was lost (A174-L4). A finding that cannot be read counts as unknown,
// so a retry errs toward not writing twice.
func (d *issuanceDispatcher) annotationOutcomeUnknown(ctx context.Context, tenantID string, in orchestrator.FindingAnnotationIntent) bool {
	finding, err := d.store.GetDiscoveryFinding(ctx, tenantID, in.FindingID)
	if err != nil {
		return true
	}
	var meta struct {
		ProviderActions map[string]struct {
			Status    string `json:"status"`
			RequestID string `json:"request_id"`
		} `json:"provider_actions"`
	}
	if json.Unmarshal(finding.Metadata, &meta) != nil {
		return true
	}
	state, ok := meta.ProviderActions[orchestrator.FindingActionAnnotate]
	return ok && state.Status == orchestrator.AnnotationUnconfirmed && state.RequestID == in.RequestID
}

// resolveScanAnnotation settles a resolved finding's annotation at its
// provider (A174-L1): the Slack reply deleted, the Jira comment rewritten,
// the CI status set to success, the image referrer deleted.
func (d *issuanceDispatcher) resolveScanAnnotation(ctx context.Context, m orchestrator.Message, in orchestrator.FindingAnnotationIntent,
	annotator scanannotate.Annotator, annotation scanannotate.Annotation, fail func(string) error) error {
	resolver, ok := annotator.(scanannotate.Resolver)
	if !ok {
		return fail("this provider's annotations cannot be settled")
	}
	result, err := resolver.Resolve(ctx, annotation, in.ProviderRef)
	if err != nil {
		if scanannotate.Retryable(err) {
			return fmt.Errorf("server: resolve scan annotation: %w", err)
		}
		return fail(err.Error())
	}
	status := orchestrator.AnnotationResolved
	if result.Status == scanannotate.AlreadyResolved {
		status = orchestrator.AnnotationAlreadyResolved
	}
	return d.orch.RecordFindingAnnotation(ctx, m.TenantID, in, status, result.ProviderRef, result.Detail)
}

func annotationObject(o map[string]string) scanannotate.Object {
	return scanannotate.Object{
		Channel: o["channel"], ChannelID: o["channel_id"], MessageTS: o["message_ts"], ThreadTS: o["thread_ts"],
		IssueKey: o["issue_key"], Repo: o["repo"], CommitSHA: o["commit_sha"], Repository: o["repository"], Digest: o["digest"],
	}
}

// thirdPartyFindingObject is the provider object of a third-party finding,
// recorded on the finding so an annotation knows where to write and the
// console can say where the credential was seen.
func thirdPartyFindingObject(cfg secretscan.ThirdPartyScanConfig, artifactPath string, f secretscan.Finding) map[string]string {
	object, ok := cfg.ProviderObject(artifactPath, f.File, f.Line)
	if !ok {
		return nil
	}
	return object
}

// autoAnnotate queues the annotation of a new finding when its source asks
// for it. The request key is the finding, so a run that records the same
// finding again does not annotate twice.
func (d *issuanceDispatcher) autoAnnotate(ctx context.Context, tenantID string, cfg secretscan.ThirdPartyScanConfig, finding store.DiscoveryFinding, rule string, object map[string]string) error {
	if cfg.Annotation == nil || !cfg.Annotation.Auto || len(object) == 0 {
		return nil
	}
	_, err := d.orch.QueueFindingAnnotation(ctx, tenantID, "auto:"+finding.ID, "system:discovery", orchestrator.FindingAnnotationIntent{
		FindingID: finding.ID, SourceID: finding.SourceID, Provider: cfg.AnnotationProvider(), Rule: rule,
		Location: finding.Ref, DetectedAt: finding.DiscoveredAt.UTC().Format(time.RFC3339), Object: object,
	})
	return err
}
