// SPDX-License-Identifier: BUSL-1.1

package evaluate

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"trstctl.com/trstctl/internal/crypto"
)

// The incident journey (A249). It responds to a compromise of the key behind
// the certificate the certificate journey left deployed, the way an operator
// would: the effect-free compromise preview, a game day that rehearses the
// response before anything is done, the one reviewed command that revokes the
// certificate at its CA and stops the listener serving it, and checks of both
// from where the evaluator runs.

// JourneyIncident is the incident journey.
const JourneyIncident = "incident"

// The incident journey's steps, in order.
const (
	StepIncidentPreview  = "incident_preview"
	StepIncidentRehearse = "incident_rehearse"
	StepIncidentContain  = "incident_contain"
	StepIncidentVerify   = "incident_verify"
)

// compromisePlan is the effect-free key-compromise preview, as far as the
// journey reads and echoes it.
type compromisePlan struct {
	Ready              bool   `json:"ready"`
	EffectFree         bool   `json:"effect_free"`
	IdentityID         string `json:"identity_id"`
	ExpectedVersion    int64  `json:"expected_version"`
	PreviewFingerprint string `json:"preview_fingerprint"`
	Target             struct {
		Ready               bool   `json:"ready"`
		TargetID            string `json:"target_id"`
		TargetName          string `json:"target_name"`
		TargetRevision      string `json:"target_revision"`
		Connector           string `json:"connector"`
		ExpectedFingerprint string `json:"expected_fingerprint"`
		RequiredAgentID     string `json:"required_agent_id"`
	} `json:"target"`
	Certificates []struct {
		ID          string `json:"id"`
		Fingerprint string `json:"fingerprint"`
		Authority   string `json:"authority"`
	} `json:"certificates"`
	Warnings []string `json:"warnings"`
}

// sameFingerprint compares SHA-256 fingerprints written with or without a
// prefix, colons or upper case.
func sameFingerprint(a, b string) bool {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimPrefix(s, "sha256:")
		return strings.ReplaceAll(s, ":", "")
	}
	return a != "" && norm(a) == norm(b)
}

func (j *journey) incidentJourney(ctx context.Context) JourneyResult {
	t := j.track(JourneyIncident)
	limits := []string{
		"The incident journey responds to a compromise of the certificate journey's own identity on the lab target: it revokes the certificate that identity serves and stops the listener serving it.",
		"The game day is a static preview and a mocked rehearsal; neither ran against a target, and their labels say so.",
	}
	steps := []string{StepIncidentPreview, StepIncidentRehearse, StepIncidentContain, StepIncidentVerify}
	if j.failed != "" || j.identity == "" || j.renewed.Fingerprint == "" || len(j.servedChain) == 0 || len(j.issued.Chain) < 2 {
		for _, name := range steps {
			t.step(ctx, name, func(context.Context, *Step) error {
				return skippedStep{"Skipped because the certificate journey left no deployed identity to respond for."}
			})
		}
		return t.finish(limits...)
	}
	compromised, issuer := j.servedChain[0], j.issued.Chain[1]
	containKey := j.key("incident-contain")
	var plan compromisePlan

	t.step(ctx, StepIncidentPreview, func(ctx context.Context, s *Step) error {
		if err := j.api.post(ctx, "/api/v1/identities/"+url.PathEscape(j.identity)+"/compromise/preview",
			map[string]any{"target_id": j.pack.Target.DeploymentTargetID}, "", &plan); err != nil {
			return fmt.Errorf("the compromise preview was refused: %w", err)
		}
		served := false
		for _, c := range plan.Certificates {
			served = served || sameFingerprint(c.Fingerprint, j.renewed.Fingerprint)
		}
		switch {
		case !plan.EffectFree:
			return errors.New("the compromise preview says it had effects")
		case !plan.Ready:
			return fmt.Errorf("the compromise preview is not ready: %s", firstNonEmpty(strings.Join(plan.Warnings, "; "), "no reason given"))
		case !sameFingerprint(plan.Target.ExpectedFingerprint, j.renewed.Fingerprint):
			return fmt.Errorf("the preview would stop %s serving %s, not the deployed %s",
				plan.Target.TargetName, short(plan.Target.ExpectedFingerprint), short(j.renewed.Fingerprint))
		case !served:
			return fmt.Errorf("the preview's revocations do not include the deployed certificate %s", short(j.renewed.Fingerprint))
		}
		s.Basis = BasisRecorded
		s.Evidence["preview_fingerprint"] = plan.PreviewFingerprint
		s.Evidence["certificates"] = strconv.Itoa(len(plan.Certificates))
		s.Detail = fmt.Sprintf("The effect-free preview plans to revoke %d %s at the issuing CA, the deployed %s among them, and to have agent %s stop %s serving it.",
			len(plan.Certificates), plural(len(plan.Certificates), "certificate", "certificates"), short(j.renewed.Fingerprint),
			plan.Target.RequiredAgentID, plan.Target.TargetName)
		return nil
	})

	t.step(ctx, StepIncidentRehearse, func(ctx context.Context, s *Step) error {
		var scenario struct {
			ID string `json:"id"`
		}
		if err := j.api.post(ctx, "/api/v1/rehearsals/scenarios", map[string]any{
			"name":      "trstctl evaluate " + strings.TrimSuffix(j.keyPrefix, "-") + ": compromised key",
			"kind":      "revoked_credential",
			"candidate": map[string]string{"kind": "identity", "ref": j.identity},
			"data_set":  map[string]any{"kind": "identities", "identity_ids": []string{j.identity}},
		}, j.key("incident-scenario"), &scenario); err != nil {
			return fmt.Errorf("saving the game-day scenario was refused: %w", err)
		}
		var labels []string
		for _, mode := range []string{"static_preview", "mocked_rehearsal"} {
			var run struct {
				ID      string `json:"id"`
				Status  string `json:"status"`
				Verdict string `json:"verdict"`
				Label   string `json:"label"`
				Detail  string `json:"detail"`
			}
			if err := j.api.post(ctx, "/api/v1/rehearsals/scenarios/"+url.PathEscape(scenario.ID)+"/runs",
				map[string]string{"mode": mode}, j.key("incident-"+mode), &run); err != nil {
				return fmt.Errorf("the game day's %s was refused: %w", mode, err)
			}
			if err := j.poll(ctx, "the game day's "+mode+" did not complete", func(ctx context.Context) (bool, error) {
				if run.Status == "completed" {
					return true, nil
				}
				return false, j.api.get(ctx, "/api/v1/rehearsals/runs/"+url.PathEscape(run.ID), &run)
			}); err != nil {
				return err
			}
			if run.Verdict != "matched" {
				return fmt.Errorf("the game day's %s is %s: %s", mode, firstNonEmpty(run.Label, run.Verdict), firstNonEmpty(run.Detail, "no detail"))
			}
			labels = append(labels, run.Label)
			s.Evidence[mode+"_run"] = run.ID
		}
		s.Basis = BasisRecorded
		s.Evidence["scenario_id"] = scenario.ID
		s.Detail = fmt.Sprintf("A revoked-credential game day for identity %s: %s. Neither run touched a target.", j.identity, strings.Join(labels, ", "))
		return nil
	})

	t.step(ctx, StepIncidentContain, func(ctx context.Context, s *Step) error {
		body := map[string]any{
			"target_id": plan.Target.TargetID, "target_revision": plan.Target.TargetRevision, "target_name": plan.Target.TargetName,
			"connector": plan.Target.Connector, "identity_id": j.identity, "expected_fingerprint": plan.Target.ExpectedFingerprint,
			"required_agent_id": plan.Target.RequiredAgentID, "expected_version": plan.ExpectedVersion, "preview_fingerprint": plan.PreviewFingerprint,
		}
		if _, err := j.api.do(ctx, http.MethodPost, "/api/v1/identities/"+url.PathEscape(j.identity)+"/compromise", body, containKey); err != nil {
			return fmt.Errorf("the reviewed compromise response was refused: %w", err)
		}
		var result struct {
			Revocation struct {
				Status    string `json:"status"`
				LastError string `json:"last_error"`
			} `json:"revocation"`
			Containment struct {
				ID     string `json:"id"`
				Status string `json:"status"`
				Detail string `json:"detail"`
			} `json:"containment"`
		}
		if err := j.poll(ctx, "the CA revocation and the host's containment did not both finish", func(ctx context.Context) (bool, error) {
			if err := j.api.get(ctx, "/api/v1/identities/"+url.PathEscape(j.identity)+"/compromise?request_key="+url.QueryEscape(containKey), &result); err != nil {
				return false, err
			}
			switch result.Containment.Status {
			case "containment_different_leaf", "containment_unverified", "containment_failed", "cancelled":
				return false, fmt.Errorf("the host reported %s: %s", result.Containment.Status, firstNonEmpty(result.Containment.Detail, "no detail"))
			}
			if result.Revocation.Status == "failed" {
				return false, fmt.Errorf("the CA revocation failed: %s", firstNonEmpty(result.Revocation.LastError, "no detail"))
			}
			return result.Revocation.Status == "delivered" && result.Containment.Status == "containment_stopped", nil
		}); err != nil {
			return err
		}
		s.Basis = BasisRecorded
		s.Evidence["revocation_status"], s.Evidence["containment_status"], s.Evidence["containment_id"] =
			result.Revocation.Status, result.Containment.Status, result.Containment.ID
		s.Detail = fmt.Sprintf("One reviewed command revoked the compromised certificate at its CA (%s) and the host agent stopped %s serving it (%s, receipt %s).",
			result.Revocation.Status, plan.Target.TargetName, result.Containment.Status, result.Containment.ID)
		return nil
	})

	t.step(ctx, StepIncidentVerify, func(ctx context.Context, s *Step) error {
		if err := crypto.VerifyLeafSignedByCA(compromised, issuer); err != nil {
			return fmt.Errorf("the served certificate does not chain to the issuing CA the journey holds: %w", err)
		}
		status, responder, err := j.awaitOCSP(ctx, compromised, issuer, "revoked")
		if err != nil {
			return err
		}
		if t.result.ForcedFailure {
			return fmt.Errorf("expected the compromised certificate to still answer good over OCSP, and %s says %s", responder, status.Status)
		}
		var observed string
		if err := j.poll(ctx, "the endpoint still serves the compromised certificate", func(ctx context.Context) (bool, error) {
			result, err := j.opts.Probe(ctx, j.pack.Target.Endpoint, j.pack.Target.Name)
			switch {
			case err != nil:
				observed = "refused the handshake"
			case len(result.PeerCertificates) == 0:
				observed = "presented no certificate"
			case !sameFingerprint(crypto.SHA256Hex(result.PeerCertificates[0]), j.renewed.Fingerprint):
				observed = "served another certificate (" + short(crypto.SHA256Hex(result.PeerCertificates[0])) + ")"
			default:
				return false, nil
			}
			return true, nil
		}); err != nil {
			return err
		}
		s.Basis = BasisObserved
		s.Evidence["ocsp_responder"], s.Evidence["ocsp_status"], s.Evidence["endpoint"] = responder, status.Status, observed
		s.Detail = fmt.Sprintf("An OCSP request to %s returned a signed answer saying the compromised certificate is revoked, and %s %s to this evaluator.",
			responder, j.pack.Target.Endpoint, observed)
		return nil
	})
	return t.finish(limits...)
}
